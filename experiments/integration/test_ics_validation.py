"""
test_ics_validation.py — ICS/OT Constraint Validation Suite.

Validates Phases 1+2 against realistic ICS protocol constraint patterns:
  - Modbus RTU: 5 walls (TID, PID, UID whitelist, FC dispatch, CRC-16)
  - IEC-104:    4 walls (Start byte, APDU length, I/S/U format, Sequence number)

Run:  python experiments/integration/test_ics_validation.py
"""
from __future__ import annotations
import asyncio, json, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.constants import Architecture, ConstraintTag, Z3Verdict
from agentic_afl.extractor.constraint_profiler import ConstraintProfiler
from agentic_afl.extractor.pcode_slicer import PCodeSlicer
from agentic_afl.extractor.spec_exporter import SpecExporter
from agentic_afl.models import Z3Script
from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox

FIXTURES = Path(__file__).resolve().parents[1] / "test_targets" / "pcode_fixtures"
profiler = ConstraintProfiler()
sandbox = Z3Sandbox(timeout_seconds=5)

# ── Test Definitions ─────────────────────────────────────────────────
# (fixture_file, expected_tags, z3_script, expected_model_check)

WALL_TESTS = [
    # ── Modbus RTU ──
    (
        "modbus_rtu_wall1_tid.json",
        "Modbus: Transaction ID",
        {ConstraintTag.CONSTANT_EQUALITY},
        """
tid_hi = BitVec('tid_hi', 8)
tid_lo = BitVec('tid_lo', 8)
tid = Concat(tid_hi, tid_lo)
s.add(tid == BitVecVal(0x0001, 16))
""",
        {"tid_hi": 0x00, "tid_lo": 0x01},
    ),
    (
        "modbus_rtu_wall2_pid.json",
        "Modbus: Protocol ID",
        {ConstraintTag.CONSTANT_EQUALITY},
        """
pid_hi = BitVec('pid_hi', 8)
pid_lo = BitVec('pid_lo', 8)
pid = Concat(pid_hi, pid_lo)
s.add(pid == BitVecVal(0x0000, 16))
""",
        {"pid_hi": 0x00, "pid_lo": 0x00},
    ),
    (
        "modbus_rtu_wall3_uid.json",
        "Modbus: Unit ID Whitelist",
        {ConstraintTag.CONSTANT_EQUALITY},  # 4x INT_EQUAL → STATE_MACHINE too
        """
uid = BitVec('uid', 8)
s.add(Or(uid == 1, uid == 2, uid == 10, uid == 255))
""",
        None,  # Any of {1,2,10,255} is valid
    ),
    (
        "modbus_rtu_wall4_fc.json",
        "Modbus: Function Code",
        # A function-code whitelist (1<=fc<=6 OR fc==15 OR fc==16) profiles
        # structurally as a bounded range + discrete equalities. The old
        # dedicated FUNCTION_CODE_DISPATCH tag was consolidated out of the
        # ontology; RANGE_BOUND is the structural signal the profiler
        # actually and correctly emits for this pattern.
        {ConstraintTag.RANGE_BOUND},
        """
fc = BitVec('fc', 8)
s.add(Or(
    And(UGE(fc, 1), ULE(fc, 6)),
    fc == 15,
    fc == 16
))
""",
        None,  # Any valid FC
    ),
    (
        "modbus_rtu_wall5_crc.json",
        "Modbus: CRC-16",
        {ConstraintTag.BITWISE_LOOP},
        """
# Simplified: just prove CRC function is satisfiable
data_byte = BitVec('data_byte', 8)
crc_lo = BitVec('crc_lo', 8)
crc_hi = BitVec('crc_hi', 8)
# CRC of single byte 0x01 with Modbus poly = 0x807E (precomputed)
s.add(data_byte == BitVecVal(0x01, 8))
s.add(crc_lo == BitVecVal(0x7E, 8))
s.add(crc_hi == BitVecVal(0x80, 8))
""",
        {"data_byte": 0x01, "crc_lo": 0x7E, "crc_hi": 0x80},
    ),
    # ── IEC-104 ──
    (
        "iec104_wall1_start.json",
        "IEC-104: Start Byte",
        {ConstraintTag.CONSTANT_EQUALITY},
        """
start = BitVec('start', 8)
s.add(start == BitVecVal(0x68, 8))
""",
        {"start": 0x68},
    ),
    (
        "iec104_wall2_length.json",
        "IEC-104: APDU Length",
        {ConstraintTag.RANGE_BOUND},
        """
apdu_len = BitVec('apdu_len', 8)
s.add(UGE(apdu_len, 4))
s.add(ULE(apdu_len, 253))
""",
        None,  # Any value in [4,253]
    ),
    (
        "iec104_wall3_format.json",
        "IEC-104: Frame Format",
        {ConstraintTag.BITMASK_CHECK},
        """
ctrl = BitVec('ctrl', 8)
fmt = ctrl & 0x03
s.add(Or(fmt == 0, fmt == 1, fmt == 3))
""",
        None,  # Any valid format bits
    ),
    (
        "iec104_wall4_seqnum.json",
        "IEC-104: Sequence Number",
        {ConstraintTag.BITMASK_CHECK},  # INT_AND with 0x7fff
        """
ctrl_lo = BitVec('ctrl_lo', 8)
ctrl_hi = BitVec('ctrl_hi', 8)
ctrl_word = Concat(ctrl_hi, ctrl_lo)
ssn = (ctrl_word >> 1) & 0x7FFF
s.add(ssn == BitVecVal(0x0000, 16))
""",
        None,
    ),
]


def run_test(fixture_file, name, expected_tags, z3_code, expected_model):
    """Run a single wall test: load fixture → profile → Z3 solve."""
    fixture_path = FIXTURES / fixture_file
    assert fixture_path.exists(), f"Fixture not found: {fixture_path}"

    # Phase A: Load and profile
    pslice = PCodeSlicer.from_json_file(fixture_path)
    profile = profiler.analyze(pslice)

    # Check expected tags
    missing = expected_tags - profile.tags
    assert not missing, (
        f"Missing tags: {[t.name for t in missing]}. "
        f"Got: {[t.name for t in profile.tags]}"
    )
    tag_names = [t.name for t in profile.tags]

    # Phase B: Export (JSON fallback)
    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = SpecExporter(json_dir=Path(tmpdir))
        spec = asyncio.run(exporter.export(pslice, profile))
        assert spec.spec_id

    # Phase C: Z3 solve
    script = Z3Script(script_text=z3_code, generation_idx=0, attempt_number=1)
    result = asyncio.run(sandbox.execute(script))
    assert result.verdict == Z3Verdict.SAT, (
        f"Expected SAT, got {result.verdict}: {result.error_message}"
    )

    # Check model values if specified
    if expected_model:
        for var, expected_val in expected_model.items():
            actual = result.model.get(var)
            assert actual == expected_val, (
                f"{var}: expected {expected_val:#x}, got {actual:#x}"
            )

    print(f"  ✓ Tags: {tag_names} | Complexity: {profile.estimated_complexity}")
    print(f"    Z3: SAT in {result.execution_time:.3f}s | Model: {result.model}")


def main():
    print("=" * 70)
    print("ICS/OT Constraint Validation Suite")
    print("=" * 70)

    passed = failed = 0
    for fixture, name, tags, z3, model in WALL_TESTS:
        print(f"\n▸ {name} ({fixture})")
        try:
            run_test(fixture, name, tags, z3, model)
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}")
            import traceback; traceback.print_exc()

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All ICS validation tests PASSED")


if __name__ == "__main__":
    main()
