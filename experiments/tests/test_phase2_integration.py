"""
test_phase2_integration.py — End-to-End Phase 2 Tests.

Tests the full data pipeline:
    JSON Slice → ConstraintProfiler → SpecExporter → LLM Client (mocked) → Z3 Sandbox → Verdict

Run with:
    cd <project_root>
    source venv/bin/activate
    python -m pytest experiments/tests/test_phase2_integration.py -v

Or run standalone:
    python experiments/tests/test_phase2_integration.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

# Ensure the project root is on the path.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PROJECT_ROOT))

from agentic_afl.constants import Architecture, ConstraintTag, Z3Verdict
from agentic_afl.extractor.constraint_profiler import ConstraintProfiler
from agentic_afl.extractor.pcode_slicer import PCodeSlicer
from agentic_afl.extractor.spec_exporter import SpecExporter
from agentic_afl.models import (
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
    Z3GenerationRequest,
    Z3Script,
)
from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox


# ============================================================================
# Test Fixtures: Synthetic P-Code Slices
# ============================================================================


def _make_wall1_slice() -> PCodeSlice:
    """Wall 1: Magic number check — byte0:byte1 == 0x5A01."""
    instructions = [
        PCodeInstruction(
            address="0x101200",
            mnemonic="LOAD",
            inputs=["(const, 0x1b1, 4)", "(register, RDI, 8)"],
            output="(unique, 0x100@101200, 1)",
            raw_pcode="(unique, 0x100@101200, 1) = LOAD (const, 0x1b1, 4) (register, RDI, 8)",
        ),
        PCodeInstruction(
            address="0x101204",
            mnemonic="LOAD",
            inputs=["(const, 0x1b1, 4)", "(unique, 0x200@101204, 8)"],
            output="(unique, 0x300@101204, 1)",
            raw_pcode="(unique, 0x300@101204, 1) = LOAD (const, 0x1b1, 4) (unique, 0x200@101204, 8)",
        ),
        PCodeInstruction(
            address="0x101210",
            mnemonic="INT_ADD",
            inputs=["(register, RDI, 8)", "(const, 0x1, 8)"],
            output="(unique, 0x200@101204, 8)",
            raw_pcode="(unique, 0x200@101204, 8) = INT_ADD (register, RDI, 8) (const, 0x1, 8)",
        ),
        PCodeInstruction(
            address="0x101220",
            mnemonic="PIECE",
            inputs=["(unique, 0x100@101200, 1)", "(unique, 0x300@101204, 1)"],
            output="(unique, 0x400@101220, 2)",
            raw_pcode="(unique, 0x400@101220, 2) = PIECE (unique, 0x100@101200, 1) (unique, 0x300@101204, 1)",
        ),
        PCodeInstruction(
            address="0x101230",
            mnemonic="INT_EQUAL",
            inputs=["(unique, 0x400@101220, 2)", "(const, 0x5a01, 2)"],
            output="(unique, 0x500@101230, 1)",
            raw_pcode="(unique, 0x500@101230, 1) = INT_EQUAL (unique, 0x400@101220, 2) (const, 0x5a01, 2)",
        ),
        PCodeInstruction(
            address="0x101234",
            mnemonic="CBRANCH",
            inputs=["(ram, 0x101250, 8)", "(unique, 0x500@101230, 1)"],
            output=None,
            raw_pcode="CBRANCH (ram, 0x101250, 8) (unique, 0x500@101230, 1)",
        ),
    ]

    return PCodeSlice(
        binary_path=Path("./test_binary"),
        stall_address="0x101234",
        function_name="check_magic",
        function_entry="0x101200",
        instructions=instructions,
        taint_source="RDI",
        slice_depth=5,
        truncated=False,
        architecture=Architecture.X86_64,
    )


def _make_wall3_slice() -> PCodeSlice:
    """Wall 3: Function code range — fc must be in [1, 6]."""
    instructions = [
        PCodeInstruction(
            address="0x101250",
            mnemonic="LOAD",
            inputs=["(const, 0x1b1, 4)", "(register, RDI, 8)"],
            output="(unique, 0x100@101250, 1)",
            raw_pcode="(unique, 0x100@101250, 1) = LOAD (const, 0x1b1, 4) (register, RDI, 8)",
        ),
        PCodeInstruction(
            address="0x101254",
            mnemonic="CAST",
            inputs=["(unique, 0x100@101250, 1)"],
            output="(unique, 0x200@101254, 4)",
            raw_pcode="(unique, 0x200@101254, 4) = CAST (unique, 0x100@101250, 1)",
        ),
        PCodeInstruction(
            address="0x101258",
            mnemonic="INT_SUB",
            inputs=["(unique, 0x200@101254, 4)", "(const, 0x1, 4)"],
            output="(unique, 0x300@101258, 4)",
            raw_pcode="(unique, 0x300@101258, 4) = INT_SUB (unique, 0x200@101254, 4) (const, 0x1, 4)",
        ),
        PCodeInstruction(
            address="0x10125c",
            mnemonic="INT_LESS",
            inputs=["(unique, 0x300@101258, 4)", "(const, 0x6, 4)"],
            output="(unique, 0x400@10125c, 1)",
            raw_pcode="(unique, 0x400@10125c, 1) = INT_LESS (unique, 0x300@101258, 4) (const, 0x6, 4)",
        ),
        PCodeInstruction(
            address="0x101260",
            mnemonic="CBRANCH",
            inputs=["(ram, 0x101280, 8)", "(unique, 0x400@10125c, 1)"],
            output=None,
            raw_pcode="CBRANCH (ram, 0x101280, 8) (unique, 0x400@10125c, 1)",
        ),
    ]

    return PCodeSlice(
        binary_path=Path("./test_binary"),
        stall_address="0x101260",
        function_name="check_function_code",
        function_entry="0x101245",
        instructions=instructions,
        taint_source="RDI",
        slice_depth=5,
        truncated=False,
        architecture=Architecture.X86_64,
    )


# ============================================================================
# Test 1: Constraint Profiler
# ============================================================================


def test_profiler_wall1():
    """Wall 1 should produce CONSTANT_EQUALITY."""
    pslice = _make_wall1_slice()
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pslice)

    assert ConstraintTag.CONSTANT_EQUALITY in profile.tags, (
        f"Expected CONSTANT_EQUALITY in tags, got {profile.tags}"
    )
    print(f"  ✓ Wall 1 tags: {[t.name for t in profile.tags]}")
    print(f"    Complexity: {profile.estimated_complexity}")


def test_profiler_wall3():
    """Wall 3 should produce RANGE_BOUND or MULTI_WAY_BRANCH."""
    pslice = _make_wall3_slice()
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pslice)

    has_range = ConstraintTag.RANGE_BOUND in profile.tags
    has_fc = ConstraintTag.MULTI_WAY_BRANCH in profile.tags
    assert has_range or has_fc, (
        f"Expected RANGE_BOUND or MULTI_WAY_BRANCH, got {profile.tags}"
    )
    print(f"  ✓ Wall 3 tags: {[t.name for t in profile.tags]}")


# ============================================================================
# Test 2: Spec Exporter (JSON fallback)
# ============================================================================


def test_spec_exporter_roundtrip():
    """Export a spec to JSON and load it back."""
    pslice = _make_wall1_slice()
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pslice)

    with tempfile.TemporaryDirectory() as tmpdir:
        json_dir = Path(tmpdir)
        exporter = SpecExporter(json_dir=json_dir)

        # Export.
        spec = asyncio.run(
            exporter.export(pslice, profile)
        )

        assert spec.spec_id, "spec_id should be populated"
        assert spec.stall_address == "0x101234"
        assert spec.function_name == "check_magic"
        assert ConstraintTag.CONSTANT_EQUALITY in spec.constraint_profile.tags

        # Verify JSON file was created.
        json_path = json_dir / f"{spec.spec_id}.json"
        assert json_path.exists(), f"JSON file not created at {json_path}"

        # Load it back.
        loaded = asyncio.run(
            exporter.load_spec(spec.spec_id)
        )

        assert loaded is not None, "load_spec returned None"
        assert loaded.spec_id == spec.spec_id
        assert loaded.stall_address == spec.stall_address
        assert loaded.function_name == spec.function_name
        assert loaded.constraint_profile.tags == spec.constraint_profile.tags

        print(f"  ✓ Roundtrip OK: spec_id={spec.spec_id}")
        print(f"    JSON: {json_path}")
        print(f"    Tags: {[t.name for t in loaded.constraint_profile.tags]}")


# ============================================================================
# Test 3: LLM Client — Code Extraction (Mock)
# ============================================================================


def test_llm_code_extraction():
    """Test that _extract_z3_code correctly parses code blocks."""
    from agentic_afl.orchestrator.llm_client import _CODE_BLOCK_RE

    # Simulated LLM response with a Python code block.
    response = '''
Here is the Z3 script:

```python
byte0 = BitVec('byte0', 8)
byte1 = BitVec('byte1', 8)
s.add(Concat(byte0, byte1) == BitVecVal(0x5A01, 16))
```

This script models the magic number check.
'''

    matches = _CODE_BLOCK_RE.findall(response)
    assert len(matches) >= 1, f"Expected at least 1 code block, got {len(matches)}"

    code = matches[0].strip()
    assert "BitVec" in code, f"Extracted code missing BitVec: {code}"
    assert "Concat" in code, f"Extracted code missing Concat: {code}"

    print(f"  ✓ Code extraction OK ({len(code)} chars)")
    print(f"    First line: {code.splitlines()[0]}")


# ============================================================================
# Test 4: Z3 Sandbox — SAT (Magic Number)
# ============================================================================


def test_z3_sandbox_sat():
    """Execute a known-good Z3 script and verify SAT verdict."""
    z3_script = Z3Script(
        script_text="""
byte0 = BitVec('byte0', 8)
byte1 = BitVec('byte1', 8)
s.add(Concat(byte0, byte1) == BitVecVal(0x5A01, 16))
""",
        generation_idx=0,
        attempt_number=1,
    )

    sandbox = Z3Sandbox(timeout_seconds=5)
    result = asyncio.run(sandbox.execute(z3_script))

    assert result.verdict == Z3Verdict.SAT, (
        f"Expected SAT, got {result.verdict} (error: {result.error_message})"
    )
    assert result.model is not None, "SAT but no model returned"
    assert result.model.get("byte0") == 0x5A, (
        f"Expected byte0=0x5A, got {result.model.get('byte0')}"
    )
    assert result.model.get("byte1") == 0x01, (
        f"Expected byte1=0x01, got {result.model.get('byte1')}"
    )

    print(f"  ✓ SAT: {result.model}")
    print(f"    Exec time: {result.execution_time:.3f}s")


# ============================================================================
# Test 5: Z3 Sandbox — UNSAT
# ============================================================================


def test_z3_sandbox_unsat():
    """Execute a contradictory Z3 script and verify UNSAT."""
    z3_script = Z3Script(
        script_text="""
x = BitVec('x', 8)
s.add(x == BitVecVal(0x01, 8))
s.add(x == BitVecVal(0x02, 8))
""",
        generation_idx=0,
        attempt_number=1,
    )

    sandbox = Z3Sandbox(timeout_seconds=5)
    result = asyncio.run(sandbox.execute(z3_script))

    assert result.verdict == Z3Verdict.UNSAT, (
        f"Expected UNSAT, got {result.verdict}"
    )

    print(f"  ✓ UNSAT (as expected)")


# ============================================================================
# Test 6: Z3 Sandbox — Runtime Error
# ============================================================================


def test_z3_sandbox_runtime_error():
    """Execute a buggy Z3 script and verify error capture."""
    z3_script = Z3Script(
        script_text="""
# Deliberate error: undefined variable
s.add(undefined_var == 42)
""",
        generation_idx=0,
        attempt_number=1,
    )

    sandbox = Z3Sandbox(timeout_seconds=5)
    result = asyncio.run(sandbox.execute(z3_script))

    assert result.verdict in (Z3Verdict.RUNTIME_ERROR, Z3Verdict.SYNTAX_ERROR), (
        f"Expected error verdict, got {result.verdict}"
    )
    assert result.error_message, "Expected error message"

    print(f"  ✓ Error captured: {result.error_message[:80]}")


# ============================================================================
# Test 7: PCodeSlicer — from_json_file()
# ============================================================================


def test_slicer_from_json():
    """Test that PCodeSlicer.from_json_file() parses Ghidra JSON correctly."""
    # Create a synthetic Ghidra JSON output.
    ghidra_json = {
        "function_name": "check_magic",
        "function_entry": "0x101200",
        "stall_address": "0x101234",
        "taint_source": "RDI",
        "taint_mode": "register",
        "slice_depth": 5,
        "instruction_count": 3,
        "was_truncated": False,
        "pruned_loads": [],
        "instructions": [
            {
                "address": "0x101200",
                "mnemonic": "LOAD",
                "inputs": ["(const, 0x1b1, 4)", "(register, RDI, 8)"],
                "output": "(unique, 0x100@101200, 1)",
                "raw_pcode": "(unique, 0x100@101200, 1) = LOAD (const, 0x1b1, 4) (register, RDI, 8)",
                "call_target": None,
            },
            {
                "address": "0x101230",
                "mnemonic": "INT_EQUAL",
                "inputs": ["(unique, 0x400@101220, 2)", "(const, 0x5a01, 2)"],
                "output": "(unique, 0x500@101230, 1)",
                "raw_pcode": "(unique, 0x500@101230, 1) = INT_EQUAL ...",
                "call_target": None,
            },
            {
                "address": "0x101234",
                "mnemonic": "CBRANCH",
                "inputs": ["(ram, 0x101250, 8)", "(unique, 0x500@101230, 1)"],
                "output": None,
                "raw_pcode": "CBRANCH ...",
                "call_target": None,
            },
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(ghidra_json, f)
        json_path = Path(f.name)

    try:
        pslice = PCodeSlicer.from_json_file(json_path)

        assert pslice.function_name == "check_magic"
        assert pslice.stall_address == "0x101234"
        assert len(pslice.instructions) == 3
        assert pslice.instructions[0].mnemonic == "LOAD"
        assert pslice.instructions[1].mnemonic == "INT_EQUAL"
        assert pslice.instructions[2].mnemonic == "CBRANCH"

        print(f"  ✓ from_json_file: {len(pslice.instructions)} instructions")
        print(f"    Function: {pslice.function_name}")
    finally:
        json_path.unlink(missing_ok=True)


# ============================================================================
# Test 8: Full Pipeline (JSON → Profile → Export → Z3 → Verdict)
# ============================================================================


def test_full_pipeline():
    """
    End-to-end: construct a PCodeSlice, profile it, export it,
    generate a Z3 script (hardcoded — LLM is mocked), execute, verify SAT.
    """
    # Step 1: Construct slice.
    pslice = _make_wall1_slice()

    # Step 2: Profile constraints.
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pslice)
    assert ConstraintTag.CONSTANT_EQUALITY in profile.tags

    # Step 3: Export spec (JSON fallback).
    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = SpecExporter(json_dir=Path(tmpdir))
        spec = asyncio.run(
            exporter.export(pslice, profile)
        )
        assert spec.spec_id

    # Step 4: "LLM generates" a Z3 script (mocked — hardcoded known-good).
    z3_code = """
byte0 = BitVec('byte0', 8)
byte1 = BitVec('byte1', 8)
s.add(Concat(byte0, byte1) == BitVecVal(0x5A01, 16))
"""

    z3_script = Z3Script(
        script_text=z3_code,
        generation_idx=0,
        attempt_number=1,
        model_name="mock_gpt4",
    )

    # Step 5: Execute in sandbox.
    sandbox = Z3Sandbox(timeout_seconds=5)
    result = asyncio.run(
        sandbox.execute(z3_script)
    )

    # Step 6: Verify.
    assert result.verdict == Z3Verdict.SAT
    assert result.model["byte0"] == 0x5A
    assert result.model["byte1"] == 0x01

    # Step 7: Construct payload bytes.
    payload_bytes = bytes([result.model["byte0"], result.model["byte1"]])
    assert payload_bytes == b"\x5a\x01"

    print(f"  ✓ Full pipeline: JSON → Profile → Export → Z3 → SAT")
    print(f"    Payload: {payload_bytes.hex()}")
    print(f"    Model: {result.model}")
    print(f"    Spec ID: {spec.spec_id}")
    print(f"    Tags: {[t.name for t in profile.tags]}")
    print(f"    Exec time: {result.execution_time:.3f}s")


# ============================================================================
# Runner
# ============================================================================


def main():
    """Run all tests and report results."""
    tests = [
        ("Profiler: Wall 1 (magic number)", test_profiler_wall1),
        ("Profiler: Wall 3 (range bound)", test_profiler_wall3),
        ("Spec Exporter: roundtrip", test_spec_exporter_roundtrip),
        ("LLM Client: code extraction", test_llm_code_extraction),
        ("Z3 Sandbox: SAT", test_z3_sandbox_sat),
        ("Z3 Sandbox: UNSAT", test_z3_sandbox_unsat),
        ("Z3 Sandbox: Runtime Error", test_z3_sandbox_runtime_error),
        ("PCodeSlicer: from_json_file", test_slicer_from_json),
        ("Full Pipeline: end-to-end", test_full_pipeline),
    ]

    print("=" * 70)
    print("Phase 2 Integration Tests")
    print("=" * 70)

    passed = 0
    failed = 0

    for name, test_fn in tests:
        print(f"\n▸ {name}")
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All tests PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
