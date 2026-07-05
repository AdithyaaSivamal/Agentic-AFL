"""
test_phase4_bridge.py — Phase 4 Tests: AFL++ Fuzzer Bridge.

Tests StallDetector and PayloadInjector against simulated AFL++ directory
structures (no running AFL++ instance required).

Run:  python experiments/tests/test_phase4_bridge.py
"""
from __future__ import annotations
import asyncio, os, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.constants import StallSeverity
from agentic_afl.fuzzer_bridge.stall_detector import StallDetector
from agentic_afl.fuzzer_bridge.payload_injector import PayloadInjector
from agentic_afl.models import SolvedPayload


def create_afl_output_dir(tmpdir: Path) -> Path:
    """Create a realistic AFL++ output directory structure."""
    afl_dir = tmpdir / "afl_output"
    default = afl_dir / "default"
    queue = default / "queue"
    queue.mkdir(parents=True)

    # fuzzer_stats
    (default / "fuzzer_stats").write_text(
        "start_time        : 1715400000\n"
        "last_update        : 1715400600\n"
        "cycles_done        : 100\n"
        "execs_done         : 500000\n"
        "execs_per_sec      : 10000.00\n"
        "corpus_count       : 42\n"
        "corpus_found       : 42\n"
        "pending_favs       : 0\n"
        "pending_total      : 0\n"
        "edges_found        : 256\n"
        "max_depth          : 8\n"
        "cur_item           : 41\n"
        "saved_crashes      : 0\n"
        "command_line       : afl-fuzz -i corpus -o afl_output -- ./modbus_rtu_x86 @@\n"
    )

    # cmdline
    (default / "cmdline").write_text("./modbus_rtu_x86 @@\n")

    # Queue with seed files
    for i in range(5):
        seed_data = bytes([0x00, 0x01, 0x00, 0x00, i, 0x03, 0x00, 0x06])
        (queue / f"id:{i:06d},src:000000,time:{1715400000+i},execs:{i*100},op:havoc,rep:2").write_bytes(seed_data)

    # plot_data with a plateau (edges stuck at 256 for many entries)
    lines = ["# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, max_depth, edges_found\n"]
    for c in range(100):
        edges = 256 if c > 40 else 200 + c  # Plateau starts at cycle 41
        lines.append(f"{c*10}, {c}, {min(c,41)}, {min(c+1,42)}, 0, 0, 8, {edges}\n")
    (default / "plot_data").write_text("".join(lines))

    return afl_dir


async def run_tests():
    passed = 0
    failed = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        afl_dir = create_afl_output_dir(tmpdir)

        # ── StallDetector Tests ───────────────────────────────────────

        # Test 1: Parse fuzzer_stats
        print("\n▸ StallDetector: parse fuzzer_stats")
        try:
            detector = StallDetector(afl_output_dir=afl_dir, min_stall_cycles=5)
            stats = detector._parse_fuzzer_stats()
            assert stats["cycles_done"] == "100"
            assert stats["edges_found"] == "256"
            assert stats["pending_favs"] == "0"
            print(f"  ✓ Parsed: cycles={stats['cycles_done']}, edges={stats['edges_found']}")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 2: Get binary path
        print("\n▸ StallDetector: get binary path")
        try:
            binary = detector._get_binary_path()
            assert "modbus_rtu_x86" in str(binary), f"Expected modbus_rtu_x86, got {binary}"
            print(f"  ✓ Binary: {binary}")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 3: Find closest seed
        print("\n▸ StallDetector: find closest seed")
        try:
            seed = detector._find_closest_seed("0x101234")
            assert seed.exists()
            assert seed.name.startswith("id:")
            seed_bytes = seed.read_bytes()
            print(f"  ✓ Seed: {seed.name} ({len(seed_bytes)} bytes)")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 4: Compute severity
        print("\n▸ StallDetector: compute severity")
        try:
            sev_low = detector._compute_severity("0x1000", 3, 256)
            sev_med = detector._compute_severity("0x1000", 5, 256)
            sev_high = detector._compute_severity("0x1000", 10, 256)
            sev_crit = detector._compute_severity("0x1000", 20, 256)
            assert sev_low == StallSeverity.LOW
            assert sev_med == StallSeverity.MEDIUM
            assert sev_high == StallSeverity.HIGH
            assert sev_crit == StallSeverity.CRITICAL
            print(f"  ✓ LOW=3, MEDIUM=5, HIGH=10, CRITICAL=20 cycles")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 5: Detect stalls (first poll needs plateau buildup)
        print("\n▸ StallDetector: detect stalls (plateau detection)")
        try:
            # Simulate enough polls to exceed min_stall_cycles.
            detector2 = StallDetector(afl_output_dir=afl_dir, min_stall_cycles=3)
            detector2._last_edges_found = 256  # Simulate prior knowledge
            detector2._plateau_cycles = 5       # Simulate 5 plateau cycles

            stalls = await detector2.detect()
            assert len(stalls) >= 1, f"Expected >= 1 stall, got {len(stalls)}"
            stall = stalls[0]
            assert stall.binary_path == Path("./modbus_rtu_x86")
            assert stall.seed_input_path.exists()
            print(f"  ✓ Detected: {stall.stall_address} (severity={stall.severity.name})")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}"); import traceback; traceback.print_exc()

        # Test 6: Deduplication
        print("\n▸ StallDetector: deduplication")
        try:
            stalls2 = await detector2.detect()
            assert len(stalls2) == 0, f"Expected 0 new stalls (dedup), got {len(stalls2)}"
            print(f"  ✓ No duplicate stalls reported")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 7: Resolve and re-detect
        print("\n▸ StallDetector: resolve and re-detect")
        try:
            addr = stalls[0].stall_address
            detector2.resolve_stall(addr)
            assert addr not in detector2._known_stalls
            print(f"  ✓ Resolved {addr}, can be re-detected")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 8: Status
        print("\n▸ StallDetector: get_status")
        try:
            status = detector2.get_status()
            assert "known_stalls" in status
            assert "plateau_cycles" in status
            print(f"  ✓ Status: {status}")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # ── PayloadInjector Tests ─────────────────────────────────────

        sync_dir = tmpdir / "sync_dir"

        # Test 9: Inject payload
        print("\n▸ PayloadInjector: inject payload")
        try:
            injector = PayloadInjector(sync_dir=sync_dir)
            assert sync_dir.exists()

            payload = SolvedPayload(
                raw_bytes=bytes([0x00, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x06, 0x7E, 0x80]),
                source_spec_id="abc12345deadbeef",
                stall_address="0x101234",
                z3_model={"byte0": 0, "byte1": 1, "fc": 3, "crc_lo": 0x7E, "crc_hi": 0x80},
                confidence=0.95,
            )
            path = await injector.inject(payload)
            assert path.exists()
            assert path.read_bytes() == payload.raw_bytes
            assert path.name.startswith("agentic_")
            assert path.name.endswith(".bin")
            print(f"  ✓ Written: {path.name} ({len(payload.raw_bytes)} bytes)")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}"); import traceback; traceback.print_exc()

        # Test 10: Atomic write (no .tmp files left)
        print("\n▸ PayloadInjector: atomic write (no temp files)")
        try:
            tmp_files = list(sync_dir.glob("*.tmp"))
            assert len(tmp_files) == 0, f"Found .tmp files: {tmp_files}"
            print(f"  ✓ No .tmp files in sync directory")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 11: List injected
        print("\n▸ PayloadInjector: list_injected")
        try:
            files = injector.list_injected()
            assert len(files) == 1
            print(f"  ✓ {len(files)} payload(s) in sync directory")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 12: Multiple payloads
        print("\n▸ PayloadInjector: multiple payloads")
        try:
            payload2 = SolvedPayload(
                raw_bytes=bytes([0x68, 0x04, 0x00, 0x00, 0x00, 0x00]),
                source_spec_id="iec10400000000",
                stall_address="0x101418",
                z3_model={"start": 0x68, "len": 4},
                confidence=1.0,
            )
            path2 = await injector.inject(payload2)
            assert path2.exists()
            files = injector.list_injected()
            assert len(files) == 2
            print(f"  ✓ {len(files)} payloads in sync directory")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 13: Cleanup (max_age_hours=0 removes all)
        print("\n▸ PayloadInjector: cleanup_old_payloads")
        try:
            # Touch files to make them "old" (set mtime to 2 days ago).
            for f in injector.list_injected():
                old_time = time.time() - 48 * 3600
                os.utime(f, (old_time, old_time))
            removed = injector.cleanup_old_payloads(max_age_hours=24)
            assert removed == 2
            assert len(injector.list_injected()) == 0
            print(f"  ✓ Cleaned up {removed} old payload(s)")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

        # Test 14: Stats
        print("\n▸ PayloadInjector: get_stats")
        try:
            stats = injector.get_stats()
            assert stats["total_injected"] == 2
            assert stats["current_files"] == 0  # cleaned up
            print(f"  ✓ Stats: {stats}")
            passed += 1
        except Exception as e:
            failed += 1; print(f"  ✗ FAILED: {e}")

    return passed, failed


def main():
    print("=" * 70)
    print("Phase 4 Tests: AFL++ Fuzzer Bridge")
    print("=" * 70)

    passed, failed = asyncio.run(run_tests())

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All Phase 4 tests PASSED")


if __name__ == "__main__":
    main()
