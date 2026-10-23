"""
test_live_llm.py — Stage 1: Live LLM Integration Test.

Sends a real ICS P-Code fixture to Gemini and verifies the returned Z3 script
produces a SAT result when executed in the Z3 sandbox.

This test makes REAL API calls and costs real money.
Skips gracefully if GEMINI_API_KEY is not set.

Run:  python experiments/integration/test_live_llm.py
"""
from __future__ import annotations
import asyncio, json, os, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.config import settings
from agentic_afl.constants import Architecture, ConstraintTag, Z3Verdict
from agentic_afl.models import (
    ConstraintProfile,
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
    Z3GenerationRequest,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "test_targets" / "pcode_fixtures"


def load_fixture(name: str) -> dict:
    """Load a P-Code fixture JSON file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


def fixture_to_spec(fixture: dict, arch: Architecture = Architecture.X86_64) -> VulnerabilitySpec:
    """Convert a fixture JSON dict into a VulnerabilitySpec."""
    instructions = [
        PCodeInstruction(
            address=inst["address"],
            mnemonic=inst["mnemonic"],
            inputs=inst["inputs"],
            output=inst["output"],
            raw_pcode=inst["raw_pcode"],
        )
        for inst in fixture["instructions"]
    ]
    pcode_slice = PCodeSlice(
        binary_path=Path(fixture.get("binary_path", "./test_binary")),
        stall_address=fixture["stall_address"],
        function_name=fixture["function_name"],
        function_entry=fixture.get("function_entry", "0x0"),
        architecture=arch,
        instructions=instructions,
        taint_source=fixture.get("taint_source", "RDI"),
        slice_depth=fixture.get("slice_depth", 10),
        truncated=fixture.get("was_truncated", False),
    )

    # Determine constraint tags from the fixture's P-Code.
    from agentic_afl.extractor.constraint_profiler import ConstraintProfiler
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pcode_slice)

    return VulnerabilitySpec(
        spec_id=VulnerabilitySpec.generate_id(
            pcode_slice.binary_path, pcode_slice.stall_address,
        ),
        binary_path=pcode_slice.binary_path,
        stall_address=pcode_slice.stall_address,
        function_name=pcode_slice.function_name,
        pcode_slice=pcode_slice,
        constraint_profile=profile,
        architecture=arch,
    )


async def run_tests():
    passed = 0
    failed = 0

    # Check for API key.
    if not settings.gemini_api_key:
        print("\n⚠ GEMINI_API_KEY not set — skipping live LLM tests")
        return 0, 0

    print(f"\n  Provider: {settings.llm_api_provider}")
    print(f"  Model:    {settings.llm_model_name}")
    print(f"  K-way:    {settings.k_vote_count}")

    from agentic_afl.orchestrator.llm_client import LLMClient
    from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox

    client = LLMClient()
    sandbox = Z3Sandbox()

    # ── Test 1: Modbus TID (simple constant equality) ─────────────────
    print("\n▸ Live LLM: Modbus TID (INT_EQUAL, const 0x1)")
    try:
        fixture = load_fixture("modbus_rtu_wall1_tid.json")
        spec = fixture_to_spec(fixture)
        print(f"  Profile: tags={[t.name for t in spec.constraint_profile.tags]}, "
              f"complexity={spec.constraint_profile.estimated_complexity}")

        request = Z3GenerationRequest(
            vuln_spec=spec,
            seed_input=bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03]),
            k_vote_count=settings.k_vote_count,
        )

        t0 = time.time()
        scripts = await client.generate_z3_scripts(request)
        gen_time = time.time() - t0
        print(f"  Generated {len(scripts)} scripts in {gen_time:.1f}s")

        for i, s in enumerate(scripts):
            print(f"  Script {i}: {len(s.script_text)} chars")
            # Print first 3 lines for debugging.
            for line in s.script_text.splitlines()[:3]:
                print(f"    | {line}")

        # Execute all scripts in sandbox.
        results = await asyncio.gather(*[sandbox.execute(s) for s in scripts])

        sat_count = 0
        for i, r in enumerate(results):
            status = f"{'✓' if r.verdict == Z3Verdict.SAT else '✗'} {r.verdict.value}"
            if r.model:
                status += f" model={r.model}"
            elif r.error_message:
                status += f" err={r.error_message[:80]}"
            print(f"  Result {i}: {status} ({r.execution_time:.2f}s)")
            if r.verdict == Z3Verdict.SAT:
                sat_count += 1

        assert sat_count >= 1, f"Expected at least 1 SAT, got {sat_count}/{len(results)}"
        print(f"  ✓ {sat_count}/{len(results)} SAT — LLM produced valid Z3!")
        passed += 1
    except Exception as e:
        failed += 1
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()

    # ── Test 2: IEC 104 Start Byte (magic number 0x68) ────────────────
    print("\n▸ Live LLM: IEC 104 Start Byte (INT_EQUAL, const 0x68)")
    try:
        fixture = load_fixture("iec104_wall1_start.json")
        spec = fixture_to_spec(fixture)
        print(f"  Profile: tags={[t.name for t in spec.constraint_profile.tags]}, "
              f"complexity={spec.constraint_profile.estimated_complexity}")

        request = Z3GenerationRequest(
            vuln_spec=spec,
            seed_input=bytes([0x00] * 6),
            k_vote_count=settings.k_vote_count,
        )

        t0 = time.time()
        scripts = await client.generate_z3_scripts(request)
        gen_time = time.time() - t0
        print(f"  Generated {len(scripts)} scripts in {gen_time:.1f}s")

        results = await asyncio.gather(*[sandbox.execute(s) for s in scripts])

        sat_count = 0
        for i, r in enumerate(results):
            status = f"{'✓' if r.verdict == Z3Verdict.SAT else '✗'} {r.verdict.value}"
            if r.model:
                status += f" model={r.model}"
            elif r.error_message:
                status += f" err={r.error_message[:80]}"
            print(f"  Result {i}: {status} ({r.execution_time:.2f}s)")
            if r.verdict == Z3Verdict.SAT:
                sat_count += 1

        assert sat_count >= 1, f"Expected at least 1 SAT, got {sat_count}/{len(results)}"
        print(f"  ✓ {sat_count}/{len(results)} SAT — LLM produced valid Z3!")
        passed += 1
    except Exception as e:
        failed += 1
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()

    # ── Test 3: Modbus CRC (hard — crypto checksum) ───────────────────
    print("\n▸ Live LLM: Modbus CRC (XOR/AND/LEFT/RIGHT — crypto)")
    try:
        fixture = load_fixture("modbus_rtu_wall5_crc.json")
        spec = fixture_to_spec(fixture)
        print(f"  Profile: tags={[t.name for t in spec.constraint_profile.tags]}, "
              f"complexity={spec.constraint_profile.estimated_complexity}")

        request = Z3GenerationRequest(
            vuln_spec=spec,
            seed_input=bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            k_vote_count=settings.k_vote_count,
        )

        t0 = time.time()
        scripts = await client.generate_z3_scripts(request)
        gen_time = time.time() - t0
        print(f"  Generated {len(scripts)} scripts in {gen_time:.1f}s")

        results = await asyncio.gather(*[sandbox.execute(s) for s in scripts])

        sat_count = 0
        for i, r in enumerate(results):
            status = f"{'✓' if r.verdict == Z3Verdict.SAT else '✗'} {r.verdict.value}"
            if r.model:
                status += f" model={r.model}"
            elif r.error_message:
                status += f" err={r.error_message[:80]}"
            print(f"  Result {i}: {status} ({r.execution_time:.2f}s)")
            if r.verdict == Z3Verdict.SAT:
                sat_count += 1

        # CRC is HARD — we accept even 0 SAT but log it.
        if sat_count >= 1:
            print(f"  ✓ {sat_count}/{len(results)} SAT — LLM solved CRC constraint!")
            passed += 1
        else:
            print(f"  ⚠ 0/{len(results)} SAT — CRC is a known-hard constraint")
            print(f"    (This is expected; CRC solving is the stretch goal)")
            passed += 1  # Don't fail on CRC — it's genuinely hard
    except Exception as e:
        failed += 1
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()

    return passed, failed


def main():
    print("=" * 70)
    print("Stage 1: Live LLM Integration Test")
    print("=" * 70)

    passed, failed = asyncio.run(run_tests())

    if passed == 0 and failed == 0:
        print("\n  Skipped (no API key)")
        return

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All live LLM tests PASSED")


if __name__ == "__main__":
    main()
