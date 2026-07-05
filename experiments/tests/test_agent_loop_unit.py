"""
test_agent_loop_unit.py — Unit tests for AgentLoop orchestration logic.

Tests the agent loop's internal methods (model_to_payload, select_best_failure,
stall_priority) without requiring running AFL++, LLM API, or Ghidra.

Run:  python experiments/tests/test_agent_loop_unit.py
"""
from __future__ import annotations
import asyncio, sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.constants import Architecture, StallSeverity, Z3Verdict
from agentic_afl.models import (
    ConstraintProfile,
    PCodeInstruction,
    PCodeSlice,
    SolvedPayload,
    VulnerabilitySpec,
    Z3Result,
    Z3Script,
)
from agentic_afl.orchestrator.agent_loop import AgentLoop


def make_test_spec() -> VulnerabilitySpec:
    """Create a minimal VulnerabilitySpec for testing."""
    from agentic_afl.constants import ConstraintTag
    pcode_slice = PCodeSlice(
        binary_path=Path("./test_binary"),
        stall_address="0x1000",
        function_name="test_func",
        function_entry="0x0F00",
        architecture=Architecture.X86_64,
        instructions=[
            PCodeInstruction(
                address="0x1000", mnemonic="INT_EQUAL",
                inputs=["reg_0", "0x5A"], output="cond_0",
                raw_pcode="(unique, 0x1000, 4) INT_EQUAL (register, reg_0, 4) , (const, 0x5a, 4)",
            ),
        ],
        taint_source="input_buffer",
        slice_depth=1,
        truncated=False,
    )
    profile = ConstraintProfile(
        tags=frozenset({ConstraintTag.CONSTANT_EQUALITY}),
        bitwise_density=0.0,
        arithmetic_density=0.0,
        loop_depth=0,
        register_count=1,
        estimated_complexity=12,
    )
    return VulnerabilitySpec(
        spec_id="test_spec_001",
        binary_path=Path("./test_binary"),
        stall_address="0x1000",
        function_name="test_func",
        pcode_slice=pcode_slice,
        constraint_profile=profile,
        architecture=Architecture.X86_64,
    )


def make_z3_script(text: str = "from z3 import *", idx: int = 0) -> Z3Script:
    return Z3Script(script_text=text, generation_idx=idx, attempt_number=1)


def run_tests():
    passed = 0
    failed = 0
    agent = AgentLoop()

    # ── Test 1: Stall priority mapping ────────────────────────────────
    print("\n▸ AgentLoop: stall priority mapping")
    try:
        assert AgentLoop._stall_priority(StallSeverity.CRITICAL) == 0
        assert AgentLoop._stall_priority(StallSeverity.HIGH) == 1
        assert AgentLoop._stall_priority(StallSeverity.MEDIUM) == 2
        assert AgentLoop._stall_priority(StallSeverity.LOW) == 3
        print("  ✓ CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 2: Select best failure — UNSAT preferred ─────────────────
    print("\n▸ AgentLoop: select_best_failure (UNSAT preferred)")
    try:
        results = [
            Z3Result(verdict=Z3Verdict.SYNTAX_ERROR, model=None,
                     error_message="SyntaxError", execution_time=0.1,
                     script=make_z3_script(idx=0)),
            Z3Result(verdict=Z3Verdict.UNSAT, model=None,
                     error_message="unsatisfiable", execution_time=0.5,
                     script=make_z3_script(idx=1)),
            Z3Result(verdict=Z3Verdict.TIMEOUT, model=None,
                     error_message="timeout", execution_time=5.0,
                     script=make_z3_script(idx=2)),
        ]
        best = agent._select_best_failure(results)
        assert best is not None
        assert best.verdict == Z3Verdict.UNSAT
        print(f"  ✓ Best failure: {best.verdict.value}")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 3: Select best failure — RUNTIME_ERROR over SYNTAX ───────
    print("\n▸ AgentLoop: select_best_failure (RUNTIME > SYNTAX)")
    try:
        results = [
            Z3Result(verdict=Z3Verdict.SYNTAX_ERROR, model=None,
                     error_message="SyntaxError", execution_time=0.1,
                     script=make_z3_script(idx=0)),
            Z3Result(verdict=Z3Verdict.RUNTIME_ERROR, model=None,
                     error_message="NameError", execution_time=0.3,
                     script=make_z3_script(idx=1)),
        ]
        best = agent._select_best_failure(results)
        assert best.verdict == Z3Verdict.RUNTIME_ERROR
        print(f"  ✓ Best failure: {best.verdict.value}")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 4: Select best failure — empty list ──────────────────────
    print("\n▸ AgentLoop: select_best_failure (empty list)")
    try:
        best = agent._select_best_failure([])
        assert best is None
        print("  ✓ None returned for empty list")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 5: Model to payload — byte-named variables ───────────────
    print("\n▸ AgentLoop: model_to_payload (byte-named variables)")
    try:
        spec = make_test_spec()
        result = Z3Result(
            verdict=Z3Verdict.SAT,
            model={"byte0": 0x5A, "byte1": 0x01},
            error_message=None,
            execution_time=0.1,
            script=make_z3_script(),
        )
        payload = agent._model_to_payload(result, spec)
        assert isinstance(payload, SolvedPayload)
        assert payload.raw_bytes == bytes([0x5A, 0x01])
        assert payload.stall_address == "0x1000"
        assert payload.z3_model == {"byte0": 0x5A, "byte1": 0x01}
        print(f"  ✓ Payload: {payload.raw_bytes.hex()} ({len(payload.raw_bytes)} bytes)")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 6: Model to payload — _lo/_hi variables ──────────────────
    print("\n▸ AgentLoop: model_to_payload (_lo/_hi variables)")
    try:
        spec = make_test_spec()
        result = Z3Result(
            verdict=Z3Verdict.SAT,
            model={"crc_hi": 0x80, "crc_lo": 0x7E},
            error_message=None,
            execution_time=0.1,
            script=make_z3_script(),
        )
        payload = agent._model_to_payload(result, spec)
        assert payload.raw_bytes == bytes([0x80, 0x7E])
        print(f"  ✓ Payload: {payload.raw_bytes.hex()}")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 7: Model to payload — register-width variables ───────────
    print("\n▸ AgentLoop: model_to_payload (register-width variables)")
    try:
        spec = make_test_spec()
        result = Z3Result(
            verdict=Z3Verdict.SAT,
            model={"reg_0": 0x5A01, "reg_1": 0xFF},
            error_message=None,
            execution_time=0.1,
            script=make_z3_script(),
        )
        payload = agent._model_to_payload(result, spec)
        # reg_0 = 0x5A01 → 2 bytes, reg_1 = 0xFF → 1 byte
        assert len(payload.raw_bytes) >= 2
        print(f"  ✓ Payload: {payload.raw_bytes.hex()} ({len(payload.raw_bytes)} bytes)")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 8: Model to payload — filename format ────────────────────
    print("\n▸ AgentLoop: payload filename format")
    try:
        spec = make_test_spec()
        result = Z3Result(
            verdict=Z3Verdict.SAT,
            model={"byte0": 0x68},
            error_message=None,
            execution_time=0.1,
            script=make_z3_script(),
        )
        payload = agent._model_to_payload(result, spec)
        assert payload.filename.startswith("agentic_")
        assert payload.filename.endswith(".bin")
        assert "0x1000" in payload.filename
        print(f"  ✓ Filename: {payload.filename}")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    # ── Test 9: Metrics ───────────────────────────────────────────────
    print("\n▸ AgentLoop: get_metrics")
    try:
        metrics = agent.get_metrics()
        assert "stalls_detected" in metrics
        assert "payloads_injected" in metrics
        assert "queue_size" in metrics
        print(f"  ✓ Metrics: {metrics}")
        passed += 1
    except Exception as e:
        failed += 1; print(f"  ✗ FAILED: {e}")

    return passed, failed


def main():
    print("=" * 70)
    print("Agent Loop Unit Tests")
    print("=" * 70)

    passed, failed = run_tests()

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All agent loop tests PASSED")


if __name__ == "__main__":
    main()
