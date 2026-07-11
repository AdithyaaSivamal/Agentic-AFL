"""
test_agent_loop_recovery.py — Unit tests for the AgentLoop ReAct
self-repair / failure-recovery cycle.

Covers the gap identified in the health review: agent_loop.py had only
22% coverage, and there was no dedicated test for the ReAct loop's
recovery behavior (the exact area where "infinite LLM retry loops"
were previously fixed). These tests drive _generate_and_solve() with
stubbed LLM/sandbox components -- no network, Ghidra, or AFL++ needed.

Focus areas:
  - All-UNSAT across every turn -> clean deferral (returns None), not
    an infinite loop.
  - _select_best_failure ranking (UNSAT > RUNTIME_ERROR > SYNTAX_ERROR
    > TIMEOUT > UNKNOWN).
  - Turn budget is respected (settings.max_react_turns bounds attempts).
  - A SAT result on a later turn is returned immediately.
  - Correction history accumulates across turns.
  - The C2 sandbox-gather defense-in-depth timeout degrades gracefully.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from agentic_afl.config import settings
from agentic_afl.constants import Architecture, ConstraintTag, StallSeverity, Z3Verdict
from agentic_afl.models import (
    ConstraintProfile,
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
    Z3GenerationRequest,
    Z3Result,
    Z3Script,
)
from agentic_afl.orchestrator.agent_loop import AgentLoop


# ═══════════════════════════════════════════════════════════════════════
#  Fixtures / fakes
# ═══════════════════════════════════════════════════════════════════════


class FakeLLMClient:
    """Returns a pre-scripted sequence of Z3Script batches, one per turn."""

    def __init__(self, script_batches: list[list[str]]):
        self.script_batches = script_batches
        self.call_count = 0

    async def generate_z3_scripts(self, request: Z3GenerationRequest) -> list[Z3Script]:
        idx = min(self.call_count, len(self.script_batches) - 1)
        self.call_count += 1
        texts = self.script_batches[idx]
        return [
            Z3Script(script_text=t, generation_idx=i, attempt_number=1)
            for i, t in enumerate(texts)
        ]


class FakeSandbox:
    """Maps script text -> a scripted Z3Result verdict, in call order."""

    def __init__(self, verdict_batches: list[list[Z3Verdict]]):
        self.verdict_batches = verdict_batches
        self.turn = -1
        self.calls_this_turn = 0
        self.timeout_seconds = 5  # matches Z3Sandbox's attribute the fix reads

    async def execute(self, script: Z3Script, seed_input: bytes = b"") -> Z3Result:
        if script.generation_idx == 0:
            self.turn += 1
            self.calls_this_turn = 0
        verdicts = self.verdict_batches[min(self.turn, len(self.verdict_batches) - 1)]
        verdict = verdicts[min(script.generation_idx, len(verdicts) - 1)]
        self.calls_this_turn += 1

        model = {"byte_0": 0x5A, "byte_1": 0x01} if verdict == Z3Verdict.SAT else None
        return Z3Result(
            verdict=verdict,
            model=model,
            error_message=None if verdict == Z3Verdict.SAT else f"{verdict.value} error",
            execution_time=0.01,
            script=script,
        )


class HangingSandbox:
    """Simulates a sandbox whose internal timeout guard has regressed."""

    timeout_seconds = 1  # tiny, so the defense-in-depth wait_for fires fast

    async def execute(self, script: Z3Script, seed_input: bytes = b"") -> Z3Result:
        await asyncio.Event().wait()  # never resolves on its own


def _make_slice() -> PCodeSlice:
    return PCodeSlice(
        binary_path="./test_binary",
        stall_address="0x1000",
        function_name="check_magic",
        function_entry="0x0ff0",
        instructions=[
            PCodeInstruction(
                address="0x1000", mnemonic="INT_EQUAL",
                inputs=["reg_0", "0x5a01"], output="ZF",
                raw_pcode="ZF = INT_EQUAL reg_0 0x5a01",
            )
        ],
        taint_source="RDI",
        slice_depth=1,
        truncated=False,
        architecture=Architecture.X86_64,
    )


def _make_spec() -> VulnerabilitySpec:
    pslice = _make_slice()
    profile = ConstraintProfile(
        tags=frozenset({ConstraintTag.CONSTANT_EQUALITY}),
        bitwise_density=0.0, arithmetic_density=0.0,
        loop_depth=0, register_count=1, estimated_complexity=5,
    )
    return VulnerabilitySpec(
        spec_id="feedface00000000",
        binary_path=pslice.binary_path,
        stall_address=pslice.stall_address,
        function_name=pslice.function_name,
        pcode_slice=pslice,
        constraint_profile=profile,
        architecture=Architecture.X86_64,
    )


def _make_request() -> Z3GenerationRequest:
    return Z3GenerationRequest(
        vuln_spec=_make_spec(),
        seed_input=b"\x00\x01",
        k_vote_count=2,
    )


def _agent_with(llm_client, sandbox) -> AgentLoop:
    agent = AgentLoop()
    agent._llm_client = llm_client
    agent._sandbox = sandbox
    agent._store = None
    return agent


# ═══════════════════════════════════════════════════════════════════════
#  All-failure -> clean deferral (no infinite loop)
# ═══════════════════════════════════════════════════════════════════════


class TestAllFailuresDefer:
    @pytest.mark.asyncio
    async def test_all_unsat_across_all_turns_returns_none(self, monkeypatch):
        """The historical bug class: an unsolvable stall must terminate
        after max_react_turns, not loop forever calling the LLM."""
        monkeypatch.setattr(settings, "max_react_turns", 3)
        llm = FakeLLMClient(script_batches=[["s.add(x == 1)\ns.add(x == 2)"]] * 3)
        sandbox = FakeSandbox(verdict_batches=[[Z3Verdict.UNSAT, Z3Verdict.UNSAT]] * 3)
        agent = _agent_with(llm, sandbox)
        request = _make_request()

        result = await agent._generate_and_solve(request, _make_spec())

        assert result is None
        # Must have made exactly max_react_turns LLM calls -- not more.
        assert llm.call_count == 3

    @pytest.mark.asyncio
    async def test_correction_history_accumulates_across_turns(self, monkeypatch):
        monkeypatch.setattr(settings, "max_react_turns", 2)
        llm = FakeLLMClient(script_batches=[["bad script"]] * 2)
        sandbox = FakeSandbox(verdict_batches=[[Z3Verdict.SYNTAX_ERROR]] * 2)
        agent = _agent_with(llm, sandbox)
        request = _make_request()

        await agent._generate_and_solve(request, _make_spec())

        assert len(request.correction_history) == 2

    @pytest.mark.asyncio
    async def test_empty_results_from_sandbox_breaks_cleanly(self, monkeypatch):
        """If the sandbox gather ever comes back empty (e.g. via the C2
        defense-in-depth timeout path), the loop must break, not crash."""
        monkeypatch.setattr(settings, "max_react_turns", 3)

        class EmptyResultSandbox:
            timeout_seconds = 5
            async def execute(self, script):
                raise AssertionError("should not be called in this scenario")

        llm = FakeLLMClient(script_batches=[[]])  # zero scripts generated
        agent = _agent_with(llm, EmptyResultSandbox())
        request = _make_request()

        result = await agent._generate_and_solve(request, _make_spec())

        assert result is None


# ═══════════════════════════════════════════════════════════════════════
#  SAT on a later turn
# ═══════════════════════════════════════════════════════════════════════


class TestEventualSat:
    @pytest.mark.asyncio
    async def test_sat_on_second_turn_returns_immediately(self, monkeypatch):
        monkeypatch.setattr(settings, "max_react_turns", 5)
        llm = FakeLLMClient(script_batches=[
            ["s.add(byte_0 == 1)\ns.add(byte_0 == 2)"],       # turn 1: bad
            ["s.add(byte_0 == 0x5a)\ns.add(byte_1 == 0x01)"],  # turn 2: good
        ])
        sandbox = FakeSandbox(verdict_batches=[
            [Z3Verdict.UNSAT],
            [Z3Verdict.SAT],
        ])
        agent = _agent_with(llm, sandbox)
        request = _make_request()

        result = await agent._generate_and_solve(request, _make_spec())

        assert result is not None
        payload, winning_script = result
        assert payload.raw_bytes[:2] == b"\x5a\x01"
        # Must not have continued past the turn that found SAT.
        assert llm.call_count == 2


# ═══════════════════════════════════════════════════════════════════════
#  _select_best_failure ranking
# ═══════════════════════════════════════════════════════════════════════


class TestSelectBestFailure:
    def _result(self, verdict: Z3Verdict) -> Z3Result:
        script = Z3Script(script_text="x", generation_idx=0, attempt_number=1)
        return Z3Result(verdict=verdict, model=None, error_message="e", execution_time=0.1, script=script)

    def test_empty_list_returns_none(self):
        agent = AgentLoop()
        assert agent._select_best_failure([]) is None

    def test_unsat_preferred_over_all(self):
        agent = AgentLoop()
        results = [
            self._result(Z3Verdict.TIMEOUT),
            self._result(Z3Verdict.UNSAT),
            self._result(Z3Verdict.SYNTAX_ERROR),
        ]
        assert agent._select_best_failure(results).verdict == Z3Verdict.UNSAT

    def test_runtime_error_preferred_over_syntax_and_timeout(self):
        agent = AgentLoop()
        results = [
            self._result(Z3Verdict.TIMEOUT),
            self._result(Z3Verdict.SYNTAX_ERROR),
            self._result(Z3Verdict.RUNTIME_ERROR),
        ]
        assert agent._select_best_failure(results).verdict == Z3Verdict.RUNTIME_ERROR

    def test_all_sat_filtered_out_returns_none(self):
        agent = AgentLoop()
        results = [self._result(Z3Verdict.SAT) for _ in range(3)]
        # SAT results have no model in this helper, but the method only
        # filters by verdict != SAT -- so an all-SAT input yields None.
        assert agent._select_best_failure(results) is None


# ═══════════════════════════════════════════════════════════════════════
#  C2 defense-in-depth: sandbox gather timeout
# ═══════════════════════════════════════════════════════════════════════


class TestSandboxGatherTimeout:
    @pytest.mark.asyncio
    async def test_hung_sandbox_does_not_hang_forever(self, monkeypatch):
        """If Z3Sandbox.execute() ever regresses and stops bounding itself
        internally, the outer wait_for in _generate_and_solve must still
        cap total wait time instead of hanging the stall-processing loop."""
        monkeypatch.setattr(settings, "max_react_turns", 1)
        llm = FakeLLMClient(script_batches=[["s.add(x == 1)"]])
        agent = _agent_with(llm, HangingSandbox())
        request = _make_request()
        request.k_vote_count = 1

        # agent_loop's own defense-in-depth bound is
        # (sandbox.timeout_seconds + 10) * n_scripts = (1 + 10) * 1 = 11s
        # here. Give a generous test-harness backstop above that, then
        # assert we resolved close to the PRODUCTION bound, not the
        # backstop -- proving the code's own timeout fired, not the test's.
        start = time.monotonic()
        result = await asyncio.wait_for(
            agent._generate_and_solve(request, _make_spec()),
            timeout=25,
        )
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed < 15, (
            f"took {elapsed:.1f}s -- expected ~11s from the production-side "
            f"defense-in-depth timeout, not the test harness backstop"
        )
