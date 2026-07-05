"""
test_llm_client.py — Unit tests for the LLM Translation Engine.

Covers the gap identified in the health review: llm_client.py had 0%
test coverage prior to this file. All tests mock BaseLLMProvider so no
network calls or API keys are required.

Focus areas:
  - _extract_z3_code: empty/malformed completions, fence-stripping fallback.
  - generate_z3_scripts: K-way fan-out, debug-dir writes.
  - repair_z3_script: single-completion repair path.
  - Provider-call timeout behavior (guards the C1 finding: a hung LLM
    HTTP call previously had no timeout and could block the event loop
    forever). These tests fail before the asyncio.wait_for fix lands
    and pass after.
  - LocalProvider stub surfaces NotImplementedError cleanly.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from agentic_afl.config import settings
from agentic_afl.constants import Architecture, ConstraintTag, Z3Verdict
from agentic_afl.models import (
    ConstraintProfile,
    CorrectionEntry,
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
    Z3GenerationRequest,
    Z3Result,
    Z3Script,
)
from agentic_afl.orchestrator.llm_client import (
    BaseLLMProvider,
    LLMClient,
    LLMClientError,
    LocalProvider,
)
from agentic_afl.orchestrator.rate_limiter import RateLimiter


# ═══════════════════════════════════════════════════════════════════════
#  Fixtures / fakes
# ═══════════════════════════════════════════════════════════════════════


class FakeProvider(BaseLLMProvider):
    """Deterministic stand-in for OpenAI/Gemini — no network calls."""

    def __init__(self, completions: list[str] | None = None, delay: float = 0.0):
        self.completions = completions
        self.delay = delay
        self.calls: list[dict] = []

    async def generate(self, system_prompt, user_prompt, temperature, max_tokens, n):
        self.calls.append({
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "n": n,
        })
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.completions is not None:
            return list(self.completions)
        return [f"```python\ns.add(x == {i})\n```" for i in range(n)]


class HangingProvider(BaseLLMProvider):
    """Simulates a stuck HTTP call that never resolves on its own."""

    async def generate(self, system_prompt, user_prompt, temperature, max_tokens, n):
        await asyncio.Event().wait()  # never completes
        return []  # pragma: no cover


def _make_slice() -> PCodeSlice:
    return PCodeSlice(
        binary_path=__file__,
        stall_address="0x1000",
        function_name="check_magic",
        function_entry="0x0ff0",
        instructions=[
            PCodeInstruction(
                address="0x1000",
                mnemonic="INT_EQUAL",
                inputs=["(register, AX, 2)", "(const, 0x5a01, 2)"],
                output="(register, ZF, 1)",
                raw_pcode="(register, ZF, 1) = INT_EQUAL (register, AX, 2) (const, 0x5a01, 2)",
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
        bitwise_density=0.0,
        arithmetic_density=0.0,
        loop_depth=0,
        register_count=1,
        estimated_complexity=5,
    )
    return VulnerabilitySpec(
        spec_id="deadbeef00000000",
        binary_path=pslice.binary_path,
        stall_address=pslice.stall_address,
        function_name=pslice.function_name,
        pcode_slice=pslice,
        constraint_profile=profile,
        architecture=Architecture.X86_64,
    )


def _make_request(k=2) -> Z3GenerationRequest:
    return Z3GenerationRequest(
        vuln_spec=_make_spec(),
        seed_input=b"\x00\x01",
        k_vote_count=k,
    )


def _client_with(provider: BaseLLMProvider) -> LLMClient:
    # burst_size >= k so rate limiting never throttles the test itself.
    return LLMClient(
        provider=provider,
        rate_limiter=RateLimiter(max_rpm=6000, burst_size=50),
    )


# ═══════════════════════════════════════════════════════════════════════
#  _extract_z3_code
# ═══════════════════════════════════════════════════════════════════════


class TestExtractZ3Code:
    def test_empty_completion_returns_empty_string(self):
        client = _client_with(FakeProvider())
        assert client._extract_z3_code("") == ""

    def test_none_like_empty_completion(self):
        client = _client_with(FakeProvider())
        # generate_z3_scripts guards provider output with `or ""` upstream,
        # but _extract_z3_code itself must also tolerate a falsy string.
        assert client._extract_z3_code("") == ""

    def test_standard_fenced_block(self):
        client = _client_with(FakeProvider())
        completion = "Here you go:\n```python\ns.add(x == 1)\n```\nDone."
        assert client._extract_z3_code(completion) == "s.add(x == 1)"

    def test_relaxed_fence_without_newline(self):
        client = _client_with(FakeProvider())
        completion = "```python s.add(x == 2)```"
        code = client._extract_z3_code(completion)
        assert "s.add(x == 2)" in code

    def test_no_fence_prose_before_code_is_stripped(self):
        client = _client_with(FakeProvider())
        completion = (
            "Sure, here is the constraint you need for this check.\n"
            "s.add(byte_0 == 0x5a)\n"
            "s.add(byte_1 == 0x01)\n"
        )
        code = client._extract_z3_code(completion)
        assert "s.add(byte_0 == 0x5a)" in code
        assert "Sure, here is" not in code

    def test_malformed_completion_with_only_prose_falls_back_to_full_text(self):
        client = _client_with(FakeProvider())
        completion = "I cannot help with that request."
        code = client._extract_z3_code(completion)
        # No code-like line found — fallback returns the cleaned prose as-is,
        # which downstream will correctly fail as a SYNTAX_ERROR in the sandbox.
        assert code == completion


# ═══════════════════════════════════════════════════════════════════════
#  generate_z3_scripts — K-way fan-out
# ═══════════════════════════════════════════════════════════════════════


class TestGenerateZ3Scripts:
    @pytest.mark.asyncio
    async def test_k_way_fan_out_produces_k_scripts(self):
        provider = FakeProvider()
        client = _client_with(provider)
        request = _make_request(k=3)

        scripts = await client.generate_z3_scripts(request)

        assert len(scripts) == 3
        assert provider.calls[0]["n"] == 3
        assert all(isinstance(s, Z3Script) for s in scripts)
        assert [s.generation_idx for s in scripts] == [0, 1, 2]

    @pytest.mark.asyncio
    async def test_empty_completions_yield_empty_scripts_not_crash(self):
        """All K completions empty — must not raise, produces empty scripts."""
        provider = FakeProvider(completions=["", "", ""])
        client = _client_with(provider)
        request = _make_request(k=3)

        scripts = await client.generate_z3_scripts(request)

        assert len(scripts) == 3
        assert all(s.script_text == "" for s in scripts)

    @pytest.mark.asyncio
    async def test_malformed_completion_mixed_with_valid(self):
        provider = FakeProvider(completions=[
            "```python\ns.add(x == 1)\n```",
            "not valid code at all, sorry",
        ])
        client = _client_with(provider)
        request = _make_request(k=2)

        scripts = await client.generate_z3_scripts(request)

        assert scripts[0].script_text == "s.add(x == 1)"
        assert scripts[1].script_text == "not valid code at all, sorry"


# ═══════════════════════════════════════════════════════════════════════
#  repair_z3_script
# ═══════════════════════════════════════════════════════════════════════


class TestRepairZ3Script:
    @pytest.mark.asyncio
    async def test_repair_uses_single_completion(self):
        provider = FakeProvider(completions=["```python\ns.add(x == 99)\n```"])
        client = _client_with(provider)
        request = _make_request(k=1)
        failed_script = Z3Script(script_text="s.add(x == 1)\ns.add(x == 2)", generation_idx=0, attempt_number=1)
        error_result = Z3Result(
            verdict=Z3Verdict.UNSAT,
            model=None,
            error_message="contradictory constraints",
            execution_time=0.1,
            script=failed_script,
        )

        repaired = await client.repair_z3_script(request, failed_script, error_result, attempt_number=2)

        assert repaired.script_text == "s.add(x == 99)"
        assert repaired.attempt_number == 2
        assert provider.calls[-1]["n"] == 1


# ═══════════════════════════════════════════════════════════════════════
#  Timeout behavior (C1 regression guard)
# ═══════════════════════════════════════════════════════════════════════


class TestProviderTimeout:
    """
    Guards against the Critical finding: LLM provider network calls had
    no timeout, so a stuck HTTP call could hang the AgentLoop's single
    event loop forever (an infinite *wait*, not an infinite *retry*).

    Each test monkeypatches settings.llm_timeout_seconds down to a tiny
    value and asserts the call actually returns within that bound (not
    just "eventually raises something"). An outer asyncio.wait_for is
    used only as a generous test-harness backstop so a true regression
    fails fast with an assertion rather than hanging the whole suite;
    the real assertion is on ELAPSED TIME, which only a production-side
    timeout can satisfy.
    """

    @pytest.mark.asyncio
    async def test_generate_z3_scripts_times_out_on_hung_provider(self, monkeypatch):
        monkeypatch.setattr(settings, "llm_timeout_seconds", 0.2)
        client = _client_with(HangingProvider())

        start = time.monotonic()
        with pytest.raises((LLMClientError, asyncio.TimeoutError)):
            await asyncio.wait_for(
                client.generate_z3_scripts(_make_request(k=1)),
                timeout=5,  # harness backstop only — should never be reached
            )
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"generate_z3_scripts() was not bounded by llm_timeout_seconds "
            f"(took {elapsed:.1f}s) — the provider.generate() call has no "
            f"internal timeout and relies on the test harness backstop"
        )

    @pytest.mark.asyncio
    async def test_repair_times_out_on_hung_provider(self, monkeypatch):
        monkeypatch.setattr(settings, "llm_timeout_seconds", 0.2)
        client = _client_with(HangingProvider())
        failed_script = Z3Script(script_text="s.add(x == 1)", generation_idx=0, attempt_number=1)
        error_result = Z3Result(
            verdict=Z3Verdict.UNSAT, model=None, error_message="x",
            execution_time=0.1, script=failed_script,
        )

        start = time.monotonic()
        with pytest.raises((LLMClientError, asyncio.TimeoutError)):
            await asyncio.wait_for(
                client.repair_z3_script(_make_request(k=1), failed_script, error_result, attempt_number=2),
                timeout=5,
            )
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"repair_z3_script() was not bounded by llm_timeout_seconds "
            f"(took {elapsed:.1f}s)"
        )


# ═══════════════════════════════════════════════════════════════════════
#  LocalProvider stub
# ═══════════════════════════════════════════════════════════════════════


class TestLocalProvider:
    @pytest.mark.asyncio
    async def test_local_provider_raises_not_implemented(self):
        provider = LocalProvider()
        with pytest.raises(NotImplementedError):
            await provider.generate("sys", "user", 0.7, 1000, 1)
