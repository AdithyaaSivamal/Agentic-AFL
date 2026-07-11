"""
test_z3_sandbox.py — Unit tests for the Z3Sandbox.

Tests script sanitization, harness wrapping, execution, and result parsing.
Requires z3-solver to be installed (but no LLM, Ghidra, or PostgreSQL).
"""

import asyncio
import pytest
from pathlib import Path

from agentic_afl.constants import Z3Verdict
from agentic_afl.models import Z3Script, Z3Result
from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox


def _script(text: str) -> Z3Script:
    """Create a minimal Z3Script for testing."""
    return Z3Script(
        script_text=text,
        generation_idx=0,
        attempt_number=1,
        model_name="test",
    )


@pytest.fixture
def sandbox(tmp_path):
    return Z3Sandbox(
        timeout_seconds=5,
        sandbox_dir=tmp_path / "sandbox",
        keep_scripts=True,
    )


# ═══════════════════════════════════════════════════════════════════════
#  Script Sanitization
# ═══════════════════════════════════════════════════════════════════════

class TestSanitization:
    """Verify that the sanitizer correctly strips harness-provided lines."""

    def test_strips_z3_import(self, sandbox):
        script = _script("from z3 import *\nx = BitVec('x', 32)\ns.add(x > 0)")
        wrapped = sandbox._wrap_script(script.script_text)
        # Should NOT have double import
        assert wrapped.count("from z3 import *") == 1

    def test_strips_solver_creation(self, sandbox):
        script = _script("s = Solver()\ns.add(x > 0)")
        wrapped = sandbox._wrap_script(script.script_text)
        # The harness already has s = Solver() — LLM's should be stripped
        assert wrapped.count("s = Solver()") == 1

    def test_strips_check_and_model(self, sandbox):
        script = _script(
            "x = BitVec('x', 32)\n"
            "s.add(x > 0)\n"
            "result = s.check()\n"
            "if result == sat:\n"
            "    m = s.model()\n"
            "    for d in m.decls():\n"
            "        print(d, m[d])\n"
        )
        wrapped = sandbox._wrap_script(script.script_text)
        # Extract only the LLM script section between delimiters
        begin = wrapped.find("# === BEGIN LLM SCRIPT ===")
        end = wrapped.find("# === END LLM SCRIPT ===")
        llm_section = wrapped[begin:end]
        # The LLM's check/model code should be stripped from the script section
        assert "result = s.check()" not in llm_section
        assert "m = s.model()" not in llm_section
        # But the constraint logic should be preserved
        assert "s.add(x > 0)" in llm_section

    def test_preserves_constraint_logic(self, sandbox):
        script = _script(
            "x = BitVec('x', 32)\n"
            "y = BitVec('y', 32)\n"
            "s.add(x ^ y == 0x1234)\n"
            "s.add(x > 0)\n"
        )
        wrapped = sandbox._wrap_script(script.script_text)
        assert "x ^ y == 0x1234" in wrapped
        assert "s.add(x > 0)" in wrapped


# ═══════════════════════════════════════════════════════════════════════
#  Execution: SAT
# ═══════════════════════════════════════════════════════════════════════

class TestSATExecution:
    """Test that solvable constraints return SAT with correct models."""

    @pytest.mark.asyncio
    async def test_simple_sat(self, sandbox):
        """x == 42 should be trivially SAT."""
        script = _script("x = BitVec('x', 32)\ns.add(x == 42)")
        result = await sandbox.execute(script)
        assert result.verdict == Z3Verdict.SAT
        assert result.model is not None
        assert result.model.get("x") == 42

    @pytest.mark.asyncio
    async def test_xor_constraint(self, sandbox):
        """x ^ 0xABCD == 0 → x must be 0xABCD."""
        script = _script(
            "x = BitVec('x', 16)\n"
            "s.add(x ^ 0xABCD == 0)\n"
        )
        result = await sandbox.execute(script)
        assert result.verdict == Z3Verdict.SAT
        assert result.model is not None
        assert result.model.get("x") == 0xABCD

    @pytest.mark.asyncio
    async def test_multi_variable_sat(self, sandbox):
        """System of constraints with multiple variables."""
        script = _script(
            "a = BitVec('a', 8)\n"
            "b = BitVec('b', 8)\n"
            "s.add(a + b == 100)\n"
            "s.add(a > 0)\n"
            "s.add(b > 0)\n"
        )
        result = await sandbox.execute(script)
        assert result.verdict == Z3Verdict.SAT
        assert result.model is not None
        a_val = result.model["a"]
        b_val = result.model["b"]
        assert (a_val + b_val) % 256 == 100


# ═══════════════════════════════════════════════════════════════════════
#  Execution: UNSAT
# ═══════════════════════════════════════════════════════════════════════

class TestUNSATExecution:
    """Test that contradictory constraints return UNSAT."""

    @pytest.mark.asyncio
    async def test_simple_unsat(self, sandbox):
        """x == 1 AND x == 2 is contradictory."""
        script = _script(
            "x = BitVec('x', 32)\n"
            "s.add(x == 1)\n"
            "s.add(x == 2)\n"
        )
        result = await sandbox.execute(script)
        assert result.verdict == Z3Verdict.UNSAT


# ═══════════════════════════════════════════════════════════════════════
#  Execution: Error Handling
# ═══════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Test that syntax errors and runtime errors are handled gracefully."""

    @pytest.mark.asyncio
    async def test_syntax_error(self, sandbox):
        """Invalid Python should return SYNTAX_ERROR or RUNTIME_ERROR."""
        script = _script("this is not valid python code!!!")
        result = await sandbox.execute(script)
        assert result.verdict in (Z3Verdict.SYNTAX_ERROR, Z3Verdict.RUNTIME_ERROR)
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_undefined_variable(self, sandbox):
        """Using undeclared variable should return runtime error."""
        script = _script("s.add(undefined_var > 0)")
        result = await sandbox.execute(script)
        assert result.verdict in (Z3Verdict.SYNTAX_ERROR, Z3Verdict.RUNTIME_ERROR)
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_blocked_import(self, sandbox):
        """Importing os should be blocked by the sandbox."""
        script = _script("import os\nos.system('echo pwned')")
        result = await sandbox.execute(script)
        assert result.verdict in (Z3Verdict.SYNTAX_ERROR, Z3Verdict.RUNTIME_ERROR)
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_execution_time_recorded(self, sandbox):
        """Verify that execution_time is always populated."""
        script = _script("x = BitVec('x', 32)\ns.add(x == 1)")
        result = await sandbox.execute(script)
        assert result.execution_time > 0


# ═══════════════════════════════════════════════════════════════════════
#  Seed preservation (unconstrained byte_N vars should not zero out
#  already-valid seed bytes — see magma_libpng validation finding)
# ═══════════════════════════════════════════════════════════════════════

class TestSeedPreservation:
    """
    _model_to_payload() only preserves seed bytes for positions that
    never appear as a byte_N variable in the Z3 model at all. If the
    LLM's script *declares* byte_0..byte_N (e.g. to model the whole
    buffer) but only *constrains* a few of them, Z3 is free to pick an
    arbitrary value (usually 0) for the rest -- silently corrupting
    already-valid seed data on merge. The sandbox should pin any
    declared-but-unconstrained byte var to its seed value, relaxing the
    pin only when it actually conflicts with the script's real
    constraints.
    """

    @pytest.mark.asyncio
    async def test_unconstrained_byte_preserves_seed_value(self, sandbox):
        script = _script(
            "byte_0 = BitVec('byte_0', 8)\n"
            "byte_1 = BitVec('byte_1', 8)\n"
            "s.add(byte_0 == 0x11)\n"
            # byte_1 is declared but never constrained by the script.
        )
        seed = bytes([0x11, 0xAA])
        result = await sandbox.execute(script, seed_input=seed)
        assert result.verdict == Z3Verdict.SAT
        assert result.model["byte_0"] == 0x11
        assert result.model["byte_1"] == 0xAA  # preserved, not Z3's default 0

    @pytest.mark.asyncio
    async def test_genuinely_constrained_byte_still_solves_correctly(self, sandbox):
        # Seed for both bytes is 0xAA; XOR of two 0xAA is 0, not 0x11, so
        # at least one pin MUST be relaxed for the real constraint to hold.
        script = _script(
            "byte_0 = BitVec('byte_0', 8)\n"
            "byte_1 = BitVec('byte_1', 8)\n"
            "s.add(byte_0 ^ byte_1 == 0x11)\n"
        )
        seed = bytes([0xAA, 0xAA])
        result = await sandbox.execute(script, seed_input=seed)
        assert result.verdict == Z3Verdict.SAT
        assert (result.model["byte_0"] ^ result.model["byte_1"]) == 0x11

    @pytest.mark.asyncio
    async def test_no_seed_behaves_as_before(self, sandbox):
        """Without a seed (default), no pinning is applied at all."""
        script = _script("x = BitVec('x', 32)\ns.add(x == 42)")
        result = await sandbox.execute(script)
        assert result.verdict == Z3Verdict.SAT
        assert result.model["x"] == 42

    @pytest.mark.asyncio
    async def test_pin_bookkeeping_vars_excluded_from_model(self, sandbox):
        """Internal '_pin_*' assumption vars must never leak into the
        returned model dict."""
        script = _script(
            "byte_0 = BitVec('byte_0', 8)\n"
            "s.add(byte_0 == 5)\n"
        )
        result = await sandbox.execute(script, seed_input=bytes([9]))
        assert result.verdict == Z3Verdict.SAT
        assert all(not k.startswith("_pin_") for k in result.model)


# ═══════════════════════════════════════════════════════════════════════
#  Execution: Timeout (health-review gap — previously untested)
# ═══════════════════════════════════════════════════════════════════════

class TestTimeoutExecution:
    """
    UNSAT and TIMEOUT are easy to confuse (both mean "no SAT model"), but
    they imply opposite repair strategies: UNSAT means the constraints
    are logically contradictory (needs a different formulation), while
    TIMEOUT means the solver ran out of time (may need concretization or
    a longer budget). This distinction was previously untested.
    """

    @pytest.mark.asyncio
    async def test_slow_constraint_returns_timeout_not_unsat(self, tmp_path):
        """A genuinely hard (but satisfiable) constraint under a very
        tight solver budget must report TIMEOUT, not UNSAT or an error."""
        tight_sandbox = Z3Sandbox(
            timeout_seconds=1,
            sandbox_dir=tmp_path / "sandbox",
            keep_scripts=True,
        )
        # A wide multiplication constraint over large bitvectors is cheap
        # to state but can be slow for Z3 to fully explore; combined with
        # a 1-second budget this reliably times out without any process
        # actually hanging (the harness's own s.set("timeout", ...) fires).
        script = _script(
            "a = BitVec('a', 64)\n"
            "b = BitVec('b', 64)\n"
            "c = BitVec('c', 64)\n"
            "s.add(a * a * a == b * b * b * b + c)\n"
            "s.add(a > 1000000)\n"
            "s.add(b > 1000000)\n"
            "s.add(c > 1000000)\n"
        )
        result = await tight_sandbox.execute(script)
        # Z3 may occasionally solve this instantly on a fast machine, but
        # it must never be misreported as a hard UNSAT/error -- only
        # SAT, TIMEOUT, or UNKNOWN are acceptable outcomes here.
        assert result.verdict in (Z3Verdict.TIMEOUT, Z3Verdict.SAT, Z3Verdict.UNKNOWN)

    @pytest.mark.asyncio
    async def test_process_level_timeout_when_harness_itself_hangs(self, tmp_path, monkeypatch):
        """
        If the Z3 harness process itself never produces output (e.g. it
        hangs before reaching s.check(), such as an infinite Python loop
        in the LLM-generated script BEFORE any s.add() call), the
        asyncio.wait_for around the subprocess (not Z3's own internal
        timeout) must still bound total wall-clock time.
        """
        tight_sandbox = Z3Sandbox(
            timeout_seconds=1,
            sandbox_dir=tmp_path / "sandbox",
            keep_scripts=True,
        )
        # An infinite loop that never reaches s.check() -- Z3's internal
        # solver timeout cannot help here; only the subprocess-level
        # asyncio.wait_for (timeout_seconds + 5s overhead) can.
        script = _script("while True:\n    pass\n")
        result = await tight_sandbox.execute(script)
        assert result.verdict == Z3Verdict.TIMEOUT
        # Bounded by timeout_seconds(1) + 5s overhead, with generous slack.
        assert result.execution_time < 10
