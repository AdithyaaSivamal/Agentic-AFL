"""
Quick integration test for Z3Sandbox.
Executes a known-good Z3 script (magic number solver) and verifies SAT + model.
"""
import asyncio
import sys
sys.path.insert(0, ".")

from agentic_afl.models import Z3Script
from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox
from agentic_afl.constants import Z3Verdict


KNOWN_GOOD_SCRIPT = """\
# Magic number check: Concat(byte0, byte1) == 0x5A01
byte0 = BitVec('byte0', 8)
byte1 = BitVec('byte1', 8)
header = Concat(byte0, byte1)
s.add(header == BitVecVal(0x5A01, 16))
"""

KNOWN_UNSAT_SCRIPT = """\
# Impossible: x == 5 AND x == 10
x = BitVec('x', 8)
s.add(x == 5)
s.add(x == 10)
"""

KNOWN_SYNTAX_ERROR_SCRIPT = """\
# Intentional syntax error
x = BitVec('x', 8)
s.add(x == UNDEFINED_VARIABLE)
"""


async def test_sat():
    """Test that a valid Z3 script returns SAT with correct model."""
    sandbox = Z3Sandbox(timeout_seconds=5)
    script = Z3Script(
        script_text=KNOWN_GOOD_SCRIPT,
        generation_idx=0,
        attempt_number=1,
    )
    result = await sandbox.execute(script)

    assert result.verdict == Z3Verdict.SAT, f"Expected SAT, got {result.verdict}: {result.error_message}"
    assert result.model is not None, "Expected model, got None"
    assert result.model.get("byte0") == 0x5A, f"Expected byte0=0x5A, got {result.model.get('byte0')}"
    assert result.model.get("byte1") == 0x01, f"Expected byte1=0x01, got {result.model.get('byte1')}"
    print(f"  PASS: SAT test -- model={result.model}, time={result.execution_time:.2f}s")


async def test_unsat():
    """Test that an unsatisfiable script returns UNSAT."""
    sandbox = Z3Sandbox(timeout_seconds=5)
    script = Z3Script(
        script_text=KNOWN_UNSAT_SCRIPT,
        generation_idx=0,
        attempt_number=1,
    )
    result = await sandbox.execute(script)

    assert result.verdict == Z3Verdict.UNSAT, f"Expected UNSAT, got {result.verdict}: {result.error_message}"
    assert result.model is None, f"Expected no model, got {result.model}"
    print(f"  PASS: UNSAT test -- time={result.execution_time:.2f}s")


async def test_runtime_error():
    """Test that a script with undefined variables returns an error."""
    sandbox = Z3Sandbox(timeout_seconds=5)
    script = Z3Script(
        script_text=KNOWN_SYNTAX_ERROR_SCRIPT,
        generation_idx=0,
        attempt_number=1,
    )
    result = await sandbox.execute(script)

    assert result.verdict in (Z3Verdict.RUNTIME_ERROR, Z3Verdict.SYNTAX_ERROR), \
        f"Expected error verdict, got {result.verdict}"
    assert result.error_message is not None, "Expected error message"
    print(f"  PASS: Error test -- verdict={result.verdict.value}, error={result.error_message[:80]}")


async def main():
    print("\n" + "=" * 60)
    print("  Z3 Sandbox Integration Tests")
    print("=" * 60)

    await test_sat()
    await test_unsat()
    await test_runtime_error()

    print("\n" + "=" * 60)
    print("  All sandbox tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
