"""
react_templates.py -- Structural Strategy Hints for the Orchestrator.

These strategy hints are generated DYNAMICALLY from ConstraintProfile metrics,
replacing the old hardcoded Thought Cards. Hints are algorithm-agnostic:
they guide the LLM based on structural patterns (bitwise density, loop depth,
comparison type) rather than specific algorithms.

Reference: ConstraintLLM S2.1 -- structural constraint profiles.
Reference: MCTS-based_2 / HiAR-ICL -- abstract reasoning pattern templates.
"""

from __future__ import annotations

from agentic_afl.constants import ConstraintTag
from agentic_afl.models import ConstraintProfile


# ---------------------------------------------------------------------------
# Strategy Hint Builder -- Dynamic, metric-driven guidance for the LLM.
# ---------------------------------------------------------------------------

def build_strategy_hints(profile: ConstraintProfile) -> str:
    """
    Generate algorithm-agnostic solving strategy hints from structural metrics.

    These hints replace the old hardcoded Thought Cards. Instead of saying
    "this is a CRC, use z3_crc16_modbus()", we say "this has high bitwise
    density with a loop -- model ALL XOR/shift operations symbolically."

    Args:
        profile: The ConstraintProfile from the profiler.

    Returns:
        A formatted string of strategy hints to append to the LLM prompt.
        Empty string if no hints are applicable.
    """
    hints: list[str] = []

    # --- Bitwise density hint ---
    if profile.bitwise_density > 0.3:
        hints.append(
            "**High bitwise density detected (%.0f%%)**: "
            "This constraint involves significant bit manipulation (XOR, shift, AND). "
            "Use `BitVec('name', 8)` for individual bytes and model ALL bitwise "
            "operations symbolically. Do NOT approximate or skip any step in the "
            "computation chain."
            % (profile.bitwise_density * 100)
        )

    # --- Loop structure hint ---
    if profile.loop_depth > 0:
        if ConstraintTag.COUNTED_LOOP in profile.tags:
            hints.append(
                "**Counted loop detected (depth=%d)**: "
                "The constraint contains a loop with a constant iteration bound. "
                "Unroll the loop completely in Z3 using a Python `for` loop "
                "that iterates over `BitVec` variables. Do NOT use recursive "
                "Z3 functions or symbolic loop bounds."
                % profile.loop_depth
            )
        elif ConstraintTag.INPUT_DEPENDENT_LOOP in profile.tags:
            hints.append(
                "**Input-dependent loop detected (depth=%d)**: "
                "The loop bound comes from the input buffer. Concretize the "
                "loop bound to the value from the seed input and unroll."
                % profile.loop_depth
            )

    # --- Bitwise loop hint (CRC/hash/scrambler-like) ---
    if ConstraintTag.BITWISE_LOOP in profile.tags:
        hints.append(
            "**Bitwise loop detected**: The constraint contains a loop body "
            "dominated by XOR, shift, and AND operations. This is characteristic "
            "of checksum, CRC, hash, or scrambling algorithms. Read the decompiled "
            "C code carefully to understand the EXACT computation. Model each "
            "iteration of the loop in Z3 using BitVec operations:\n"
            "  - `^` for XOR → `a ^ b` (Z3 BitVec XOR)\n"
            "  - `>> N` for right shift → `LShR(a, N)` (logical shift right)\n"
            "  - `<< N` for left shift → `a << N`\n"
            "  - `& MASK` for AND → `a & BitVecVal(MASK, width)`\n"
            "  - Use `If(condition, then, else)` for conditional branches inside the loop."
        )

    # --- Callee dependency hint ---
    if ConstraintTag.CALLEE_DEPENDENCY in profile.tags:
        hints.append(
            "**Function call dependency detected**: The constraint depends on "
            "the return value of a called function. Read the decompiled C "
            "carefully to understand the callee's logic. INLINE the callee's "
            "computation into your Z3 script -- model it as a sequence of "
            "BitVec operations, not as an opaque function."
        )

    # --- Indexed lookup hint ---
    if ConstraintTag.INDEXED_LOOKUP in profile.tags:
        hints.append(
            "**Lookup table detected (INDEXED_LOOKUP)**: The decompiled C uses "
            "an array/table indexed by an input-derived value (e.g., "
            "`crc_table[byte ^ crc_lo]`).\n\n"
            "  **CRITICAL**: Do NOT hardcode the table as a Python list — it will "
            "truncate and cause SyntaxError. Instead, replace the table lookup "
            "with the equivalent BITWISE POLYNOMIAL DIVISION loop.\n\n"
            "  **CRC-16 Bitwise Template** (works for CRC-16/DNP3, CRC-16/Modbus, etc.):\n"
            "  ```python\n"
            "  # Identify the polynomial from the decompiled C table.\n"
            "  # For CRC-16/DNP3: poly = 0xA6BC (bit-reversed 0x3D65)\n"
            "  # For CRC-16/Modbus: poly = 0xA001 (bit-reversed 0x8005)\n"
            "  poly = BitVecVal(POLY_VALUE, 16)\n"
            "  crc = BitVecVal(INIT_VALUE, 16)  # 0 for DNP3, 0xFFFF for Modbus\n\n"
            "  for i in range(NUM_BYTES):  # iterate over input bytes\n"
            "      crc = crc ^ ZeroExt(8, input_bytes[i])\n"
            "      for _ in range(8):  # 8 bits of polynomial division\n"
            "          lsb = Extract(0, 0, crc)\n"
            "          crc = If(lsb == 1, LShR(crc, 1) ^ poly, LShR(crc, 1))\n\n"
            "  final_crc = ~crc  # or just crc, depending on the algorithm\n"
            "  # Compare with the CRC bytes in the input (little-endian):\n"
            "  s.add(final_crc == Concat(input_bytes[crc_hi], input_bytes[crc_lo]))\n"
            "  ```\n"
            "  Adapt the polynomial, init value, and final XOR to match the specific algorithm."
        )

    # --- Chained load hint ---
    if ConstraintTag.CHAINED_LOAD in profile.tags:
        hints.append(
            "**Multi-hop pointer dereference detected**: A memory load's "
            "result is used as the address for another load. Model each "
            "dereference step explicitly in Z3."
        )

    # --- Length-gated access hint ---
    if ConstraintTag.LENGTH_GATED_ACCESS in profile.tags:
        hints.append(
            "**Length-gated access detected**: A loaded value controls "
            "the size of a subsequent memory access or loop iteration. "
            "Constrain the length field to a valid range from the protocol spec."
        )

    # --- Multi-way branch hint ---
    if ConstraintTag.MULTI_WAY_BRANCH in profile.tags:
        hints.append(
            "**Multi-way branch detected**: The constraint involves a "
            "switch/dispatch table or dense if/else chain. Pick ONE valid "
            "branch value and constrain the input byte to that value."
        )

    # --- Complexity warning ---
    if profile.estimated_complexity > 60:
        hints.append(
            "**⚠ High complexity (score=%d/100)**: Consider simplifying by "
            "concretizing peripheral variables that are not directly from "
            "the input buffer. Focus Z3 constraints on the input bytes only."
            % profile.estimated_complexity
        )

    if not hints:
        return ""

    return (
        "## Structural Strategy Hints\n"
        "The following hints are derived from the structural analysis of the "
        "P-Code slice. Use them to guide your Z3 script generation.\n\n"
        + "\n\n".join(hints)
    )


# ---------------------------------------------------------------------------
# Symbolic ReAct System Prompt (kept for structured reasoning)
# ---------------------------------------------------------------------------

SYMBOLIC_REACT_SYSTEM = """\
You are a firmware constraint solver. Analyze the given P-Code slice and
produce a Z3Py script using the Symbolic ReAct reasoning format.

For EACH reasoning step, use this format:

**Thought**: [What you plan to do next and why]
**Action**: [The specific symbolic operation: DECLARE, TRANSLATE, CONSTRAIN, or SOLVE]
**Observation**: [The Z3Py code or formal result of that action]

Available Actions:
  - DECLARE: Declare BitVec variables for registers/memory.
  - TRANSLATE: Convert a P-Code instruction to a Z3 constraint.
  - CONSTRAIN: Add path condition constraints for the target branch.
  - SOLVE: Write the final s.check() + model extraction block.

After all reasoning steps, provide the complete Z3Py script in a ```python block.
"""
