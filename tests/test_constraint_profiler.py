"""
test_constraint_profiler.py — Unit tests for the ConstraintProfiler.

Tests the deterministic heuristic detectors against synthetic P-Code slices.
No external dependencies (no Ghidra, no LLM, no PostgreSQL).
"""

import pytest
from pathlib import Path

from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.models import PCodeInstruction, PCodeSlice, ConstraintProfile
from agentic_afl.extractor.constraint_profiler import ConstraintProfiler


# ── Helpers ──────────────────────────────────────────────────────────

def _inst(mnemonic: str, inputs: list[str] | None = None,
          output: str | None = None, address: str = "0x1000") -> PCodeInstruction:
    """Create a minimal PCodeInstruction for testing."""
    inputs = inputs or []
    raw = f"({output}) = {mnemonic} {' '.join(inputs)}" if output else f"{mnemonic} {' '.join(inputs)}"
    return PCodeInstruction(
        address=address,
        mnemonic=mnemonic,
        inputs=inputs,
        output=output,
        raw_pcode=raw,
    )


def _slice(instructions: list[PCodeInstruction],
           decompiled_c: str = "") -> PCodeSlice:
    """Create a minimal PCodeSlice for testing."""
    return PCodeSlice(
        binary_path=Path("/tmp/test_binary"),
        stall_address="0x4000",
        function_name="test_function",
        function_entry="0x3000",
        instructions=instructions,
        taint_source="input_buffer @ 0x20001000",
        slice_depth=5,
        truncated=False,
        architecture=Architecture.ARM32,
        decompiled_c=decompiled_c,
    )


@pytest.fixture
def profiler():
    return ConstraintProfiler()


# ═══════════════════════════════════════════════════════════════════════
#  Tag Detection Tests
# ═══════════════════════════════════════════════════════════════════════

class TestConstantEquality:
    """INT_EQUAL with a const operand → CONSTANT_EQUALITY."""

    def test_detects_int_equal_with_const(self, profiler):
        instructions = [
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x5a01, 2)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.CONSTANT_EQUALITY in profile.tags

    def test_ignores_int_equal_without_const(self, profiler):
        instructions = [
            _inst("INT_EQUAL", ["(register, r0, 4)", "(register, r1, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.CONSTANT_EQUALITY not in profile.tags


class TestRangeBound:
    """INT_LESS with a const operand → RANGE_BOUND."""

    def test_detects_int_less_with_const(self, profiler):
        instructions = [
            _inst("INT_LESS", ["(register, r0, 4)", "(const, 0x100, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.RANGE_BOUND in profile.tags

    def test_detects_int_sless_with_const(self, profiler):
        instructions = [
            _inst("INT_SLESS", ["(register, r0, 4)", "(const, 0x80, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.RANGE_BOUND in profile.tags


class TestMultiWayBranch:
    """BRANCHIND or dense INT_EQUAL chain → MULTI_WAY_BRANCH."""

    def test_detects_branchind(self, profiler):
        instructions = [_inst("BRANCHIND", ["(register, r0, 4)"])]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.MULTI_WAY_BRANCH in profile.tags

    def test_detects_dense_equality_chain(self, profiler):
        instructions = [
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x1, 4)"]),
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x2, 4)"]),
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x3, 4)"]),
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x4, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.MULTI_WAY_BRANCH in profile.tags


class TestBitmaskCheck:
    """INT_AND with a const mask → BITMASK_CHECK."""

    def test_detects_and_with_const_mask(self, profiler):
        instructions = [
            _inst("INT_AND", ["(register, r0, 4)", "(const, 0xFF, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.BITMASK_CHECK in profile.tags


class TestBitwiseLoop:
    """Loop with high bitwise density (XOR + shift) → BITWISE_LOOP."""

    def test_detects_crc_like_pattern(self, profiler):
        """Classic CRC: MULTIEQUAL + XOR + shift loop."""
        instructions = [
            _inst("MULTIEQUAL", ["(register, r0, 4)", "(register, r1, 4)"],
                  output="(register, r2, 4)"),
            _inst("INT_XOR", ["(register, r2, 4)", "(register, r3, 4)"],
                  output="(register, r4, 4)"),
            _inst("INT_RIGHT", ["(register, r4, 4)", "(const, 0x1, 4)"],
                  output="(register, r5, 4)"),
            _inst("INT_AND", ["(register, r5, 4)", "(const, 0xff, 4)"],
                  output="(register, r6, 4)"),
            _inst("INT_XOR", ["(register, r6, 4)", "(register, r7, 4)"],
                  output="(register, r8, 4)"),
            _inst("INT_LEFT", ["(register, r8, 4)", "(const, 0x8, 4)"],
                  output="(register, r9, 4)"),
            _inst("CBRANCH", ["(const, 0x3000, 4)", "(register, flags, 1)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.BITWISE_LOOP in profile.tags

    def test_no_loop_no_bitwise_loop(self, profiler):
        """High bitwise ops but no MULTIEQUAL → might still detect via fallback."""
        instructions = [
            _inst("INT_XOR", ["(register, r0, 4)", "(register, r1, 4)"],
                  output="(register, r2, 4)"),
            _inst("INT_ADD", ["(register, r2, 4)", "(register, r3, 4)"],
                  output="(register, r4, 4)"),
        ]
        profile = profiler.analyze(_slice(instructions))
        # No loop, low density → should NOT be BITWISE_LOOP
        assert ConstraintTag.BITWISE_LOOP not in profile.tags


class TestIndexedLookup:
    """PTRADD + LOAD → INDEXED_LOOKUP."""

    def test_detects_table_lookup(self, profiler):
        instructions = [
            _inst("PTRADD", ["(register, r0, 4)", "(register, r1, 4)", "(const, 0x4, 4)"],
                  output="(register, r2, 4)"),
            _inst("LOAD", ["(const, 0x0, 4)", "(register, r2, 4)"],
                  output="(register, r3, 4)"),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.INDEXED_LOOKUP in profile.tags


class TestLengthGatedAccess:
    """LOAD output used as INT_LESS input → LENGTH_GATED_ACCESS."""

    def test_detects_length_gate(self, profiler):
        load_output = "(register, r0, 4)"
        instructions = [
            _inst("LOAD", ["(const, 0x0, 4)", "(register, sp, 4)"],
                  output=load_output),
            _inst("INT_LESS", [load_output, "(register, r1, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.LENGTH_GATED_ACCESS in profile.tags


class TestChainedLoad:
    """LOAD output feeds another LOAD's address → CHAINED_LOAD."""

    def test_detects_ptr_deref_chain(self, profiler):
        load1_output = "(register, r0, 4)"
        instructions = [
            _inst("LOAD", ["(const, 0x0, 4)", "(register, sp, 4)"],
                  output=load1_output),
            _inst("LOAD", ["(const, 0x0, 4)", load1_output],
                  output="(register, r1, 4)"),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.CHAINED_LOAD in profile.tags


class TestCountedLoop:
    """MULTIEQUAL + INT_LESS with const → COUNTED_LOOP."""

    def test_detects_counted_loop(self, profiler):
        instructions = [
            _inst("MULTIEQUAL", ["(register, r0, 4)", "(register, r1, 4)"],
                  output="(register, r2, 4)"),
            _inst("INT_LESS", ["(register, r2, 4)", "(const, 0x10, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.COUNTED_LOOP in profile.tags


class TestInputDependentLoop:
    """MULTIEQUAL + comparison with LOAD output → INPUT_DEPENDENT_LOOP."""

    def test_detects_input_loop(self, profiler):
        load_output = "(register, len, 4)"
        instructions = [
            _inst("LOAD", ["(const, 0x0, 4)", "(register, sp, 4)"],
                  output=load_output),
            _inst("MULTIEQUAL", ["(register, r0, 4)", "(register, r1, 4)"],
                  output="(register, i, 4)"),
            _inst("INT_LESS", ["(register, i, 4)", load_output]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.INPUT_DEPENDENT_LOOP in profile.tags


class TestCalleeDependency:
    """CALL instruction → CALLEE_DEPENDENCY."""

    def test_detects_call(self, profiler):
        instructions = [
            _inst("CALL", ["(ram, 0x8000, 4)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.CALLEE_DEPENDENCY in profile.tags


class TestNestedConditional:
    """>2 CBRANCH without BRANCHIND → NESTED_CONDITIONAL."""

    def test_detects_nested_if(self, profiler):
        instructions = [
            _inst("CBRANCH", ["(const, 0x1000, 4)", "(register, flags, 1)"]),
            _inst("CBRANCH", ["(const, 0x2000, 4)", "(register, flags, 1)"]),
            _inst("CBRANCH", ["(const, 0x3000, 4)", "(register, flags, 1)"]),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert ConstraintTag.NESTED_CONDITIONAL in profile.tags


# ═══════════════════════════════════════════════════════════════════════
#  Decompiled C Supplementary Analysis
# ═══════════════════════════════════════════════════════════════════════

class TestDecompiledCAnalysis:
    """Tags from decompiled C pseudocode."""

    def test_detects_bitwise_loop_from_c(self, profiler):
        c_code = """
        for (int i = 0; i < len; i++) {
            crc = crc ^ data[i];
            crc = crc >> 1;
        }
        """
        profile = profiler.analyze(_slice([], decompiled_c=c_code))
        assert ConstraintTag.BITWISE_LOOP in profile.tags

    def test_detects_indexed_lookup_from_c(self, profiler):
        c_code = "result = lookup_table[input_byte];"
        profile = profiler.analyze(_slice([], decompiled_c=c_code))
        assert ConstraintTag.INDEXED_LOOKUP in profile.tags

    def test_detects_callee_from_c(self, profiler):
        c_code = "result = compute_checksum(data, len);"
        profile = profiler.analyze(_slice([], decompiled_c=c_code))
        assert ConstraintTag.CALLEE_DEPENDENCY in profile.tags


# ═══════════════════════════════════════════════════════════════════════
#  Structural Metrics
# ═══════════════════════════════════════════════════════════════════════

class TestMetrics:
    """Quantitative metrics: density, loop depth, register count, complexity."""

    def test_bitwise_density(self, profiler):
        instructions = [
            _inst("INT_XOR", ["r0", "r1"], output="r2"),
            _inst("INT_AND", ["r2", "r3"], output="r4"),
            _inst("INT_ADD", ["r4", "r5"], output="r6"),
        ]
        profile = profiler.analyze(_slice(instructions))
        # 2 bitwise / 3 total = 0.6667
        assert 0.6 < profile.bitwise_density < 0.7
        assert 0.3 < profile.arithmetic_density < 0.4

    def test_loop_depth_from_multiequal(self, profiler):
        instructions = [
            _inst("MULTIEQUAL", ["r0", "r1"], output="r2"),
            _inst("MULTIEQUAL", ["r3", "r4"], output="r5"),
            _inst("INT_ADD", ["r2", "r5"], output="r6"),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert profile.loop_depth == 2

    def test_register_count(self, profiler):
        instructions = [
            _inst("INT_XOR",
                  ["(register, AX@101222, 2)", "(register, BX@101224, 2)"],
                  output="(register, CX@101226, 2)"),
        ]
        profile = profiler.analyze(_slice(instructions))
        assert profile.register_count == 3  # AX, BX, CX

    def test_complexity_higher_with_bitwise_loop(self, profiler):
        simple_instructions = [
            _inst("INT_EQUAL", ["(register, r0, 4)", "(const, 0x5a, 4)"]),
        ]
        complex_instructions = [
            _inst("MULTIEQUAL", ["(register, r0, 4)", "(register, r1, 4)"],
                  output="(register, r2, 4)"),
            _inst("INT_XOR", ["(register, r2, 4)", "(register, r3, 4)"],
                  output="(register, r4, 4)"),
            _inst("INT_RIGHT", ["(register, r4, 4)", "(const, 0x1, 4)"],
                  output="(register, r5, 4)"),
            _inst("INT_XOR", ["(register, r5, 4)", "(register, r6, 4)"],
                  output="(register, r7, 4)"),
            _inst("INT_LEFT", ["(register, r7, 4)", "(const, 0x8, 4)"],
                  output="(register, r8, 4)"),
        ]
        simple_profile = profiler.analyze(_slice(simple_instructions))
        complex_profile = profiler.analyze(_slice(complex_instructions))
        assert complex_profile.estimated_complexity > simple_profile.estimated_complexity


# ═══════════════════════════════════════════════════════════════════════
#  Composite: Real-World-Like Slices
# ═══════════════════════════════════════════════════════════════════════

class TestRealWorldPatterns:
    """Composite tests mimicking real P-Code from Ghidra."""

    def test_crc16_modbus_pattern(self, profiler):
        """Simulates the CRC-16/Modbus P-Code slice structure."""
        instructions = [
            # LOAD input byte
            _inst("LOAD", ["(const, 0x0, 4)", "(register, r0, 4)"],
                  output="(register, r1, 4)"),
            # PHI for loop
            _inst("MULTIEQUAL", ["(register, crc_init, 2)", "(register, crc_next, 2)"],
                  output="(register, crc, 2)"),
            # XOR input byte with CRC
            _inst("INT_XOR", ["(register, crc, 2)", "(register, r1, 4)"],
                  output="(register, tmp0, 2)"),
            # Inner loop PHI
            _inst("MULTIEQUAL", ["(register, tmp0, 2)", "(register, tmp1, 2)"],
                  output="(register, bit_crc, 2)"),
            # Shift right
            _inst("INT_RIGHT", ["(register, bit_crc, 2)", "(const, 0x1, 2)"],
                  output="(register, shifted, 2)"),
            # Mask low bit
            _inst("INT_AND", ["(register, bit_crc, 2)", "(const, 0x1, 2)"],
                  output="(register, lsb, 1)"),
            # Conditional XOR with polynomial
            _inst("INT_XOR", ["(register, shifted, 2)", "(const, 0xa001, 2)"],
                  output="(register, tmp1, 2)"),
            # Inner loop bound
            _inst("INT_LESS", ["(register, bit_count, 4)", "(const, 0x8, 4)"]),
            _inst("CBRANCH", ["(const, 0x1000, 4)", "(register, flags, 1)"]),
            # Outer loop bound
            _inst("INT_LESS", ["(register, i, 4)", "(const, 0x100, 4)"]),
            _inst("CBRANCH", ["(const, 0x2000, 4)", "(register, flags, 1)"]),
            # Final comparison
            _inst("INT_EQUAL", ["(register, crc, 2)", "(const, 0x0, 2)"]),
        ]
        profile = profiler.analyze(_slice(instructions))

        # Should detect CRC-like structural tags.
        assert ConstraintTag.BITWISE_LOOP in profile.tags
        assert ConstraintTag.CONSTANT_EQUALITY in profile.tags
        assert ConstraintTag.COUNTED_LOOP in profile.tags
        # Should have high complexity.
        assert profile.estimated_complexity >= 40
        assert profile.bitwise_density > 0.2

    def test_empty_slice(self, profiler):
        """Empty slice should produce empty tags."""
        profile = profiler.analyze(_slice([]))
        assert len(profile.tags) == 0
        assert profile.estimated_complexity == 0
