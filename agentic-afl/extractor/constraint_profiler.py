"""
constraint_profiler.py -- Structural Heuristic Engine for Constraint Classification.

This module analyzes a PCodeSlice and produces a ConstraintProfile -- a set of
STRUCTURAL ConstraintTag enums plus numerical metrics that characterize the
mathematical structure of a stall site.

Tags are ALGORITHM-AGNOSTIC: they describe structural patterns (loop shape,
bitwise density, comparison type) rather than specific algorithms (CRC, HMAC).
A proprietary `validate_xor_twist()` and a standard CRC-16 produce the same
structural fingerprint, enabling Jaccard-based CARM retrieval across domains.

Inputs:
    - PCodeSlice    -- From pcode_slicer.py

Outputs:
    - ConstraintProfile  -- Tags + metrics (see models.py)

The ConstraintProfile is the KEY input for CARM retrieval. Two stall sites
with similar profiles should be solvable with similar Z3 templates.

Reference: ConstraintLLM S2.1 -- "Constraint Type Identification"
Reference: TDD_v2 S4.1 -- "Constraint Profiling: operational density"

Design Notes:
    - This is a DETERMINISTIC heuristic engine. No LLM calls.
    - Each ConstraintTag has a corresponding detection function.
    - Detection is based on P-Code mnemonic patterns and operand analysis.
    - The profiler is intentionally conservative: it's better to miss a tag
      (causing CARM to retrieve a slightly less relevant template) than to
      falsely tag (causing the LLM to apply the wrong solving strategy).
"""

from __future__ import annotations

import logging
import re
from collections import Counter

from agentic_afl.constants import ConstraintTag
from agentic_afl.models import ConstraintProfile, PCodeSlice

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# P-Code mnemonic classification sets.
#
# Ghidra P-Code mnemonics reference:
#   https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html
# ---------------------------------------------------------------------------

BITWISE_OPS = frozenset({
    "INT_AND", "INT_OR", "INT_XOR", "INT_NEGATE",
    "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
})

ARITHMETIC_OPS = frozenset({
    "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
    "INT_REM", "INT_SREM",
})

COMPARISON_OPS = frozenset({
    "INT_EQUAL", "INT_NOTEQUAL",
    "INT_LESS", "INT_SLESS",
    "INT_LESSEQUAL", "INT_SLESSEQUAL",
})

BRANCH_OPS = frozenset({
    "BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN",
})

MEMORY_OPS = frozenset({
    "LOAD", "STORE",
})

# Regex for extracting register names from varnode strings like "(register, AX@101222, 2)"
_REGISTER_RE = re.compile(r"\(register,\s*([A-Za-z][A-Za-z0-9_]*)(?:@[0-9a-fA-F]+)?,\s*\d+\)")

# Regex for detecting constant varnodes like "(const, 0x5a01, 2)"
_CONST_RE = re.compile(r"\(const,\s*(0x[0-9a-fA-F]+|\d+),\s*\d+\)")


class ConstraintProfiler:
    """
    Analyzes P-Code slices and produces ConstraintProfiles with structural tags.

    All tags are algorithm-agnostic structural patterns. No algorithm-specific
    detection (e.g., "is this CRC?") is performed.

    Usage:
        profiler = ConstraintProfiler()
        profile = profiler.analyze(pcode_slice)
    """

    def analyze(self, pcode_slice: PCodeSlice) -> ConstraintProfile:
        """
        Analyze a PCodeSlice and produce a ConstraintProfile.

        Args:
            pcode_slice: The extracted P-Code slice from pcode_slicer.py.

        Returns:
            ConstraintProfile with detected tags and computed metrics.
        """
        mnemonic_counts = self._count_mnemonics(pcode_slice)

        total_ops = max(pcode_slice.instruction_count, 1)
        bitwise_density = mnemonic_counts["bitwise"] / total_ops
        arithmetic_density = mnemonic_counts["arithmetic"] / total_ops

        # Run all structural tag detectors.
        tags: set[ConstraintTag] = set()
        detectors = [
            self._detect_constant_equality,
            self._detect_range_bound,
            self._detect_multi_way_branch,
            self._detect_bitmask_check,
            self._detect_bitwise_loop,
            self._detect_bit_field_extraction,
            self._detect_indexed_lookup,
            self._detect_length_gated_access,
            self._detect_chained_load,
            self._detect_counted_loop,
            self._detect_input_dependent_loop,
            self._detect_callee_dependency,
            self._detect_nested_conditional,
        ]
        for detector in detectors:
            detected = detector(pcode_slice, mnemonic_counts)
            if detected is not None:
                tags.add(detected)

        # Supplementary: scan decompiled C for structural signals the
        # P-Code slice may have missed (e.g., callee analysis).
        c_tags = self._analyze_decompiled_c(pcode_slice)
        tags.update(c_tags)

        # Compute structural metrics.
        loop_depth = self._estimate_loop_depth(pcode_slice)
        register_count = self._count_distinct_registers(pcode_slice)
        complexity = self._estimate_complexity(tags, loop_depth, register_count)

        profile = ConstraintProfile(
            tags=frozenset(tags),
            bitwise_density=round(bitwise_density, 4),
            arithmetic_density=round(arithmetic_density, 4),
            loop_depth=loop_depth,
            register_count=register_count,
            estimated_complexity=complexity,
        )

        logger.info(
            "Profiled %s @ %s: tags=%s complexity=%d",
            pcode_slice.function_name,
            pcode_slice.stall_address,
            {t.name for t in profile.tags},
            profile.estimated_complexity,
        )
        return profile

    # -- Mnemonic Counting ---------------------------------------------------

    def _count_mnemonics(self, pcode_slice: PCodeSlice) -> dict[str, int]:
        """
        Count P-Code mnemonics by category.

        Returns:
            Dict with keys: "bitwise", "arithmetic", "comparison", "branch",
            "memory", "other" -- each mapping to the count in the slice.
        """
        counts: dict[str, int] = {
            "bitwise": 0,
            "arithmetic": 0,
            "comparison": 0,
            "branch": 0,
            "memory": 0,
            "other": 0,
        }
        for inst in pcode_slice.instructions:
            m = inst.mnemonic
            if m in BITWISE_OPS:
                counts["bitwise"] += 1
            elif m in ARITHMETIC_OPS:
                counts["arithmetic"] += 1
            elif m in COMPARISON_OPS:
                counts["comparison"] += 1
            elif m in BRANCH_OPS:
                counts["branch"] += 1
            elif m in MEMORY_OPS:
                counts["memory"] += 1
            else:
                counts["other"] += 1
        return counts

    # -- Structural Tag Detectors --------------------------------------------
    # Each detector returns a ConstraintTag if the structural pattern is
    # detected, or None if not. Detectors are algorithm-agnostic.

    def _detect_constant_equality(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: INT_EQUAL/INT_NOTEQUAL with a constant operand.

        Pattern: (register, rX) == (const, 0x5A01)
        Structural meaning: the branch depends on matching a fixed value.
        """
        for inst in pcode_slice.instructions:
            if inst.mnemonic not in ("INT_EQUAL", "INT_NOTEQUAL"):
                continue
            has_const = any(_CONST_RE.search(inp) for inp in inst.inputs)
            if has_const:
                return ConstraintTag.CONSTANT_EQUALITY
        return None

    def _detect_range_bound(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Range bound check (value must fall within [lo, hi]).

        Pattern: INT_LESS or INT_SLESS with a constant bound.
        """
        for inst in pcode_slice.instructions:
            if inst.mnemonic not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
                continue
            has_const = any(_CONST_RE.search(inp) for inp in inst.inputs)
            if has_const:
                return ConstraintTag.RANGE_BOUND
        return None

    def _detect_multi_way_branch(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: BRANCHIND or dense comparison chain (switch-table pattern).

        Pattern: BRANCHIND indicates indirect branch (switch/dispatch table).
        Alternatively, >3 sequential INT_EQUAL comparisons suggest if/else chain.
        """
        if "BRANCHIND" in pcode_slice.unique_mnemonics:
            return ConstraintTag.MULTI_WAY_BRANCH

        eq_count = sum(
            1 for inst in pcode_slice.instructions
            if inst.mnemonic == "INT_EQUAL"
        )
        if eq_count > 3:
            return ConstraintTag.MULTI_WAY_BRANCH

        return None

    def _detect_bitmask_check(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: AND operation with a constant mask.

        Pattern: (rX & MASK) followed by a comparison.
        """
        for inst in pcode_slice.instructions:
            if inst.mnemonic != "INT_AND":
                continue
            has_const = any(_CONST_RE.search(inp) for inp in inst.inputs)
            if has_const:
                return ConstraintTag.BITMASK_CHECK
        return None

    def _detect_bitwise_loop(
        self, pcode_slice: PCodeSlice, counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Loop body dominated by bitwise operations (XOR + shift).

        This is the STRUCTURAL signature of CRC, LRC, hash, scrambler, etc.
        Algorithm-agnostic: any loop with high bitwise density matches.

        Signals:
          1. MULTIEQUAL (PHI node) present = loop exists.
          2. Bitwise density > 0.3 AND both XOR and shift present.
        """
        # Must have a loop (indicated by PHI/MULTIEQUAL nodes).
        has_loop = "MULTIEQUAL" in pcode_slice.unique_mnemonics

        total = max(pcode_slice.instruction_count, 1)
        high_bitwise = counts["bitwise"] / total > 0.3

        mnemonics = pcode_slice.unique_mnemonics
        has_xor = "INT_XOR" in mnemonics
        has_shift = bool({"INT_RIGHT", "INT_LEFT", "INT_SRIGHT"} & mnemonics)

        if has_loop and high_bitwise and has_xor and has_shift:
            return ConstraintTag.BITWISE_LOOP

        # Fallback: even without MULTIEQUAL, very high bitwise density
        # (>0.5) with both XOR and shift is a strong signal (the loop
        # may have been unrolled by the decompiler).
        if counts["bitwise"] / total > 0.5 and has_xor and has_shift:
            return ConstraintTag.BITWISE_LOOP

        return None

    def _detect_bit_field_extraction(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Shift followed by AND (sub-field extraction from a word).

        Pattern: (value >> N) & MASK or (value & MASK) >> N.
        """
        mnemonics = pcode_slice.unique_mnemonics
        has_shift = bool({"INT_RIGHT", "INT_LEFT", "INT_SRIGHT"} & mnemonics)
        has_and = "INT_AND" in mnemonics

        if has_shift and has_and:
            # Verify there's a constant mask involved.
            for inst in pcode_slice.instructions:
                if inst.mnemonic == "INT_AND":
                    has_const = any(_CONST_RE.search(inp) for inp in inst.inputs)
                    if has_const:
                        return ConstraintTag.BIT_FIELD_EXTRACTION
        return None

    def _detect_indexed_lookup(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Array/table indexed by an input-derived value.

        Pattern: PTRADD or PTRSUB in the slice (address arithmetic) followed
        by a LOAD. Indicates table[input_value] access pattern.
        """
        mnemonics = pcode_slice.unique_mnemonics
        has_ptr_arith = bool({"PTRADD", "PTRSUB"} & mnemonics)
        has_load = "LOAD" in mnemonics

        if has_ptr_arith and has_load:
            return ConstraintTag.INDEXED_LOOKUP
        return None

    def _detect_length_gated_access(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: A loaded value used as a loop bound or memory access size.

        Pattern: LOAD output varnode appears as an input to INT_LESS/INT_LESSEQUAL.
        """
        load_outputs: set[str] = set()
        for inst in pcode_slice.instructions:
            if inst.mnemonic == "LOAD" and inst.output is not None:
                load_outputs.add(inst.output)

        if not load_outputs:
            return None

        for inst in pcode_slice.instructions:
            if inst.mnemonic not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
                continue
            for inp in inst.inputs:
                if inp in load_outputs:
                    return ConstraintTag.LENGTH_GATED_ACCESS
        return None

    def _detect_chained_load(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Multi-hop pointer dereference (LOAD output used as LOAD address).

        Pattern: Output of LOAD A feeds into the address input of LOAD B.
        """
        load_outputs: set[str] = set()
        for inst in pcode_slice.instructions:
            if inst.mnemonic == "LOAD" and inst.output is not None:
                load_outputs.add(inst.output)

        if not load_outputs:
            return None

        for inst in pcode_slice.instructions:
            if inst.mnemonic != "LOAD":
                continue
            # LOAD inputs: [space_id, address]. Check if address is a LOAD output.
            if len(inst.inputs) >= 2 and inst.inputs[1] in load_outputs:
                return ConstraintTag.CHAINED_LOAD
        return None

    def _detect_counted_loop(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Loop with a constant iteration bound.

        Pattern: MULTIEQUAL (PHI node) + INT_LESS with a constant bound.
        """
        if "MULTIEQUAL" not in pcode_slice.unique_mnemonics:
            return None

        for inst in pcode_slice.instructions:
            if inst.mnemonic not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL"):
                continue
            has_const = any(_CONST_RE.search(inp) for inp in inst.inputs)
            if has_const:
                return ConstraintTag.COUNTED_LOOP
        return None

    def _detect_input_dependent_loop(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Loop whose bound comes from a LOAD (input-derived).

        Pattern: MULTIEQUAL + comparison where one input is a LOAD output.
        """
        if "MULTIEQUAL" not in pcode_slice.unique_mnemonics:
            return None

        load_outputs: set[str] = set()
        for inst in pcode_slice.instructions:
            if inst.mnemonic == "LOAD" and inst.output is not None:
                load_outputs.add(inst.output)

        for inst in pcode_slice.instructions:
            if inst.mnemonic not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL"):
                continue
            for inp in inst.inputs:
                if inp in load_outputs:
                    return ConstraintTag.INPUT_DEPENDENT_LOOP
        return None

    def _detect_callee_dependency(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Constraint involves a CALL to another function.

        Pattern: CALL or CALLIND instruction present in the slice.
        """
        for inst in pcode_slice.instructions:
            if inst.mnemonic in ("CALL", "CALLIND"):
                return ConstraintTag.CALLEE_DEPENDENCY
        return None

    def _detect_nested_conditional(
        self, pcode_slice: PCodeSlice, _counts: dict[str, int]
    ) -> ConstraintTag | None:
        """
        Detect: Multiple CBRANCH instructions suggesting nested if/else.

        Pattern: >2 CBRANCH instructions without BRANCHIND (not a switch table).
        """
        cbranch_count = sum(
            1 for inst in pcode_slice.instructions
            if inst.mnemonic == "CBRANCH"
        )
        if cbranch_count > 2 and "BRANCHIND" not in pcode_slice.unique_mnemonics:
            return ConstraintTag.NESTED_CONDITIONAL
        return None

    # -- Decompiled C Supplementary Analysis ---------------------------------

    def _analyze_decompiled_c(self, pcode_slice: PCodeSlice) -> set[ConstraintTag]:
        """
        Extract supplementary structural signals from decompiled C pseudocode.

        This catches patterns that the P-Code slice may miss due to taint
        bounding or decompiler transformations. Signals are conservative --
        only added when the C code strongly indicates the pattern.
        """
        tags: set[ConstraintTag] = set()
        decompiled_c = getattr(pcode_slice, "decompiled_c", "") or ""
        if not decompiled_c:
            return tags

        c_lower = decompiled_c.lower()

        # Bitwise loop: for/while loop body with ^, >>, <<, &
        if ("for " in c_lower or "while " in c_lower):
            # Check for bitwise operators in the same function
            bitwise_ops = sum(1 for op in ["^", ">>", "<<", "& "] if op in decompiled_c)
            if bitwise_ops >= 2:
                tags.add(ConstraintTag.BITWISE_LOOP)

        # Indexed lookup: array access with [] and pointer arithmetic
        if "[" in decompiled_c and "]" in decompiled_c:
            tags.add(ConstraintTag.INDEXED_LOOKUP)

        # Callee dependency: function calls visible in decompiled C
        # Look for function call patterns: identifier followed by (
        import re as _re
        call_pattern = _re.findall(r'\b[a-zA-Z_]\w*\s*\(', decompiled_c)
        # Filter out control flow keywords
        control_keywords = {"if", "for", "while", "switch", "return", "sizeof"}
        actual_calls = [c for c in call_pattern
                        if c.strip().rstrip("(").strip() not in control_keywords]
        if len(actual_calls) > 0:
            tags.add(ConstraintTag.CALLEE_DEPENDENCY)

        return tags

    # -- Structural Metrics --------------------------------------------------

    def _estimate_loop_depth(self, pcode_slice: PCodeSlice) -> int:
        """
        Estimate maximum loop nesting depth from PHI (MULTIEQUAL) nodes.

        In SSA form, each MULTIEQUAL (PHI) node indicates a control-flow
        merge point, which typically corresponds to a loop header.
        """
        phi_count = sum(
            1 for inst in pcode_slice.instructions
            if inst.mnemonic == "MULTIEQUAL"
        )
        return phi_count

    def _count_distinct_registers(self, pcode_slice: PCodeSlice) -> int:
        """
        Count the number of distinct register varnodes in the slice.

        This correlates with the number of BitVec variables the LLM will
        need to declare in the Z3 script.
        """
        register_names: set[str] = set()
        for inst in pcode_slice.instructions:
            for inp in inst.inputs:
                match = _REGISTER_RE.search(inp)
                if match:
                    register_names.add(match.group(1))
            if inst.output is not None:
                match = _REGISTER_RE.search(inst.output)
                if match:
                    register_names.add(match.group(1))
        return len(register_names)

    def _estimate_complexity(
        self,
        tags: set[ConstraintTag],
        loop_depth: int,
        register_count: int,
    ) -> int:
        """
        Compute a heuristic difficulty score (0-100).

        Factors:
          - Number of tags (more structural patterns = harder)
          - Presence of loop tags (significant penalty)
          - Bitwise loop (heavy penalty -- CRC/hash-like constraints)
          - Loop depth (significant penalty)
          - Register count (linear penalty)
        """
        score = 10 * len(tags)

        # Heavy penalties for complex structural patterns.
        if ConstraintTag.BITWISE_LOOP in tags:
            score += 30
        if ConstraintTag.CHAINED_LOAD in tags:
            score += 15
        if ConstraintTag.INPUT_DEPENDENT_LOOP in tags:
            score += 20

        # Loop and register penalties.
        score += 5 * loop_depth
        score += 2 * register_count

        return min(100, max(0, score))
"""
<parameter name="Description">Complete rewrite of constraint_profiler.py replacing all algorithm-specific detectors with structural, algorithm-agnostic detectors. No more CRC/LRC/hash-specific detection — instead we detect structural patterns like BITWISE_LOOP, INDEXED_LOOKUP, CALLEE_DEPENDENCY, COUNTED_LOOP, CHAINED_LOAD, etc."
"""
