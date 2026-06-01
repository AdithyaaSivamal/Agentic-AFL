"""
constants.py — Structural Constraint Ontology and System-Wide Enumerations.

This module defines the formal vocabulary of STRUCTURAL constraint types
that flows through the entire pipeline:
  - constraint_profiler.py PRODUCES ConstraintTag sets from P-Code analysis.
  - retrieval_carm.py CONSUMES ConstraintTag sets for Jaccard similarity matching.
  - llm_client.py READS ConstraintTag sets to generate strategy hints.

The ontology is algorithm-agnostic: tags describe STRUCTURAL patterns
(loop shape, bitwise density, comparison type) rather than specific
algorithms (CRC, HMAC). This ensures scalability to unknown/custom
algorithms via Jaccard similarity (ConstraintLLM §2.1 Eq. 3).

Adding a new tag:
  1. Add the enum member below.
  2. Add the detection heuristic in constraint_profiler.py.
"""

from enum import Enum, auto


class ConstraintTag(Enum):
    """
    Structural constraint type tags derived from P-Code analysis.

    Each tag represents a STRUCTURAL pattern observed in a backward slice,
    NOT a specific algorithm. This ensures the ontology scales to unknown
    algorithms — a proprietary checksum and a standard CRC-16 produce the
    same structural fingerprint for Jaccard matching in CARM.

    Reference: ConstraintLLM §2.1 — Constraint type ontology O.
    """

    # --- Comparison Patterns ---
    CONSTANT_EQUALITY = auto()       # (reg == CONST): magic numbers, header checks
    RANGE_BOUND = auto()             # (reg < CONST): bounds checks, value validation
    MULTI_WAY_BRANCH = auto()        # Dense if/else chain or BRANCHIND (switch/dispatch table)

    # --- Bitwise Structure ---
    BITMASK_CHECK = auto()           # (input & MASK) == EXPECTED: flag checks
    BITWISE_LOOP = auto()            # Loop body dominated by XOR/shift/AND (CRC, hash, scrambler)
    BIT_FIELD_EXTRACTION = auto()    # Shift + mask to extract sub-fields from a word

    # --- Arithmetic Structure ---
    MODULAR_ARITHMETIC = auto()      # Modulo/remainder operations
    OVERFLOW_DEPENDENT = auto()      # Logic depends on integer overflow behavior
    LINEAR_CONSTRAINT = auto()       # ax + by + c == 0 style constraints

    # --- Memory / Data Flow ---
    INDEXED_LOOKUP = auto()          # Array/table indexed by input-derived value
    LENGTH_GATED_ACCESS = auto()     # Memory access bounded by a loaded length field
    CHAINED_LOAD = auto()            # Multi-hop pointer dereference chain (LOAD → addr → LOAD)

    # --- Loop Structure ---
    COUNTED_LOOP = auto()            # Loop with a constant iteration bound
    INPUT_DEPENDENT_LOOP = auto()    # Loop bound derived from input bytes

    # --- Complexity Markers ---
    CALLEE_DEPENDENCY = auto()       # Constraint involves a CALL to another function
    NESTED_CONDITIONAL = auto()      # Multi-level if/else nesting


class Architecture(Enum):
    """Target CPU architecture — determines BitVec widths in Z3 scripts."""
    ARM32 = "arm32"       # 32-bit ARM (Cortex-M, Cortex-R)
    ARM64 = "arm64"       # 64-bit ARM (Cortex-A)
    X86 = "x86"           # 32-bit x86
    X86_64 = "x86_64"     # 64-bit x86
    MIPS32 = "mips32"     # 32-bit MIPS (common in routers/IoT)
    PPC32 = "ppc32"       # 32-bit PowerPC (some PLCs)


class Z3Verdict(Enum):
    """Possible outcomes of Z3 script execution in the sandbox."""
    SAT = "sat"               # Satisfiable — concrete model found
    UNSAT = "unsat"           # Unsatisfiable — no solution exists
    TIMEOUT = "timeout"       # s.check() exceeded time budget
    SYNTAX_ERROR = "syntax_error"   # Z3 script failed to parse/compile
    RUNTIME_ERROR = "runtime_error" # Script executed but threw an exception
    UNKNOWN = "unknown"       # Z3 returned unknown (e.g., non-linear arithmetic)


class StallSeverity(Enum):
    """
    Priority classification for AFL++ stall sites.

    Reference: HyLLfuzz §3.1 — "interestingness" scoring for roadblock selection.
    Higher severity = attacked first by the Orchestrator.
    """
    CRITICAL = auto()    # Coverage completely blocked (0 new edges after N cycles)
    HIGH = auto()        # Very few new edges, high cyclomatic complexity at stall
    MEDIUM = auto()      # Some coverage possible but branch is consistently missed
    LOW = auto()         # Stall exists but alternative paths provide coverage


# ---------------------------------------------------------------------------
# System defaults — referenced by config.py but defined here to avoid
# circular imports.
# ---------------------------------------------------------------------------

# LLM-Sym §3.2: 3-attempt self-repair cycle
DEFAULT_MAX_REPAIR_ATTEMPTS = 3

# LINC §2: K-way voting — generate K scripts, pick the one that returns SAT
DEFAULT_K_WAY_VOTE_COUNT = 3

# TDD_v2 §4.3: Strict s.check() timeout to prevent Z3 path explosion
DEFAULT_Z3_TIMEOUT_SECONDS = 5

# SAILOR §4: Cap iterative refinement turns (SAILOR uses 60, we use 5 for real-time)
DEFAULT_MAX_REACT_TURNS = 5

# BitVec width lookup by architecture
ARCH_REGISTER_WIDTH: dict[Architecture, int] = {
    Architecture.ARM32: 32,
    Architecture.ARM64: 64,
    Architecture.X86: 32,
    Architecture.X86_64: 64,
    Architecture.MIPS32: 32,
    Architecture.PPC32: 32,
}
