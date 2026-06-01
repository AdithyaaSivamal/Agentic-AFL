"""
models.py — Shared Data Structures for the Agentic-AFL Pipeline.

This is the SINGLE SOURCE OF TRUTH for all data types that flow between
components. Every inter-component boundary uses these dataclasses.

Data Flow:
  Binary + StallAddr
       ↓
  PCodeSlice         (pcode_slicer.py produces)
       ↓
  ConstraintProfile  (constraint_profiler.py produces)
       ↓
  VulnerabilitySpec  (spec_exporter.py produces — persisted to PostgreSQL)
       ↓
  StallReport        (stall_detector.py produces when AFL++ stalls)
       ↓
  CARMQuery          (retrieval_carm.py consumes StallReport.constraint_profile)
       ↓
  Z3GenerationRequest (llm_client.py consumes)
       ↓
  Z3Script           (llm_client.py produces — K scripts for voting)
       ↓
  Z3Result           (z3_sandbox.py produces)
       ↓
  SolvedPayload      (extracted from Z3Result.model)
       ↓
  sync_dir/          (payload_injector.py writes raw bytes)

IMPORTANT: When adding a new field to any dataclass, ensure:
  1. The PRODUCER is updated to populate it.
  2. The CONSUMER is updated to read it.
  3. The JSON serialization in spec_exporter.py handles it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    Architecture,
    ConstraintTag,
    StallSeverity,
    Z3Verdict,
)


# =============================================================================
# Phase 1: Extractor Outputs
# =============================================================================


@dataclass(frozen=True)
class PCodeInstruction:
    """
    A single Ghidra P-Code operation extracted from a basic block.

    P-Code is Ghidra's intermediate representation — architecture-neutral
    but preserving all semantic information from the original machine code.

    Attributes:
        address:   The original machine code address (hex string, e.g., "0x08001234").
        mnemonic:  The P-Code operation mnemonic (e.g., "INT_ADD", "CBRANCH", "LOAD").
        inputs:    List of input varnodes as strings (e.g., ["r0", "0x10", "(ram, 0x20001000, 4)"]).
        output:    The output varnode, or None for operations like BRANCH/STORE.
        raw_pcode: The full Ghidra P-Code text line for debugging.
    """
    address: str
    mnemonic: str
    inputs: list[str]
    output: str | None
    raw_pcode: str
    call_target: str | None = None   # Resolved function name for CALL ops (e.g., "crc16_modbus")


@dataclass
class PCodeSlice:
    """
    A taint-bounded backward slice of P-Code instructions from a stall site.

    Produced by: extractor/pcode_slicer.py
    Consumed by: extractor/constraint_profiler.py, orchestrator/llm_client.py

    The slice contains ONLY the P-Code instructions that are data-dependent
    on the fuzzer's input buffer (taint source). Instructions that resolve
    to global state not connected to the input are pruned.

    Reference: AutoBug Algorithm 2 (GenSlice) — backward slicing on CFG.
    Reference: TDD_v2 §4.1 — Taint-bounded slicing prevents memory-state explosion.

    Attributes:
        binary_path:      Path to the analyzed binary.
        stall_address:    The address where AFL++ coverage stalled (hex string).
        function_name:    Ghidra's decompiled function name (may be "FUN_xxxxx" for stripped binaries).
        function_entry:   Entry point address of the containing function.
        instructions:     Ordered list of P-Code instructions in the slice.
        taint_source:     Description of the taint origin (e.g., "input_buffer @ 0x20001000").
        slice_depth:      How many basic blocks backward the slice traversed.
        truncated:        True if the slice was truncated via assuming(0) to fit token budget.
        architecture:     Target CPU architecture (determines register widths).
        decompiled_c:     Ghidra's decompiled C pseudocode for the function (best-effort).
        extraction_time:  When this slice was extracted.
    """
    binary_path: Path
    stall_address: str
    function_name: str
    function_entry: str
    instructions: list[PCodeInstruction]
    taint_source: str
    slice_depth: int
    truncated: bool
    architecture: Architecture
    decompiled_c: str = ""
    extraction_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def pcode_text(self) -> str:
        """Concatenated P-Code text for prompt injection."""
        return "\n".join(inst.raw_pcode for inst in self.instructions)

    @property
    def unique_mnemonics(self) -> set[str]:
        """Set of distinct P-Code operations — used by constraint_profiler."""
        return {inst.mnemonic for inst in self.instructions}


@dataclass(frozen=True)
class ConstraintProfile:
    """
    A set of constraint type tags characterizing a stall site's mathematical structure.

    Produced by: extractor/constraint_profiler.py
    Consumed by: orchestrator/retrieval_carm.py (Jaccard similarity input)

    This is the KEY TYPE for CARM retrieval. Two stall sites with similar
    ConstraintProfiles should be solvable with similar Z3 templates.

    Reference: ConstraintLLM §2.1 — Constraint type extraction from problem description.

    Attributes:
        tags:              Frozenset of ConstraintTag enums identified in the P-Code.
        bitwise_density:   Ratio of bitwise operations to total operations (0.0 - 1.0).
        arithmetic_density: Ratio of arithmetic operations to total operations (0.0 - 1.0).
        loop_depth:        Maximum nesting depth of loop structures in the slice.
        register_count:    Number of distinct symbolic registers in the slice.
        estimated_complexity: Heuristic difficulty score (0-100). Higher = harder for Z3.
    """
    tags: frozenset[ConstraintTag]
    bitwise_density: float
    arithmetic_density: float
    loop_depth: int
    register_count: int
    estimated_complexity: int

    def jaccard_similarity(self, other: ConstraintProfile) -> float:
        """
        Compute Jaccard similarity between two constraint profiles.

        J(A, B) = |A ∩ B| / |A ∪ B|

        Reference: ConstraintLLM Eq. 3

        Returns:
            Float in [0.0, 1.0]. 1.0 = identical tag sets.
        """
        if not self.tags and not other.tags:
            return 0.0
        intersection = self.tags & other.tags
        union = self.tags | other.tags
        return len(intersection) / len(union)


@dataclass
class VulnerabilitySpec:
    """
    A self-contained JSON-serializable specification for a single stall site.

    Produced by: extractor/spec_exporter.py
    Consumed by: database/spec_store.py (PostgreSQL persistence), orchestrator/retrieval_carm.py (retrieval)

    This is the primary data artifact stored in the PostgreSQL spec store. It bundles
    the P-Code slice, constraint profile, and metadata needed for the Orchestrator
    to generate a Z3 script without re-running the Extractor.

    Reference: SAILOR §3.3 — JSON Vulnerability Specification schema.

    Attributes:
        spec_id:            Unique identifier (SHA-256 of binary_path + stall_address).
        binary_path:        Path to the analyzed binary.
        stall_address:      The stall site address.
        function_name:      Containing function name.
        pcode_slice:        The extracted P-Code slice.
        constraint_profile: The computed constraint tags and metrics.
        architecture:       Target CPU architecture.
        z3_template_hint:   Optional — a previously successful Z3 template for similar constraints.
        correction_history: List of (error, corrected_script) pairs from past attempts.
        created_at:         When this spec was first created.
        last_attempted:     When the Orchestrator last tried to solve this spec.
        solve_count:        How many times this spec has been successfully solved.
    """
    spec_id: str
    binary_path: Path
    stall_address: str
    function_name: str
    pcode_slice: PCodeSlice
    constraint_profile: ConstraintProfile
    architecture: Architecture
    z3_template_hint: str | None = None
    correction_history: list[CorrectionEntry] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_attempted: datetime | None = None
    solve_count: int = 0

    @staticmethod
    def generate_id(binary_path: Path, stall_address: str) -> str:
        """Deterministic ID from binary path + stall address."""
        raw = f"{binary_path.resolve()}:{stall_address}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary for persistence."""
        return {
            "spec_id": self.spec_id,
            "binary_path": str(self.binary_path),
            "stall_address": self.stall_address,
            "function_name": self.function_name,
            "pcode_text": self.pcode_slice.pcode_text,
            "constraint_tags": [tag.name for tag in self.constraint_profile.tags],
            "bitwise_density": self.constraint_profile.bitwise_density,
            "arithmetic_density": self.constraint_profile.arithmetic_density,
            "loop_depth": self.constraint_profile.loop_depth,
            "register_count": self.constraint_profile.register_count,
            "estimated_complexity": self.constraint_profile.estimated_complexity,
            "architecture": self.architecture.value,
            "z3_template_hint": self.z3_template_hint,
            "correction_history": [
                {"error": c.error_message, "corrected_script": c.corrected_script}
                for c in self.correction_history
            ],
            "created_at": self.created_at.isoformat(),
            "last_attempted": self.last_attempted.isoformat() if self.last_attempted else None,
            "solve_count": self.solve_count,
        }


@dataclass(frozen=True)
class CorrectionEntry:
    """
    A single error → correction pair from a past Z3 generation attempt.

    Reference: SAILOR §4.4 — Iterative compile-execute-refine loop.

    Stored in VulnerabilitySpec.correction_history to help future attempts
    avoid the same mistakes (fed to the LLM as negative examples).
    """
    error_message: str
    corrected_script: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Phase 2: Runtime / Orchestrator Types
# =============================================================================


@dataclass
class StallReport:
    """
    A report from AFL++ indicating a coverage stall at a specific address.

    Produced by: fuzzer_bridge/stall_detector.py
    Consumed by: orchestrator/agent_loop.py

    Reference: HyLLfuzz §3.1 — Coverage analyzer with "interestingness" scoring.

    Attributes:
        stall_address:    The address where coverage stalled (hex string).
        binary_path:      Path to the binary being fuzzed.
        severity:         Priority classification for attack ordering.
        cycles_stalled:   Number of AFL++ cycles with no new coverage at this address.
        seed_input:       The closest seed input that reached this address (raw bytes).
        seed_input_path:  Filesystem path to the seed file in AFL++'s queue/.
        coverage_bitmap:  Snapshot of AFL++'s coverage bitmap (for diffing).
        detected_at:      When the stall was first detected.
    """
    stall_address: str
    binary_path: Path
    severity: StallSeverity
    cycles_stalled: int
    seed_input: bytes
    seed_input_path: Path
    coverage_bitmap: bytes | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Z3GenerationRequest:
    """
    A request to the LLM to generate a Z3 script for a specific stall.

    Produced by: orchestrator/agent_loop.py
    Consumed by: orchestrator/llm_client.py

    Bundles all context the LLM needs: the P-Code slice, constraint profile,
    architecture metadata, retrieved templates, and correction history.

    Attributes:
        vuln_spec:          The VulnerabilitySpec for the stall site.
        seed_input:         The closest seed input (provides concrete context).
        retrieved_templates: Previously successful Z3 scripts for similar constraint profiles.
        correction_history: Past errors for this specific stall (negative examples).
        max_attempts:       Max self-repair cycles (default: 3, per LLM-Sym §3.2).
        k_vote_count:       Number of parallel Z3 scripts to generate for voting (LINC §2).
    """
    vuln_spec: VulnerabilitySpec
    seed_input: bytes
    retrieved_templates: list[str] = field(default_factory=list)
    correction_history: list[CorrectionEntry] = field(default_factory=list)
    max_attempts: int = 3
    k_vote_count: int = 3
    base_offset: int = 0  # File offset where this function's input starts
    runtime_state: dict[str, str] = field(default_factory=dict)  # GDB arg memory dumps


@dataclass
class Z3Script:
    """
    A Z3 Python script generated by the LLM.

    Produced by: orchestrator/llm_client.py
    Consumed by: orchestrator/z3_sandbox.py

    Attributes:
        script_text:    The full Z3Py Python code.
        generation_idx: Which of the K voting candidates this is (0-indexed).
        attempt_number: Which self-repair attempt produced this (1-indexed).
        prompt_tokens:  Token count of the prompt used (for cost tracking).
        completion_tokens: Token count of the LLM's response.
        model_name:     Which LLM model generated this script.
    """
    script_text: str
    generation_idx: int
    attempt_number: int
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model_name: str = ""


@dataclass
class Z3Result:
    """
    The result of executing a Z3 script in the sandbox.

    Produced by: orchestrator/z3_sandbox.py
    Consumed by: orchestrator/agent_loop.py

    Attributes:
        verdict:         SAT, UNSAT, TIMEOUT, SYNTAX_ERROR, RUNTIME_ERROR, or UNKNOWN.
        model:           If SAT — the concrete variable assignments as {name: int_value}.
        error_message:   If not SAT — the error string (fed back to LLM for self-repair).
        execution_time:  Wall-clock seconds the script ran.
        script:          The Z3Script that produced this result.
    """
    verdict: Z3Verdict
    model: dict[str, int] | None
    error_message: str | None
    execution_time: float
    script: Z3Script


@dataclass
class SolvedPayload:
    """
    A concrete byte-array payload ready for injection into AFL++'s sync directory.

    Produced by: orchestrator/agent_loop.py (from Z3Result.model)
    Consumed by: fuzzer_bridge/payload_injector.py

    Attributes:
        raw_bytes:       The payload bytes to write to the sync directory.
        source_spec_id:  The VulnerabilitySpec.spec_id that this payload solves.
        stall_address:   The stall address this payload is designed to bypass.
        z3_model:        The Z3 model that produced this payload.
        confidence:      Float 0.0-1.0. Based on K-way voting agreement.
        generated_at:    Timestamp.
    """
    raw_bytes: bytes
    source_spec_id: str
    stall_address: str
    z3_model: dict[str, int]
    confidence: float = 1.0
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def filename(self) -> str:
        """
        Generate a descriptive filename for the sync directory.

        Format: agentic_<spec_id_prefix>_<stall_addr>_<timestamp>.bin
        AFL++ will ingest any file in the sync directory on its next cycle.
        """
        ts = self.generated_at.strftime("%Y%m%d_%H%M%S")
        spec_prefix = self.source_spec_id[:8]
        return f"agentic_{spec_prefix}_{self.stall_address}_{ts}.bin"
