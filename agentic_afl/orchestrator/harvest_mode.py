"""
harvest_mode.py — Autonomous CARM Corpus Builder via Verified Fuzzing.

This module implements the AutoHarvest daemon: it runs Agentic-AFL in a
special mode where CARM retrieval is disabled (zero-shot), and every
successful solve that is VERIFIED by AFL++ edge coverage is automatically
committed to the PostgreSQL database as a new CARM template.

This creates a self-bootstrapping corpus: the system generates its own
training data by running in the wild against real-world binaries.

Architecture:
    1. HarvestDaemon accepts a list of target binaries.
    2. For each binary, it:
       a) Launches AFL++ with a temp sync_dir
       b) Instantiates an AgentLoop with harvest_mode=True
       c) Monitors AFL++ edge deltas post-injection
       d) On verified solve (new_edges > 0), commits the triplet:
          (pcode_slice, constraint_tags, z3_script) → PostgreSQL

    The verification step is critical: the LLM can produce Z3 scripts
    that are SAT but semantically wrong. AFL++ edge coverage acts as
    the ground-truth oracle.

Deployment:
    - Beelink miniPC:   Serialize targets (1-2 at a time)
    - Lab servers:      Core-partition (N-4 fuzzer / 4 agent)

Reference:
    - REDQUEEN §3: Input-to-state colorization (our probe is analogous)
    - Driller §2: Stall→solve→inject (our core loop)
    - ConstraintLLM §2: CARM tag-based retrieval (what we're populating)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.database.spec_store import SpecStore

logger = logging.getLogger(__name__)


@dataclass
class HarvestResult:
    """Result of harvesting a single binary."""
    binary_path: str
    duration_seconds: float
    stalls_detected: int = 0
    solves_attempted: int = 0
    solves_sat: int = 0
    solves_verified: int = 0      # SAT ∩ new_edges > 0
    templates_committed: int = 0
    verification_rate: float = 0.0  # verified / sat

    def __post_init__(self):
        if self.solves_sat > 0:
            self.verification_rate = self.solves_verified / self.solves_sat


@dataclass
class HarvestMetrics:
    """Aggregate metrics across all harvested binaries."""
    total_binaries: int = 0
    total_stalls: int = 0
    total_sat: int = 0
    total_verified: int = 0
    total_templates: int = 0
    results: list[HarvestResult] = field(default_factory=list)

    @property
    def overall_verification_rate(self) -> float:
        return self.total_verified / self.total_sat if self.total_sat > 0 else 0.0


async def read_edges_from_stats(afl_output_dir: Path) -> int:
    """
    Read current edges_found from AFL++ fuzzer_stats.

    Returns 0 if the file doesn't exist or can't be parsed.
    """
    stats_file = afl_output_dir / "default" / "fuzzer_stats"
    if not stats_file.exists():
        # Try without 'default' subdirectory
        stats_file = afl_output_dir / "fuzzer_stats"
    if not stats_file.exists():
        return 0

    try:
        text = stats_file.read_text()
        for line in text.splitlines():
            if line.startswith("edges_found"):
                return int(line.split(":")[-1].strip())
    except (ValueError, IOError) as e:
        logger.debug("Could not parse edges_found: %s", e)
    return 0


async def wait_for_edge_delta(
    afl_output_dir: Path,
    baseline_edges: int,
    timeout_seconds: float = 30.0,
    poll_interval: float = 2.0,
) -> int:
    """
    Wait for AFL++ to discover new edges after payload injection.

    This is the verification oracle: if AFL++ finds new edges after
    we injected a payload, the solve was correct (the payload actually
    bypassed the math wall in the real binary).

    Args:
        afl_output_dir: Path to AFL++ output directory.
        baseline_edges: Edge count BEFORE injection.
        timeout_seconds: Max time to wait for new edges.
        poll_interval: Seconds between edge count polls.

    Returns:
        Number of new edges discovered (0 if timeout with no change).
    """
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        current_edges = await read_edges_from_stats(afl_output_dir)
        delta = current_edges - baseline_edges

        if delta > 0:
            logger.info(
                "Edge delta detected: +%d edges (baseline=%d, current=%d)",
                delta, baseline_edges, current_edges,
            )
            return delta

        await asyncio.sleep(poll_interval)

    logger.debug(
        "No edge delta after %.1fs (baseline=%d)",
        timeout_seconds, baseline_edges,
    )
    return 0


async def commit_verified_template(
    store: SpecStore,
    pcode_text: str,
    constraint_tags: list[int],
    z3_script: str,
    binary_path: str,
    function_name: str = "auto",
    stall_address: str = "auto",
    architecture: str = "x86_64",
) -> str:
    """
    Commit a verified (P-Code, Tags, Z3) triplet to the CARM corpus.

    This is called ONLY after AFL++ has confirmed new edges — meaning
    the solve was correct and the payload actually bypassed the math wall.

    Args:
        store: Initialized SpecStore instance.
        pcode_text: The raw P-Code slice text.
        constraint_tags: List of ConstraintTag enum values (as integers).
        z3_script: The winning Z3 script text.
        binary_path: Source binary for provenance.
        function_name: Function name at the stall site.
        stall_address: Address where the stall occurred.
        architecture: Target architecture.

    Returns:
        The spec_id of the committed template.
    """
    import hashlib
    from datetime import datetime, timezone

    # Generate a deterministic spec_id from the P-Code content.
    pcode_hash = hashlib.sha256(pcode_text.encode()).hexdigest()[:12]
    spec_id = f"harvest_{pcode_hash}"

    # Convert integer tag values back to tag names for save_spec().
    from agentic_afl.constants import ConstraintTag
    tag_names = [ConstraintTag(v).name for v in constraint_tags]

    await store.save_spec({
        "spec_id": spec_id,
        "binary_path": str(binary_path),
        "stall_address": stall_address,
        "function_name": function_name,
        "architecture": str(architecture.value) if hasattr(architecture, 'value') else str(architecture),
        "constraint_tags": tag_names,
        "pcode_text": pcode_text,
        "z3_template_hint": z3_script,
        "bitwise_density": 0.0,
        "arithmetic_density": 0.0,
        "loop_depth": 0,
        "register_count": 0,
        "estimated_complexity": 50,  # Default mid-range
        "correction_history": [],
        "solve_count": 1,  # Verified solve = initial confidence
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    # Also set the z3_template directly (save_spec stores it as hint).
    await store.update_template(spec_id, z3_script)

    logger.info(
        "✓ Committed verified template: %s (tags=%s, binary=%s)",
        spec_id, tag_names, binary_path,
    )
    return spec_id
