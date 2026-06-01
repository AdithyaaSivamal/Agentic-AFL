"""
retrieval_carm.py — Constraint-Aware Retrieval Module via PostgreSQL Server-Side Jaccard.

This module implements the CARM retrieval logic. Given a new stall site's
ConstraintProfile, it queries PostgreSQL using the server-side Jaccard
similarity function to find the most relevant historical VulnerabilitySpecs
and their associated Z3 templates.

Inputs:
    - ConstraintProfile   — From the current stall (via constraint_profiler.py)

Outputs:
    - list[RetrievalResult] — Ranked list of similar VulnerabilitySpecs with
                               their Jaccard scores and Z3 template hints.

Reference: ConstraintLLM §2.1-2.3 — Constraint-Aware Retrieval Module (CARM).

Key Design Decisions:
    1. SERVER-SIDE JACCARD: The Jaccard similarity computation happens
       ENTIRELY in PostgreSQL via the custom jaccard_similarity() function
       on INTEGER[] columns. Python receives only the top-N results,
       pre-sorted by score. This eliminates the O(N) Python loop that
       mem0 would have required.

    2. TWO-STAGE RETRIEVAL (ConstraintLLM §2.2):
       Stage 1: PostgreSQL Jaccard filter — fast, index-assisted.
       Stage 2: Python re-rank by secondary metrics (complexity, solve history).
       Stage 2 operates on at most N rows (default 5), not the full table.

    3. ARCHITECTURE FILTERING: The query optionally filters by CPU
       architecture, preventing ARM32 templates from being suggested
       for MIPS32 targets (different register widths → incompatible BitVec).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agentic_afl.config import settings
from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.database.spec_store import SpecStore
from agentic_afl.models import ConstraintProfile

logger = logging.getLogger(__name__)


@dataclass
class RetrievalResult:
    """
    A single CARM retrieval result.

    Attributes:
        spec_id:           The matched VulnerabilitySpec's ID.
        stall_address:     The stall address of the matched spec.
        jaccard_score:     Jaccard similarity (computed by PostgreSQL).
        z3_template:       The Z3 template associated with this spec (if any).
        constraint_tags:   The stored spec's constraint tags (as int array).
        profile_data:      The stored spec's profile metrics (JSONB dict).
        relevance_score:   Combined score after Python re-ranking.
    """
    spec_id: str
    stall_address: str
    jaccard_score: float
    z3_template: str | None
    constraint_tags: list[int]
    profile_data: dict[str, Any]
    relevance_score: float


class CARMRetriever:
    """
    Constraint-Aware Retrieval Module backed by PostgreSQL.

    All Jaccard computation is server-side. This class adds Python-side
    re-ranking on the small result set returned by the database.

    Usage:
        store = SpecStore()
        await store.initialize()
        retriever = CARMRetriever(store=store)

        results = await retriever.query(
            query_profile=current_stall_profile,
            architecture=Architecture.ARM32,
        )
        templates = [r.z3_template for r in results if r.z3_template]
    """

    def __init__(
        self,
        store: SpecStore,
        similarity_threshold: float = settings.carm_similarity_threshold,
        max_results: int = settings.carm_max_results,
    ) -> None:
        self.store = store
        self.similarity_threshold = similarity_threshold
        self.max_results = max_results

    async def query(
        self,
        query_profile: ConstraintProfile,
        architecture: Architecture | None = None,
    ) -> list[RetrievalResult]:
        """
        Retrieve the most similar VulnerabilitySpecs for a constraint profile.

        Args:
            query_profile: The ConstraintProfile of the current stall site.
            architecture:  Optional — filter results to matching architecture.

        Returns:
            List of RetrievalResult, sorted by relevance_score descending.
            Maximum length: self.max_results.

        Flow:
            Stage 1 (PostgreSQL): Server-side Jaccard on INTEGER[] arrays.
                → Returns at most max_results rows with jaccard_score >= threshold.
            Stage 2 (Python): Re-rank by secondary metrics on the small result set.
                → Returns final sorted list.
        """
        # Stage 1: Convert tags to int array and query PostgreSQL.
        query_tags = SpecStore.tags_to_int_array(query_profile.tags)
        arch_value = architecture.value if architecture else None

        rows = await self.store.query_by_jaccard(
            query_tags=query_tags,
            threshold=self.similarity_threshold,
            limit=self.max_results,
            architecture=arch_value,
        )

        # Stage 2: Python re-ranking on the small result set.
        results = []
        for row in rows:
            relevance = self._compute_relevance(
                query_profile=query_profile,
                stored_profile_data=row.get("profile_data", {}),
                jaccard_score=row["jaccard_score"],
                solve_count=row.get("solve_count", 0),
            )
            results.append(RetrievalResult(
                spec_id=row["spec_id"],
                stall_address=row["stall_address"],
                jaccard_score=row["jaccard_score"],
                z3_template=row.get("z3_template"),
                constraint_tags=row.get("constraint_tags", []),
                profile_data=row.get("profile_data", {}),
                relevance_score=relevance,
            ))

        # Sort by relevance_score descending (re-rank from Jaccard order).
        results.sort(key=lambda r: r.relevance_score, reverse=True)

        logger.info(
            "CARM query: %d results for tags=%s (threshold=%.2f)",
            len(results),
            [t.name for t in query_profile.tags],
            self.similarity_threshold,
        )
        return results

    def _compute_relevance(
        self,
        query_profile: ConstraintProfile,
        stored_profile_data: dict[str, Any],
        jaccard_score: float,
        solve_count: int,
    ) -> float:
        """
        Compute a combined relevance score for Stage 2 re-ranking.

        This runs in Python but ONLY on the pre-filtered result set from
        PostgreSQL (at most max_results rows), so it's cheap.

        Factors (weighted):
          - Jaccard similarity (primary, weight 0.6)
          - Complexity similarity (weight 0.2) — prefer specs with similar difficulty
          - Solve history (weight 0.2) — prefer specs that have been successfully solved

        Returns:
            Float in [0.0, 1.0].
        """
        # Complexity similarity: how close is the stored spec's complexity
        # to the query's? Range-normalized to [0, 1].
        query_complexity = query_profile.estimated_complexity
        stored_complexity = stored_profile_data.get("estimated_complexity", 50)
        complexity_diff = abs(query_complexity - stored_complexity)
        complexity_score = 1.0 - min(complexity_diff / 100.0, 1.0)

        # Solve history: prefer specs that have been solved before.
        # Capped at 5 solves to prevent runaway bias.
        solve_score = min(solve_count / 5.0, 1.0)

        # Weighted combination.
        relevance = (
            0.6 * jaccard_score +
            0.2 * complexity_score +
            0.2 * solve_score
        )

        return round(relevance, 4)

    async def update_template(self, spec_id: str, z3_template: str) -> None:
        """
        Update the Z3 template for a spec after a successful solve.

        This makes the winning script available for future CARM retrievals.
        Delegates to SpecStore.update_template().
        """
        await self.store.update_template(spec_id, z3_template)
