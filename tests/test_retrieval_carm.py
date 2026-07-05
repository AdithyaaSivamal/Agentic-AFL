"""
test_retrieval_carm.py — Unit tests for the CARM retriever.

Covers a module that was at 0% coverage. Uses a fake store (an object
exposing an async query_by_jaccard) so no PostgreSQL is required —
tests/test_phase3_carm.py exercises the real DB path.
"""

from __future__ import annotations

import pytest

from agentic_afl.config import settings
from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.models import ConstraintProfile
from agentic_afl.orchestrator.retrieval_carm import CARMRetriever, RetrievalResult


class FakeStore:
    """Minimal store double exposing the one method CARMRetriever calls."""

    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.last_query: dict | None = None

    async def query_by_jaccard(self, query_tags, threshold, limit, architecture):
        self.last_query = {
            "query_tags": query_tags,
            "threshold": threshold,
            "limit": limit,
            "architecture": architecture,
        }
        return self.rows


def _profile(tags, complexity=30) -> ConstraintProfile:
    return ConstraintProfile(
        tags=frozenset(tags),
        bitwise_density=0.0,
        arithmetic_density=0.0,
        loop_depth=0,
        register_count=1,
        estimated_complexity=complexity,
    )


def _row(spec_id, jaccard, complexity=30, solve_count=0, template=None):
    return {
        "spec_id": spec_id,
        "stall_address": "0x1000",
        "jaccard_score": jaccard,
        "z3_template": template,
        "constraint_tags": [1, 2],
        "profile_data": {"estimated_complexity": complexity},
        "solve_count": solve_count,
    }


# ═══════════════════════════════════════════════════════════════════════
#  _compute_relevance (pure)
# ═══════════════════════════════════════════════════════════════════════

class TestComputeRelevance:
    def test_perfect_match_scores_high(self):
        r = CARMRetriever(store=FakeStore([]))
        score = r._compute_relevance(
            query_profile=_profile({ConstraintTag.BITWISE_LOOP}, complexity=30),
            stored_profile_data={"estimated_complexity": 30},
            jaccard_score=1.0,
            solve_count=5,
        )
        # 0.6*1.0 + 0.2*1.0(complexity match) + 0.2*1.0(solve cap) = 1.0
        assert score == pytest.approx(1.0)

    def test_jaccard_dominates_weighting(self):
        r = CARMRetriever(store=FakeStore([]))
        low = r._compute_relevance(_profile({ConstraintTag.BITWISE_LOOP}), {"estimated_complexity": 30}, 0.0, 0)
        high = r._compute_relevance(_profile({ConstraintTag.BITWISE_LOOP}), {"estimated_complexity": 30}, 1.0, 0)
        assert high > low
        # With jaccard=0 and matching complexity + no solves: 0.2*1.0 = 0.2
        assert low == pytest.approx(0.2)

    def test_complexity_mismatch_lowers_score(self):
        r = CARMRetriever(store=FakeStore([]))
        close = r._compute_relevance(_profile(set(), complexity=30), {"estimated_complexity": 30}, 0.5, 0)
        far = r._compute_relevance(_profile(set(), complexity=30), {"estimated_complexity": 130}, 0.5, 0)
        assert close > far


# ═══════════════════════════════════════════════════════════════════════
#  query
# ═══════════════════════════════════════════════════════════════════════

class TestQuery:
    @pytest.mark.asyncio
    async def test_query_returns_results_sorted_by_relevance(self):
        store = FakeStore([
            _row("low_match", jaccard=0.4),
            _row("high_match", jaccard=0.95),
            _row("mid_match", jaccard=0.7),
        ])
        r = CARMRetriever(store=store, similarity_threshold=0.3, max_results=5)
        results = await r.query(_profile({ConstraintTag.BITWISE_LOOP}))

        assert [x.spec_id for x in results] == ["high_match", "mid_match", "low_match"]
        assert all(isinstance(x, RetrievalResult) for x in results)

    @pytest.mark.asyncio
    async def test_query_passes_threshold_and_arch_to_store(self):
        store = FakeStore([])
        r = CARMRetriever(store=store, similarity_threshold=0.42, max_results=7)
        await r.query(_profile({ConstraintTag.BITWISE_LOOP}), architecture=Architecture.ARM32)

        assert store.last_query["threshold"] == 0.42
        assert store.last_query["limit"] == 7
        assert store.last_query["architecture"] == "arm32"

    @pytest.mark.asyncio
    async def test_empty_store_yields_empty_results(self):
        r = CARMRetriever(store=FakeStore([]))
        results = await r.query(_profile({ConstraintTag.CONSTANT_EQUALITY}))
        assert results == []


# ═══════════════════════════════════════════════════════════════════════
#  M8: settings read at call time
# ═══════════════════════════════════════════════════════════════════════

class TestSettingsAtCallTime:
    def test_none_args_pick_up_current_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "carm_similarity_threshold", 0.99)
        monkeypatch.setattr(settings, "carm_max_results", 42)
        r = CARMRetriever(store=FakeStore([]))
        assert r.similarity_threshold == 0.99
        assert r.max_results == 42
