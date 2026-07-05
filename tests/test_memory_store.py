"""
test_memory_store.py — Unit tests for the InMemorySpecStore.

Exercises the same interface contract as the PostgreSQL-backed SpecStore.
"""

import pytest

from agentic_afl.constants import ConstraintTag
from agentic_afl.database.memory_store import InMemorySpecStore


@pytest.fixture
async def store():
    s = InMemorySpecStore()
    await s.initialize()
    yield s
    await s.close()


def _make_spec(
    spec_id: str = "spec_001",
    tags: list[str] | None = None,
    architecture: str = "arm32",
    function_name: str = "check_crc",
    z3_template: str | None = None,
) -> dict:
    return {
        "spec_id": spec_id,
        "binary_path": "/tmp/test_binary",
        "stall_address": "0x4012a0",
        "function_name": function_name,
        "architecture": architecture,
        "constraint_tags": tags or ["BITWISE_LOOP", "INDEXED_LOOKUP", "COUNTED_LOOP"],
        "pcode_text": "INT_XOR r0, r1\nINT_RIGHT r1, (const, 0x1, 4)",
        "bitwise_density": 0.65,
        "arithmetic_density": 0.12,
        "loop_depth": 2,
        "register_count": 4,
        "estimated_complexity": 72,
        "z3_template_hint": z3_template,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Save / Load
# ═══════════════════════════════════════════════════════════════════════

class TestSaveLoad:
    @pytest.mark.asyncio
    async def test_save_and_load(self, store):
        await store.save_spec(_make_spec())
        spec = await store.load_spec("spec_001")
        assert spec is not None
        assert spec["function_name"] == "check_crc"
        assert spec["architecture"] == "arm32"

    @pytest.mark.asyncio
    async def test_load_nonexistent(self, store):
        spec = await store.load_spec("nonexistent")
        assert spec is None

    @pytest.mark.asyncio
    async def test_upsert_preserves_corrections(self, store):
        await store.save_spec(_make_spec())
        await store.append_correction("spec_001", "UNSAT", "fixed script v1")

        # Re-save (upsert) — corrections should be preserved,
        # and pcode_text should be updated. function_name is NOT updated
        # on conflict (matches PostgreSQL ON CONFLICT behavior).
        updated = _make_spec()
        updated["pcode_text"] = "UPDATED_PCODE"
        await store.save_spec(updated)
        spec = await store.load_spec("spec_001")
        assert len(spec["correction_history"]) == 1
        assert spec["pcode_text"] == "UPDATED_PCODE"


# ═══════════════════════════════════════════════════════════════════════
#  Jaccard Similarity
# ═══════════════════════════════════════════════════════════════════════

class TestJaccard:
    @pytest.mark.asyncio
    async def test_exact_match(self, store):
        await store.save_spec(_make_spec())
        tag_ints = [
            ConstraintTag.BITWISE_LOOP.value,
            ConstraintTag.INDEXED_LOOKUP.value,
            ConstraintTag.COUNTED_LOOP.value,
        ]
        results = await store.query_by_jaccard(query_tags=tag_ints, threshold=0.3)
        assert len(results) == 1
        assert results[0]["jaccard_score"] == 1.0

    @pytest.mark.asyncio
    async def test_partial_match(self, store):
        await store.save_spec(_make_spec())
        # Query with 2/3 matching tags + 1 extra
        tag_ints = [
            ConstraintTag.BITWISE_LOOP.value,
            ConstraintTag.INDEXED_LOOKUP.value,
            ConstraintTag.BITMASK_CHECK.value,
        ]
        results = await store.query_by_jaccard(query_tags=tag_ints, threshold=0.3)
        assert len(results) == 1
        # Jaccard: |{BL,IL}| / |{BL,IL,CL,BC}| = 2/4 = 0.5
        assert abs(results[0]["jaccard_score"] - 0.5) < 0.01

    @pytest.mark.asyncio
    async def test_below_threshold(self, store):
        await store.save_spec(_make_spec())
        # Only 1 matching tag out of many → Jaccard below 0.3
        tag_ints = [
            ConstraintTag.BITWISE_LOOP.value,
            ConstraintTag.MODULAR_ARITHMETIC.value,
            ConstraintTag.OVERFLOW_DEPENDENT.value,
            ConstraintTag.LINEAR_CONSTRAINT.value,
        ]
        results = await store.query_by_jaccard(query_tags=tag_ints, threshold=0.3)
        # Jaccard: |{BL}| / |{BL,IL,CL,MA,OD,LC}| = 1/6 ≈ 0.17 < 0.3
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_architecture_filter(self, store):
        await store.save_spec(_make_spec(spec_id="arm_spec", architecture="arm32"))
        await store.save_spec(_make_spec(spec_id="x86_spec", architecture="x86_64"))

        tag_ints = [ConstraintTag.BITWISE_LOOP.value]
        results = await store.query_by_jaccard(
            query_tags=tag_ints, threshold=0.1, architecture="arm32",
        )
        assert all(r["architecture"] == "arm32" for r in results)

    @pytest.mark.asyncio
    async def test_empty_query_tags(self, store):
        await store.save_spec(_make_spec())
        results = await store.query_by_jaccard(query_tags=[], threshold=0.0)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_ranking_order(self, store):
        """Results should be sorted by Jaccard score descending."""
        await store.save_spec(_make_spec(
            spec_id="exact", tags=["BITWISE_LOOP", "INDEXED_LOOKUP"],
        ))
        await store.save_spec(_make_spec(
            spec_id="partial", tags=["BITWISE_LOOP", "MODULAR_ARITHMETIC"],
        ))
        tag_ints = [ConstraintTag.BITWISE_LOOP.value, ConstraintTag.INDEXED_LOOKUP.value]
        results = await store.query_by_jaccard(query_tags=tag_ints, threshold=0.1)
        assert len(results) == 2
        assert results[0]["spec_id"] == "exact"
        assert results[0]["jaccard_score"] > results[1]["jaccard_score"]


# ═══════════════════════════════════════════════════════════════════════
#  Template Updates
# ═══════════════════════════════════════════════════════════════════════

class TestTemplateUpdates:
    @pytest.mark.asyncio
    async def test_update_template(self, store):
        await store.save_spec(_make_spec())
        await store.update_template("spec_001", "from z3 import *; winning_script()")

        spec = await store.load_spec("spec_001")
        assert spec["z3_template"] == "from z3 import *; winning_script()"
        assert spec["solve_count"] == 1

    @pytest.mark.asyncio
    async def test_increment_solve_count(self, store):
        await store.save_spec(_make_spec())
        await store.update_template("spec_001", "v1")
        await store.update_template("spec_001", "v2")

        spec = await store.load_spec("spec_001")
        assert spec["solve_count"] == 2
        assert spec["z3_template"] == "v2"


# ═══════════════════════════════════════════════════════════════════════
#  Store Statistics
# ═══════════════════════════════════════════════════════════════════════

class TestStoreStats:
    @pytest.mark.asyncio
    async def test_empty_store(self, store):
        stats = await store.get_store_stats()
        assert stats["total_specs"] == 0
        assert stats["specs_with_templates"] == 0

    @pytest.mark.asyncio
    async def test_populated_store(self, store):
        await store.save_spec(_make_spec(spec_id="s1"))
        await store.save_spec(_make_spec(spec_id="s2"))
        await store.update_template("s1", "winning_script")
        await store.append_correction("s2", "error", "fix")

        stats = await store.get_store_stats()
        assert stats["total_specs"] == 2
        assert stats["specs_with_templates"] == 1
        assert stats["total_corrections"] == 1


# ═══════════════════════════════════════════════════════════════════════
#  Static Helpers
# ═══════════════════════════════════════════════════════════════════════

class TestStaticHelpers:
    def test_tags_to_int_array(self):
        tags = frozenset({ConstraintTag.BITWISE_LOOP, ConstraintTag.COUNTED_LOOP})
        ints = InMemorySpecStore.tags_to_int_array(tags)
        assert sorted(ints) == ints  # Must be sorted
        assert len(ints) == 2

    def test_int_array_to_tags(self):
        ints = [ConstraintTag.BITWISE_LOOP.value, ConstraintTag.COUNTED_LOOP.value]
        tags = InMemorySpecStore.int_array_to_tags(ints)
        assert ConstraintTag.BITWISE_LOOP in tags
        assert ConstraintTag.COUNTED_LOOP in tags
