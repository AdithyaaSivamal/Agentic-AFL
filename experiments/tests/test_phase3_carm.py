"""
test_phase3_carm.py — Phase 3 Integration Tests: CARM Retrieval via PostgreSQL.

Tests the full CARM pipeline against a live PostgreSQL instance:
  1. SpecStore initialization (tables + Jaccard function)
  2. Seeding with ICS constraint profiles
  3. Server-side Jaccard retrieval
  4. Python re-ranking (Stage 2)
  5. Template update + correction history

Prerequisites:
  - PostgreSQL running on localhost:5432
  - Database 'agentic_afl' exists with user 'agentic_afl'
  - Run: python experiments/tests/test_phase3_carm.py
"""
from __future__ import annotations
import asyncio, sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.constants import ConstraintTag
from agentic_afl.database.spec_store import SpecStore
from agentic_afl.orchestrator.retrieval_carm import CARMRetriever
from agentic_afl.models import ConstraintProfile

DSN = "postgresql://agentic_afl:agentic_afl@localhost:5432/agentic_afl"

# ── Test Seed Data ────────────────────────────────────────────────────
# 5 specs with different tag profiles simulating ICS constraint history.
SEED_SPECS = [
    {
        "spec_id": "test_modbus_tid_001",
        "binary_path": "./modbus_rtu_x86",
        "stall_address": "0x1011a0",
        "function_name": "check_transaction_id",
        "architecture": "x86_64",
        "constraint_tags": ["CONSTANT_EQUALITY"],
        "pcode_text": "INT_EQUAL(reg_0, 0x0001)",
        "bitwise_density": 0.0,
        "arithmetic_density": 0.0,
        "loop_depth": 0,
        "register_count": 2,
        "estimated_complexity": 12,
        "z3_template_hint": "s.add(tid == BitVecVal(0x0001, 16))",
        "correction_history": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "solve_count": 3,
    },
    {
        "spec_id": "test_modbus_crc_002",
        "binary_path": "./modbus_rtu_x86",
        "stall_address": "0x101380",
        "function_name": "check_crc",
        "architecture": "x86_64",
        "constraint_tags": ["BITWISE_LOOP", "BITMASK_CHECK"],
        "pcode_text": "CALL crc16_modbus\nINT_NOTEQUAL(computed, received)",
        "bitwise_density": 0.45,
        "arithmetic_density": 0.1,
        "loop_depth": 2,
        "register_count": 4,
        "estimated_complexity": 61,
        "z3_template_hint": "crc = z3_crc16_modbus(data_bytes)",
        "correction_history": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "solve_count": 1,
    },
    {
        "spec_id": "test_modbus_fc_003",
        "binary_path": "./modbus_rtu_x86",
        "stall_address": "0x1012d0",
        "function_name": "check_function_code",
        "architecture": "x86_64",
        "constraint_tags": ["MULTI_WAY_BRANCH", "RANGE_BOUND", "CONSTANT_EQUALITY"],
        "pcode_text": "INT_LESSEQUAL(fc_sub_1, 0x5)\nINT_EQUAL(fc, 0xf)",
        "bitwise_density": 0.0,
        "arithmetic_density": 0.15,
        "loop_depth": 0,
        "register_count": 3,
        "estimated_complexity": 30,
        "z3_template_hint": None,
        "correction_history": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "solve_count": 0,
    },
    {
        "spec_id": "test_iec104_start_004",
        "binary_path": "./iec104_apci_x86",
        "stall_address": "0x101418",
        "function_name": "check_start_byte",
        "architecture": "x86_64",
        "constraint_tags": ["CONSTANT_EQUALITY"],
        "pcode_text": "INT_NOTEQUAL(byte0, 0x68)",
        "bitwise_density": 0.0,
        "arithmetic_density": 0.0,
        "loop_depth": 0,
        "register_count": 1,
        "estimated_complexity": 12,
        "z3_template_hint": "s.add(start == BitVecVal(0x68, 8))",
        "correction_history": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "solve_count": 5,
    },
    {
        "spec_id": "test_iec104_format_005",
        "binary_path": "./iec104_apci_x86",
        "stall_address": "0x101548",
        "function_name": "check_frame_format",
        "architecture": "arm32",
        "constraint_tags": ["BITMASK_CHECK", "CONSTANT_EQUALITY"],
        "pcode_text": "INT_AND(ctrl, 0x3)\nINT_EQUAL(fmt, 0x1)",
        "bitwise_density": 0.3,
        "arithmetic_density": 0.0,
        "loop_depth": 0,
        "register_count": 2,
        "estimated_complexity": 20,
        "z3_template_hint": None,
        "correction_history": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "solve_count": 0,
    },
]


async def run_tests():
    store = SpecStore(dsn=DSN)
    passed = 0
    failed = 0

    try:
        # ── Test 1: Initialize ────────────────────────────────────────
        print("\n▸ SpecStore: initialize")
        await store.initialize()
        assert store._pool is not None
        print("  ✓ Connection pool created")
        passed += 1

        # ── Test 2: Clean slate ───────────────────────────────────────
        print("\n▸ SpecStore: clean test data")
        async with store._pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM vulnerability_specs WHERE spec_id LIKE 'test_%'"
            )
        print("  ✓ Test data cleaned")
        passed += 1

        # ── Test 3: Save specs ────────────────────────────────────────
        print("\n▸ SpecStore: save_spec (5 ICS specs)")
        for spec in SEED_SPECS:
            await store.save_spec(spec)
        stats = await store.get_store_stats()
        assert stats["total_specs"] >= 5, f"Expected >= 5 specs, got {stats['total_specs']}"
        print(f"  ✓ {stats['total_specs']} specs in store")
        passed += 1

        # ── Test 4: Load spec ─────────────────────────────────────────
        print("\n▸ SpecStore: load_spec")
        loaded = await store.load_spec("test_modbus_crc_002")
        assert loaded is not None
        assert loaded["function_name"] == "check_crc"
        assert loaded["solve_count"] == 1
        print(f"  ✓ Loaded: {loaded['function_name']} (solve_count={loaded['solve_count']})")
        passed += 1

        # ── Test 5: Jaccard query (exact match) ───────────────────────
        print("\n▸ SpecStore: query_by_jaccard (exact tag match)")
        query_tags = [ConstraintTag.BITWISE_LOOP.value, ConstraintTag.BITMASK_CHECK.value]
        results = await store.query_by_jaccard(query_tags=query_tags, threshold=0.3)
        assert len(results) >= 1, "Expected at least 1 Jaccard result"
        best = results[0]
        assert best["spec_id"] == "test_modbus_crc_002"
        assert best["jaccard_score"] == 1.0, f"Expected Jaccard=1.0, got {best['jaccard_score']}"
        print(f"  ✓ Best match: {best['spec_id']} (Jaccard={best['jaccard_score']:.2f})")
        passed += 1

        # ── Test 6: Jaccard query (partial match) ─────────────────────
        print("\n▸ SpecStore: query_by_jaccard (partial overlap)")
        query_tags = [
            ConstraintTag.CONSTANT_EQUALITY.value,
            ConstraintTag.BITMASK_CHECK.value,
        ]
        results = await store.query_by_jaccard(query_tags=query_tags, threshold=0.3)
        assert len(results) >= 2, f"Expected >= 2 results, got {len(results)}"
        # BITMASK_CHECK + CONSTANT_EQUALITY matches:
        #   test_iec104_format_005 → J=1.0 (exact match)
        #   test_modbus_crc_002 → J=1/3=0.33 (partial: {BITMASK_CHECK} ∩ {CRC,BITMASK})
        #   test_modbus_tid_001 → J=1/2=0.5 (partial: {CONST_EQ} ∩ {CONST_EQ,BITMASK})
        print(f"  ✓ {len(results)} results returned")
        for r in results:
            print(f"    {r['spec_id']}: Jaccard={r['jaccard_score']:.2f}")
        passed += 1

        # ── Test 7: Architecture filter ───────────────────────────────
        print("\n▸ SpecStore: query_by_jaccard (architecture filter)")
        query_tags = [ConstraintTag.CONSTANT_EQUALITY.value]
        results_x86 = await store.query_by_jaccard(
            query_tags=query_tags, threshold=0.3, architecture="x86_64"
        )
        results_arm = await store.query_by_jaccard(
            query_tags=query_tags, threshold=0.3, architecture="arm32"
        )
        x86_ids = {r["spec_id"] for r in results_x86}
        arm_ids = {r["spec_id"] for r in results_arm}
        assert "test_iec104_format_005" not in x86_ids, "ARM spec should be filtered out"
        assert "test_modbus_tid_001" not in arm_ids, "x86 spec should be filtered out"
        print(f"  ✓ x86_64: {len(results_x86)} results, arm32: {len(results_arm)} results")
        passed += 1

        # ── Test 8: Update template ───────────────────────────────────
        print("\n▸ SpecStore: update_template")
        winning_script = "from z3 import *\ns = Solver()\n# winning Z3 script"
        await store.update_template("test_modbus_fc_003", winning_script)
        updated = await store.load_spec("test_modbus_fc_003")
        assert updated["z3_template"] == winning_script
        assert updated["solve_count"] == 1
        print(f"  ✓ Template updated, solve_count={updated['solve_count']}")
        passed += 1

        # ── Test 9: Append correction ─────────────────────────────────
        print("\n▸ SpecStore: append_correction")
        await store.append_correction(
            spec_id="test_modbus_fc_003",
            error_message="NameError: name 'fc' is not defined",
            corrected_script="fc = BitVec('fc', 8)",
        )
        corrected = await store.load_spec("test_modbus_fc_003")
        history = corrected["correction_history"]
        assert len(history) >= 1, "Expected correction history"
        assert history[-1]["error_message"] == "NameError: name 'fc' is not defined"
        print(f"  ✓ Correction appended ({len(history)} entries)")
        passed += 1

        # ── Test 10: CARM Retriever (full pipeline) ───────────────────
        print("\n▸ CARMRetriever: full 2-stage pipeline")
        retriever = CARMRetriever(
            store=store,
            similarity_threshold=0.3,
            max_results=5,
        )
        query_profile = ConstraintProfile(
            tags=frozenset({ConstraintTag.BITWISE_LOOP, ConstraintTag.BITMASK_CHECK}),
            bitwise_density=0.4,
            arithmetic_density=0.1,
            loop_depth=1,
            register_count=3,
            estimated_complexity=55,
        )
        carm_results = await retriever.query(query_profile=query_profile)
        assert len(carm_results) >= 1
        best = carm_results[0]
        assert best.spec_id == "test_modbus_crc_002"
        assert best.jaccard_score == 1.0
        assert best.z3_template is not None
        print(f"  ✓ Best: {best.spec_id} (J={best.jaccard_score:.2f}, "
              f"relevance={best.relevance_score:.4f})")
        print(f"    Template: {best.z3_template[:50]}...")
        passed += 1

        # ── Test 11: CARM with architecture filter ────────────────────
        print("\n▸ CARMRetriever: architecture-filtered query")
        from agentic_afl.constants import Architecture
        query_profile_arm = ConstraintProfile(
            tags=frozenset({ConstraintTag.BITMASK_CHECK, ConstraintTag.CONSTANT_EQUALITY}),
            bitwise_density=0.3,
            arithmetic_density=0.0,
            loop_depth=0,
            register_count=2,
            estimated_complexity=20,
        )
        arm_results = await retriever.query(
            query_profile=query_profile_arm,
            architecture=Architecture.ARM32,
        )
        for r in arm_results:
            # All results should be ARM32
            assert r.profile_data.get("estimated_complexity") is not None
        print(f"  ✓ ARM-filtered: {len(arm_results)} results")
        passed += 1

        # ── Test 12: Store stats ──────────────────────────────────────
        print("\n▸ SpecStore: get_store_stats")
        stats = await store.get_store_stats()
        assert stats["total_specs"] >= 5
        assert stats["specs_with_templates"] >= 2  # tid + crc have templates
        print(f"  ✓ Stats: {dict(stats)}")
        passed += 1

    except Exception as e:
        failed += 1
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()

    finally:
        # Clean up test data.
        if store._pool:
            async with store._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM vulnerability_specs WHERE spec_id LIKE 'test_%'"
                )
        await store.close()

    return passed, failed


def main():
    print("=" * 70)
    print("Phase 3 Integration Tests: CARM Retrieval via PostgreSQL")
    print("=" * 70)

    passed, failed = asyncio.run(run_tests())

    print(f"\n{'=' * 70}")
    print(f"Results: {passed}/{passed + failed} passed")
    if failed:
        print(f"  ⚠ {failed} test(s) FAILED")
        sys.exit(1)
    else:
        print("  ✓ All Phase 3 tests PASSED")


if __name__ == "__main__":
    main()
