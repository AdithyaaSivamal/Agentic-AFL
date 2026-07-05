"""
import_induscp.py — One-Shot ETL: ConstraintLLM IndusCP → Agentic-AFL CARM Corpus.

Imports the ConstraintLLM knowledge_base.json (14 industrial constraint
programming problems) into the Agentic-AFL PostgreSQL vulnerability_specs
table for CARM retrieval.

Design Decisions:
    1. LOSSY TAG MAPPING: IndusCP uses high-level CSP primitives (AllDifferent,
       Circuit, Cardinality). Our ConstraintTag ontology describes low-level
       binary patterns (BITWISE_LOOP, INDEXED_LOOKUP). We intentionally map
       CSP → binary-primitive tags lossily, because:
       a) Adding CSP-level tags would force constraint_profiler.py to do
          abstract semantic inference on raw P-Code — an open research problem.
       b) Jaccard similarity on lossy primitive tags still works: two problems
          sharing {Sum, Count} map to the same {LINEAR_CONSTRAINT, COUNTED_LOOP}
          tag set, producing correct Jaccard matches.
       c) The PyCSP3 code serves as a structural few-shot hint for the LLM —
          the model's inner weights translate high-level CSP logic downward
          into Z3 BitVec expressions.

    2. Z3_TEMPLATE IS PyCSP3, NOT Z3Py: The `code` field from IndusCP is
       PyCSP3 (a constraint programming DSL), not Z3Py. It won't execute in
       our Z3 sandbox. However, it's stored as z3_template_hint because the
       structural patterns (variable declarations, constraint idioms, loop
       structures) are valuable as LLM few-shot context.

    3. THOUGHT CHAIN PROVENANCE: The `thought` field contains the IndusCP
       authors' chain-of-thought reasoning for each problem. This is stored
       in profile_data for traceability and potential future LLM prompting.

Usage:
    # Download knowledge_base.json first:
    curl -L -o data/knowledge_base.json \\
        https://raw.githubusercontent.com/william4s/ConstraintLLM/main/data/knowledge_base.json

    # Run the import:
    python scripts/import_induscp.py --kb-path data/knowledge_base.json

    # Or with a custom DSN:
    python scripts/import_induscp.py \\
        --kb-path data/knowledge_base.json \\
        --dsn postgresql://agentic:agentic@localhost:5432/agentic_afl

Reference: ConstraintLLM §2.1-2.3 — CARM tag ontology and retrieval.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Add project root to path for imports.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentic_afl.constants import ConstraintTag  # noqa: E402
from agentic_afl.database.spec_store import SpecStore  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lossy Tag Mapping: IndusCP CSP Constraints → Agentic-AFL ConstraintTags
#
# Each IndusCP constraint type is mapped to the closest binary-level
# structural pattern(s). The mapping is intentionally lossy — we do NOT
# add CSP-level concepts to the ontology.
#
# Mapping rationale documented inline.
# ---------------------------------------------------------------------------
INDUSCP_TAG_MAP: dict[str, list[ConstraintTag]] = {
    # Sum(vars) == k  ≈  ax + by + c == 0 in binary
    "Sum": [ConstraintTag.LINEAR_CONSTRAINT],

    # AllDifferent(vars)  ≈  pairwise != checks (range exclusion)
    "AllDifferent": [ConstraintTag.RANGE_BOUND, ConstraintTag.CONSTANT_EQUALITY],

    # Case-insensitive variant found in IndusCP data.
    "Alldifferent": [ConstraintTag.RANGE_BOUND, ConstraintTag.CONSTANT_EQUALITY],

    # AllDifferentList  ≈  grouped pairwise != (same structural pattern)
    "AllDifferentList": [ConstraintTag.RANGE_BOUND, ConstraintTag.CONSTANT_EQUALITY],

    # Count(vars, value=k) == n  ≈  counted loop + comparison
    "Count": [ConstraintTag.COUNTED_LOOP, ConstraintTag.CONSTANT_EQUALITY],

    # Cardinality(vars, occurrences={k: range})  ≈  bounded counting
    "Cardinality": [ConstraintTag.COUNTED_LOOP, ConstraintTag.RANGE_BOUND],

    # Table(vars, allowed_tuples)  ≈  lookup table / dispatch switch
    "Table": [ConstraintTag.INDEXED_LOOKUP, ConstraintTag.MULTI_WAY_BRANCH],

    # Circuit(vars)  ≈  Hamiltonian path ≈ pointer-chain traversal
    "Circuit": [ConstraintTag.INDEXED_LOOKUP, ConstraintTag.INPUT_DEPENDENT_LOOP],

    # Regular(vars, automaton)  ≈  FSM transitions (XOR/shift chains)
    "Regular": [ConstraintTag.BITWISE_LOOP, ConstraintTag.MULTI_WAY_BRANCH],

    # Lex(vars)  ≈  cascading range comparison chain
    "Lex": [ConstraintTag.RANGE_BOUND],

    # NValues(vars) <= k  ≈  counting distinct values in a bounded loop
    "NValues": [ConstraintTag.RANGE_BOUND, ConstraintTag.COUNTED_LOOP],

    # Element(array, index, value)  ≈  array[input] access
    "Element": [ConstraintTag.INDEXED_LOOKUP],

    # AllEqual(vars)  ≈  constant equality broadcast
    "AllEqual": [ConstraintTag.CONSTANT_EQUALITY],

    # Maximum/Minimum(vars)  ≈  range bound comparison (find extrema)
    "Maximum": [ConstraintTag.RANGE_BOUND, ConstraintTag.NESTED_CONDITIONAL],
    "Minimum": [ConstraintTag.RANGE_BOUND, ConstraintTag.NESTED_CONDITIONAL],

    # Channel(x, y)  ≈  bidirectional index mapping (x[i]=j ↔ y[j]=i)
    "Channel": [ConstraintTag.INDEXED_LOOKUP, ConstraintTag.CONSTANT_EQUALITY],

    # Cumulative(tasks, capacities)  ≈  resource-bounded scheduling
    # Maps to linear arithmetic (sum of concurrent tasks ≤ capacity)
    "Cumulative": [ConstraintTag.LINEAR_CONSTRAINT, ConstraintTag.RANGE_BOUND],

    # NoOverlap(intervals)  ≈  disjunctive scheduling (range exclusion)
    "NoOverlap": [ConstraintTag.RANGE_BOUND, ConstraintTag.LINEAR_CONSTRAINT],

    # Clause(positive_literals, negative_literals)  ≈  boolean SAT (bitmask logic)
    "Clause": [ConstraintTag.BITMASK_CHECK],

    # Slide(vars, pattern)  ≈  sliding window over input (loop + subpattern match)
    "Slide": [ConstraintTag.COUNTED_LOOP, ConstraintTag.INPUT_DEPENDENT_LOOP],
}


def map_constraints_to_tags(
    csp_constraints: list[str],
) -> list[str]:
    """
    Convert a list of IndusCP CSP constraint names to ConstraintTag names.

    Returns a deduplicated list of tag name strings (suitable for
    SpecStore.save_spec()).
    """
    tags: set[ConstraintTag] = set()
    unmapped: list[str] = []

    for csp_name in csp_constraints:
        mapped = INDUSCP_TAG_MAP.get(csp_name)
        if mapped:
            tags.update(mapped)
        else:
            unmapped.append(csp_name)

    if unmapped:
        logger.warning(
            "Unmapped IndusCP constraints (no ConstraintTag equivalent): %s",
            unmapped,
        )

    return [t.name for t in tags]


def estimate_complexity(csp_constraints: list[str], code: str) -> int:
    """
    Rough complexity estimate based on constraint count and code length.

    This feeds into CARM's Stage 2 re-ranking (complexity similarity).
    Range: 0-100.
    """
    n_constraints = len(csp_constraints)
    code_lines = code.count("\n") + 1

    # Heuristic: more constraint types + longer code = higher complexity.
    score = min(100, n_constraints * 10 + code_lines // 5)
    return score


async def import_knowledge_base(kb_path: str, dsn: str) -> int:
    """
    Import all entries from knowledge_base.json into PostgreSQL.

    Args:
        kb_path: Path to the ConstraintLLM knowledge_base.json file.
        dsn: PostgreSQL connection string.

    Returns:
        Number of entries imported.
    """
    with open(kb_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    logger.info("Loaded %d entries from %s", len(entries), kb_path)

    store = SpecStore(dsn=dsn)
    await store.initialize()

    imported = 0
    for entry in entries:
        name = entry.get("name", f"unknown_{imported}")
        csp_constraints = entry.get("constraints", [])
        code = entry.get("code", "")
        problem = entry.get("problem", "")
        thought = entry.get("thought", "")

        # Map CSP constraints → ConstraintTag names.
        tag_names = map_constraints_to_tags(csp_constraints)
        complexity = estimate_complexity(csp_constraints, code)

        spec_dict = {
            "spec_id": f"induscp_{name}",
            "binary_path": "induscp_benchmark",
            "stall_address": "synthetic",
            "function_name": name,
            "architecture": "x86_64",  # Platform-agnostic seed
            "constraint_tags": tag_names,
            "pcode_text": problem,  # Problem statement as pseudo-P-Code
            "z3_template_hint": code,  # PyCSP3, not Z3 — structural hint
            # Profile metrics for CARM Stage 2 re-ranking.
            "bitwise_density": 0.0,
            "arithmetic_density": 0.0,
            "loop_depth": 0,
            "register_count": 0,
            "estimated_complexity": complexity,
            "correction_history": [],
            "solve_count": 0,
        }

        try:
            await store.save_spec(spec_dict)
            logger.info(
                "  ✓ Imported: %s (tags=%s, complexity=%d)",
                name, tag_names, complexity,
            )
            imported += 1
        except Exception as e:
            logger.error("  ✗ Failed to import %s: %s", name, e)

    # Print store stats after import.
    stats = await store.get_store_stats()
    logger.info(
        "Store stats after import: total=%d, with_templates=%d",
        stats["total_specs"], stats["specs_with_templates"],
    )

    await store.close()
    return imported


def main():
    parser = argparse.ArgumentParser(
        description="Import ConstraintLLM IndusCP knowledge base into Agentic-AFL CARM corpus.",
    )
    parser.add_argument(
        "--kb-path",
        type=str,
        required=True,
        help="Path to knowledge_base.json from ConstraintLLM repo.",
    )
    parser.add_argument(
        "--dsn",
        type=str,
        default="postgresql://agentic:agentic@localhost:5432/agentic_afl",
        help="PostgreSQL DSN (default: local development DB).",
    )
    args = parser.parse_args()

    if not Path(args.kb_path).exists():
        logger.error("File not found: %s", args.kb_path)
        logger.info(
            "Download it with:\n"
            "  curl -L -o data/knowledge_base.json \\\n"
            "    https://raw.githubusercontent.com/william4s/ConstraintLLM"
            "/main/data/knowledge_base.json"
        )
        sys.exit(1)

    count = asyncio.run(import_knowledge_base(args.kb_path, args.dsn))
    logger.info("Import complete: %d entries committed to CARM corpus.", count)


if __name__ == "__main__":
    main()
