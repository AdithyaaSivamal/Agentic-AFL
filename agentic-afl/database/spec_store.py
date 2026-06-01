"""
spec_store.py — PostgreSQL Storage Backend for VulnerabilitySpecs.

This module manages the persistent storage of VulnerabilitySpecs, Z3
templates, and correction histories in PostgreSQL using JSONB columns
and a server-side Jaccard similarity function.

WHY POSTGRESQL (not mem0):
    mem0 is a high-level abstraction over vector databases (Qdrant/Chroma)
    optimized for cosine-similarity semantic search. Agentic-AFL's CARM
    retrieval requires Jaccard Similarity on formal logic tag sets — a
    fundamentally different mathematical operation. Forcing Jaccard through
    mem0 would require pulling ALL records to Python RAM and looping,
    which is unacceptable for a fuzzer-adjacent tool.

    PostgreSQL with JSONB solves both retrieval needs:
      1. CARM Retrieval: Server-side Jaccard via a custom SQL function
         on integer arrays (intarray extension). The DB does the math
         and returns only the top-N matches.
      2. Future two-stage retrieval (ConstraintLLM §2.2): pgvector
         handles embedding pre-filtering in the same database, unified
         with CARM re-ranking in a single query.

Schema:
    vulnerability_specs:
        spec_id          TEXT PRIMARY KEY
        binary_path      TEXT NOT NULL
        stall_address    TEXT NOT NULL
        function_name    TEXT NOT NULL
        architecture     TEXT NOT NULL
        constraint_tags  INTEGER[]          -- ConstraintTag enum values as int array
        pcode_text       TEXT NOT NULL
        profile_data     JSONB NOT NULL     -- Full ConstraintProfile metrics
        z3_template      TEXT               -- Winning Z3 script (nullable)
        correction_history JSONB DEFAULT '[]'
        created_at       TIMESTAMPTZ DEFAULT NOW()
        last_attempted   TIMESTAMPTZ
        solve_count      INTEGER DEFAULT 0

Deployment:
    PostgreSQL can run as:
      - A local Docker container (docker-compose.yml provided)
      - A Proxmox LXC/VM provisioned via Terraform
      - A managed instance (Supabase, Neon, etc.)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import asyncpg

from agentic_afl.config import settings
from agentic_afl.constants import ConstraintTag

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL Statements — asyncpg uses $1, $2, ... positional parameters
# ---------------------------------------------------------------------------

CREATE_EXTENSION_SQL = """
CREATE EXTENSION IF NOT EXISTS intarray;
"""

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_specs (
    spec_id             TEXT PRIMARY KEY,
    binary_path         TEXT NOT NULL,
    stall_address       TEXT NOT NULL,
    function_name       TEXT NOT NULL,
    architecture        TEXT NOT NULL,
    constraint_tags     INTEGER[] NOT NULL DEFAULT '{}',
    pcode_text          TEXT NOT NULL,
    profile_data        JSONB NOT NULL DEFAULT '{}',
    z3_template         TEXT,
    correction_history  JSONB NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempted      TIMESTAMPTZ,
    solve_count         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_specs_architecture ON vulnerability_specs (architecture);
CREATE INDEX IF NOT EXISTS idx_specs_stall_address ON vulnerability_specs (stall_address);
CREATE INDEX IF NOT EXISTS idx_specs_tags ON vulnerability_specs USING GIN (constraint_tags);
"""

CREATE_JACCARD_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION jaccard_similarity(a INTEGER[], b INTEGER[])
RETURNS FLOAT AS $$
DECLARE
    intersection_size INTEGER;
    union_size INTEGER;
BEGIN
    SELECT COUNT(*) INTO intersection_size
    FROM (SELECT UNNEST(a) INTERSECT SELECT UNNEST(b)) t;

    SELECT COUNT(*) INTO union_size
    FROM (SELECT UNNEST(a) UNION SELECT UNNEST(b)) t;

    IF union_size = 0 THEN RETURN 0.0; END IF;
    RETURN intersection_size::FLOAT / union_size::FLOAT;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
"""

UPSERT_SPEC_SQL = """
INSERT INTO vulnerability_specs (
    spec_id, binary_path, stall_address, function_name, architecture,
    constraint_tags, pcode_text, profile_data, z3_template,
    correction_history, created_at, solve_count
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
ON CONFLICT (spec_id) DO UPDATE SET
    pcode_text = EXCLUDED.pcode_text,
    constraint_tags = EXCLUDED.constraint_tags,
    profile_data = EXCLUDED.profile_data,
    correction_history = vulnerability_specs.correction_history || EXCLUDED.correction_history,
    last_attempted = NOW();
"""

# Architecture filter is appended conditionally — see query_by_jaccard().
JACCARD_QUERY_BASE_SQL = """
SELECT
    spec_id,
    binary_path,
    stall_address,
    function_name,
    architecture,
    constraint_tags,
    pcode_text,
    profile_data,
    z3_template,
    correction_history,
    solve_count,
    jaccard_similarity(constraint_tags, $1) AS jaccard_score
FROM vulnerability_specs
WHERE
    jaccard_similarity(constraint_tags, $1) >= $2
    {architecture_filter}
ORDER BY jaccard_score DESC
LIMIT $3;
"""

# With architecture filter: $4 is the architecture string.
JACCARD_QUERY_ARCH_SQL = """
SELECT
    spec_id,
    binary_path,
    stall_address,
    function_name,
    architecture,
    constraint_tags,
    pcode_text,
    profile_data,
    z3_template,
    correction_history,
    solve_count,
    jaccard_similarity(constraint_tags, $1) AS jaccard_score
FROM vulnerability_specs
WHERE
    jaccard_similarity(constraint_tags, $1) >= $2
    AND architecture = $4
ORDER BY jaccard_score DESC
LIMIT $3;
"""

LOAD_SPEC_SQL = """
SELECT * FROM vulnerability_specs WHERE spec_id = $1;
"""

UPDATE_TEMPLATE_SQL = """
UPDATE vulnerability_specs
SET z3_template = $2, solve_count = solve_count + 1, last_attempted = NOW()
WHERE spec_id = $1;
"""

APPEND_CORRECTION_SQL = """
UPDATE vulnerability_specs
SET correction_history = correction_history || $2::jsonb, last_attempted = NOW()
WHERE spec_id = $1;
"""

STORE_STATS_SQL = """
SELECT
    COUNT(*) AS total_specs,
    COUNT(z3_template) AS specs_with_templates,
    COALESCE(SUM(jsonb_array_length(correction_history)), 0) AS total_corrections,
    COALESCE(AVG(solve_count), 0) AS avg_solve_count
FROM vulnerability_specs;
"""


class SpecStore:
    """
    PostgreSQL-backed storage for VulnerabilitySpecs with server-side Jaccard.

    This replaces the filesystem-based mem0 store. All Jaccard similarity
    computation happens in PostgreSQL, not in Python.

    Usage:
        store = SpecStore()
        await store.initialize()  # Creates tables + Jaccard function

        # Write
        await store.save_spec(spec_dict)

        # CARM retrieval (Jaccard computed server-side)
        results = await store.query_by_jaccard(
            query_tags=[1, 3, 7, 12],  # ConstraintTag enum values
            threshold=0.3,
            limit=5,
        )

        # Update after successful solve
        await store.update_template(spec_id, winning_z3_script)
    """

    def __init__(
        self,
        dsn: str = settings.postgres_dsn,
    ) -> None:
        """
        Initialize the store.

        Args:
            dsn: PostgreSQL connection string.
                 Format: "postgresql://user:pass@host:port/dbname"
        """
        self.dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def initialize(self) -> None:
        """
        Initialize the database: create tables, indexes, and the Jaccard function.

        Call this once at startup (in agent_loop.setup()).
        Idempotent — safe to call multiple times.
        """
        self._pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10)

        async with self._pool.acquire() as conn:
            # CREATE EXTENSION requires superuser; skip gracefully if already installed
            # (the extension is created by init.sql or a DBA).
            try:
                await conn.execute(CREATE_EXTENSION_SQL)
            except asyncpg.exceptions.InsufficientPrivilegeError:
                logger.debug("intarray extension already exists (created by superuser)")

            await conn.execute(CREATE_JACCARD_FUNCTION_SQL)
            await conn.execute(CREATE_TABLE_SQL)

        logger.info("SpecStore initialized (PostgreSQL at %s)", self.dsn.split("@")[-1])

    async def save_spec(self, spec_dict: dict[str, Any]) -> None:
        """
        Upsert a VulnerabilitySpec into PostgreSQL.

        The constraint_tags field is stored as INTEGER[] where each integer
        is the ConstraintTag enum's value. This enables the server-side
        Jaccard function to operate directly on the array.

        Args:
            spec_dict: From VulnerabilitySpec.to_dict(). Must include:
                       spec_id, binary_path, stall_address, function_name,
                       architecture, constraint_tags (list of tag name strings),
                       pcode_text, and profile metrics.
        """
        assert self._pool is not None, "Call initialize() before save_spec()"

        # Convert tag names to integer values for the INTEGER[] column.
        tag_names = spec_dict.get("constraint_tags", [])
        tag_ints = [ConstraintTag[name].value for name in tag_names]

        # Bundle profile metrics into a JSONB dict.
        profile_data = {
            "bitwise_density": spec_dict.get("bitwise_density", 0.0),
            "arithmetic_density": spec_dict.get("arithmetic_density", 0.0),
            "loop_depth": spec_dict.get("loop_depth", 0),
            "register_count": spec_dict.get("register_count", 0),
            "estimated_complexity": spec_dict.get("estimated_complexity", 0),
        }

        # Parse created_at timestamp.
        created_at_str = spec_dict.get("created_at")
        if isinstance(created_at_str, str):
            created_at = datetime.fromisoformat(created_at_str)
        elif isinstance(created_at_str, datetime):
            created_at = created_at_str
        else:
            created_at = datetime.now(timezone.utc)

        async with self._pool.acquire() as conn:
            await conn.execute(
                UPSERT_SPEC_SQL,
                spec_dict["spec_id"],                                     # $1
                spec_dict.get("binary_path", ""),                         # $2
                spec_dict.get("stall_address", ""),                       # $3
                spec_dict.get("function_name", ""),                       # $4
                spec_dict.get("architecture", "x86_64"),                  # $5
                tag_ints,                                                 # $6
                spec_dict.get("pcode_text", ""),                          # $7
                json.dumps(profile_data),                                 # $8
                spec_dict.get("z3_template_hint"),                        # $9
                json.dumps(spec_dict.get("correction_history", [])),      # $10
                created_at,                                               # $11
                spec_dict.get("solve_count", 0),                          # $12
            )

        logger.debug("Saved spec %s (tags=%s)", spec_dict["spec_id"], tag_ints)

    async def query_by_jaccard(
        self,
        query_tags: list[int],
        threshold: float = settings.carm_similarity_threshold,
        limit: int = settings.carm_max_results,
        architecture: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query for VulnerabilitySpecs by Jaccard similarity — computed SERVER-SIDE.

        This is the critical method that justifies PostgreSQL over mem0.
        The Jaccard computation happens entirely in the database; Python
        receives only the top-N matching rows, pre-sorted by score.

        Args:
            query_tags:   List of ConstraintTag enum values (integers) for the
                          current stall site's constraint profile.
            threshold:    Minimum Jaccard score (default 0.3).
            limit:        Maximum results to return (default 5).
            architecture: Optional architecture filter (e.g., "arm32").

        Returns:
            List of dicts, each containing the spec fields plus a
            'jaccard_score' float. Sorted by jaccard_score descending.
        """
        assert self._pool is not None, "Call initialize() before query_by_jaccard()"

        async with self._pool.acquire() as conn:
            if architecture:
                rows = await conn.fetch(
                    JACCARD_QUERY_ARCH_SQL,
                    query_tags,     # $1
                    threshold,      # $2
                    limit,          # $3
                    architecture,   # $4
                )
            else:
                query = JACCARD_QUERY_BASE_SQL.format(architecture_filter="")
                rows = await conn.fetch(
                    query,
                    query_tags,     # $1
                    threshold,      # $2
                    limit,          # $3
                )

        results = []
        for row in rows:
            result = dict(row)
            # Parse JSONB strings back to Python dicts.
            if isinstance(result.get("profile_data"), str):
                result["profile_data"] = json.loads(result["profile_data"])
            if isinstance(result.get("correction_history"), str):
                result["correction_history"] = json.loads(result["correction_history"])
            results.append(result)

        logger.debug(
            "Jaccard query: %d results (threshold=%.2f, tags=%s)",
            len(results), threshold, query_tags,
        )
        return results

    async def load_spec(self, spec_id: str) -> dict[str, Any] | None:
        """
        Load a single VulnerabilitySpec by its spec_id.

        Returns:
            The spec as a dict, or None if not found.
        """
        assert self._pool is not None, "Call initialize() before load_spec()"

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(LOAD_SPEC_SQL, spec_id)

        if row is None:
            return None

        result = dict(row)
        if isinstance(result.get("profile_data"), str):
            result["profile_data"] = json.loads(result["profile_data"])
        if isinstance(result.get("correction_history"), str):
            result["correction_history"] = json.loads(result["correction_history"])
        return result

    async def update_template(self, spec_id: str, z3_script: str) -> None:
        """
        Update the winning Z3 template and increment solve_count.

        Called after a successful Z3 solve. The winning script becomes
        the template for future CARM retrieval matches.
        """
        assert self._pool is not None, "Call initialize() before update_template()"

        async with self._pool.acquire() as conn:
            await conn.execute(UPDATE_TEMPLATE_SQL, spec_id, z3_script)

        logger.debug("Updated template for spec %s", spec_id)

    async def append_correction(
        self,
        spec_id: str,
        error_message: str,
        corrected_script: str,
    ) -> None:
        """
        Append a correction entry to the spec's correction history (JSONB append).

        Reference: SAILOR §4.4 — Iterative compile-execute-refine loop.
        """
        assert self._pool is not None, "Call initialize() before append_correction()"

        correction_entry = json.dumps([{
            "error_message": error_message,
            "corrected_script": corrected_script,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])

        async with self._pool.acquire() as conn:
            await conn.execute(APPEND_CORRECTION_SQL, spec_id, correction_entry)

        logger.debug("Appended correction for spec %s", spec_id)

    async def get_store_stats(self) -> dict[str, Any]:
        """
        Get aggregate statistics about the store.

        Returns:
            Dict: {total_specs, specs_with_templates, total_corrections, avg_solve_count}
        """
        assert self._pool is not None, "Call initialize() before get_store_stats()"

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(STORE_STATS_SQL)

        return dict(row) if row else {
            "total_specs": 0,
            "specs_with_templates": 0,
            "total_corrections": 0,
            "avg_solve_count": 0,
        }

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("SpecStore connection pool closed")

    @staticmethod
    def tags_to_int_array(tags: frozenset[ConstraintTag]) -> list[int]:
        """
        Convert a frozenset of ConstraintTag enums to a sorted list of integers.

        This is the bridge between the Python type system and PostgreSQL's
        INTEGER[] column. Called by spec_exporter.py before persisting.
        """
        return sorted(tag.value for tag in tags)

    @staticmethod
    def int_array_to_tags(values: list[int]) -> frozenset[ConstraintTag]:
        """
        Convert a list of integers back to a frozenset of ConstraintTag enums.

        Called when loading specs from PostgreSQL back into Python.
        """
        return frozenset(ConstraintTag(v) for v in values)
