-- init.sql — PostgreSQL initialization for Agentic-AFL Spec Store.
-- Mounted into the container via docker-compose.yml.
-- Runs automatically on first container startup.

-- Enable the intarray extension for INTEGER[] operations.
CREATE EXTENSION IF NOT EXISTS intarray;

-- Server-side Jaccard similarity function.
-- Operates on INTEGER[] columns (ConstraintTag enum values).
-- This is the CORE FUNCTION that justifies PostgreSQL over mem0.
--
-- Reference: ConstraintLLM Eq. 3 — J(A,B) = |A ∩ B| / |A ∪ B|
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

-- Main table for VulnerabilitySpecs.
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

-- Indexes for common query patterns.
CREATE INDEX IF NOT EXISTS idx_specs_architecture
    ON vulnerability_specs (architecture);
CREATE INDEX IF NOT EXISTS idx_specs_stall_address
    ON vulnerability_specs (stall_address);
-- GIN index on the tag array for fast set operations.
CREATE INDEX IF NOT EXISTS idx_specs_tags
    ON vulnerability_specs USING GIN (constraint_tags);
