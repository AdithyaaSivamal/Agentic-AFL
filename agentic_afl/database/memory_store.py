"""
memory_store.py — In-Memory Fallback for SpecStore.

Drop-in replacement for SpecStore when PostgreSQL is unavailable. Provides
the same interface backed by Python dicts. Data is ephemeral — lost when
the process exits.

Design rationale:
    PostgreSQL is the CANONICAL backend for CARM retrieval (server-side
    Jaccard on GIN-indexed INTEGER[] arrays). This in-memory fallback
    exists solely to eliminate the hard PostgreSQL dependency for
    single-campaign runs where template persistence isn't needed.

    The in-memory store implements Jaccard similarity in Python. This is
    O(N) per query where N = total stored specs, but N is typically < 100
    for a single campaign run, so performance is not a concern.

Limitations:
    - No persistence: data is lost on process exit.
    - No GIN index: Jaccard queries are O(N) scans.
    - No concurrent access safety: single-process only.
    - No correction_history JSONB append semantics (uses list append).

Usage:
    from agentic_afl.database.memory_store import InMemorySpecStore

    store = InMemorySpecStore()
    await store.initialize()       # No-op, but maintains interface parity
    await store.save_spec(spec_dict)
    results = await store.query_by_jaccard(query_tags=[1, 3, 7])
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from agentic_afl.constants import ConstraintTag

logger = logging.getLogger(__name__)


class InMemorySpecStore:
    """
    In-memory fallback for SpecStore — same interface, backed by dicts.

    All methods are async to maintain interface compatibility with the
    PostgreSQL-backed SpecStore. The agent_loop, spec_exporter, and
    CARMRetriever can use this as a transparent drop-in replacement.
    """

    def __init__(self, dsn: str = "") -> None:
        """
        Initialize the in-memory store.

        Args:
            dsn: Ignored — exists only for interface compatibility.
        """
        self.dsn = dsn
        self._specs: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> None:
        """No-op — maintains interface parity with SpecStore."""
        logger.info(
            "InMemorySpecStore initialized (no PostgreSQL — "
            "CARM templates will not persist across campaigns)"
        )

    async def save_spec(self, spec_dict: dict[str, Any]) -> None:
        """
        Upsert a VulnerabilitySpec into the in-memory store.

        Mirrors SpecStore.save_spec() semantics:
        - On conflict (same spec_id): update pcode_text, tags, profile;
          APPEND to correction_history (don't replace).
        """
        spec_id = spec_dict["spec_id"]

        # Convert tag names to integer values (same as SpecStore).
        tag_names = spec_dict.get("constraint_tags", [])
        tag_ints = []
        for name in tag_names:
            if isinstance(name, int):
                tag_ints.append(name)
            elif isinstance(name, str):
                tag_ints.append(ConstraintTag[name].value)
            else:
                tag_ints.append(int(name))

        profile_data = {
            "bitwise_density": spec_dict.get("bitwise_density", 0.0),
            "arithmetic_density": spec_dict.get("arithmetic_density", 0.0),
            "loop_depth": spec_dict.get("loop_depth", 0),
            "register_count": spec_dict.get("register_count", 0),
            "estimated_complexity": spec_dict.get("estimated_complexity", 0),
        }

        # Parse created_at.
        created_at_str = spec_dict.get("created_at")
        if isinstance(created_at_str, str):
            created_at = datetime.fromisoformat(created_at_str)
        elif isinstance(created_at_str, datetime):
            created_at = created_at_str
        else:
            created_at = datetime.now(timezone.utc)

        if spec_id in self._specs:
            # Upsert: update fields, APPEND correction history.
            existing = self._specs[spec_id]
            existing["pcode_text"] = spec_dict.get("pcode_text", existing["pcode_text"])
            existing["constraint_tags"] = tag_ints
            existing["profile_data"] = profile_data
            # Append new corrections (don't replace).
            new_corrections = spec_dict.get("correction_history", [])
            if new_corrections:
                existing["correction_history"].extend(new_corrections)
            existing["last_attempted"] = datetime.now(timezone.utc).isoformat()
        else:
            # Insert new spec.
            self._specs[spec_id] = {
                "spec_id": spec_id,
                "binary_path": spec_dict.get("binary_path", ""),
                "stall_address": spec_dict.get("stall_address", ""),
                "function_name": spec_dict.get("function_name", ""),
                "architecture": spec_dict.get("architecture", "x86_64"),
                "constraint_tags": tag_ints,
                "pcode_text": spec_dict.get("pcode_text", ""),
                "profile_data": profile_data,
                "z3_template": spec_dict.get("z3_template_hint"),
                "correction_history": spec_dict.get("correction_history", []),
                "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
                "last_attempted": None,
                "solve_count": spec_dict.get("solve_count", 0),
            }

        logger.debug("Saved spec %s (tags=%s) [in-memory]", spec_id, tag_ints)

    async def query_by_jaccard(
        self,
        query_tags: list[int],
        threshold: float = 0.3,
        limit: int = 5,
        architecture: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query for VulnerabilitySpecs by Jaccard similarity — computed in Python.

        This is O(N) where N = number of stored specs. For the in-memory
        fallback this is fine (N < 100 in a single campaign).
        """
        query_set = set(query_tags)
        if not query_set:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for spec in self._specs.values():
            # Architecture filter.
            if architecture and spec.get("architecture") != architecture:
                continue

            stored_set = set(spec.get("constraint_tags", []))
            if not stored_set:
                continue

            # Jaccard similarity: |A ∩ B| / |A ∪ B|
            intersection = len(query_set & stored_set)
            union = len(query_set | stored_set)
            jaccard = intersection / union if union > 0 else 0.0

            if jaccard >= threshold:
                result = dict(spec)
                result["jaccard_score"] = jaccard
                scored.append((jaccard, result))

        # Sort by Jaccard descending, take top `limit`.
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:limit]]

    async def load_spec(self, spec_id: str) -> dict[str, Any] | None:
        """Load a single VulnerabilitySpec by its spec_id."""
        return self._specs.get(spec_id)

    async def update_template(self, spec_id: str, z3_script: str) -> None:
        """Update the winning Z3 template and increment solve_count."""
        if spec_id in self._specs:
            self._specs[spec_id]["z3_template"] = z3_script
            self._specs[spec_id]["solve_count"] += 1
            self._specs[spec_id]["last_attempted"] = datetime.now(timezone.utc).isoformat()
            logger.debug("Updated template for spec %s [in-memory]", spec_id)

    async def append_correction(
        self,
        spec_id: str,
        error_message: str,
        corrected_script: str,
    ) -> None:
        """Append a correction entry to the spec's correction history."""
        if spec_id in self._specs:
            self._specs[spec_id]["correction_history"].append({
                "error_message": error_message,
                "corrected_script": corrected_script,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self._specs[spec_id]["last_attempted"] = datetime.now(timezone.utc).isoformat()
            logger.debug("Appended correction for spec %s [in-memory]", spec_id)

    async def get_store_stats(self) -> dict[str, Any]:
        """Get aggregate statistics about the in-memory store."""
        total = len(self._specs)
        with_templates = sum(1 for s in self._specs.values() if s.get("z3_template"))
        total_corrections = sum(
            len(s.get("correction_history", []))
            for s in self._specs.values()
        )
        avg_solve = (
            sum(s.get("solve_count", 0) for s in self._specs.values()) / total
            if total > 0
            else 0
        )
        return {
            "total_specs": total,
            "specs_with_templates": with_templates,
            "total_corrections": total_corrections,
            "avg_solve_count": avg_solve,
        }

    async def close(self) -> None:
        """No-op — no resources to release."""
        logger.info("InMemorySpecStore closed (%d specs discarded)", len(self._specs))
        self._specs.clear()

    # ── Static helpers (same as SpecStore) ──────────────────────────────

    @staticmethod
    def tags_to_int_array(tags: frozenset[ConstraintTag]) -> list[int]:
        """Convert a frozenset of ConstraintTag enums to a sorted list of integers."""
        return sorted(tag.value for tag in tags)

    @staticmethod
    def int_array_to_tags(values: list[int]) -> frozenset[ConstraintTag]:
        """Convert a list of integers back to a frozenset of ConstraintTag enums."""
        return frozenset(ConstraintTag(v) for v in values)
