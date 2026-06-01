"""
spec_exporter.py — Packages Extractor Output into VulnerabilitySpecs.

This module is the FINAL step of Phase 1. It takes a PCodeSlice and
ConstraintProfile, bundles them into a VulnerabilitySpec, and provides
persistence via PostgreSQL (when available) or JSON file fallback.

Inputs:
    - PCodeSlice          — From pcode_slicer.py
    - ConstraintProfile   — From constraint_profiler.py

Outputs:
    - VulnerabilitySpec   — Persisted to PostgreSQL via database/spec_store.py
                           or serialized to JSON on disk.

Reference: SAILOR §3.3 — JSON Vulnerability Specification schema.

This is a thin packaging layer. The heavy lifting is in pcode_slicer and
constraint_profiler. This module:
  1. Constructs the VulnerabilitySpec dataclass.
  2. Generates a deterministic spec_id.
  3. Serializes to a dict.
  4. Persists to PostgreSQL (or JSON fallback).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.models import (
    ConstraintProfile,
    CorrectionEntry,
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
)

logger = logging.getLogger(__name__)


class SpecExporter:
    """
    Packages P-Code slices and constraint profiles into VulnerabilitySpecs
    and persists them.

    Supports two persistence backends:
      1. PostgreSQL via SpecStore (preferred for production + CARM retrieval)
      2. JSON file fallback (for development and testing without PostgreSQL)

    Usage (PostgreSQL):
        store = SpecStore()
        await store.initialize()
        exporter = SpecExporter(store=store)
        spec = await exporter.export(pcode_slice, constraint_profile)

    Usage (JSON fallback):
        exporter = SpecExporter(json_dir=Path("./specs"))
        spec = await exporter.export(pcode_slice, constraint_profile)
    """

    def __init__(
        self,
        store: Any | None = None,
        json_dir: Path | None = None,
    ) -> None:
        """
        Initialize the exporter.

        Args:
            store:    Optional SpecStore instance for PostgreSQL persistence.
            json_dir: Optional directory for JSON file fallback.
                     If neither store nor json_dir is provided, export()
                     will construct the spec but skip persistence.
        """
        self.store = store
        self.json_dir = json_dir

        if self.json_dir is not None:
            self.json_dir.mkdir(parents=True, exist_ok=True)

    async def export(
        self,
        pcode_slice: PCodeSlice,
        constraint_profile: ConstraintProfile,
    ) -> VulnerabilitySpec:
        """
        Create a VulnerabilitySpec from extractor outputs and persist it.

        Args:
            pcode_slice:        The extracted P-Code slice.
            constraint_profile: The computed constraint profile.

        Returns:
            The persisted VulnerabilitySpec (with spec_id populated).
        """
        # Step 1: Generate deterministic spec_id.
        spec_id = VulnerabilitySpec.generate_id(
            pcode_slice.binary_path, pcode_slice.stall_address
        )

        # Step 2: Construct the VulnerabilitySpec.
        spec = VulnerabilitySpec(
            spec_id=spec_id,
            binary_path=pcode_slice.binary_path,
            stall_address=pcode_slice.stall_address,
            function_name=pcode_slice.function_name,
            pcode_slice=pcode_slice,
            constraint_profile=constraint_profile,
            architecture=pcode_slice.architecture,
        )

        # Step 3: Persist.
        spec_dict = spec.to_dict()

        if self.store is not None:
            try:
                await self.store.save_spec(spec_dict)
                logger.info(
                    "Exported spec %s → PostgreSQL (%s @ %s)",
                    spec_id, pcode_slice.function_name, pcode_slice.stall_address,
                )
            except Exception as e:
                logger.error(
                    "PostgreSQL write failed for spec %s: %s. "
                    "Falling back to JSON if json_dir is set.",
                    spec_id, e,
                )
                # Fall through to JSON fallback if available.
                if self.json_dir is not None:
                    self._write_json_fallback(spec_id, spec_dict)

        elif self.json_dir is not None:
            self._write_json_fallback(spec_id, spec_dict)

        else:
            logger.info(
                "Exported spec %s (in-memory only — no persistence backend configured)",
                spec_id,
            )

        return spec

    async def load_spec(self, spec_id: str) -> VulnerabilitySpec | None:
        """
        Load a VulnerabilitySpec by its spec_id.

        Attempts PostgreSQL first, then JSON fallback.

        Returns:
            The VulnerabilitySpec, or None if not found.
        """
        # Try PostgreSQL store first.
        if self.store is not None:
            try:
                row = await self.store.load_spec(spec_id)
                if row is not None:
                    return self._row_to_spec(row)
            except Exception as e:
                logger.warning("PostgreSQL load failed for spec %s: %s", spec_id, e)

        # Try JSON fallback.
        if self.json_dir is not None:
            json_path = self.json_dir / f"{spec_id}.json"
            if json_path.exists():
                try:
                    return self._load_json_spec(json_path)
                except Exception as e:
                    logger.warning("JSON load failed for spec %s: %s", spec_id, e)

        return None

    def _write_json_fallback(self, spec_id: str, spec_dict: dict[str, Any]) -> None:
        """Write a spec to the JSON fallback directory."""
        assert self.json_dir is not None
        json_path = self.json_dir / f"{spec_id}.json"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(spec_dict, f, indent=2, default=str)

        logger.info("Exported spec %s → %s (JSON fallback)", spec_id, json_path)

    def _load_json_spec(self, json_path: Path) -> VulnerabilitySpec:
        """Load a VulnerabilitySpec from a JSON file."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return self._dict_to_spec(data)

    @staticmethod
    def _dict_to_spec(data: dict[str, Any]) -> VulnerabilitySpec:
        """
        Deserialize a dict (from JSON or PostgreSQL) into a VulnerabilitySpec.

        This reconstructs the nested dataclasses from flat/serialized form.
        """
        # Reconstruct ConstraintProfile from the flat fields.
        tag_names = data.get("constraint_tags", [])
        tags = frozenset(
            ConstraintTag[name] if isinstance(name, str) else ConstraintTag(name)
            for name in tag_names
        )

        constraint_profile = ConstraintProfile(
            tags=tags,
            bitwise_density=data.get("bitwise_density", 0.0),
            arithmetic_density=data.get("arithmetic_density", 0.0),
            loop_depth=data.get("loop_depth", 0),
            register_count=data.get("register_count", 0),
            estimated_complexity=data.get("estimated_complexity", 0),
        )

        # Reconstruct PCodeSlice with a minimal representation.
        # The full P-Code text is stored; individual instructions can be
        # reparsed from raw_pcode lines if needed.
        pcode_text = data.get("pcode_text", "")
        instructions = []
        for line in pcode_text.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Parse the raw_pcode line into a minimal PCodeInstruction.
            # Format: "(output) = MNEMONIC (input1) (input2) ..."
            # For loading purposes, we create a simplified instruction.
            instructions.append(PCodeInstruction(
                address="0x0",
                mnemonic="UNKNOWN",
                inputs=[],
                output=None,
                raw_pcode=line,
            ))

        # Determine architecture.
        arch_str = data.get("architecture", "x86_64")
        try:
            architecture = Architecture(arch_str)
        except ValueError:
            architecture = Architecture.X86_64

        pcode_slice = PCodeSlice(
            binary_path=Path(data.get("binary_path", "unknown")),
            stall_address=data.get("stall_address", "0x0"),
            function_name=data.get("function_name", "unknown"),
            function_entry="0x0",
            instructions=instructions,
            taint_source="unknown",
            slice_depth=0,
            truncated=False,
            architecture=architecture,
        )

        # Reconstruct correction history.
        corrections = []
        for entry in data.get("correction_history", []):
            corrections.append(CorrectionEntry(
                error_message=entry.get("error", entry.get("error_message", "")),
                corrected_script=entry.get("corrected_script", ""),
            ))

        # Parse timestamps.
        created_at = datetime.now(timezone.utc)
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(data["created_at"])
            except (ValueError, TypeError):
                pass

        last_attempted = None
        if data.get("last_attempted"):
            try:
                last_attempted = datetime.fromisoformat(data["last_attempted"])
            except (ValueError, TypeError):
                pass

        return VulnerabilitySpec(
            spec_id=data["spec_id"],
            binary_path=Path(data.get("binary_path", "unknown")),
            stall_address=data.get("stall_address", "0x0"),
            function_name=data.get("function_name", "unknown"),
            pcode_slice=pcode_slice,
            constraint_profile=constraint_profile,
            architecture=architecture,
            z3_template_hint=data.get("z3_template_hint") or data.get("z3_template"),
            correction_history=corrections,
            created_at=created_at,
            last_attempted=last_attempted,
            solve_count=data.get("solve_count", 0),
        )

    @staticmethod
    def _row_to_spec(row: dict[str, Any]) -> VulnerabilitySpec:
        """
        Convert a PostgreSQL row dict into a VulnerabilitySpec.

        PostgreSQL rows use slightly different field names (profile_data JSONB,
        constraint_tags as INTEGER[]) so this adapter normalizes them.
        """
        # Merge profile_data JSONB into the flat dict format _dict_to_spec expects.
        normalized = dict(row)

        profile = row.get("profile_data", {})
        if isinstance(profile, str):
            import json as _json
            profile = _json.loads(profile)

        normalized["bitwise_density"] = profile.get("bitwise_density", 0.0)
        normalized["arithmetic_density"] = profile.get("arithmetic_density", 0.0)
        normalized["loop_depth"] = profile.get("loop_depth", 0)
        normalized["register_count"] = profile.get("register_count", 0)
        normalized["estimated_complexity"] = profile.get("estimated_complexity", 0)

        # Convert INTEGER[] tags to ConstraintTag enum values.
        tag_ints = row.get("constraint_tags", [])
        normalized["constraint_tags"] = tag_ints  # _dict_to_spec handles int→enum

        return SpecExporter._dict_to_spec(normalized)
