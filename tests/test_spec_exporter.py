"""
test_spec_exporter.py — Unit tests for the SpecExporter.

Covers a module that was at 0% coverage. Exercises the JSON-fallback
persistence path, the no-backend path, dict<->spec round-tripping, and
graceful handling of unknown constraint-tag names on load (the same
ontology-drift resilience hardened in spec_store this pass).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.models import (
    ConstraintProfile,
    PCodeInstruction,
    PCodeSlice,
    VulnerabilitySpec,
)
from agentic_afl.extractor.spec_exporter import SpecExporter


def _slice() -> PCodeSlice:
    return PCodeSlice(
        binary_path=Path("./test_binary"),
        stall_address="0x1234",
        function_name="check_crc",
        function_entry="0x1200",
        instructions=[
            PCodeInstruction(
                address="0x1234", mnemonic="INT_EQUAL",
                inputs=["r0", "0x5a01"], output="ZF",
                raw_pcode="ZF = INT_EQUAL r0 0x5a01",
            )
        ],
        taint_source="RDI",
        slice_depth=1,
        truncated=False,
        architecture=Architecture.X86_64,
    )


def _profile() -> ConstraintProfile:
    return ConstraintProfile(
        tags=frozenset({ConstraintTag.BITWISE_LOOP, ConstraintTag.BITMASK_CHECK}),
        bitwise_density=0.5,
        arithmetic_density=0.1,
        loop_depth=1,
        register_count=3,
        estimated_complexity=42,
    )


# ═══════════════════════════════════════════════════════════════════════
#  export() persistence paths
# ═══════════════════════════════════════════════════════════════════════

class TestExport:
    @pytest.mark.asyncio
    async def test_no_backend_still_returns_spec(self):
        exporter = SpecExporter()  # neither store nor json_dir
        spec = await exporter.export(_slice(), _profile())
        assert isinstance(spec, VulnerabilitySpec)
        assert spec.function_name == "check_crc"
        # Deterministic id from binary + stall address.
        assert spec.spec_id == VulnerabilitySpec.generate_id(Path("./test_binary"), "0x1234")

    @pytest.mark.asyncio
    async def test_json_fallback_writes_file(self, tmp_path):
        exporter = SpecExporter(json_dir=tmp_path / "specs")
        spec = await exporter.export(_slice(), _profile())
        json_file = (tmp_path / "specs" / f"{spec.spec_id}.json")
        assert json_file.exists()

    @pytest.mark.asyncio
    async def test_store_failure_falls_back_to_json(self, tmp_path):
        class FailingStore:
            async def save_spec(self, spec_dict):
                raise RuntimeError("db down")

        exporter = SpecExporter(store=FailingStore(), json_dir=tmp_path / "specs")
        spec = await exporter.export(_slice(), _profile())
        # On store failure with a json_dir configured, it must fall back.
        assert (tmp_path / "specs" / f"{spec.spec_id}.json").exists()

    @pytest.mark.asyncio
    async def test_store_success_path(self, tmp_path):
        saved = {}

        class RecordingStore:
            async def save_spec(self, spec_dict):
                saved.update(spec_dict)

        exporter = SpecExporter(store=RecordingStore())
        spec = await exporter.export(_slice(), _profile())
        assert saved["spec_id"] == spec.spec_id
        assert set(saved["constraint_tags"]) == {"BITWISE_LOOP", "BITMASK_CHECK"}


# ═══════════════════════════════════════════════════════════════════════
#  Round-trip via JSON
# ═══════════════════════════════════════════════════════════════════════

class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_export_then_load_preserves_core_fields(self, tmp_path):
        exporter = SpecExporter(json_dir=tmp_path / "specs")
        spec = await exporter.export(_slice(), _profile())

        loaded = await exporter.load_spec(spec.spec_id)
        assert loaded is not None
        assert loaded.spec_id == spec.spec_id
        assert loaded.function_name == "check_crc"
        assert loaded.constraint_profile.tags == _profile().tags
        assert loaded.constraint_profile.estimated_complexity == 42

    @pytest.mark.asyncio
    async def test_load_missing_spec_returns_none(self, tmp_path):
        exporter = SpecExporter(json_dir=tmp_path / "specs")
        assert await exporter.load_spec("nonexistent_id") is None


# ═══════════════════════════════════════════════════════════════════════
#  Ontology-drift resilience on load
# ═══════════════════════════════════════════════════════════════════════

class TestDictToSpec:
    def test_unknown_tag_name_is_skipped_not_fatal(self):
        data = {
            "spec_id": "abc",
            "binary_path": "./b",
            "stall_address": "0x1",
            "function_name": "f",
            "constraint_tags": ["BITWISE_LOOP", "OLD_REMOVED_TAG"],
            "architecture": "x86_64",
            "pcode_text": "",
        }
        spec = SpecExporter._dict_to_spec(data)
        # Known tag survives, unknown is dropped without raising.
        assert ConstraintTag.BITWISE_LOOP in spec.constraint_profile.tags
        assert len(spec.constraint_profile.tags) == 1

    def test_integer_tags_are_accepted(self):
        data = {
            "spec_id": "abc",
            "binary_path": "./b",
            "stall_address": "0x1",
            "function_name": "f",
            "constraint_tags": [ConstraintTag.BITWISE_LOOP.value],
            "architecture": "x86_64",
            "pcode_text": "",
        }
        spec = SpecExporter._dict_to_spec(data)
        assert ConstraintTag.BITWISE_LOOP in spec.constraint_profile.tags

    def test_unknown_architecture_defaults_to_x86_64(self):
        data = {
            "spec_id": "abc",
            "binary_path": "./b",
            "stall_address": "0x1",
            "function_name": "f",
            "constraint_tags": [],
            "architecture": "vax_11_780",
            "pcode_text": "",
        }
        spec = SpecExporter._dict_to_spec(data)
        assert spec.architecture == Architecture.X86_64
