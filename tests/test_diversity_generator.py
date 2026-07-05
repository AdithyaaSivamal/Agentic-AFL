"""
test_diversity_generator.py — Unit tests for the DiversityGenerator.

Covers a module that was at 0% coverage. Pure logic + filesystem, no
Ghidra/AFL/LLM/Postgres needed. Verifies CRC correctness (the whole
point of the module — every emitted frame must pass the math wall it's
meant to fan out past), protocol auto-detection, and atomic writes.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from agentic_afl.fuzzer_bridge.diversity_generator import (
    DiversityGenerator,
    _make_ics_frame,
    _make_modbus_rtu_frame,
    crc16_modbus,
    _MODBUS_VARIANTS,
    _CRC32_VARIANTS,
)


# ═══════════════════════════════════════════════════════════════════════
#  CRC-16/Modbus correctness
# ═══════════════════════════════════════════════════════════════════════

class TestCrc16Modbus:
    def test_known_test_vector(self):
        """The canonical CRC-16/Modbus check value for b'123456789' is 0x4B37."""
        assert crc16_modbus(b"123456789") == 0x4B37

    def test_empty_input_returns_init(self):
        # With no bytes processed, the CRC stays at its init value 0xFFFF.
        assert crc16_modbus(b"") == 0xFFFF

    def test_deterministic(self):
        assert crc16_modbus(b"\x01\x03\x00\x00") == crc16_modbus(b"\x01\x03\x00\x00")


class TestMakeModbusRtuFrame:
    def test_frame_has_valid_trailing_crc(self):
        frame = _make_modbus_rtu_frame(0x01, 0x03, bytes([0x00, 0x00, 0x00, 0x0A]))
        pdu, crc_bytes = frame[:-2], frame[-2:]
        stored = struct.unpack("<H", crc_bytes)[0]
        assert stored == crc16_modbus(pdu)

    def test_frame_structure(self):
        frame = _make_modbus_rtu_frame(0x11, 0x06, b"\xAB\xCD")
        assert frame[0] == 0x11  # slave
        assert frame[1] == 0x06  # func
        assert frame[2:4] == b"\xAB\xCD"  # payload
        assert len(frame) == 2 + 2 + 2  # slave+func + payload + crc16


class TestMakeIcsFrame:
    def test_frame_has_sync_and_valid_crc32(self):
        frame = _make_ics_frame(0x01, 0x05, bytes([0x01, 0x02, 0x03]))
        assert frame[:2] == b"\xA5\x5A"  # sync
        crc_data = frame[2:-4]
        stored = struct.unpack("<I", frame[-4:])[0]
        assert stored == (zlib.crc32(crc_data) & 0xFFFFFFFF)


# ═══════════════════════════════════════════════════════════════════════
#  Variant tables — every frame must self-verify
# ═══════════════════════════════════════════════════════════════════════

class TestVariantTablesAreValid:
    def test_all_modbus_variants_produce_valid_crc(self):
        for v in _MODBUS_VARIANTS:
            frame = _make_modbus_rtu_frame(v["slave"], v["func"], v["payload"])
            assert struct.unpack("<H", frame[-2:])[0] == crc16_modbus(frame[:-2]), v["name"]

    def test_all_crc32_variants_produce_valid_crc(self):
        for i, v in enumerate(_CRC32_VARIANTS):
            frame = _make_ics_frame(v["type"], (i + 1) & 0xFF, v["payload"])
            crc_data = frame[2:-4]
            assert struct.unpack("<I", frame[-4:])[0] == (zlib.crc32(crc_data) & 0xFFFFFFFF), v["name"]


# ═══════════════════════════════════════════════════════════════════════
#  Protocol auto-detection
# ═══════════════════════════════════════════════════════════════════════

class TestProtocolDetection:
    def test_no_tags_defaults_to_crc32(self, tmp_path):
        gen = DiversityGenerator(sync_dir=tmp_path / "sync")
        assert gen._detect_protocol(None) == "crc32"
        assert gen._detect_protocol(set()) == "crc32"

    def test_bitwise_loop_with_modbus_c_detects_modbus(self, tmp_path):
        gen = DiversityGenerator(sync_dir=tmp_path / "sync")
        # Decompiled C containing the Modbus poly 0xA001 should be
        # positively identified as modbus_rtu.
        modbus_c = "crc = crc >> 1 ^ 0xa001;"
        result = gen._detect_protocol({"BITWISE_LOOP"}, decompiled_c=modbus_c)
        assert result == "modbus_rtu"

    def test_tags_without_c_falls_back_to_crc32(self, tmp_path):
        gen = DiversityGenerator(sync_dir=tmp_path / "sync")
        assert gen._detect_protocol({"BITWISE_LOOP"}, decompiled_c=None) == "crc32"


# ═══════════════════════════════════════════════════════════════════════
#  End-to-end variant generation (writes to a tmp sync dir)
# ═══════════════════════════════════════════════════════════════════════

class TestGenerateVariants:
    @pytest.mark.asyncio
    async def test_modbus_generation_writes_all_variants(self, tmp_path):
        sync = tmp_path / "sync"
        gen = DiversityGenerator(sync_dir=sync)
        count = await gen.generate_variants(protocol="modbus_rtu")
        assert count == len(_MODBUS_VARIANTS)
        files = list(sync.glob("agentic_diverse_*.bin"))
        assert len(files) == len(_MODBUS_VARIANTS)
        # No orphaned temp files.
        assert list(sync.glob("*.tmp")) == []

    @pytest.mark.asyncio
    async def test_crc32_generation_writes_all_variants(self, tmp_path):
        sync = tmp_path / "sync"
        gen = DiversityGenerator(sync_dir=sync)
        count = await gen.generate_variants(protocol="crc32")
        assert count == len(_CRC32_VARIANTS)

    @pytest.mark.asyncio
    async def test_auto_protocol_dispatches(self, tmp_path):
        gen = DiversityGenerator(sync_dir=tmp_path / "sync")
        # No tags → crc32 path.
        count = await gen.generate_variants(protocol="auto")
        assert count == len(_CRC32_VARIANTS)

    @pytest.mark.asyncio
    async def test_every_written_modbus_frame_is_verifiable_on_disk(self, tmp_path):
        sync = tmp_path / "sync"
        gen = DiversityGenerator(sync_dir=sync)
        await gen.generate_variants(protocol="modbus_rtu")
        for f in sync.glob("agentic_diverse_*.bin"):
            data = f.read_bytes()
            assert struct.unpack("<H", data[-2:])[0] == crc16_modbus(data[:-2]), f.name
