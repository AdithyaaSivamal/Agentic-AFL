"""
diversity_generator.py — Post-bypass diverse payload injection.

After the agent solves a CRC/checksum constraint, this module generates
structurally diverse payloads with correct checksums and injects them
into AFL++'s sync directory.

Supports:
    - CRC-16 Modbus RTU (polynomial 0xA001, init 0xFFFF)
    - CRC-32 IEEE 802.3 (via zlib.crc32)

The generator auto-detects the correct protocol from the constraint
profile or can be told explicitly via the `protocol` parameter.

Usage:
    gen = DiversityGenerator(sync_dir=Path("./afl_output/agentic/queue"))
    count = await gen.generate_variants(protocol="modbus_rtu")
"""
from __future__ import annotations

import logging
import struct
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


# ── CRC Functions ────────────────────────────────────────────────────

def crc16_modbus(data: bytes) -> int:
    """
    Compute CRC-16/Modbus.

    Polynomial: 0xA001 (reversed 0x8005), Init: 0xFFFF, Final XOR: 0x0000.
    The result is returned as a 16-bit integer (low byte first in the frame).
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def _make_modbus_rtu_frame(slave: int, func: int, payload: bytes) -> bytes:
    """
    Build a Modbus RTU frame with valid CRC-16.

    Frame format: [SLAVE(1)] [FUNC(1)] [DATA(N)] [CRC16_LO(1)] [CRC16_HI(1)]
    """
    pdu = bytes([slave, func]) + payload
    crc = crc16_modbus(pdu)
    return pdu + struct.pack("<H", crc)


def _make_ics_frame(frame_type: int, seq: int, payload: bytes) -> bytes:
    """
    Build a CRC-32 ICS frame (legacy format).

    Frame format: [SYNC(2)] [HEADER(4)] [PAYLOAD(N)] [CRC32(4)]
    """
    sync = bytes([0xA5, 0x5A])
    header = bytes([frame_type, seq]) + struct.pack("<H", len(payload))
    crc_data = header + payload
    crc = zlib.crc32(crc_data) & 0xFFFFFFFF
    return sync + crc_data + struct.pack("<I", crc)


# ── Modbus RTU Frame Variants ────────────────────────────────────────

_MODBUS_VARIANTS: list[dict] = [
    # Read Coils (FC 0x01)
    {"name": "read_coils", "slave": 0x01, "func": 0x01,
     "payload": bytes([0x00, 0x00, 0x00, 0x08])},
    # Read Discrete Inputs (FC 0x02)
    {"name": "read_discrete", "slave": 0x01, "func": 0x02,
     "payload": bytes([0x00, 0x00, 0x00, 0x10])},
    # Read Holding Registers (FC 0x03)
    {"name": "read_holding", "slave": 0x01, "func": 0x03,
     "payload": bytes([0x00, 0x00, 0x00, 0x0A])},
    # Read Input Registers (FC 0x04)
    {"name": "read_input_reg", "slave": 0x01, "func": 0x04,
     "payload": bytes([0x00, 0x00, 0x00, 0x04])},
    # Write Single Coil (FC 0x05) — ON
    {"name": "write_coil_on", "slave": 0x01, "func": 0x05,
     "payload": bytes([0x00, 0x10, 0xFF, 0x00])},
    # Write Single Coil (FC 0x05) — OFF
    {"name": "write_coil_off", "slave": 0x01, "func": 0x05,
     "payload": bytes([0x00, 0x10, 0x00, 0x00])},
    # Write Single Register (FC 0x06)
    {"name": "write_single_reg", "slave": 0x01, "func": 0x06,
     "payload": bytes([0x00, 0x01, 0x00, 0x03])},
    # Write Multiple Coils (FC 0x0F)
    {"name": "write_multi_coils", "slave": 0x01, "func": 0x0F,
     "payload": bytes([0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01])},
    # Write Multiple Registers (FC 0x10)
    {"name": "write_multi_regs", "slave": 0x01, "func": 0x10,
     "payload": bytes([0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02])},
    # Diagnostics — Return Query Data (FC 0x08, sub 0x0000)
    {"name": "diag_query", "slave": 0x01, "func": 0x08,
     "payload": bytes([0x00, 0x00, 0xA5, 0x37])},
    # Diagnostics — Restart Communications (FC 0x08, sub 0x0001)
    {"name": "diag_restart", "slave": 0x01, "func": 0x08,
     "payload": bytes([0x00, 0x01, 0x00, 0x00])},
    # Read Exception Status (FC 0x07)
    {"name": "read_exception", "slave": 0x01, "func": 0x07,
     "payload": bytes([])},
    # Report Server ID (FC 0x11)
    {"name": "report_server_id", "slave": 0x01, "func": 0x11,
     "payload": bytes([])},
    # Different slave addresses
    {"name": "slave_2_read", "slave": 0x02, "func": 0x03,
     "payload": bytes([0x00, 0x00, 0x00, 0x01])},
    {"name": "slave_ff_read", "slave": 0xFF, "func": 0x03,
     "payload": bytes([0x00, 0x00, 0x00, 0x01])},
    # Broadcast (slave 0x00)
    {"name": "broadcast_write", "slave": 0x00, "func": 0x06,
     "payload": bytes([0x00, 0x01, 0x00, 0x01])},
    # Read Holding with max register count
    {"name": "read_holding_max", "slave": 0x01, "func": 0x03,
     "payload": bytes([0x00, 0x00, 0x00, 0x7D])},
    # Write to high address range
    {"name": "write_high_addr", "slave": 0x01, "func": 0x06,
     "payload": bytes([0xFF, 0xFF, 0x00, 0x01])},
]

# ── CRC-32 ICS Frame Variants (legacy, from original generator) ──────

_CRC32_VARIANTS: list[dict] = [
    {"name": "pd_read_coils", "type": 0x01,
     "payload": bytes([0x01, 0x00, 0x00, 0x05, 0x00])},
    {"name": "pd_read_hold", "type": 0x01,
     "payload": bytes([0x03, 0x00, 0x00, 0x0A, 0x00])},
    {"name": "pd_write_coil", "type": 0x01,
     "payload": bytes([0x05, 0x00, 0x10, 0xFF, 0x00])},
    {"name": "param_comm", "type": 0x02,
     "payload": bytes([0x01, 0x03, 0x00])},
    {"name": "diag_status", "type": 0x05,
     "payload": bytes([0x01])},
    {"name": "diag_reset", "type": 0x05,
     "payload": bytes([0x02])},
    {"name": "safety_hb", "type": 0x06,
     "payload": bytes([0x01, 0x03])},
    {"name": "config_nodeid", "type": 0x0A,
     "payload": bytes([0x01, 0x05])},
    {"name": "net_discover", "type": 0x0B,
     "payload": bytes([0x01, 0x05])},
    {"name": "profile_vendor", "type": 0x0C,
     "payload": bytes([0x01])},
]


class DiversityGenerator:
    """
    Generate diverse valid-CRC payloads for protocol frame variants.

    Supports auto-detection from constraint tags:
        - BITWISE_LOOP + polynomial 0xA001 → Modbus CRC-16
        - Default / explicit → CRC-32 ICS frames
    """

    def __init__(self, sync_dir: Path) -> None:
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)

    async def generate_variants(
        self,
        stall_address: str = "0x00000000",
        protocol: str = "auto",
        constraint_tags: set[str] | None = None,
        decompiled_c: str | None = None,
    ) -> int:
        """
        Generate and inject protocol-appropriate frame variants.

        Args:
            stall_address: Address of the solved stall (for logging).
            protocol: "modbus_rtu", "crc32", or "auto" (detect from tags + C).
            constraint_tags: Tag names from the constraint profiler.
            decompiled_c: Ghidra decompiled C (for polynomial detection).

        Returns:
            Number of payloads injected.
        """
        if protocol == "auto":
            protocol = self._detect_protocol(constraint_tags, decompiled_c)

        if protocol == "modbus_rtu":
            return await self._generate_modbus_rtu(stall_address)
        else:
            return await self._generate_crc32(stall_address)

    def _detect_protocol(
        self,
        tags: set[str] | None,
        decompiled_c: str | None = None,
    ) -> str:
        """
        Detect protocol from constraint profiler tags and decompiled C.

        Uses polynomial constants in the decompiled C to positively
        identify the CRC variant, rather than guessing from tags alone.
        """
        if not tags:
            return "crc32"

        # If we have decompiled C, use polynomial detection (most reliable).
        if decompiled_c and "BITWISE_LOOP" in tags:
            from agentic_afl.orchestrator.prompts.z3_translation import detect_crc_variant
            variant = detect_crc_variant(decompiled_c)
            if variant and variant.startswith("crc16_modbus"):
                return "modbus_rtu"
            # For other CRC-16 variants or CRC-32, fall through to CRC-32.

        return "crc32"

    async def _generate_modbus_rtu(self, stall_address: str) -> int:
        """Generate Modbus RTU frame variants with valid CRC-16."""
        count = 0
        for variant in _MODBUS_VARIANTS:
            frame = _make_modbus_rtu_frame(
                variant["slave"], variant["func"], variant["payload"],
            )

            # Verify CRC before injection.
            crc_data = frame[:-2]
            stored_crc = struct.unpack("<H", frame[-2:])[0]
            computed_crc = crc16_modbus(crc_data)
            if stored_crc != computed_crc:
                logger.error(
                    "CRC-16 mismatch in %s: stored=0x%04X computed=0x%04X",
                    variant["name"], stored_crc, computed_crc,
                )
                continue

            self._write_payload(variant["name"], frame)
            count += 1
            logger.debug(
                "Diverse payload: %s (FC=0x%02X, %d bytes, CRC=0x%04X)",
                variant["name"], variant["func"], len(frame), computed_crc,
            )

        logger.info(
            "Diverse payload injection: %d/%d Modbus RTU variants with valid CRC-16",
            count, len(_MODBUS_VARIANTS),
        )
        return count

    async def _generate_crc32(self, stall_address: str) -> int:
        """Generate CRC-32 ICS frame variants (legacy)."""
        count = 0
        for i, variant in enumerate(_CRC32_VARIANTS):
            seq = (i + 1) & 0xFF
            frame = _make_ics_frame(variant["type"], seq, variant["payload"])

            # Verify CRC before injection.
            crc_data = frame[2:-4]
            stored_crc = struct.unpack("<I", frame[-4:])[0]
            computed_crc = zlib.crc32(crc_data) & 0xFFFFFFFF
            if stored_crc != computed_crc:
                logger.error(
                    "CRC-32 mismatch in %s: stored=0x%08X computed=0x%08X",
                    variant["name"], stored_crc, computed_crc,
                )
                continue

            self._write_payload(variant["name"], frame)
            count += 1
            logger.debug(
                "Diverse payload: %s (type=0x%02X, %d bytes, CRC=0x%08X)",
                variant["name"], variant["type"], len(frame), computed_crc,
            )

        logger.info(
            "Diverse payload injection: %d/%d CRC-32 variants",
            count, len(_CRC32_VARIANTS),
        )
        return count

    # Legacy API compat
    async def generate_ics_crc32_variants(self, **kwargs) -> int:
        """Legacy API — redirects to generate_variants(protocol='crc32')."""
        return await self.generate_variants(protocol="crc32", **kwargs)

    def _write_payload(self, name: str, data: bytes) -> Path:
        """Atomically write a payload file to the sync directory."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"agentic_diverse_{name}_{ts}.bin"
        final_path = self.sync_dir / filename

        fd = tempfile.NamedTemporaryFile(
            dir=self.sync_dir, delete=False,
            suffix=".tmp", prefix="div_",
        )
        try:
            fd.write(data)
            fd.flush()
            tmp_path = Path(fd.name)
        finally:
            fd.close()
        tmp_path.rename(final_path)
        return final_path
