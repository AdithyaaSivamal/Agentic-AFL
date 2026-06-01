"""
diversity_generator.py — Post-bypass diverse payload injection.

After the agent solves a CRC/checksum constraint, this module generates
structurally diverse payloads (one per protocol frame type) with correct
checksums and injects them into AFL++'s sync directory.

This enables massive coverage spikes: instead of AFL++ exploring from
one valid frame type, it gets seed frames covering all 12 handlers,
multiplying the reachable edge count.

Architecture:
    1. Agent solves CRC-32 → first payload injected → FULL ACCEPT confirmed.
    2. Agent calls diversity_generator with the solved constraint metadata.
    3. Generator creates valid frames for all frame types using zlib.crc32.
    4. Each frame is atomically written to the sync dir for AFL++ pickup.

Usage:
    from agentic_afl.fuzzer_bridge.diversity_generator import DiversityGenerator

    gen = DiversityGenerator(sync_dir=Path("./afl_output/agentic/queue"))
    count = await gen.generate_ics_crc32_variants()
"""
from __future__ import annotations

import logging
import struct
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _make_ics_frame(frame_type: int, seq: int, payload: bytes) -> bytes:
    """
    Build a complete ICS CRC-32 frame with valid checksum.

    Frame format: [SYNC(2)] [HEADER(4)] [PAYLOAD(N)] [CRC32(4)]
      - SYNC: 0xA5 0x5A
      - HEADER: type(1) seq(1) payload_len(2 LE)
      - CRC32: IEEE 802.3 over HEADER+PAYLOAD
    """
    sync = bytes([0xA5, 0x5A])
    header = bytes([frame_type, seq]) + struct.pack("<H", len(payload))
    crc_data = header + payload
    crc = zlib.crc32(crc_data) & 0xFFFFFFFF
    return sync + crc_data + struct.pack("<I", crc)


# ── Frame type definitions (mirrors protocol.h) ──────────────────────

_FRAME_VARIANTS: list[dict] = [
    # Process Data — read coils
    {"name": "pd_read_coils", "type": 0x01,
     "payload": bytes([0x01, 0x00, 0x00, 0x05, 0x00])},
    # Process Data — read holding registers
    {"name": "pd_read_hold", "type": 0x01,
     "payload": bytes([0x03, 0x00, 0x00, 0x0A, 0x00])},
    # Process Data — write single coil
    {"name": "pd_write_coil", "type": 0x01,
     "payload": bytes([0x05, 0x00, 0x10, 0xFF, 0x00])},
    # Process Data — read input registers
    {"name": "pd_read_input", "type": 0x01,
     "payload": bytes([0x04, 0x00, 0x00, 0x08, 0x00])},
    # Parameter Read — comm group
    {"name": "param_comm", "type": 0x02,
     "payload": bytes([0x01, 0x03, 0x00])},
    # Parameter Read — timing group
    {"name": "param_timing", "type": 0x02,
     "payload": bytes([0x02, 0x01, 0x00])},
    # Parameter Read — network group
    {"name": "param_net", "type": 0x02,
     "payload": bytes([0x03, 0x01, 0x00])},
    # Parameter Write
    {"name": "param_write", "type": 0x03,
     "payload": bytes([0x01, 0x01, 0x00, 0xE8, 0x03])},
    # Alarm — warning
    {"name": "alarm_warn", "type": 0x04,
     "payload": bytes([0x02, 0x42, 0x00, 0x01, 0x10, 0x00])},
    # Alarm — critical with timestamp
    {"name": "alarm_crit", "type": 0x04,
     "payload": bytes([0x03, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12])},
    # Alarm — info
    {"name": "alarm_info", "type": 0x04,
     "payload": bytes([0x01, 0x10, 0x00, 0x01])},
    # Diagnostics — status request
    {"name": "diag_status", "type": 0x05,
     "payload": bytes([0x01])},
    # Diagnostics — reset counters
    {"name": "diag_reset", "type": 0x05,
     "payload": bytes([0x02])},
    # Diagnostics — identification
    {"name": "diag_ident", "type": 0x05,
     "payload": bytes([0x03])},
    # Diagnostics — trace capture
    {"name": "diag_trace", "type": 0x05,
     "payload": bytes([0x04, 0x80, 0x00, 0xE8, 0x03])},
    # Safety — heartbeat SIL3
    {"name": "safety_hb_sil3", "type": 0x06,
     "payload": bytes([0x01, 0x03])},
    # Safety — heartbeat SIL2
    {"name": "safety_hb_sil2", "type": 0x06,
     "payload": bytes([0x01, 0x02])},
    # Safety — watchdog config
    {"name": "safety_wdog", "type": 0x06,
     "payload": bytes([0x02, 0x02, 0xE8, 0x03])},
    # Safety — emergency stop
    {"name": "safety_estop", "type": 0x06,
     "payload": bytes([0x03])},
    # Firmware — start (will fail auth check but explores branches)
    {"name": "fw_start", "type": 0x07,
     "payload": bytes([0x01, 0x00, 0x10, 0x00, 0x00, 0x00])},
    # Firmware — data chunk
    {"name": "fw_data", "type": 0x07,
     "payload": bytes([0x02, 0x00, 0x00] + list(range(16)))},
    # Time Sync — valid nsec
    {"name": "time_sync_valid", "type": 0x08,
     "payload": struct.pack("<II", 0x12345678, 500000000) + bytes([0x03, 0x00, 0x00])},
    # Time Sync — UTC source
    {"name": "time_sync_utc", "type": 0x08,
     "payload": struct.pack("<II", 0x12345678, 100000000) + bytes([0x01, 0x00, 0x00])},
    # Auth — token request
    {"name": "auth_token", "type": 0x09,
     "payload": bytes([0x01, 0x02, 0x03, 0x04])},
    # Auth — challenge response
    {"name": "auth_challenge", "type": 0x09,
     "payload": struct.pack("<I", 0xDEADBEEF) + struct.pack("<I", 0xCAFEBABE)},
    # Config — set node ID
    {"name": "config_nodeid", "type": 0x0A,
     "payload": bytes([0x01, 0x05])},
    # Config — set watchdog
    {"name": "config_wdog", "type": 0x0A,
     "payload": bytes([0x02, 0xE8, 0x03])},
    # Network — discover
    {"name": "net_discover", "type": 0x0B,
     "payload": bytes([0x01, 0x05])},
    # Network — ping
    {"name": "net_ping", "type": 0x0B,
     "payload": bytes([0x02, 0x0A, 0xE8, 0x03])},
    # Network — topology
    {"name": "net_topo", "type": 0x0B,
     "payload": bytes([0x03])},
    # Profile — vendor
    {"name": "profile_vendor", "type": 0x0C,
     "payload": bytes([0x01])},
    # Profile — model
    {"name": "profile_model", "type": 0x0C,
     "payload": bytes([0x02])},
    # Profile — firmware version
    {"name": "profile_fwver", "type": 0x0C,
     "payload": bytes([0x03])},
    # Profile — serial
    {"name": "profile_serial", "type": 0x0C,
     "payload": bytes([0x04])},
    # Profile — capabilities
    {"name": "profile_caps", "type": 0x0C,
     "payload": bytes([0x05])},
]


class DiversityGenerator:
    """
    Generate diverse valid-CRC payloads for all ICS frame types.

    After the agent solves the CRC-32 constraint for one frame type,
    this generator creates valid frames for ALL types and injects them
    into the AFL++ sync directory. This enables AFL++ to explore the
    entire post-CRC state machine instead of just one handler.
    """

    def __init__(self, sync_dir: Path) -> None:
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)

    async def generate_ics_crc32_variants(
        self,
        stall_address: str = "0x0000000000002bc0",
        spec_id: str = "diversity",
    ) -> int:
        """
        Generate and inject all ICS CRC-32 frame variants.

        Returns:
            Number of payloads injected.
        """
        count = 0
        for i, variant in enumerate(_FRAME_VARIANTS):
            seq = (i + 1) & 0xFF
            frame = _make_ics_frame(variant["type"], seq, variant["payload"])

            # Verify CRC before injection (paranoia check).
            sync = frame[:2]
            crc_data = frame[2:-4]
            stored_crc = struct.unpack("<I", frame[-4:])[0]
            computed_crc = zlib.crc32(crc_data) & 0xFFFFFFFF
            if stored_crc != computed_crc:
                logger.error(
                    "CRC mismatch in %s: stored=0x%08X computed=0x%08X",
                    variant["name"], stored_crc, computed_crc,
                )
                continue

            # Write atomically to sync dir.
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"agentic_diverse_{variant['name']}_{ts}.bin"
            final_path = self.sync_dir / filename

            fd = tempfile.NamedTemporaryFile(
                dir=self.sync_dir, delete=False,
                suffix=".tmp", prefix="div_",
            )
            try:
                fd.write(frame)
                fd.flush()
                tmp_path = Path(fd.name)
            finally:
                fd.close()
            tmp_path.rename(final_path)

            count += 1
            logger.debug(
                "Diverse payload: %s (type=0x%02X, %d bytes, CRC=0x%08X)",
                variant["name"], variant["type"], len(frame), computed_crc,
            )

        logger.info(
            "Diverse payload injection: %d/%d variants with valid CRC-32",
            count, len(_FRAME_VARIANTS),
        )
        return count
