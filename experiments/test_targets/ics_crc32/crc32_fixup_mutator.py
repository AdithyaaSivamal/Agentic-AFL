"""
crc32_fixup_mutator.py — AFL++ Custom Mutator for CRC-32 Aware Fuzzing.

This mutator hooks into AFL++'s post-processing stage to recompute the
IEEE 802.3 CRC-32 checksum after every mutation. AFL++ mutates the payload
freely, and this mutator ensures the CRC is always valid — allowing the
fuzzer to explore past the CRC math wall indefinitely.

Architecture:
    AFL++ mutates seed → crc32_fixup_mutator recomputes CRC → valid frame
    is executed → new edges are discovered → AFL++ mutates again → ...

Frame format (ICS CRC-32):
    [SYNC(2)] [TYPE(1) SEQ(1) LEN(2)] [PAYLOAD(N)] [CRC32(4)]
    
    - SYNC: 0xA5, 0x5A (2 bytes, fixed)
    - Header: type, seq, payload_len (4 bytes)
    - Payload: variable length
    - CRC-32: IEEE 802.3 over (header + payload), 4 bytes LE

Usage:
    AFL_PYTHON_MODULE=crc32_fixup_mutator afl-fuzz -i seeds -o out -- ./harness @@

    Or set in env:
        export AFL_PYTHON_MODULE=crc32_fixup_mutator
        export PYTHONPATH=/path/to/this/dir

Notes:
    - This mutator ONLY fixes up the CRC. It does NOT generate mutations.
    - AFL++ handles all mutation logic; this mutator just ensures validity.
    - The mutator also enforces structural invariants:
      * SYNC bytes are always 0xA5, 0x5A
      * Payload length field matches actual payload size
      * Minimum frame size is 8 bytes (2 sync + 4 header + 0 payload + 4 CRC = 10)
"""
from __future__ import annotations

import struct
import zlib


# Minimum valid frame: 2 (sync) + 4 (header) + 0 (payload) + 4 (CRC) = 10
MIN_FRAME_SIZE = 10
SYNC = bytes([0xA5, 0x5A])
HEADER_SIZE = 4  # type(1) + seq(1) + payload_len(2)


def init(seed: int) -> None:
    """Called once when AFL++ loads the mutator."""
    pass


def deinit() -> None:
    """Called when AFL++ shuts down."""
    pass


def post_process(buf: bytearray) -> bytearray:
    """
    Fix up a mutated buffer to have a valid ICS CRC-32 frame structure.

    Called by AFL++ after every mutation, before the buffer is executed.
    This ensures that regardless of what AFL++ mutated, the CRC-32 is
    always valid and the frame passes the harness's gatekeeper.

    Strategy:
        1. Enforce sync bytes (0xA5, 0x5A).
        2. Clamp frame type to valid range (0x01-0x0C).
        3. Fix payload_len field to match actual remaining bytes.
        4. Recompute CRC-32 over (header + payload).
        5. Append correct CRC-32 as last 4 bytes.
    """
    buf = bytearray(buf)

    # Ensure minimum size.
    if len(buf) < MIN_FRAME_SIZE:
        # Pad to minimum size with zeros.
        buf.extend(b"\x00" * (MIN_FRAME_SIZE - len(buf)))

    # Fix sync bytes.
    buf[0] = 0xA5
    buf[1] = 0x5A

    # Clamp frame type to valid range 0x01-0x0C.
    if buf[2] < 0x01 or buf[2] > 0x0C:
        buf[2] = ((buf[2] - 1) % 0x0C) + 1  # Map to 1-12

    # Calculate payload length: total - sync(2) - header(4) - crc(4)
    payload_len = len(buf) - 2 - HEADER_SIZE - 4
    if payload_len < 0:
        payload_len = 0
        # Extend buffer to fit at least the CRC.
        buf.extend(b"\x00" * (MIN_FRAME_SIZE - len(buf)))
        payload_len = len(buf) - 2 - HEADER_SIZE - 4

    # Fix payload_len field (bytes 4-5, little-endian uint16).
    struct.pack_into("<H", buf, 4, payload_len)

    # Compute CRC-32 over header + payload (bytes 2 through -4).
    crc_region = bytes(buf[2:-4])
    crc = zlib.crc32(crc_region) & 0xFFFFFFFF

    # Write CRC-32 as last 4 bytes (little-endian).
    struct.pack_into("<I", buf, len(buf) - 4, crc)

    return buf
