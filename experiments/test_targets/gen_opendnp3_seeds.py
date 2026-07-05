#!/usr/bin/env python3
"""
Generate DNP3 seed corpus with INTENTIONALLY CORRUPTED CRC-16 checksums.

Seeds have valid DNP3 frame structure (sync bytes, length, control, addresses,
transport/app layer data) but ALL CRC bytes are zeroed out. This ensures:

  1. AFL++ reaches the CRC validation code path (valid frame structure)
  2. AFL++ CANNOT pass the CRC wall (wrong checksums)
  3. Agentic-AFL must solve the CRC-16/DNP3 constraint symbolically

The CRC computation functions are retained for verification/debugging only.
"""

import struct
import os

# CRC-16/DNP3 lookup table (from OpenDNP3 CRC.cpp)
CRC_TABLE = [
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
]


def calc_crc(data: bytes) -> int:
    """Calculate CRC-16/DNP3 over data (for verification only)."""
    crc = 0
    for b in data:
        index = (crc ^ b) & 0xFF
        crc = CRC_TABLE[index] ^ (crc >> 8)
    return (~crc) & 0xFFFF


def build_header_broken_crc(length: int, ctrl: int, dest: int, src: int) -> bytearray:
    """Build a 10-byte DNP3 header with ZEROED CRC (invalid)."""
    header = bytearray([
        0x05, 0x64,              # Sync bytes
        length & 0xFF,           # LEN
        ctrl & 0xFF,             # CTRL
        dest & 0xFF,             # DEST low
        (dest >> 8) & 0xFF,      # DEST high
        src & 0xFF,              # SRC low
        (src >> 8) & 0xFF,       # SRC high
        0x00, 0x00,              # CRC = 0x0000 (INTENTIONALLY WRONG)
    ])
    return header


def build_frame_broken_crc(ctrl: int, dest: int, src: int,
                           user_data: bytes) -> bytearray:
    """Build a DNP3 frame with valid structure but ALL CRCs zeroed."""
    length = 5 + len(user_data)
    frame = build_header_broken_crc(length, ctrl, dest, src)

    # Split user data into 16-byte blocks, each with zeroed CRC
    offset = 0
    while offset < len(user_data):
        block_size = min(16, len(user_data) - offset)
        block = bytearray(user_data[offset:offset + block_size])
        block.extend([0x00, 0x00])  # Body block CRC = 0x0000 (WRONG)
        frame.extend(block)
        offset += block_size

    return frame


def main():
    seed_dir = os.path.join(os.path.dirname(__file__), "opendnp3_seeds")
    os.makedirs(seed_dir, exist_ok=True)

    # Clear old seeds
    for f in os.listdir(seed_dir):
        os.remove(os.path.join(seed_dir, f))

    OUTSTATION = 1
    MASTER = 3

    # ── Seed 1: RESET_LINK_STATES (header-only, no body) ──
    # CTRL: DIR=1, PRM=1, FCB=0, FCV=0, FC=0x00 → 0xC0
    frame = build_header_broken_crc(5, 0xC0, OUTSTATION, MASTER)
    path = os.path.join(seed_dir, "reset_link.bin")
    with open(path, "wb") as f:
        f.write(frame)
    correct_crc = calc_crc(bytes(frame[:8]))
    print(f"  {path}: {len(frame)}B  CRC=0x0000 (correct=0x{correct_crc:04X})")

    # ── Seed 2: REQUEST_LINK_STATUS (header-only) ──
    # CTRL: DIR=1, PRM=1, FC=0x09 → 0xC9
    frame = build_header_broken_crc(5, 0xC9, OUTSTATION, MASTER)
    path = os.path.join(seed_dir, "request_link_status.bin")
    with open(path, "wb") as f:
        f.write(frame)
    correct_crc = calc_crc(bytes(frame[:8]))
    print(f"  {path}: {len(frame)}B  CRC=0x0000 (correct=0x{correct_crc:04X})")

    # ── Seed 3: READ Class 0 (header + 1 data block) ──
    # CTRL: DIR=1, PRM=1, FC=0x04 → 0xC4
    transport_hdr = bytes([0xC0])
    app_data = bytes([0xC0, 0x01, 0x3C, 0x01, 0x06])
    user_data = transport_hdr + app_data
    frame = build_frame_broken_crc(0xC4, OUTSTATION, MASTER, user_data)
    path = os.path.join(seed_dir, "read_class0.bin")
    with open(path, "wb") as f:
        f.write(frame)
    correct_crc = calc_crc(bytes(frame[:8]))
    print(f"  {path}: {len(frame)}B  CRC=0x0000 (correct=0x{correct_crc:04X})")

    # ── Seed 4: DIRECT_OPERATE CROB (header + 2 data blocks) ──
    # CTRL: DIR=1, PRM=1, FCB=1, FCV=1, FC=0x03 → 0xF3
    transport_hdr = bytes([0xC0])
    app_data = bytes([
        0xC1, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x00,
        0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    user_data = transport_hdr + app_data
    frame = build_frame_broken_crc(0xF3, OUTSTATION, MASTER, user_data)
    path = os.path.join(seed_dir, "direct_operate.bin")
    with open(path, "wb") as f:
        f.write(frame)
    correct_crc = calc_crc(bytes(frame[:8]))
    print(f"  {path}: {len(frame)}B  CRC=0x0000 (correct=0x{correct_crc:04X})")

    print(f"\n✓ Generated 4 seeds in {seed_dir}")
    print("  All CRC bytes are 0x0000 (intentionally wrong).")
    print("  AFL++ will stall at the CRC wall; Agentic-AFL must solve it.")


if __name__ == "__main__":
    main()
