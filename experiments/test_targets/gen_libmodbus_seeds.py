#!/usr/bin/env python3
"""
gen_libmodbus_seeds.py — Generate Modbus RTU seed files for AFL++ fuzzing.

Creates seed files that are structurally valid Modbus RTU frames but with
WRONG CRC values. This gives AFL++ the right frame structure without
giving away the CRC solution.

Modbus RTU frame format:
    [slave_addr(1)] [function_code(1)] [data(N)] [CRC_lo(1)] [CRC_hi(1)]

CRC-16/Modbus algorithm:
    - Polynomial: 0xA001 (reflected)
    - Init: 0xFFFF
    - CRC is little-endian (low byte first)
"""
import struct
from pathlib import Path


def modbus_crc16(data: bytes) -> int:
    """Compute CRC-16/Modbus (matching libmodbus table-driven result)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def make_seed(name: str, payload: bytes, wrong_crc: bool = True) -> tuple[str, bytes]:
    """Create a Modbus RTU frame with correct or wrong CRC."""
    crc = modbus_crc16(payload)
    if wrong_crc:
        # Flip some bits in CRC to make it wrong
        crc ^= 0xDEAD
    # CRC is little-endian: low byte first
    frame = payload + struct.pack("<H", crc)
    return name, frame


def main():
    seed_dir = Path(__file__).parent / "libmodbus_seeds"
    seed_dir.mkdir(exist_ok=True)

    seeds = []

    # ── Read Holding Registers (FC 03) ──────────────────────────────
    # Slave=1, FC=03, Start=0x0000, Qty=0x000A
    seeds.append(make_seed(
        "read_holding_regs.bin",
        bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]),
    ))

    # ── Write Single Register (FC 06) ──────────────────────────────
    # Slave=1, FC=06, Addr=0x0001, Value=0x0003
    seeds.append(make_seed(
        "write_single_reg.bin",
        bytes([0x01, 0x06, 0x00, 0x01, 0x00, 0x03]),
    ))

    # ── Read Coils (FC 01) ─────────────────────────────────────────
    # Slave=2, FC=01, Start=0x0000, Qty=0x0008
    seeds.append(make_seed(
        "read_coils.bin",
        bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x08]),
    ))

    # ── Write Multiple Registers (FC 16) ───────────────────────────
    # Slave=1, FC=16, Start=0x0000, Qty=0x0002, ByteCount=4, Data...
    seeds.append(make_seed(
        "write_multi_regs.bin",
        bytes([0x01, 0x10, 0x00, 0x00, 0x00, 0x02, 0x04,
               0x00, 0x0A, 0x01, 0x02]),
    ))

    # ── Near-miss: correct CRC with 1 bit flipped ─────────────────
    # This seed has almost-correct CRC to help AFL++ discover the
    # gradient toward the solution.
    payload = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    correct_crc = modbus_crc16(payload)
    near_miss_crc = correct_crc ^ 0x0001  # Single bit flip
    frame = payload + struct.pack("<H", near_miss_crc)
    seeds.append(("near_miss_crc.bin", frame))

    for name, data in seeds:
        (seed_dir / name).write_bytes(data)
        crc_in_frame = struct.unpack("<H", data[-2:])[0]
        correct = modbus_crc16(data[:-2])
        status = "✓ VALID" if crc_in_frame == correct else "✗ WRONG"
        print(f"  {name:30s}  {len(data):3d} bytes  "
              f"CRC={crc_in_frame:04X} (correct={correct:04X})  {status}")

    print(f"\nGenerated {len(seeds)} seeds in {seed_dir}")


if __name__ == "__main__":
    main()
