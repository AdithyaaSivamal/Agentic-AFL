#!/usr/bin/env python3
"""
gen_cfs_seeds.py — Generate AFL++ seed files for NASA cFS checksum fuzzing.

Generates CCSDS command packets with VALID primary header fields (version,
type, secondary header flag, APID, sequence, length) but INVALID checksum
bytes. This forces AFL++ to stall at CFE_MSG_ValidateChecksum() — the math
wall that the LLM must solve.

Usage:
    python gen_cfs_seeds.py [output_dir]
"""
import os
import struct
import sys
from pathlib import Path


def make_ccsds_cmd(apid: int, seq_count: int, func_code: int,
                   payload: bytes = b"", checksum: int = 0x00) -> bytes:
    """Build a CCSDS command packet with the specified fields.

    CCSDS Primary Header (6 bytes, big-endian):
      Byte 0: [Version(3)=000 | Type(1)=1 | SecHdrFlag(1)=1 | APID_hi(3)]
      Byte 1: [APID_lo(8)]
      Byte 2: [SeqFlags(2)=11 | SeqCount_hi(6)]
      Byte 3: [SeqCount_lo(8)]
      Byte 4-5: [PacketDataLength(16)] = len(secondary_hdr + payload) - 1

    Command Secondary Header (2 bytes):
      Byte 6: FunctionCode
      Byte 7: Checksum (intentionally wrong for seeds)
    """
    # StreamId: Version=0, Type=1(Cmd), SecHdr=1, APID
    stream_id = (0b000_1_1_000 << 8) | (apid & 0x7FF)
    # Fix high byte: version(3)=000, type(1)=1, sechdr(1)=1, apid_hi(3)
    byte0 = 0x18 | ((apid >> 8) & 0x07)
    byte1 = apid & 0xFF

    # Sequence: flags=11 (unsegmented), count
    byte2 = 0xC0 | ((seq_count >> 8) & 0x3F)
    byte3 = seq_count & 0xFF

    # Packet Data Length = secondary_hdr(2) + payload_len - 1
    pkt_data_len = 2 + len(payload) - 1
    byte4 = (pkt_data_len >> 8) & 0xFF
    byte5 = pkt_data_len & 0xFF

    # Assemble
    packet = bytearray([byte0, byte1, byte2, byte3, byte4, byte5,
                        func_code, checksum])
    packet.extend(payload)
    return bytes(packet)


def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "cfs_seeds"
    out_dir.mkdir(exist_ok=True)

    seeds = [
        # Seed 1: Minimal NOOP command (8 bytes, no payload)
        ("noop_cmd.bin", make_ccsds_cmd(
            apid=0x001, seq_count=0, func_code=0x00,
            payload=b"", checksum=0x00  # WRONG checksum
        )),

        # Seed 2: Reset counters command
        ("reset_cmd.bin", make_ccsds_cmd(
            apid=0x001, seq_count=1, func_code=0x01,
            payload=b"", checksum=0x00
        )),

        # Seed 3: Different APID (diagnostic subsystem)
        ("diag_cmd.bin", make_ccsds_cmd(
            apid=0x002, seq_count=0, func_code=0x03,
            payload=b"", checksum=0x00
        )),

        # Seed 4: Command with 4-byte payload (SET_PARAM)
        ("payload_cmd.bin", make_ccsds_cmd(
            apid=0x001, seq_count=2, func_code=0x02,
            payload=b"\x00\x00\x00\x42", checksum=0x00
        )),
    ]

    for name, data in seeds:
        path = out_dir / name
        path.write_bytes(data)

        # Verify: compute what checksum SHOULD be
        buf = bytearray(data)
        xor = 0xFF
        for b in buf:
            xor ^= b
        # The correct checksum byte would make total XOR == 0
        # Since we set checksum=0x00, the residual XOR tells us the correct value
        correct_cksum = xor  # This is what byte[7] should be
        print(f"  {name}: {len(data)} bytes, cksum=0x{data[7]:02X} "
              f"(correct=0x{correct_cksum:02X}), hex={data.hex()}")

    print(f"\n✓ Generated {len(seeds)} seeds in {out_dir}")
    print(f"  All seeds have VALID headers but WRONG checksums (0x00)")
    print(f"  AFL++ will stall at CFE_MSG_ValidateChecksum()")


if __name__ == "__main__":
    main()
