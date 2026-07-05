"""
Quick validation of ConstraintProfiler against the three Phase 1 test wall outputs.
Run from the project root: python3 -m experiments.test_profiler
"""
import sys
sys.path.insert(0, ".")

from pathlib import Path
from datetime import datetime, timezone

from agentic_afl.constants import Architecture, ConstraintTag
from agentic_afl.models import PCodeInstruction, PCodeSlice
from agentic_afl.extractor.constraint_profiler import ConstraintProfiler


def make_slice(function_name, stall_address, instructions):
    """Helper to build a PCodeSlice from raw instruction data."""
    pcode_instructions = [
        PCodeInstruction(
            address=inst["address"],
            mnemonic=inst["mnemonic"],
            inputs=inst["inputs"],
            output=inst.get("output"),
            raw_pcode=inst.get("raw_pcode", ""),
            call_target=inst.get("call_target"),
        )
        for inst in instructions
    ]
    return PCodeSlice(
        binary_path=Path("./experiments/test_targets/math_wall_x86"),
        stall_address=stall_address,
        function_name=function_name,
        function_entry="0x0",
        instructions=pcode_instructions,
        taint_source="RDI",
        slice_depth=20,
        truncated=False,
        architecture=Architecture.X86_64,
    )


# === Wall 1: Magic Number (check_magic @ 0x1011b7) ===
wall1_instructions = [
    {
        "address": "0x1011ab",
        "mnemonic": "LOAD",
        "inputs": ["(const, 0x1b1, 4)", "(register, RDI, 8)"],
        "output": "(unique, 0x23b00@1011ab, 1)",
        "raw_pcode": "(unique, 0x23b00@1011ab, 1) = LOAD (const, 0x1b1, 4) (register, RDI, 8)",
    },
    {
        "address": "0x1011b1",
        "mnemonic": "LOAD",
        "inputs": ["(const, 0x1b1, 4)", "(unique, 0x8f00@1011b1, 8)"],
        "output": "(unique, 0x23b00@1011b1, 1)",
        "raw_pcode": "(unique, 0x23b00@1011b1, 1) = LOAD (const, 0x1b1, 4) (unique, 0x8f00@1011b1, 8)",
    },
    {
        "address": "0x1011b5",
        "mnemonic": "PIECE",
        "inputs": ["(unique, 0x23b00@1011ab, 1)", "(unique, 0x23b00@1011b1, 1)"],
        "output": "(register, AX@1011b5, 2)",
        "raw_pcode": "(register, AX@1011b5, 2) = PIECE (unique, 0x23b00@1011ab, 1) (unique, 0x23b00@1011b1, 1)",
    },
    {
        "address": "0x1011b7",
        "mnemonic": "INT_EQUAL",
        "inputs": ["(register, AX@1011b5, 2)", "(const, 0x5a01, 2)"],
        "output": "(register, ZF@1011b7, 1)",
        "raw_pcode": "(register, ZF@1011b7, 1) = INT_EQUAL (register, AX@1011b5, 2) (const, 0x5a01, 2)",
    },
]

# === Wall 2: CRC-16/Modbus (check_crc @ 0x101238) ===
wall2_instructions = [
    {
        "address": "0x101222",
        "mnemonic": "CALL",
        "inputs": ["(func, crc16_modbus, 0x1011c2)", "(register, RDI, 8)", "(unique, 0x8f00@10121e, 8)"],
        "output": "(register, AX@101222, 2)",
        "raw_pcode": "(register, AX@101222, 2) = CALL (func, crc16_modbus, 0x1011c2) (register, RDI, 8) (unique, 0x8f00@10121e, 8)",
        "call_target": "crc16_modbus",
    },
    {
        "address": "0x101229",
        "mnemonic": "LOAD",
        "inputs": ["(const, 0x1b1, 4)", "(unique, 0xa100@101229, 8)"],
        "output": "(unique, 0x23b00@101229, 1)",
        "raw_pcode": "(unique, 0x23b00@101229, 1) = LOAD (const, 0x1b1, 4) (unique, 0xa100@101229, 8)",
    },
    {
        "address": "0x101231",
        "mnemonic": "LOAD",
        "inputs": ["(const, 0x1b1, 4)", "(unique, 0xa100@101231, 8)"],
        "output": "(unique, 0x23b00@101231, 1)",
        "raw_pcode": "(unique, 0x23b00@101231, 1) = LOAD (const, 0x1b1, 4) (unique, 0xa100@101231, 8)",
    },
    {
        "address": "0x101236",
        "mnemonic": "PIECE",
        "inputs": ["(unique, 0x23b00@101229, 1)", "(unique, 0x23b00@101231, 1)"],
        "output": "(register, AX@101236, 2)",
        "raw_pcode": "(register, AX@101236, 2) = PIECE (unique, 0x23b00@101229, 1) (unique, 0x23b00@101231, 1)",
    },
    {
        "address": "0x101238",
        "mnemonic": "INT_EQUAL",
        "inputs": ["(register, AX@101236, 2)", "(register, AX@101222, 2)"],
        "output": "(register, ZF@101238, 1)",
        "raw_pcode": "(register, ZF@101238, 1) = INT_EQUAL (register, AX@101236, 2) (register, AX@101222, 2)",
    },
]

# === Wall 3: Range Check (check_function_code @ 0x101257) ===
wall3_instructions = [
    {
        "address": "0x101250",
        "mnemonic": "LOAD",
        "inputs": ["(const, 0x1b1, 4)", "(unique, 0x8f00@101250, 8)"],
        "output": "(unique, 0x23b00@101250, 1)",
        "raw_pcode": "(unique, 0x23b00@101250, 1) = LOAD (const, 0x1b1, 4) (unique, 0x8f00@101250, 8)",
    },
    {
        "address": "0x101250",
        "mnemonic": "CAST",
        "inputs": ["(unique, 0x10000010@101250, 8)"],
        "output": "(unique, 0x8f00@101250, 8)",
        "raw_pcode": "(unique, 0x8f00@101250, 8) = CAST (unique, 0x10000010@101250, 8)",
    },
    {
        "address": "0x101250",
        "mnemonic": "INT_ADD",
        "inputs": ["(register, RDI, 8)", "(const, 0x2, 8)"],
        "output": "(unique, 0x10000010@101250, 8)",
        "raw_pcode": "(unique, 0x10000010@101250, 8) = INT_ADD (register, RDI, 8) (const, 0x2, 8)",
    },
    {
        "address": "0x101254",
        "mnemonic": "INT_SUB",
        "inputs": ["(unique, 0x23b00@101250, 1)", "(const, 0x1, 1)"],
        "output": "(register, AL@101254, 1)",
        "raw_pcode": "(register, AL@101254, 1) = INT_SUB (unique, 0x23b00@101250, 1) (const, 0x1, 1)",
    },
    {
        "address": "0x101259",
        "mnemonic": "INT_LESS",
        "inputs": ["(unique, 0x10000018@101259, 1)", "(const, 0x6, 1)"],
        "output": "(unique, 0x25100@101259, 1)",
        "raw_pcode": "(unique, 0x25100@101259, 1) = INT_LESS (unique, 0x10000018@101259, 1) (const, 0x6, 1)",
    },
    {
        "address": "0x101259",
        "mnemonic": "CAST",
        "inputs": ["(register, AL@101254, 1)"],
        "output": "(unique, 0x10000018@101259, 1)",
        "raw_pcode": "(unique, 0x10000018@101259, 1) = CAST (register, AL@101254, 1)",
    },
]


def run_test(name, function_name, stall_address, instructions, expected_tags):
    """Run a single profiler test."""
    profiler = ConstraintProfiler()
    pcode_slice = make_slice(function_name, stall_address, instructions)
    profile = profiler.analyze(pcode_slice)

    actual_tag_names = {t.name for t in profile.tags}
    expected_tag_names = {t.name for t in expected_tags}

    passed = expected_tag_names.issubset(actual_tag_names)
    status = "PASS" if passed else "FAIL"

    print(f"\n{'='*60}")
    print(f"  {status}: {name}")
    print(f"{'='*60}")
    print(f"  Expected tags (subset): {expected_tag_names}")
    print(f"  Actual tags:            {actual_tag_names}")
    print(f"  Bitwise density:        {profile.bitwise_density}")
    print(f"  Arithmetic density:     {profile.arithmetic_density}")
    print(f"  Loop depth:             {profile.loop_depth}")
    print(f"  Register count:         {profile.register_count}")
    print(f"  Complexity score:       {profile.estimated_complexity}")

    if not passed:
        missing = expected_tag_names - actual_tag_names
        print(f"  MISSING TAGS: {missing}")

    return passed


if __name__ == "__main__":
    results = []

    results.append(run_test(
        "Wall 1: Magic Number (check_magic)",
        "check_magic", "0x1011b7",
        wall1_instructions,
        {ConstraintTag.CONSTANT_EQUALITY},
    ))

    results.append(run_test(
        "Wall 2: CRC-16/Modbus (check_crc)",
        "check_crc", "0x101238",
        wall2_instructions,
        {ConstraintTag.BITWISE_LOOP},
    ))

    results.append(run_test(
        "Wall 3: Range Check (check_function_code)",
        "check_function_code", "0x101257",
        wall3_instructions,
        {ConstraintTag.RANGE_BOUND},
    ))

    print(f"\n{'='*60}")
    print(f"  Results: {sum(results)}/{len(results)} passed")
    print(f"{'='*60}")

    sys.exit(0 if all(results) else 1)
