"""
offset_probe.py — REDQUEEN-Style Input-to-State Offset Discovery.

Uses GDB to dynamically determine the base offset of a constraint
function's input pointer relative to the file buffer.

Problem:
    When a constraint function receives a pointer-with-offset (e.g.,
    ``transition_auth_challenge(buf + 6, len)``), the LLM sees
    ``input[2]..input[5]`` in the decompiled C and maps them to
    ``byte_2..byte_5`` of the file — but the actual file offsets are
    ``byte_8..byte_11``.

Solution:
    1. Run the original seed under GDB with a breakpoint at the stall
       function entry.
    2. When the breakpoint triggers, read the first argument (the input
       pointer) and dump N bytes of memory starting there.
    3. Search for that byte sequence in the original seed file.
    4. The match position is the base offset.

Implementation Notes:
    - Uses ``set follow-fork-mode child`` to handle AFL++ forkserver.
    - Reads the named ``input`` parameter (not ``$rdi``) because AFL's
      instrumentation prologue clobbers RDI before GDB stops.
    - Falls back to ``$rdi`` if ``input`` is not available (stripped binary).

References:
    - REDQUEEN: Fuzzing with Input-to-State Correspondence (NDSS 2019)
    - AFL++ CmpLog (similar I2S mapping via instrumented comparisons)

Usage:
    offset = await discover_base_offset(binary, seed, "0x402520", "transition_auth_challenge")
    # offset = 6  → input[0] corresponds to byte_6 of the file
"""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Default number of bytes to read from the function's input pointer.
# More bytes = more unique match, but must not exceed the actual buffer.
_DEFAULT_PROBE_BYTES = 16


async def discover_base_offset(
    binary: Path,
    seed: bytes,
    stall_address: str,
    function_name: str | None = None,
    probe_bytes: int = _DEFAULT_PROBE_BYTES,
    timeout_seconds: float = 15.0,
) -> int:
    """
    Discover the file offset where a function's input pointer starts.

    Runs the binary under GDB, breaks at the stall function, reads
    ``probe_bytes`` from the first argument (input pointer), and matches
    the memory contents against the seed to find the base offset.

    Args:
        binary:          Path to the binary (may be AFL-instrumented).
        seed:            The seed input bytes (same as the AFL seed file).
        stall_address:   Hex address of the stall function (e.g., "0x402520").
        function_name:   Symbol name (e.g., "transition_auth_challenge").
                         Used for breakpoint if available; falls back to address.
        probe_bytes:     Number of bytes to read from the input pointer.
        timeout_seconds: GDB execution timeout.

    Returns:
        Base offset (0 = function receives pointer to start of file).
        Returns 0 on any failure (safe fallback — matches current behavior).
    """
    if not seed:
        return 0

    # Clamp probe_bytes to seed length.
    probe_bytes = min(probe_bytes, len(seed))

    # Write seed to a temp file.
    seed_file = Path(tempfile.mktemp(suffix=".bin", prefix="offset_probe_"))
    seed_file.write_bytes(seed)

    # Determine breakpoint target: prefer function name over raw address.
    break_target = function_name if function_name else f"*{stall_address}"

    # Build GDB batch script.
    #
    # Multi-register buffer scanning: scan all x86-64 argument registers
    # (RDI, RSI, RDX, RCX, R8, R9) to find the one that points to memory
    # matching the seed file. This handles:
    #   - Static/inlined functions where RDI may not hold the buffer
    #   - Functions with signature (table, buf, len) where buf is in RSI
    #   - AFL instrumentation clobbering registers
    gdb_script_lines = [
        "set pagination off",
        "set confirm off",
        "set debuginfod enabled off",
        "set follow-fork-mode child",
        f"break {break_target}",
        f"run {seed_file}",
        # Embedded Python: scan all argument registers for buffer match.
        # Emit ALL readable register memories so the matching logic
        # downstream can pick the one that contains seed bytes.
        "python",
        "import gdb",
        "regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']",
        f"probe_n = {probe_bytes}",
        "found = False",
        "for reg in regs:",
        "    try:",
        "        addr = int(gdb.parse_and_eval('$' + reg))",
        "        if addr < 0x1000:",
        "            continue",
        "        mem = gdb.selected_inferior().read_memory(addr, probe_n)",
        "        hex_str = ''.join('%02x' % b for b in bytes(mem))",
        "        print('PROBE_REG=' + reg)",
        "        print('PROBE_MEM=' + hex_str)",
        "        found = True",
        "    except:",
        "        continue",
        "if not found:",
        "    try:",
        "        p = gdb.parse_and_eval('input')",
        "        addr = int(p)",
        "        mem = gdb.selected_inferior().read_memory(addr, probe_n)",
        "        hex_str = ''.join('%02x' % b for b in bytes(mem))",
        "        print('PROBE_REG=input')",
        "        print('PROBE_MEM=' + hex_str)",
        "    except:",
        "        print('PROBE_MEM=NONE')",
        "end",
        "quit",
    ]
    gdb_script_text = "\n".join(gdb_script_lines) + "\n"
    gdb_script = Path(tempfile.mktemp(suffix=".gdb", prefix="offset_probe_"))
    gdb_script.write_text(gdb_script_text)

    try:
        proc = await asyncio.create_subprocess_exec(
            "gdb", "--batch", "--nx", "-x", str(gdb_script), str(binary),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_raw, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning("Offset probe: GDB timed out after %.1fs", timeout_seconds)
            proc.kill()
            await proc.wait()
            return 0

        output = stdout_raw.decode("utf-8", errors="replace")

        # Parse all PROBE_REG/PROBE_MEM pairs from GDB output.
        # Each register that held a valid pointer emits one pair.
        probe_results: list[tuple[str, bytes]] = []
        current_reg = "unknown"
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("PROBE_REG="):
                current_reg = line.split("=", 1)[1]
            elif line.startswith("PROBE_MEM="):
                hex_str = line.split("=", 1)[1]
                if hex_str != "NONE" and all(c in "0123456789abcdefABCDEF" for c in hex_str):
                    probe_results.append((current_reg, bytes.fromhex(hex_str)))

        if not probe_results:
            logger.warning(
                "Offset probe: breakpoint not hit "
                "(function %s may not be reached by this seed)",
                function_name or stall_address,
            )
            return 0

        # Find the register whose memory best matches the seed.
        # Try each register's memory dump against the seed, preferring
        # the longest match.
        best_offset = 0
        best_match_len = 0
        best_reg = "none"
        min_match_length = max(probe_bytes // 2, 4)  # At least 4 bytes

        for reg, mem_bytes in probe_results:
            for length in range(len(mem_bytes), min_match_length - 1, -1):
                idx = seed.find(mem_bytes[:length])
                if idx >= 0 and length > best_match_len:
                    best_offset = idx
                    best_match_len = length
                    best_reg = reg
                    break  # Found best for this register

        if best_match_len >= min_match_length:
            logger.info(
                "Offset probe: input[0] = byte_%d of file "
                "(register=%s, matched %d/%d probe bytes)",
                best_offset, best_reg, best_match_len, probe_bytes,
            )
            return best_offset

        # No high-confidence match found.
        logger.warning(
            "Offset probe: low-confidence match (best %d/%d bytes from %d registers) — "
            "falling back to offset 0",
            best_match_len, probe_bytes, len(probe_results),
        )
        return 0

    except FileNotFoundError:
        logger.warning("Offset probe: GDB not found — falling back to offset 0")
        return 0
    except Exception as e:
        logger.warning("Offset probe failed: %s — falling back to offset 0", e)
        return 0
    finally:
        seed_file.unlink(missing_ok=True)
        gdb_script.unlink(missing_ok=True)


# Default number of bytes to dump from each argument pointer.
# 128 bytes: enough for most struct headers, shallow enough to avoid
# context pollution. LLMs excel at overlaying raw hex with C struct defs.
_ARG_DUMP_BYTES = 128


async def extract_arg_memory(
    binary: Path,
    seed: bytes,
    stall_address: str,
    function_name: str | None = None,
    dump_bytes: int = _ARG_DUMP_BYTES,
    timeout_seconds: float = 15.0,
) -> dict[str, str]:
    """
    Dump raw memory at function arguments (RDI, RSI) when the stall
    breakpoint is hit.

    Returns a flat hex view of the first ``dump_bytes`` bytes pointed to
    by each pointer argument. This exposes runtime struct state (e.g.,
    connection->receiveCount) without any struct-aware parsing.

    Args:
        binary:          Path to the binary (may be AFL-instrumented).
        seed:            The seed input bytes.
        stall_address:   Hex address of the stall function.
        function_name:   Symbol name for breakpoint (optional).
        dump_bytes:      Bytes to dump from each argument (default 128).
        timeout_seconds: GDB execution timeout.

    Returns:
        Dict mapping argument names to hex strings:
        {
            "rdi_hex": "31323733...",   # 128 bytes from *RDI
            "rsi_value": "0x1a2b",     # RSI as scalar value
        }
        Empty dict on failure (safe fallback).
    """
    if not seed:
        return {}

    seed_file = Path(tempfile.mktemp(suffix=".bin", prefix="argmem_"))
    seed_file.write_bytes(seed)

    break_target = function_name if function_name else f"*{stall_address}"

    # GDB script:
    # - Break at the stall function
    # - Dump RDI as pointer → first dump_bytes bytes of memory
    # - Dump RSI as scalar value (may be an int arg like seqNo)
    # - Also dump RDX, RCX for good measure (3rd, 4th args on x86-64)
    gdb_script_lines = [
        "set pagination off",
        "set confirm off",
        "set debuginfod enabled off",
        "set follow-fork-mode child",
        f"break {break_target}",
        f"run {seed_file}",
        # Dump RDI (first arg — usually struct pointer)
        "python",
        "import gdb",
        "try:",
        f"    rdi = int(gdb.parse_and_eval('$rdi'))",
        f"    inferior = gdb.selected_inferior()",
        f"    mem = inferior.read_memory(rdi, {dump_bytes})",
        f"    hex_str = ''.join('%02x' % b for b in bytes(mem))",
        f"    print('ARG_RDI_MEM=' + hex_str)",
        f"    print('ARG_RDI_PTR=0x%x' % rdi)",
        "except Exception as e:",
        "    print('ARG_RDI_MEM=FAIL:' + str(e))",
        "end",
        # Dump RSI (second arg — may be int or pointer)
        "python",
        "try:",
        f"    rsi = int(gdb.parse_and_eval('$rsi'))",
        f"    print('ARG_RSI_VAL=0x%x' % rsi)",
        f"    if rsi > 0x10000:",  # Likely a pointer
        f"        mem = gdb.selected_inferior().read_memory(rsi, {dump_bytes})",
        f"        hex_str = ''.join('%02x' % b for b in bytes(mem))",
        f"        print('ARG_RSI_MEM=' + hex_str)",
        "except Exception as e:",
        "    print('ARG_RSI_VAL=FAIL:' + str(e))",
        "end",
        # Dump RDX and RCX as scalars (3rd and 4th args)
        "python",
        "try:",
        "    rdx = int(gdb.parse_and_eval('$rdx'))",
        "    rcx = int(gdb.parse_and_eval('$rcx'))",
        "    print('ARG_RDX_VAL=0x%x' % rdx)",
        "    print('ARG_RCX_VAL=0x%x' % rcx)",
        "except:",
        "    pass",
        "end",
        "quit",
    ]
    gdb_script_text = "\n".join(gdb_script_lines) + "\n"
    gdb_script = Path(tempfile.mktemp(suffix=".gdb", prefix="argmem_"))
    gdb_script.write_text(gdb_script_text)

    result: dict[str, str] = {}

    try:
        proc = await asyncio.create_subprocess_exec(
            "gdb", "--batch", "--nx", "-x", str(gdb_script), str(binary),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_raw, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning("Arg memory probe: GDB timed out after %.1fs", timeout_seconds)
            proc.kill()
            await proc.wait()
            return {}

        output = stdout_raw.decode("utf-8", errors="replace")

        # Parse all ARG_* lines from GDB output.
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("ARG_RDI_MEM=") and "FAIL" not in line:
                result["rdi_hex"] = line.split("=", 1)[1]
            elif line.startswith("ARG_RDI_PTR="):
                result["rdi_ptr"] = line.split("=", 1)[1]
            elif line.startswith("ARG_RSI_VAL=") and "FAIL" not in line:
                result["rsi_value"] = line.split("=", 1)[1]
            elif line.startswith("ARG_RSI_MEM="):
                result["rsi_hex"] = line.split("=", 1)[1]
            elif line.startswith("ARG_RDX_VAL="):
                result["rdx_value"] = line.split("=", 1)[1]
            elif line.startswith("ARG_RCX_VAL="):
                result["rcx_value"] = line.split("=", 1)[1]

        if result:
            rdi_preview = result.get("rdi_hex", "N/A")[:32]
            logger.info(
                "Arg memory probe: RDI→%s... RSI=%s RDX=%s",
                rdi_preview,
                result.get("rsi_value", "N/A"),
                result.get("rdx_value", "N/A"),
            )
        else:
            logger.warning(
                "Arg memory probe: breakpoint not hit "
                "(function %s may not be reached by this seed)",
                function_name or stall_address,
            )

    except FileNotFoundError:
        logger.warning("Arg memory probe: GDB not found")
    except Exception as e:
        logger.warning("Arg memory probe failed: %s", e)
    finally:
        seed_file.unlink(missing_ok=True)
        gdb_script.unlink(missing_ok=True)

    return result
