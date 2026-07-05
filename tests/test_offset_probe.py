"""
test_offset_probe.py — Unit tests for the REDQUEEN-style GDB offset probe.

Covers a module that was at 0% coverage. offset_probe.py shells out to a
real `gdb` subprocess, so these tests monkeypatch
asyncio.create_subprocess_exec with a fake process that emits scripted
GDB stdout -- no real GDB, binary, or Ghidra needed. This exercises the
parsing/matching logic and the safe-fallback error paths (GDB missing,
timeout, breakpoint never hit, low-confidence match).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agentic_afl.extractor.offset_probe import discover_base_offset, extract_arg_memory


class FakeProcess:
    """Stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", hang: bool = False):
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.Event().wait()  # never resolves -> caller's wait_for fires
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return 0


def _patch_subprocess(monkeypatch, process: FakeProcess | Exception):
    async def _fake_create_subprocess_exec(*args, **kwargs):
        if isinstance(process, Exception):
            raise process
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)


# ═══════════════════════════════════════════════════════════════════════
#  discover_base_offset
# ═══════════════════════════════════════════════════════════════════════


class TestDiscoverBaseOffset:
    @pytest.mark.asyncio
    async def test_empty_seed_returns_zero_without_spawning_gdb(self, monkeypatch):
        calls = []
        async def _should_not_be_called(*a, **kw):
            calls.append(1)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", _should_not_be_called)

        offset = await discover_base_offset(Path("/bin/true"), b"", "0x1000")
        assert offset == 0
        assert calls == []

    @pytest.mark.asyncio
    async def test_gdb_not_found_returns_zero(self, monkeypatch):
        _patch_subprocess(monkeypatch, FileNotFoundError("gdb not found"))
        offset = await discover_base_offset(Path("/bin/true"), b"\x01\x02\x03\x04", "0x1000")
        assert offset == 0

    @pytest.mark.asyncio
    async def test_gdb_timeout_kills_process_and_returns_zero(self, monkeypatch):
        proc = FakeProcess(hang=True)
        _patch_subprocess(monkeypatch, proc)
        offset = await discover_base_offset(
            Path("/bin/true"), b"\x01\x02\x03\x04", "0x1000", timeout_seconds=0.05,
        )
        assert offset == 0
        assert proc.killed is True

    @pytest.mark.asyncio
    async def test_breakpoint_not_hit_returns_zero(self, monkeypatch):
        """No PROBE_REG/PROBE_MEM lines at all -- function never reached."""
        proc = FakeProcess(stdout=b"some unrelated gdb chatter\n")
        _patch_subprocess(monkeypatch, proc)
        offset = await discover_base_offset(Path("/bin/true"), b"\x01\x02\x03\x04\x05\x06\x07\x08", "0x1000")
        assert offset == 0

    @pytest.mark.asyncio
    async def test_matches_probe_memory_to_seed_offset(self, monkeypatch):
        """The function receives buf+6 -- probe memory should match seed[6:]."""
        seed = bytes(range(20))  # 0x00, 0x01, ..., 0x13
        probe_mem = seed[6:6 + 16]  # what the function's pointer sees
        stdout = (
            f"PROBE_REG=rdi\nPROBE_MEM={probe_mem.hex()}\n"
        ).encode()
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        offset = await discover_base_offset(Path("/bin/true"), seed, "0x1000", probe_bytes=16)
        assert offset == 6

    @pytest.mark.asyncio
    async def test_zero_offset_when_pointer_is_start_of_file(self, monkeypatch):
        seed = bytes(range(16))
        stdout = f"PROBE_REG=rdi\nPROBE_MEM={seed.hex()}\n".encode()
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        offset = await discover_base_offset(Path("/bin/true"), seed, "0x1000", probe_bytes=16)
        assert offset == 0

    @pytest.mark.asyncio
    async def test_picks_best_matching_register_among_several(self, monkeypatch):
        """RSI holds unrelated heap data; RDX matches the seed at offset 4."""
        seed = bytes(range(20))
        unrelated = bytes([0xAA] * 16)
        matching = seed[4:4 + 16]
        stdout = (
            f"PROBE_REG=rsi\nPROBE_MEM={unrelated.hex()}\n"
            f"PROBE_REG=rdx\nPROBE_MEM={matching.hex()}\n"
        ).encode()
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        offset = await discover_base_offset(Path("/bin/true"), seed, "0x1000", probe_bytes=16)
        assert offset == 4

    @pytest.mark.asyncio
    async def test_low_confidence_match_falls_back_to_zero(self, monkeypatch):
        """Probe memory doesn't appear in the seed at all -- no match."""
        seed = bytes(range(16))
        garbage = bytes([0xFF] * 16)
        stdout = f"PROBE_REG=rdi\nPROBE_MEM={garbage.hex()}\n".encode()
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        offset = await discover_base_offset(Path("/bin/true"), seed, "0x1000", probe_bytes=16)
        assert offset == 0

    @pytest.mark.asyncio
    async def test_probe_mem_none_is_ignored(self, monkeypatch):
        stdout = b"PROBE_REG=input\nPROBE_MEM=NONE\n"
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        offset = await discover_base_offset(Path("/bin/true"), b"\x01\x02\x03\x04", "0x1000")
        assert offset == 0

    @pytest.mark.asyncio
    async def test_probe_bytes_clamped_to_seed_length(self, monkeypatch):
        """A 3-byte seed with probe_bytes=16 requested must not crash --
        the implementation clamps probe_bytes down to len(seed)."""
        seed = b"\x01\x02\x03"
        stdout = f"PROBE_REG=rdi\nPROBE_MEM={seed.hex()}\n".encode()
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        # min_match_length = max(probe_bytes // 2, 4) after clamping probe_bytes
        # to 3 -> max(1, 4) = 4, which exceeds the 3-byte match -> falls back to 0.
        offset = await discover_base_offset(Path("/bin/true"), seed, "0x1000", probe_bytes=16)
        assert offset == 0

    @pytest.mark.asyncio
    async def test_generic_exception_returns_zero(self, monkeypatch):
        _patch_subprocess(monkeypatch, RuntimeError("unexpected gdb crash"))
        offset = await discover_base_offset(Path("/bin/true"), b"\x01\x02\x03\x04", "0x1000")
        assert offset == 0


# ═══════════════════════════════════════════════════════════════════════
#  extract_arg_memory
# ═══════════════════════════════════════════════════════════════════════


class TestExtractArgMemory:
    @pytest.mark.asyncio
    async def test_empty_seed_returns_empty_dict_without_spawning_gdb(self, monkeypatch):
        calls = []
        async def _should_not_be_called(*a, **kw):
            calls.append(1)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", _should_not_be_called)

        result = await extract_arg_memory(Path("/bin/true"), b"", "0x1000")
        assert result == {}
        assert calls == []

    @pytest.mark.asyncio
    async def test_gdb_not_found_returns_empty_dict(self, monkeypatch):
        _patch_subprocess(monkeypatch, FileNotFoundError("gdb not found"))
        result = await extract_arg_memory(Path("/bin/true"), b"\x01\x02", "0x1000")
        assert result == {}

    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_returns_empty_dict(self, monkeypatch):
        proc = FakeProcess(hang=True)
        _patch_subprocess(monkeypatch, proc)
        result = await extract_arg_memory(
            Path("/bin/true"), b"\x01\x02", "0x1000", timeout_seconds=0.05,
        )
        assert result == {}
        assert proc.killed is True

    @pytest.mark.asyncio
    async def test_parses_all_argument_fields(self, monkeypatch):
        stdout = (
            b"ARG_RDI_MEM=deadbeef\n"
            b"ARG_RDI_PTR=0x7fffdead0000\n"
            b"ARG_RSI_VAL=0x150\n"
            b"ARG_RDX_VAL=0x1\n"
            b"ARG_RCX_VAL=0x0\n"
        )
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        result = await extract_arg_memory(Path("/bin/true"), b"\x01\x02", "0x1000")
        assert result["rdi_hex"] == "deadbeef"
        assert result["rdi_ptr"] == "0x7fffdead0000"
        assert result["rsi_value"] == "0x150"
        assert result["rdx_value"] == "0x1"
        assert result["rcx_value"] == "0x0"

    @pytest.mark.asyncio
    async def test_failed_field_is_excluded_not_crashed(self, monkeypatch):
        """A FAIL: line for one register must not prevent parsing others."""
        stdout = (
            b"ARG_RDI_MEM=FAIL:Cannot access memory\n"
            b"ARG_RSI_VAL=0x150\n"
        )
        proc = FakeProcess(stdout=stdout)
        _patch_subprocess(monkeypatch, proc)

        result = await extract_arg_memory(Path("/bin/true"), b"\x01\x02", "0x1000")
        assert "rdi_hex" not in result
        assert result["rsi_value"] == "0x150"

    @pytest.mark.asyncio
    async def test_breakpoint_not_hit_returns_empty_dict(self, monkeypatch):
        proc = FakeProcess(stdout=b"unrelated gdb output\n")
        _patch_subprocess(monkeypatch, proc)

        result = await extract_arg_memory(Path("/bin/true"), b"\x01\x02", "0x1000")
        assert result == {}

    @pytest.mark.asyncio
    async def test_generic_exception_returns_empty_dict(self, monkeypatch):
        _patch_subprocess(monkeypatch, RuntimeError("unexpected gdb crash"))
        result = await extract_arg_memory(Path("/bin/true"), b"\x01\x02", "0x1000")
        assert result == {}
