"""
test_pcode_slicer.py — Unit tests for the Ghidra P-Code extraction bridge.

Covers the gap identified in the health review: pcode_slicer.py had 0%
test coverage prior to this file. These tests exercise the JSON
parsing/post-processing contract and error paths WITHOUT invoking
Ghidra itself (subprocess.run is monkeypatched), so they run in
milliseconds and need no external tooling.

Live end-to-end validation against real Ghidra headless is covered
separately by experiments/integration/test_live_ghidra.py.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agentic_afl.constants import Architecture
from agentic_afl.extractor.pcode_slicer import PCodeSlicer, PCodeSlicerError
from agentic_afl.models import PCodeInstruction


def _inst(address: str, mnemonic: str, inputs: list[str], output: str | None, call_target=None) -> PCodeInstruction:
    return PCodeInstruction(
        address=address,
        mnemonic=mnemonic,
        inputs=inputs,
        output=output,
        raw_pcode=f"{output} = {mnemonic} {' '.join(inputs)}" if output else f"{mnemonic} {' '.join(inputs)}",
        call_target=call_target,
    )


# ═══════════════════════════════════════════════════════════════════════
#  _parse_pcode_json
# ═══════════════════════════════════════════════════════════════════════


class TestParsePcodeJson:
    def test_parses_well_formed_instructions(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        raw = {
            "instructions": [
                {
                    "address": "0x1000",
                    "mnemonic": "INT_EQUAL",
                    "inputs": ["(register, AX, 2)", "(const, 0x5a01, 2)"],
                    "output": "(register, ZF, 1)",
                    "raw_pcode": "ZF = INT_EQUAL AX 0x5a01",
                    "call_target": None,
                }
            ]
        }
        instructions = slicer._parse_pcode_json(raw)
        assert len(instructions) == 1
        assert instructions[0].mnemonic == "INT_EQUAL"
        assert instructions[0].address == "0x1000"

    def test_empty_instructions_returns_empty_list(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        assert slicer._parse_pcode_json({"instructions": []}) == []

    def test_missing_instructions_key_returns_empty_list(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        assert slicer._parse_pcode_json({}) == []

    def test_malformed_instruction_is_skipped_not_fatal(self):
        """One bad instruction dict must not crash the whole slice."""
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        raw = {
            "instructions": [
                {"address": "0x1000", "mnemonic": "INT_EQUAL"},  # missing required 'mnemonic'? no wait this HAS mnemonic but no 'address'... let's make truly malformed
                {"mnemonic": "INT_ADD"},  # missing 'address' -> KeyError
                {
                    "address": "0x1004",
                    "mnemonic": "INT_ADD",
                    "inputs": [],
                    "output": None,
                    "raw_pcode": "x",
                },
            ]
        }
        instructions = slicer._parse_pcode_json(raw)
        # Only the well-formed instruction should survive.
        assert len(instructions) == 2
        addresses = {i.address for i in instructions}
        assert "0x1004" in addresses

    def test_instruction_missing_optional_fields_uses_defaults(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        raw = {"instructions": [{"address": "0x1000", "mnemonic": "COPY"}]}
        instructions = slicer._parse_pcode_json(raw)
        assert len(instructions) == 1
        assert instructions[0].inputs == []
        assert instructions[0].output is None
        assert instructions[0].call_target is None


# ═══════════════════════════════════════════════════════════════════════
#  _apply_taint_bound
# ═══════════════════════════════════════════════════════════════════════


class TestApplyTaintBound:
    def test_empty_slice_returns_empty(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        assert slicer._apply_taint_bound([], "RDI") == []

    def test_single_instruction_slice_is_preserved(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        insts = [_inst("0x1000", "INT_EQUAL", ["RDI"], "ZF")]
        result = slicer._apply_taint_bound(insts, "RDI")
        assert result == insts

    def test_prunes_instructions_not_data_dependent_on_stall(self):
        """An instruction whose output never feeds the stall chain must be dropped."""
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        insts = [
            _inst("0x1000", "COPY", ["RDI"], "v1"),          # feeds v2 -> kept
            _inst("0x1004", "COPY", ["UNRELATED_GLOBAL"], "unused_var"),  # dead end -> pruned
            _inst("0x1008", "INT_ADD", ["v1", "0x1"], "v2"),  # feeds stall -> kept
            _inst("0x100c", "INT_EQUAL", ["v2", "0x5a01"], "ZF"),  # the stall itself
        ]
        result = slicer._apply_taint_bound(insts, "RDI")
        result_addrs = [i.address for i in result]
        assert "0x100c" in result_addrs  # stall instruction always kept
        assert "0x1008" in result_addrs  # feeds the stall
        assert "0x1000" in result_addrs  # feeds 0x1008
        assert "0x1004" not in result_addrs  # unrelated dead-end pruned

    def test_preserves_chronological_order(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        insts = [
            _inst("0x1000", "COPY", ["RDI"], "v1"),
            _inst("0x1004", "INT_ADD", ["v1", "0x1"], "v2"),
            _inst("0x1008", "INT_EQUAL", ["v2", "0x5a01"], "ZF"),
        ]
        result = slicer._apply_taint_bound(insts, "RDI")
        addrs = [i.address for i in result]
        assert addrs == sorted(addrs)  # entry -> stall order preserved


# ═══════════════════════════════════════════════════════════════════════
#  _truncate_slice
# ═══════════════════════════════════════════════════════════════════════


class TestTruncateSlice:
    def test_under_limit_is_unchanged(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64, max_instructions=10)
        insts = [_inst(f"0x{i:04x}", "COPY", [], f"v{i}") for i in range(5)]
        assert slicer._truncate_slice(insts) == insts

    def test_over_limit_keeps_instructions_closest_to_stall(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64, max_instructions=3)
        insts = [_inst(f"0x{i:04x}", "COPY", [], f"v{i}") for i in range(10)]
        result = slicer._truncate_slice(insts)
        assert len(result) == 3
        # The stall is the LAST instruction; truncation must keep the tail.
        assert result[-1] == insts[-1]
        assert result == insts[-3:]


# ═══════════════════════════════════════════════════════════════════════
#  _extract_json_from_output / _run_ghidra_headless error paths
# ═══════════════════════════════════════════════════════════════════════


class TestExtractJsonFromOutput:
    def test_extracts_json_between_delimiters(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        stdout = (
            "some ghidra log noise\n"
            "===PCODE_JSON_START===\n"
            '{"function_name": "check_magic"}\n'
            "===PCODE_JSON_END===\n"
            "more noise\n"
        )
        result = slicer._extract_json_from_output(stdout, "")
        assert json.loads(result) == {"function_name": "check_magic"}

    def test_missing_delimiters_raises_pcode_slicer_error(self):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        with pytest.raises(PCodeSlicerError, match="delimiters"):
            slicer._extract_json_from_output("no delimiters here at all", "")

    def test_checks_stderr_too(self):
        """Ghidra sometimes interleaves output; delimiters may land in stderr."""
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        result = slicer._extract_json_from_output(
            "", "===PCODE_JSON_START===\n{}\n===PCODE_JSON_END==="
        )
        assert json.loads(result) == {}


class TestRunGhidraHeadlessErrorPaths:
    def test_missing_binary_raises_file_not_found(self, tmp_path):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        missing = tmp_path / "does_not_exist.elf"
        with pytest.raises(FileNotFoundError):
            slicer.extract_slice(missing, "0x1000", "RDI")

    def test_ghidra_timeout_raises_pcode_slicer_error(self, tmp_path, monkeypatch):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        binary = tmp_path / "fake_binary"
        binary.write_bytes(b"\x7fELF")

        # Ghidra install dir must "exist" for the FileNotFoundError guard to pass.
        fake_ghidra = tmp_path / "ghidra"
        (fake_ghidra / "support").mkdir(parents=True)
        (fake_ghidra / "support" / "pyghidraRun").touch()
        monkeypatch.setattr("agentic_afl.extractor.pcode_slicer.settings.ghidra_install_dir", fake_ghidra)
        monkeypatch.setattr(
            "agentic_afl.extractor.pcode_slicer.settings.ghidra_project_dir", tmp_path / "proj"
        )

        def _raise_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="pyghidraRun", timeout=180)

        monkeypatch.setattr(subprocess, "run", _raise_timeout)

        with pytest.raises(PCodeSlicerError, match="timed out"):
            slicer.extract_slice(binary, "0x1000", "RDI")

    def test_nonzero_returncode_raises_pcode_slicer_error(self, tmp_path, monkeypatch):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        binary = tmp_path / "fake_binary"
        binary.write_bytes(b"\x7fELF")

        fake_ghidra = tmp_path / "ghidra"
        (fake_ghidra / "support").mkdir(parents=True)
        (fake_ghidra / "support" / "pyghidraRun").touch()
        monkeypatch.setattr("agentic_afl.extractor.pcode_slicer.settings.ghidra_install_dir", fake_ghidra)
        monkeypatch.setattr(
            "agentic_afl.extractor.pcode_slicer.settings.ghidra_project_dir", tmp_path / "proj"
        )

        class _FakeResult:
            returncode = 1
            stdout = ""
            stderr = "Ghidra crashed: NullPointerException"

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeResult())

        with pytest.raises(PCodeSlicerError, match="exited with code 1"):
            slicer.extract_slice(binary, "0x1000", "RDI")

    def test_malformed_json_raises_pcode_slicer_error(self, tmp_path, monkeypatch):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        binary = tmp_path / "fake_binary"
        binary.write_bytes(b"\x7fELF")

        fake_ghidra = tmp_path / "ghidra"
        (fake_ghidra / "support").mkdir(parents=True)
        (fake_ghidra / "support" / "pyghidraRun").touch()
        monkeypatch.setattr("agentic_afl.extractor.pcode_slicer.settings.ghidra_install_dir", fake_ghidra)
        monkeypatch.setattr(
            "agentic_afl.extractor.pcode_slicer.settings.ghidra_project_dir", tmp_path / "proj"
        )

        class _FakeResult:
            returncode = 0
            stdout = "===PCODE_JSON_START===\n{not valid json!!!\n===PCODE_JSON_END==="
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeResult())

        with pytest.raises(PCodeSlicerError, match="Invalid JSON"):
            slicer.extract_slice(binary, "0x1000", "RDI")

    def test_ghidra_script_reported_error_is_raised(self, tmp_path, monkeypatch):
        slicer = PCodeSlicer(architecture=Architecture.X86_64)
        binary = tmp_path / "fake_binary"
        binary.write_bytes(b"\x7fELF")

        fake_ghidra = tmp_path / "ghidra"
        (fake_ghidra / "support").mkdir(parents=True)
        (fake_ghidra / "support" / "pyghidraRun").touch()
        monkeypatch.setattr("agentic_afl.extractor.pcode_slicer.settings.ghidra_install_dir", fake_ghidra)
        monkeypatch.setattr(
            "agentic_afl.extractor.pcode_slicer.settings.ghidra_project_dir", tmp_path / "proj"
        )

        class _FakeResult:
            returncode = 0
            stdout = (
                "===PCODE_JSON_START===\n"
                '{"error": "No function found at address 0x1000"}\n'
                "===PCODE_JSON_END==="
            )
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeResult())

        with pytest.raises(PCodeSlicerError, match="No function found"):
            slicer.extract_slice(binary, "0x1000", "RDI")


# ═══════════════════════════════════════════════════════════════════════
#  from_json_file
# ═══════════════════════════════════════════════════════════════════════


class TestFromJsonFile:
    def test_loads_valid_json_file(self, tmp_path):
        json_path = tmp_path / "slice.json"
        json_path.write_text(json.dumps({
            "binary_path": "./test_binary",
            "stall_address": "0x1011b7",
            "function_name": "check_magic",
            "function_entry": "0x1011a0",
            "taint_source": "RDI",
            "slice_depth": 4,
            "was_truncated": False,
            "instructions": [
                {"address": "0x1011b7", "mnemonic": "INT_EQUAL", "inputs": [], "output": None, "raw_pcode": "x"}
            ],
        }))
        pslice = PCodeSlicer.from_json_file(json_path, architecture=Architecture.X86_64)
        assert pslice.function_name == "check_magic"
        assert pslice.instruction_count == 1

    def test_malformed_json_file_raises(self, tmp_path):
        json_path = tmp_path / "bad.json"
        json_path.write_text("{not valid json")
        with pytest.raises(PCodeSlicerError):
            PCodeSlicer.from_json_file(json_path)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PCodeSlicerError):
            PCodeSlicer.from_json_file(tmp_path / "nonexistent.json")


# ═══════════════════════════════════════════════════════════════════════
#  _focus_c_around_stall
# ═══════════════════════════════════════════════════════════════════════


class TestFocusCAroundStall:
    def test_short_c_returns_none(self):
        short_c = "\n".join(f"line{i}" for i in range(10))
        assert PCodeSlicer._focus_c_around_stall(short_c, "0x1000") is None

    def test_finds_checksum_anchor_in_long_function(self):
        lines = [f"unrelated_line_{i};" for i in range(200)]
        lines[100] = "if (computed_checksum != expected) { return ERROR; }"
        long_c = "\n".join(lines)
        focused = PCodeSlicer._focus_c_around_stall(long_c, "0x1000")
        assert focused is not None
        assert "computed_checksum" in focused

    def test_no_anchor_found_returns_none(self):
        lines = [f"unrelated_line_{i};" for i in range(200)]
        long_c = "\n".join(lines)
        assert PCodeSlicer._focus_c_around_stall(long_c, "0x1000") is None
