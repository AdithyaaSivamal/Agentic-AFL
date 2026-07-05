"""
test_cli.py — Unit tests for the CLI surface.

Covers a module that was at 0% coverage. Tests the pure duration helpers
and the argument parser (via the extracted build_parser()) without
executing any subcommand — no AFL++, Ghidra, LLM, or Postgres involved.
"""

from __future__ import annotations

import pytest

from agentic_afl.cli import _format_duration, _parse_duration, build_parser


# ═══════════════════════════════════════════════════════════════════════
#  Duration helpers
# ═══════════════════════════════════════════════════════════════════════

class TestParseDuration:
    @pytest.mark.parametrize("text,expected", [
        ("6h", 6 * 3600),
        ("30m", 30 * 60),
        ("90s", 90),
        ("1.5h", 5400),
        ("120", 120),  # bare number = seconds
        (" 2H ", 2 * 3600),  # whitespace + uppercase tolerated
    ])
    def test_parse(self, text, expected):
        assert _parse_duration(text) == expected


class TestFormatDuration:
    @pytest.mark.parametrize("seconds,expected", [
        (90, "1m30s"),
        (3661, "1h01m01s"),
        (45, "45s"),
        (600, "10m00s"),
    ])
    def test_format(self, seconds, expected):
        assert _format_duration(seconds) == expected

    def test_roundtrip_seconds(self):
        # parse(format(x)) preserves value for pure-second inputs < 60.
        assert _parse_duration(_format_duration(45)) == 45


# ═══════════════════════════════════════════════════════════════════════
#  Argument parser
# ═══════════════════════════════════════════════════════════════════════

class TestBuildParser:
    def test_fuzz_minimal_args(self):
        parser = build_parser()
        args = parser.parse_args(["fuzz", "./harness", "-i", "./seeds"])
        assert args.command == "fuzz"
        assert args.harness == "./harness"
        assert args.seeds == "./seeds"
        assert args.duration == "1h"  # default
        assert args.stall_minutes == 5  # default

    def test_fuzz_requires_seeds(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["fuzz", "./harness"])  # missing -i/--seeds

    def test_fuzz_full_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "fuzz", "./h", "-i", "./s",
            "--duration", "30m", "--stall-minutes", "2",
            "--accept-marker", "PASS", "--stall-address", "0xd7e4",
            "--qemu", "--tui",
        ])
        assert args.duration == "30m"
        assert args.stall_minutes == 2
        assert args.accept_marker == "PASS"
        assert args.stall_address == "0xd7e4"
        assert args.qemu is True
        assert args.tui is True

    def test_check_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["check", "--fix"])
        assert args.command == "check"
        assert args.fix is True

    def test_analyze_requires_address(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["analyze", "./binary"])  # missing --address

    def test_analyze_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "./binary", "--address", "0x1000"])
        assert args.command == "analyze"
        assert args.address == "0x1000"
        assert args.depth == 20
        assert args.arch == "x86_64"

    def test_plot_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["plot", "result.json", "-o", "out.png"])
        assert args.command == "plot"
        assert args.json_file == "result.json"
        assert args.output == "out.png"

    def test_unknown_command_errors(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["frobnicate"])

    def test_no_command_errors(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])  # subcommand is required
