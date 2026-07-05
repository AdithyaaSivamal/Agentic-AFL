"""
test_stall_detector.py — Unit tests for the StallDetector.

Tests fuzzer_stats parsing, plateau detection logic, and stall classification.
No running AFL++ required — uses synthetic fuzzer_stats files.
"""

import pytest
from pathlib import Path

from agentic_afl.fuzzer_bridge.stall_detector import StallDetector


# ═══════════════════════════════════════════════════════════════════════
#  fuzzer_stats File Parsing
# ═══════════════════════════════════════════════════════════════════════

class TestFuzzerStatsParsing:
    """Parse AFL++'s fuzzer_stats file format."""

    def test_parse_basic_stats(self, tmp_path):
        """Standard key:value format."""
        stats_dir = tmp_path / "afl_output" / "default"
        stats_dir.mkdir(parents=True)
        stats_file = stats_dir / "fuzzer_stats"
        stats_file.write_text(
            "start_time        : 1700000000\n"
            "last_update       : 1700000060\n"
            "fuzzer_pid        : 12345\n"
            "cycles_done       : 42\n"
            "execs_done        : 100000\n"
            "execs_per_sec     : 10000.00\n"
            "corpus_count      : 15\n"
            "edges_found       : 114\n"
            "pending_favs      : 5\n"
        )
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
        )
        stats = detector._parse_fuzzer_stats()
        assert stats["cycles_done"] == "42"
        assert stats["edges_found"] == "114"
        assert stats["execs_per_sec"] == "10000.00"

    def test_parse_empty_file(self, tmp_path):
        """Empty stats file should return empty dict."""
        stats_dir = tmp_path / "afl_output" / "default"
        stats_dir.mkdir(parents=True)
        (stats_dir / "fuzzer_stats").write_text("")
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
        )
        stats = detector._parse_fuzzer_stats()
        assert stats == {}

    def test_parse_missing_file(self, tmp_path):
        """Missing stats file should return empty dict."""
        detector = StallDetector(
            afl_output_dir=tmp_path / "nonexistent",
            min_stall_cycles=10,
        )
        stats = detector._parse_fuzzer_stats()
        assert stats == {}

    def test_parse_malformed_lines(self, tmp_path):
        """Lines without ':' should be skipped."""
        stats_dir = tmp_path / "afl_output" / "default"
        stats_dir.mkdir(parents=True)
        (stats_dir / "fuzzer_stats").write_text(
            "this line has no colon\n"
            "edges_found       : 200\n"
            "\n"
            "cycles_done       : 10\n"
        )
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
        )
        stats = detector._parse_fuzzer_stats()
        assert stats["edges_found"] == "200"
        assert stats["cycles_done"] == "10"

    def test_parse_numbered_instance(self, tmp_path):
        """Should find stats in numbered fuzzer instances (fuzzer01/)."""
        stats_dir = tmp_path / "afl_output" / "fuzzer01"
        stats_dir.mkdir(parents=True)
        (stats_dir / "fuzzer_stats").write_text(
            "edges_found       : 350\n"
            "cycles_done       : 99\n"
        )
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
        )
        stats = detector._parse_fuzzer_stats()
        assert stats["edges_found"] == "350"


# ═══════════════════════════════════════════════════════════════════════
#  Stall Address Override
# ═══════════════════════════════════════════════════════════════════════

class TestStallAddressOverride:
    """When --stall-address is provided, it should be used directly."""

    def test_override_used_directly(self, tmp_path):
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
            stall_address_override="0xd518",
        )
        addrs = detector._identify_stalls({})
        assert addrs == ["0xd518"]

    def test_no_override_no_stalls_without_frontier(self, tmp_path):
        detector = StallDetector(
            afl_output_dir=tmp_path / "afl_output",
            min_stall_cycles=10,
        )
        # Without override or frontier discovery, should return empty
        # (frontier discovery requires a real binary + GDB)
        detector._frontier_discovery_attempts = detector._frontier_discovery_max_attempts
        addrs = detector._identify_stalls({})
        assert addrs == []
