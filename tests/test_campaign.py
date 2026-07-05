"""
test_campaign.py — Unit tests for campaign.py helper functions.

Covers the health-review H4 finding: the stale-AFL++ cleanup previously
used `pkill -9 -f afl-fuzz`, matching (and killing) EVERY afl-fuzz
process on the host, not just the one belonging to the current campaign.
This is a real risk on a shared research box running multiple concurrent
campaigns against different targets.

Also covers _read_edges / _read_fuzzer_stats behavior on missing and
malformed fuzzer_stats files (previously untested, swallowed via a bare
`except Exception: pass`).
"""

from __future__ import annotations

from pathlib import Path

from agentic_afl.campaign import (
    _read_edges,
    _read_fuzzer_stats,
    _stale_afl_pkill_pattern,
)


# ═══════════════════════════════════════════════════════════════════════
#  H4: pkill scoping
# ═══════════════════════════════════════════════════════════════════════


class TestStaleAflPkillPattern:
    def test_pattern_includes_afl_out_path(self):
        afl_out = Path("/home/user/project/.agentic_afl_workdir/out")
        pattern = _stale_afl_pkill_pattern(afl_out)
        assert str(afl_out) in pattern

    def test_pattern_still_anchors_on_afl_fuzz(self):
        """Must not accidentally match unrelated processes that happen to
        reference the same output directory (e.g. a text editor)."""
        afl_out = Path("/tmp/campaign_a/out")
        pattern = _stale_afl_pkill_pattern(afl_out)
        assert pattern.startswith("afl-fuzz")

    def test_two_campaigns_produce_distinct_patterns(self):
        """The core regression this guards: two concurrent campaigns
        against different harnesses must not be able to kill each other."""
        pattern_a = _stale_afl_pkill_pattern(Path("/work/target_a/.agentic_afl_workdir/out"))
        pattern_b = _stale_afl_pkill_pattern(Path("/work/target_b/.agentic_afl_workdir/out"))

        assert pattern_a != pattern_b
        # Campaign A's pattern must not match campaign B's output dir and
        # vice versa -- i.e. neither is a substring-match superset of the
        # other's afl_out path.
        assert "/work/target_b/" not in pattern_a
        assert "/work/target_a/" not in pattern_b

    def test_pattern_is_not_the_old_unscoped_string(self):
        """Regression guard: the fix must not silently degrade back to
        the bare 'afl-fuzz' pattern that matches every instance on host."""
        afl_out = Path("/tmp/some_campaign/out")
        pattern = _stale_afl_pkill_pattern(afl_out)
        assert pattern != "afl-fuzz"


# ═══════════════════════════════════════════════════════════════════════
#  fuzzer_stats parsing edge cases
# ═══════════════════════════════════════════════════════════════════════


class TestReadEdges:
    def test_missing_file_returns_zero(self, tmp_path):
        assert _read_edges(tmp_path) == 0

    def test_parses_valid_stats(self, tmp_path):
        stats_dir = tmp_path / "default"
        stats_dir.mkdir()
        (stats_dir / "fuzzer_stats").write_text("edges_found       : 42\n")
        assert _read_edges(tmp_path) == 42

    def test_malformed_stats_does_not_raise(self, tmp_path):
        stats_dir = tmp_path / "default"
        stats_dir.mkdir()
        (stats_dir / "fuzzer_stats").write_text("edges_found       : not_a_number\n")
        # Swallowed by design -- must degrade to 0, not crash the monitor loop.
        assert _read_edges(tmp_path) == 0


class TestReadFuzzerStats:
    def test_missing_file_returns_defaults(self, tmp_path):
        stats = _read_fuzzer_stats(tmp_path)
        assert stats == {
            "execs_done": 0, "corpus_count": 0, "cycles_done": 0,
            "pending_favs": 0, "edges_found": 0,
        }

    def test_parses_multiple_fields(self, tmp_path):
        stats_dir = tmp_path / "default"
        stats_dir.mkdir()
        (stats_dir / "fuzzer_stats").write_text(
            "execs_done        : 1000\n"
            "corpus_count      : 12\n"
            "cycles_done       : 3\n"
            "pending_favs      : 0\n"
            "edges_found       : 55\n"
        )
        stats = _read_fuzzer_stats(tmp_path)
        assert stats["execs_done"] == 1000
        assert stats["corpus_count"] == 12
        assert stats["edges_found"] == 55

    def test_malformed_line_does_not_raise_and_yields_defaults(self, tmp_path):
        stats_dir = tmp_path / "default"
        stats_dir.mkdir()
        (stats_dir / "fuzzer_stats").write_text("edges_found\n")  # no colon separator
        stats = _read_fuzzer_stats(tmp_path)
        # Silently degrades to defaults rather than raising -- documents
        # the swallowed-exception behavior flagged in the health review.
        assert stats["edges_found"] == 0
