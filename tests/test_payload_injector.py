"""
test_payload_injector.py — Unit tests for the PayloadInjector.

Tests atomic write semantics, filename generation, and injection tracking.
No running AFL++ required — uses a tmp directory as the sync dir.
"""

import pytest
from pathlib import Path

from agentic_afl.models import SolvedPayload
from agentic_afl.fuzzer_bridge.payload_injector import PayloadInjector


@pytest.fixture
def injector(tmp_path):
    sync_dir = tmp_path / "sync"
    sync_dir.mkdir()
    return PayloadInjector(sync_dir=sync_dir)


def _make_payload(
    raw_bytes: bytes = b"\x01\x02\x03\x04",
    stall_address: str = "0x4012a0",
    spec_id: str = "test_spec_001",
) -> SolvedPayload:
    return SolvedPayload(
        raw_bytes=raw_bytes,
        source_spec_id=spec_id,
        stall_address=stall_address,
        z3_model={"x": 42},
        confidence=0.95,
    )


# ═══════════════════════════════════════════════════════════════════════
#  Injection
# ═══════════════════════════════════════════════════════════════════════

class TestInjection:
    """Test payload injection via atomic write."""

    @pytest.mark.asyncio
    async def test_basic_injection(self, injector):
        """Payload should be written to sync dir with correct contents."""
        payload = _make_payload(raw_bytes=b"\xDE\xAD\xBE\xEF")
        path = await injector.inject(payload)

        assert path.exists()
        assert path.read_bytes() == b"\xDE\xAD\xBE\xEF"
        assert path.name.startswith("agentic_")
        assert path.name.endswith(".bin")

    @pytest.mark.asyncio
    async def test_filename_contains_stall_address(self, injector):
        """Generated filename should contain the stall address."""
        payload = _make_payload(stall_address="0xd518")
        path = await injector.inject(payload)
        assert "0xd518" in path.name

    @pytest.mark.asyncio
    async def test_injection_tracking(self, injector):
        """Injected payloads should be tracked in the injection log."""
        payload = _make_payload()
        await injector.inject(payload)

        stats = injector.get_stats()
        assert stats["total_injected"] == 1
        assert stats["current_files"] == 1

    @pytest.mark.asyncio
    async def test_multiple_injections(self, injector):
        """Multiple payloads should coexist in the sync directory."""
        from datetime import datetime, timezone, timedelta
        for i in range(5):
            payload = SolvedPayload(
                raw_bytes=bytes([i] * 4),
                source_spec_id=f"spec_{i:03d}",
                stall_address=f"0x{0x1000 + i:04x}",
                z3_model={"x": i},
                confidence=0.9,
                # Offset timestamps to get unique filenames
                generated_at=datetime(2026, 1, 1, 0, 0, i, tzinfo=timezone.utc),
            )
            await injector.inject(payload)

        files = injector.list_injected()
        assert len(files) == 5

        stats = injector.get_stats()
        assert stats["total_injected"] == 5

    @pytest.mark.asyncio
    async def test_atomic_write(self, injector):
        """No .tmp files should remain after injection (atomic rename)."""
        payload = _make_payload()
        await injector.inject(payload)

        tmp_files = list(injector.sync_dir.glob("*.tmp"))
        assert len(tmp_files) == 0, f"Temp files not cleaned up: {tmp_files}"


# ═══════════════════════════════════════════════════════════════════════
#  Cleanup
# ═══════════════════════════════════════════════════════════════════════

class TestCleanup:
    """Test old payload cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_old_payloads(self, injector):
        """Cleanup should remove old files and return count."""
        payload = _make_payload()
        path = await injector.inject(payload)

        # Artificially age the file by setting mtime to far past
        import os
        old_time = 0  # epoch
        os.utime(path, (old_time, old_time))

        removed = injector.cleanup_old_payloads(max_age_hours=1)
        assert removed == 1
        assert not path.exists()


# ═══════════════════════════════════════════════════════════════════════
#  Edge cases (health-review gaps)
# ═══════════════════════════════════════════════════════════════════════

class TestSyncDirEdgeCases:
    """Covers: injection when the sync directory disappears after
    PayloadInjector was constructed (e.g. a campaign restart wipes the
    workdir while the injector instance is still alive)."""

    @pytest.mark.asyncio
    async def test_inject_recreates_missing_sync_dir_or_raises_clearly(self, tmp_path):
        sync_dir = tmp_path / "sync"
        sync_dir.mkdir()
        injector = PayloadInjector(sync_dir=sync_dir)

        # Simulate the directory vanishing after construction (e.g. an
        # AFL++ restart cycle calling shutil.rmtree on the work dir).
        sync_dir.rmdir()

        payload = _make_payload()
        # Current behavior: tempfile.NamedTemporaryFile(dir=...) raises
        # FileNotFoundError rather than silently succeeding or recreating
        # the directory. This test documents that contract explicitly --
        # if the sync dir is deleted out from under a live injector, the
        # caller finds out immediately instead of silently losing payloads.
        with pytest.raises(FileNotFoundError):
            await injector.inject(payload)


class TestTempfileLeakOnWriteFailure:
    """
    Health-review finding H5 (now FIXED): PayloadInjector.inject() creates
    the temp file with delete=False. Previously, if `fd.write()` raised
    partway through, the temp file was never unlinked and orphaned .tmp
    files accumulated in the sync dir over a long campaign. inject() now
    unlinks the temp file on any write failure before re-raising.
    """

    @pytest.mark.asyncio
    async def test_write_failure_cleans_up_tempfile(self, tmp_path, monkeypatch):
        sync_dir = tmp_path / "sync"
        sync_dir.mkdir()
        injector = PayloadInjector(sync_dir=sync_dir)

        import tempfile as tempfile_module

        real_named_temp_file = tempfile_module.NamedTemporaryFile

        class _FailingFile:
            """Wraps a real NamedTemporaryFile but raises on write()."""
            def __init__(self, *args, **kwargs):
                self._inner = real_named_temp_file(*args, **kwargs)
                self.name = self._inner.name

            def write(self, data):
                raise OSError("simulated disk write failure")

            def flush(self):
                pass

            def close(self):
                self._inner.close()

        monkeypatch.setattr(tempfile_module, "NamedTemporaryFile", _FailingFile)

        payload = _make_payload()
        with pytest.raises(OSError, match="simulated disk write failure"):
            await injector.inject(payload)

        # H5 fix: no orphaned .tmp file must remain after a failed write.
        leaked = list(sync_dir.glob("agentic_*.tmp"))
        assert len(leaked) == 0, f"H5 regression: orphaned temp files left behind: {leaked}"
