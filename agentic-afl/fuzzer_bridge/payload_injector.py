"""
payload_injector.py — Asynchronous Payload Injection into AFL++ Sync Directory.

This module writes solved payloads to AFL++'s external sync directory.
AFL++ natively discovers and ingests these files on its next execution cycle.

Inputs:
    - SolvedPayload  — From agent_loop.py

Outputs:
    - Raw .bin file written to config.afl_sync_dir

Reference: TDD_v2 §4.4 — Asynchronous sync directory injection.

Key Design Decisions:
    1. NO BLOCKING IPC: The Orchestrator NEVER communicates with AFL++ via
       shared memory, pipes, or sockets. All communication is filesystem-based.
       This ensures the LLM's latency (seconds) never affects AFL++'s
       throughput (10,000+ exec/sec).

    2. ATOMIC WRITES: Payloads are written to a temp file first, then renamed
       into the sync directory. This prevents AFL++ from reading a partially
       written file.

    3. EXECUTION INTEGRITY (HITL): During physical hardware execution, payloads
       are written ONLY to SRAM. The framework is STRICTLY FORBIDDEN from
       overwriting the CPU's Program Counter (PC) to "jump over" stalls.
       Reference: TDD_v2 §4.4 — Execution Integrity.
"""

from __future__ import annotations

import logging
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.models import SolvedPayload

logger = logging.getLogger(__name__)


class PayloadInjector:
    """
    Writes solved payloads to AFL++'s sync directory.

    Usage:
        injector = PayloadInjector()
        path = await injector.inject(payload)
        # AFL++ will discover and ingest the payload on its next cycle.

    The sync directory is AFL++'s external input mechanism. Files placed
    here are automatically picked up, minimized, and added to the corpus
    if they trigger new coverage.
    """

    def __init__(
        self,
        sync_dir: Path = settings.afl_sync_dir,
    ) -> None:
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        # Track injected payloads for stats/dedup.
        self._injected: list[dict] = []

    async def inject(self, payload: SolvedPayload) -> Path:
        """
        Write a solved payload to the AFL++ sync directory.

        Uses atomic write (temp file + rename) to prevent AFL++ from
        reading a partially written file. The temp file is created in
        the same directory to ensure rename is atomic (same filesystem).

        Args:
            payload: The SolvedPayload to inject.

        Returns:
            Path to the written file in the sync directory.
        """
        final_path = self.sync_dir / payload.filename

        # Atomic write: temp file → rename.
        # dir= must be on the same filesystem as the final destination
        # for os.rename() to be atomic.
        fd = tempfile.NamedTemporaryFile(
            dir=self.sync_dir,
            delete=False,
            suffix=".tmp",
            prefix="agentic_",
        )
        try:
            fd.write(payload.raw_bytes)
            fd.flush()
            tmp_path = Path(fd.name)
        finally:
            fd.close()

        # Atomic rename (same filesystem guarantees atomicity).
        tmp_path.rename(final_path)

        # Track the injection.
        self._injected.append({
            "path": str(final_path),
            "stall_address": payload.stall_address,
            "spec_id": payload.source_spec_id,
            "size": len(payload.raw_bytes),
            "confidence": payload.confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            "Injected payload for %s: %s (%d bytes, confidence=%.2f)",
            payload.stall_address,
            final_path.name,
            len(payload.raw_bytes),
            payload.confidence,
        )
        return final_path

    def list_injected(self) -> list[Path]:
        """List all payload files currently in the sync directory."""
        return sorted(self.sync_dir.glob("agentic_*.bin"))

    def cleanup_old_payloads(self, max_age_hours: int = 24) -> int:
        """
        Remove payload files older than max_age_hours.

        AFL++ should have already ingested these files, so cleaning them
        up prevents the sync directory from growing unboundedly during
        long fuzzing campaigns.

        Returns:
            Number of files removed.
        """
        cutoff = time.time() - (max_age_hours * 3600)
        removed = 0
        for payload_file in self.sync_dir.glob("agentic_*.bin"):
            try:
                if payload_file.stat().st_mtime < cutoff:
                    payload_file.unlink()
                    removed += 1
                    logger.debug("Cleaned up old payload: %s", payload_file.name)
            except OSError as e:
                logger.warning("Failed to remove %s: %s", payload_file, e)
        if removed:
            logger.info("Cleaned up %d old payload(s) from sync directory", removed)
        return removed

    def get_stats(self) -> dict:
        """Return injection statistics."""
        current_files = self.list_injected()
        total_bytes = sum(f.stat().st_size for f in current_files if f.exists())
        return {
            "total_injected": len(self._injected),
            "current_files": len(current_files),
            "total_bytes_on_disk": total_bytes,
            "injection_log": self._injected[-10:],  # Last 10 entries
        }
