"""
campaign.py — AFL++ and AgentLoop Campaign Lifecycle Manager.

This is the core orchestration class that manages a complete fuzzing
campaign: starting AFL++, running the AgentLoop, monitoring coverage,
deploying custom mutators, and collecting results.

Usage from CLI:
    runner = CampaignRunner(
        harness=Path("./my_harness"),
        seed_dir=Path("./seeds"),
        duration=3600,
    )
    result = await runner.run()

Usage from Python:
    result = asyncio.run(runner.run())
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocessa
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agentic_afl.orchestrator.agent_loop import AgentLoop

log = logging.getLogger(__name__)


# ── Result dataclass ──────────────────────────────────────────────────

@dataclass
class CampaignResult:
    """Immutable result of a completed campaign."""
    target_name: str
    baseline_edges: int
    final_edges: int
    edge_gain: int
    edge_gain_pct: float
    bypass_detected: bool
    bypass_time_seconds: int | None
    bypass_evidence: str | None
    payloads_injected: int
    stalls_detected: int
    llm_calls: int
    react_turns: int
    elapsed_seconds: int
    duration_seconds: int
    timeline: list[dict]
    mutator_deployed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ── AFL++ process helpers ─────────────────────────────────────────────

def _read_edges(afl_out: Path) -> int:
    """Read edges_found from AFL++ fuzzer_stats."""
    stats_file = afl_out / "default" / "fuzzer_stats"
    if not stats_file.exists():
        return 0
    try:
        for line in stats_file.read_text().splitlines():
            if line.startswith("edges_found"):
                return int(line.split(":")[-1].strip())
    except Exception:
        pass
    return 0


def _read_fuzzer_stats(afl_out: Path) -> dict[str, int]:
    """Read multiple metrics from AFL++ fuzzer_stats."""
    stats = {"execs_done": 0, "corpus_count": 0, "cycles_done": 0,
             "pending_favs": 0, "edges_found": 0}
    stats_file = afl_out / "default" / "fuzzer_stats"
    if not stats_file.exists():
        return stats
    try:
        for line in stats_file.read_text().splitlines():
            key = line.split(":")[0].strip()
            if key in stats:
                stats[key] = int(line.split(":")[-1].strip())
    except Exception:
        pass
    return stats


def _check_for_accept(
    afl_out: Path, binary: Path, accept_marker: str = "ACCEPT",
) -> str | None:
    """Check if any queue entry produces the accept marker."""
    queue_dir = afl_out / "default" / "queue"
    if not queue_dir.exists():
        return None
    for f in sorted(queue_dir.iterdir()):
        if not f.is_file():
            continue
        if not (f.name.startswith("id:") or f.name.startswith("agentic_")):
            continue
        # Skip original unmodified seeds.
        if "time:0,execs:0" in f.name:
            continue
        try:
            result = subprocess.run(
                [str(binary), str(f)],
                capture_output=True, text=True, timeout=5,
            )
            if accept_marker in (result.stdout + result.stderr):
                return f.name
        except Exception:
            pass
    return None


async def _start_afl(
    binary: Path,
    afl_in: Path,
    afl_out: Path,
    afl_sync: Path,
    custom_mutator_module: str | None = None,
    mutator_dir: Path | None = None,
    resume: bool = False,
) -> asyncio.subprocess.Process:
    """Start an AFL++ fuzzer process."""
    env = os.environ.copy()
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_NO_UI"] = "1"
    env["AFL_SYNC_TIME"] = "1"

    if custom_mutator_module and mutator_dir:
        env["AFL_PYTHON_MODULE"] = custom_mutator_module
        env["PYTHONPATH"] = str(mutator_dir)

    input_arg = "-" if resume else str(afl_in)

    proc = await asyncio.create_subprocess_exec(
        "afl-fuzz", "-M", "default",
        "-F", str(afl_sync),
        "-i", input_arg, "-o", str(afl_out),
        "--", str(binary), "@@",
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return proc


def _safe_terminate(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.terminate()
    except ProcessLookupError:
        pass


def _format_duration(seconds: float) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    if h > 0:
        return f"{h}h{m:02d}m{s:02d}s"
    elif m > 0:
        return f"{m}m{s:02d}s"
    return f"{s}s"


# ── Callback protocol ────────────────────────────────────────────────

@dataclass
class CampaignSnapshot:
    """Periodic state snapshot passed to the on_update callback."""
    elapsed: float
    edges: int
    baseline_edges: int
    execs: int
    execs_per_sec: float
    corpus_count: int
    cycles_done: int
    pending_favs: int
    stalls_detected: int
    stalls_solved: int
    payloads_injected: int
    llm_calls: int
    react_turns: int
    bypass_detected: bool
    bypass_time: float
    bypass_evidence: str
    mutator_deployed: bool
    mutator_name: str
    edge_history: list[int]


# ── CampaignRunner ───────────────────────────────────────────────────

class CampaignRunner:
    """Manages the full AFL++ + AgentLoop lifecycle.

    This is the single class that replaces the 550-line run_e2e_campaign.py.
    It takes raw paths (pre-compiled harness, seed directory) and handles:
      - AFL++ process management (start, restart, cleanup)
      - AgentLoop orchestration (stall detection, solving, injection)
      - Custom mutator deployment (Level 3: post-solve AFL++ restart)
      - Monitoring (edge polling, timeline snapshots)
      - Result collection (JSON-serializable CampaignResult)

    No compilation. No TargetSpec. Just paths.
    """

    def __init__(
        self,
        harness: Path,
        seed_dir: Path,
        duration: int = 3600,
        *,
        stall_minutes: int = 5,
        accept_marker: str = "ACCEPT",
        custom_mutator: Path | None = None,
        log_dir: Path | None = None,
        target_name: str | None = None,
        on_update: Callable[[CampaignSnapshot], None] | None = None,
    ) -> None:
        self.harness = Path(harness).resolve()
        self.seed_dir = Path(seed_dir).resolve()
        self.duration = duration
        self.stall_minutes = stall_minutes
        self.accept_marker = accept_marker
        self.custom_mutator = Path(custom_mutator) if custom_mutator else None
        self.log_dir = Path(log_dir) if log_dir else None
        self.target_name = target_name or self.harness.stem
        self.on_update = on_update

        # Internal state.
        self._shutdown = False
        self._afl_proc: asyncio.subprocess.Process | None = None
        self._agent: AgentLoop | None = None
        self._agent_task: asyncio.Task | None = None

    def request_shutdown(self) -> None:
        """Request graceful campaign shutdown (e.g., from signal handler)."""
        self._shutdown = True

    async def run(self) -> CampaignResult:
        """Execute the full campaign lifecycle. Returns results."""

        # ── Setup directories ─────────────────────────────────────
        work_dir = self.harness.parent / ".agentic_afl_workdir"
        afl_in = work_dir / "in"
        afl_out = work_dir / "out"
        afl_sync = afl_out / "agentic" / "queue"

        # Kill stale AFL++ instances.
        try:
            subprocess.run(["pkill", "-9", "-f", "afl-fuzz"],
                           capture_output=True, timeout=5)
            await asyncio.sleep(2)
        except Exception:
            pass

        if work_dir.exists():
            shutil.rmtree(work_dir)
        afl_in.mkdir(parents=True)
        afl_sync.mkdir(parents=True, exist_ok=True)

        # Copy seeds.
        seed_count = 0
        for f in self.seed_dir.iterdir():
            if f.is_file():
                shutil.copy(f, afl_in / f.name)
                seed_count += 1
        log.info("Loaded %d seeds from %s", seed_count, self.seed_dir)

        # ── Start AFL++ ───────────────────────────────────────────
        self._afl_proc = await _start_afl(
            self.harness, afl_in, afl_out, afl_sync,
        )
        await asyncio.sleep(3)
        log.info("AFL++ started (pid=%s)", self._afl_proc.pid)

        # ── Start AgentLoop ───────────────────────────────────────
        self._agent = AgentLoop(
            afl_output_dir=afl_out,
            afl_sync_dir=afl_sync,
            target_binary=self.harness,
            stall_address_override=None,
            min_stall_cycles=10,
            register_signals=False,
        )
        await self._agent.setup()
        self._agent._stall_detector._min_stall_time_seconds = (
            self.stall_minutes * 60
        )
        self._agent_task = asyncio.create_task(self._agent.run())
        log.info("AgentLoop started (stall_threshold=%dm)", self.stall_minutes)

        # ── Monitoring loop ───────────────────────────────────────
        start = time.monotonic()
        baseline_edges = 0
        edge_history: list[int] = []
        timeline: list[dict] = []
        bypass_detected = False
        bypass_time: float = 0.0
        bypass_evidence = ""
        mutator_deployed = False
        prev_execs = 0
        prev_execs_time = start
        last_snapshot = 0.0

        while time.monotonic() - start < self.duration:
            if self._shutdown:
                log.info("Shutdown requested — ending campaign")
                break

            await asyncio.sleep(5)
            elapsed = time.monotonic() - start
            edges = _read_edges(afl_out)
            metrics = self._agent._metrics

            # Baseline.
            if elapsed < 10 and baseline_edges == 0:
                baseline_edges = edges

            # Stats polling (~every 30s).
            if elapsed - last_snapshot >= 30:
                last_snapshot = elapsed
                stats = _read_fuzzer_stats(afl_out)
                now = time.monotonic()
                dt = now - prev_execs_time
                execs_per_sec = (
                    (stats["execs_done"] - prev_execs) / dt if dt > 0 else 0
                )
                prev_execs = stats["execs_done"]
                prev_execs_time = now
                edge_history.append(edges)

                # Timeline snapshot (every 60s).
                if int(elapsed) % 60 < 35:
                    timeline.append({
                        "time_seconds": int(elapsed),
                        "edges": edges,
                        "stalls_detected": metrics["stalls_detected"],
                        "payloads_injected": metrics["payloads_injected"],
                    })

                # Fire callback.
                if self.on_update:
                    snap = CampaignSnapshot(
                        elapsed=elapsed,
                        edges=edges,
                        baseline_edges=baseline_edges,
                        execs=stats["execs_done"],
                        execs_per_sec=execs_per_sec,
                        corpus_count=stats["corpus_count"],
                        cycles_done=stats["cycles_done"],
                        pending_favs=stats["pending_favs"],
                        stalls_detected=metrics["stalls_detected"],
                        stalls_solved=metrics["stalls_processed"],
                        payloads_injected=metrics["payloads_injected"],
                        llm_calls=metrics["llm_calls_total"],
                        react_turns=metrics["react_turns_total"],
                        bypass_detected=bypass_detected,
                        bypass_time=bypass_time,
                        bypass_evidence=bypass_evidence,
                        mutator_deployed=mutator_deployed,
                        mutator_name=(
                            self.custom_mutator.stem if self.custom_mutator
                            else ""
                        ),
                        edge_history=edge_history,
                    )
                    self.on_update(snap)

            # Check for bypass.
            evidence = _check_for_accept(
                afl_out, self.harness, self.accept_marker,
            )
            if evidence and not bypass_detected:
                bypass_detected = True
                bypass_time = elapsed
                bypass_evidence = evidence
                log.info(
                    "FULL ACCEPT: %s at %s",
                    evidence, _format_duration(elapsed),
                )

                # Level 3: Deploy custom mutator.
                if self.custom_mutator and self.custom_mutator.exists():
                    log.info(
                        "Deploying custom mutator: %s",
                        self.custom_mutator.name,
                    )
                    _safe_terminate(self._afl_proc)
                    try:
                        await asyncio.wait_for(
                            self._afl_proc.wait(), timeout=5,
                        )
                    except asyncio.TimeoutError:
                        self._afl_proc.kill()
                    await asyncio.sleep(1)

                    self._afl_proc = await _start_afl(
                        self.harness, afl_in, afl_out, afl_sync,
                        custom_mutator_module=self.custom_mutator.stem,
                        mutator_dir=self.custom_mutator.parent,
                        resume=True,
                    )
                    mutator_deployed = True
                    log.info("AFL++ restarted with custom mutator")

        # ── Finalize ──────────────────────────────────────────────
        elapsed_total = time.monotonic() - start
        final_edges = _read_edges(afl_out)
        final_metrics = self._agent._metrics

        result = CampaignResult(
            target_name=self.target_name,
            baseline_edges=baseline_edges,
            final_edges=final_edges,
            edge_gain=final_edges - baseline_edges,
            edge_gain_pct=(
                (final_edges - baseline_edges) / baseline_edges * 100
                if baseline_edges > 0 else 0.0
            ),
            bypass_detected=bypass_detected,
            bypass_time_seconds=int(bypass_time) if bypass_detected else None,
            bypass_evidence=bypass_evidence or None,
            payloads_injected=final_metrics["payloads_injected"],
            stalls_detected=final_metrics["stalls_detected"],
            llm_calls=final_metrics["llm_calls_total"],
            react_turns=final_metrics["react_turns_total"],
            elapsed_seconds=int(elapsed_total),
            duration_seconds=self.duration,
            timeline=timeline,
            mutator_deployed=mutator_deployed,
        )

        # Write JSON if log_dir specified.
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = self.log_dir / f"{self.target_name}_{ts}.json"
            result_file.write_text(json.dumps(result.to_dict(), indent=2))
            log.info("Results written to %s", result_file)

        # ── Cleanup ───────────────────────────────────────────────
        self._agent._running = False
        try:
            await asyncio.wait_for(self._agent_task, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._agent_task.cancel()
        _safe_terminate(self._afl_proc)
        try:
            await asyncio.wait_for(self._afl_proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            self._afl_proc.kill()

        log.info("Campaign complete: %d edges (+%d, %+.1f%%)",
                 result.final_edges, result.edge_gain, result.edge_gain_pct)

        return result
