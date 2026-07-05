#!/usr/bin/env python3
"""
run_e2e_campaign.py — True End-to-End Agentic-AFL Campaign Runner.

Runs AFL++ against a real target for hours, monitors for coverage stalls,
and lets Agentic-AFL autonomously discover frontier functions, solve
math walls, and inject bypass payloads.

Unlike test_generalization_matrix.py (which validates with pre-configured
stall addresses), this script operates in fully autonomous mode:
  - No stall_address_override — the stall detector discovers the blocking
    function via GDB frontier tracing.
  - Time-based stall detection — triggers only after sustained edge plateaus.
  - Live dashboard — real-time metrics printed every 30 seconds.
  - JSON result logging — for post-campaign analysis.

Usage:
    python run_e2e_campaign.py lib60870 --duration 6h
    python run_e2e_campaign.py lib60870 --duration 30m --min-stall-minutes 5
    python run_e2e_campaign.py cfs --duration 1h --debug
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.orchestrator.agent_loop import AgentLoop
from agentic_afl.config import settings
# Health-review fix (M6): AFL++ launch/terminate/cleanup helpers used to be
# reimplemented here, drifting from campaign.py's CampaignRunner over time
# -- e.g. this file's own stale-instance cleanup still used the unscoped
# `pkill -9 -f afl-fuzz` (H4) after that was fixed in campaign.py. Import
# the shared, patched implementations instead of maintaining two copies.
from agentic_afl.campaign import (
    _format_duration,
    _safe_terminate,
    _stale_afl_pkill_pattern,
    _start_afl as run_afl,
)

try:
    from tui import CampaignTUI, TUIState
    _HAS_TUI = True
except ImportError:
    _HAS_TUI = False

# ── Paths ─────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[2]
TARGETS_DIR = ROOT_DIR / "experiments" / "test_targets"
TESTS_DIR = ROOT_DIR / "experiments" / "tests"

# Import target specs from the generalization matrix.
from test_generalization_matrix import (  # noqa: E402
    TARGETS, TargetSpec, compile_target, resolve_symbol, read_edges,
    check_for_accept, check_partial_bypass,
)

# ── Globals ───────────────────────────────────────────────────────────
_shutdown_requested = False


def _parse_duration(s: str) -> int:
    """Parse duration string like '6h', '30m', '90s' into seconds."""
    s = s.strip().lower()
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    elif s.endswith("m"):
        return int(float(s[:-1]) * 60)
    elif s.endswith("s"):
        return int(float(s[:-1]))
    else:
        return int(s)


async def run_campaign(args: argparse.Namespace) -> dict:
    """Run the full E2E campaign."""
    global _shutdown_requested

    target_key = args.target
    if target_key not in TARGETS:
        print(f"[E2E] Unknown target: {target_key}")
        print(f"[E2E] Available: {', '.join(TARGETS.keys())}")
        sys.exit(1)

    spec = TARGETS[target_key]
    duration_seconds = _parse_duration(args.duration)
    min_stall_seconds = args.min_stall_minutes * 60
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = log_dir / f"{target_key}_{timestamp}.json"

    test_dir = TESTS_DIR / "e2e_campaign"
    afl_in = test_dir / "in"
    afl_out = test_dir / "out"
    afl_sync = afl_out / "agentic" / "queue"

    print(f"\n{'═' * 70}")
    print(f"  E2E CAMPAIGN: {spec.name}")
    print(f"  {spec.description}")
    print(f"  Duration: {_format_duration(duration_seconds)}")
    print(f"  Stall threshold: {args.min_stall_minutes} min")
    print(f"  Results: {result_file}")
    print(f"{'═' * 70}\n")

    # ── Cleanup ───────────────────────────────────────────────────
    # Scoped to THIS campaign's output directory (H4 fix, shared with
    # campaign.py via _stale_afl_pkill_pattern) -- not every afl-fuzz
    # process on the host.
    try:
        subprocess.run(
            ["pkill", "-9", "-f", _stale_afl_pkill_pattern(afl_out)],
            capture_output=True, timeout=5,
        )
        import time as _time
        _time.sleep(2)
    except Exception:
        pass
    if test_dir.exists():
        shutil.rmtree(test_dir)
    afl_in.mkdir(parents=True)
    afl_sync.mkdir(parents=True, exist_ok=True)

    # ── Load seeds ────────────────────────────────────────────────
    if spec.seed_dir:
        seed_src = TARGETS_DIR / spec.seed_dir
        for seed_file in seed_src.glob("*"):
            if seed_file.is_file():
                shutil.copy(seed_file, afl_in / seed_file.name)
        print(f"[E2E] Loaded {len(list(afl_in.iterdir()))} seeds from {spec.seed_dir}")
    else:
        (afl_in / "seed1").write_bytes(spec.seed_bytes)

    # ── Compile ───────────────────────────────────────────────────
    binary = await compile_target(spec)
    stall_addr = resolve_symbol(binary, spec.stall_function)
    print(f"[E2E] ✓ Compiled: {binary.name}")
    print(f"[E2E] ✓ Known math wall: {spec.stall_function} @ {stall_addr}")
    print(f"[E2E]   (autonomous mode — agent will discover this independently)\n")

    # ── Start AFL++ ───────────────────────────────────────────────
    print(f"[E2E] ═══ Starting AFL++ + Agentic-AFL (concurrent) ═══")
    # NOTE: spec.custom_mutator is available but NOT loaded at startup.
    # Loading it at launch would fix CRC on initial seeds, bypassing the
    # wall before the agent fires — sabotaging the demo. The mutator is
    # designed for post-solve deployment (Level 3 benchmark).
    afl_proc = await run_afl(binary, afl_in, afl_out, afl_sync)
    await asyncio.sleep(3)

    # ── Start AgentLoop (NO stall_address_override) ──────────────
    agent = AgentLoop(
        afl_output_dir=afl_out,
        afl_sync_dir=afl_sync,
        target_binary=binary,
        stall_address_override=None,  # AUTONOMOUS MODE
        min_stall_cycles=10,
        register_signals=False,
    )
    # Override the stall detector's time-based threshold.
    await agent.setup()
    agent._stall_detector._min_stall_time_seconds = min_stall_seconds
    agent_task = asyncio.create_task(agent.run())

    # ── Main monitoring loop ──────────────────────────────────────
    start = time.monotonic()
    result = {
        "target": spec.name,
        "target_key": target_key,
        "duration_seconds": duration_seconds,
        "min_stall_seconds": min_stall_seconds,
        "start_time": datetime.now(timezone.utc).isoformat(),
        "baseline_edges": 0,
        "final_edges": 0,
        "payloads_injected": 0,
        "stalls_detected": 0,
        "react_turns": 0,
        "llm_calls": 0,
        "math_wall_bypassed": False,
        "full_accept": False,
        "bypass_evidence": None,
        "timeline": [],  # periodic snapshots
    }

    dashboard_interval = 30  # seconds between dashboard prints
    last_dashboard = 0
    last_snapshot = 0
    snapshot_interval = 60  # JSON snapshots every minute
    prev_execs = 0
    prev_execs_time = time.monotonic()

    # ── TUI or print-based dashboard ──────────────────────────────
    use_tui = getattr(args, 'tui', False) and _HAS_TUI
    tui_obj = None
    tui_state = None
    tui_live = None

    if use_tui:
        tui_state = TUIState(
            target_name=spec.name,
            target_desc=spec.description,
            duration_seconds=duration_seconds,
            start_time=start,
        )
        tui_obj = CampaignTUI(state=tui_state)
        tui_live = tui_obj.live()
        tui_live.__enter__()

        # Intercept agent logs for pipeline stage tracking.
        import logging as _logging
        class _TUILogHandler(_logging.Handler):
            def emit(self, record):
                msg = record.getMessage()
                # Map log messages to pipeline stages.
                stage_map = {
                    "Frontier discovery:": ("detect", "active"),
                    "Detected": ("detect", "done"),
                    "Running Ghidra": ("ghidra", "active"),
                    "Extracted slice:": ("ghidra", "done"),
                    "Profiled": ("profile", "done"),
                    "CARM query:": ("carm", "done"),
                    "Offset probe:": ("probe", "done"),
                    "Generating": ("llm", "active"),
                    "HTTP Request: POST": ("llm", "active"),
                    "Z3 sandbox result: verdict=sat": ("z3", "done"),
                    "Payload injected": ("inject", "done"),
                    "Diverse injection:": ("diverse", "done"),
                    "Stall.*marked as SOLVED": ("inject", "done"),
                    "restarted with CRC": ("mutator", "done"),
                }
                for pattern, (stage, status) in stage_map.items():
                    if pattern in msg:
                        tui_state.set_pipeline(stage, status)
                        tui_state.add_event(msg[:80], "success" if status == "done" else "info")
                        break

        _tui_handler = _TUILogHandler()
        _tui_handler.setLevel(_logging.INFO)
        _logging.getLogger("agentic_afl").addHandler(_tui_handler)
    else:
        print(f"[E2E] {'Time':>8s}  {'Edges':>6s}  {'Execs':>10s}  "
              f"{'Stalls':>6s}  {'Inject':>6s}  {'Status'}")
        print(f"[E2E] {'─' * 60}")

    while time.monotonic() - start < duration_seconds:
        if _shutdown_requested:
            print(f"\n[E2E] ⚡ Ctrl+C received — ending campaign early...")
            break

        await asyncio.sleep(5)
        elapsed = time.monotonic() - start
        current_edges = read_edges(afl_out)
        metrics = agent._metrics

        # Record baseline edges early.
        if elapsed < 10 and result["baseline_edges"] == 0:
            result["baseline_edges"] = current_edges

        # Dashboard output.
        if elapsed - last_dashboard >= dashboard_interval:
            last_dashboard = elapsed
            # Read execs from fuzzer_stats.
            execs = 0
            execs_str = "?"
            stats_file = afl_out / "default" / "fuzzer_stats"
            corpus_count = 0
            cycles_done = 0
            pending_favs = 0
            if stats_file.exists():
                try:
                    for line in stats_file.read_text().splitlines():
                        if line.startswith("execs_done"):
                            execs_str = line.split(":")[-1].strip()
                            execs = int(execs_str)
                        elif line.startswith("corpus_count"):
                            corpus_count = int(line.split(":")[-1].strip())
                        elif line.startswith("cycles_done"):
                            cycles_done = int(line.split(":")[-1].strip())
                        elif line.startswith("pending_favs"):
                            pending_favs = int(line.split(":")[-1].strip())
                except Exception:
                    pass

            # Compute execs/sec.
            now = time.monotonic()
            dt = now - prev_execs_time
            execs_per_sec = (execs - prev_execs) / dt if dt > 0 else 0
            prev_execs = execs
            prev_execs_time = now

            status = "fuzzing"
            if metrics["payloads_injected"] > 0:
                status = f"injected×{metrics['payloads_injected']}"
            if metrics["stalls_detected"] > 0 and metrics["payloads_injected"] == 0:
                status = f"stall×{metrics['stalls_detected']}"

            if use_tui and tui_state:
                tui_state.edges = current_edges
                tui_state.execs = execs
                tui_state.execs_per_sec = execs_per_sec
                tui_state.corpus_count = corpus_count
                tui_state.cycles_done = cycles_done
                tui_state.pending_favs = pending_favs
                tui_state.stalls_detected = metrics["stalls_detected"]
                tui_state.stalls_solved = metrics["stalls_processed"]
                tui_state.payloads_injected = metrics["payloads_injected"]
                tui_state.llm_calls = metrics["llm_calls_total"]
                tui_state.react_turns = metrics["react_turns_total"]
                tui_state.edge_history.append(current_edges)
                tui_obj.refresh()
            else:
                print(
                    f"[E2E] {_format_duration(elapsed):>8s}  "
                    f"{current_edges:>6d}  {execs_str:>10s}  "
                    f"{metrics['stalls_detected']:>6d}  "
                    f"{metrics['payloads_injected']:>6d}  "
                    f"{status}"
                )

        # Periodic timeline snapshot.
        if elapsed - last_snapshot >= snapshot_interval:
            last_snapshot = elapsed
            result["timeline"].append({
                "time_seconds": int(elapsed),
                "edges": current_edges,
                "stalls_detected": metrics["stalls_detected"],
                "payloads_injected": metrics["payloads_injected"],
            })

        # Check for bypass.
        accept_evidence = check_for_accept(
            afl_out, binary, spec.accept_marker,
        )
        if accept_evidence and not result.get("full_accept"):
            result["math_wall_bypassed"] = True
            result["full_accept"] = True
            result["bypass_evidence"] = accept_evidence
            result["bypass_time_seconds"] = int(elapsed)

            if use_tui and tui_state:
                tui_state.bypass_detected = True
                tui_state.bypass_time = elapsed
                tui_state.bypass_evidence = accept_evidence
                tui_state.add_event(f"FULL ACCEPT: {accept_evidence[:60]}", "success")
            else:
                print(f"\n[E2E] ✅ FULL ACCEPT detected: {accept_evidence}")
                print(f"[E2E]    at {_format_duration(elapsed)} into campaign")

            # ── Level 3: Deploy custom mutator ────────────────────
            # After solve, restart AFL++ with CRC-aware mutation so
            # every mutation produces a valid-CRC frame. This breaks
            # through the "avalanche plateau" where random mutation
            # always invalidates the checksum.
            if spec.custom_mutator:
                mutator_dir = TARGETS_DIR / spec.binary_name.replace("_harness", "")
                if not (mutator_dir / f"{spec.custom_mutator}.py").exists():
                    mutator_dir = TARGETS_DIR
                print(f"[E2E]    deploying custom mutator: {spec.custom_mutator}")
                if use_tui and tui_state:
                    tui_state.set_pipeline("mutator", "active")
                    tui_state.add_event(f"Deploying mutator: {spec.custom_mutator}", "info")
                _safe_terminate(afl_proc)
                try:
                    await asyncio.wait_for(afl_proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    afl_proc.kill()
                await asyncio.sleep(1)
                # Restart with mutator — resume with existing corpus.
                afl_proc = await run_afl(
                    binary, afl_in, afl_out, afl_sync,
                    custom_mutator_module=spec.custom_mutator,
                    mutator_dir=mutator_dir,
                    resume=True,
                )
                print(f"[E2E]    ✓ AFL++ restarted with CRC-aware mutator")
                if use_tui and tui_state:
                    tui_state.mutator_deployed = True
                    tui_state.mutator_name = spec.custom_mutator
                    tui_state.set_pipeline("mutator", "done")
                    tui_state.add_event("AFL++ restarted with CRC-aware mutator", "success")
            print(f"[E2E]    continuing campaign for coverage-over-time graph...\n")

        partial = check_partial_bypass(
            afl_out, binary, spec.stall_function,
        )
        if partial and not result["math_wall_bypassed"]:
            result["math_wall_bypassed"] = True
            print(f"\n[E2E] 🔓 Partial bypass: {partial}")

    # ── Finalize ──────────────────────────────────────────────────
    elapsed_total = time.monotonic() - start
    final_edges = read_edges(afl_out)
    final_metrics = agent._metrics

    result.update({
        "final_edges": final_edges,
        "payloads_injected": final_metrics["payloads_injected"],
        "stalls_detected": final_metrics["stalls_detected"],
        "react_turns": final_metrics["react_turns_total"],
        "llm_calls": final_metrics["llm_calls_total"],
        "elapsed_seconds": int(elapsed_total),
        "end_time": datetime.now(timezone.utc).isoformat(),
    })

    # Write JSON results.
    result_file.write_text(json.dumps(result, indent=2))

    # Close TUI before printing summary.
    if use_tui and tui_live:
        tui_live.__exit__(None, None, None)

    print(f"\n[E2E] Results written to {result_file}")

    # ── Cleanup ───────────────────────────────────────────────────
    print("[E2E] Cleaning up...")
    agent._running = False
    try:
        await asyncio.wait_for(agent_task, timeout=10)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        agent_task.cancel()
    _safe_terminate(afl_proc)
    try:
        await asyncio.wait_for(afl_proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        afl_proc.kill()
    print("[E2E] ✓ Cleanup complete")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  E2E CAMPAIGN RESULTS — {spec.name}")
    print(f"{'═' * 70}")
    print(f"  Duration:         {_format_duration(elapsed_total)}")
    print(f"  Baseline edges:   {result['baseline_edges']}")
    print(f"  Final edges:      {final_edges}")
    edge_delta = final_edges - result["baseline_edges"]
    if result["baseline_edges"] > 0:
        edge_pct = edge_delta / result["baseline_edges"] * 100
        print(f"  Edge gain:        +{edge_delta} ({edge_pct:+.1f}%)")
    print(f"  Stalls detected:  {final_metrics['stalls_detected']}")
    print(f"  Payloads injected:{final_metrics['payloads_injected']}")
    print(f"  LLM calls:        {final_metrics['llm_calls_total']}")
    print(f"  Math wall bypass: {'✅ YES' if result['math_wall_bypassed'] else '❌ NO'}")
    print(f"  Full ACCEPT:      {'✅ YES' if result['full_accept'] else '❌ NO'}")
    if result["bypass_evidence"]:
        print(f"  Evidence:         {result['bypass_evidence']}")
    print(f"{'═' * 70}\n")

    return result


def main():
    global _shutdown_requested

    parser = argparse.ArgumentParser(
        description="Run a true E2E Agentic-AFL campaign",
    )
    parser.add_argument(
        "target",
        help=f"Target key: {', '.join(TARGETS.keys())}",
    )
    parser.add_argument(
        "--duration", default="1h",
        help="Campaign duration (e.g., '6h', '30m', '90s'). Default: 1h",
    )
    parser.add_argument(
        "--min-stall-minutes", type=int, default=5,
        help="Minutes of no new edges before triggering agent. Default: 5",
    )
    parser.add_argument(
        "--log-dir", default="./e2e_results",
        help="Directory for JSON result files. Default: ./e2e_results",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug mode (save raw LLM completions)",
    )
    parser.add_argument(
        "--tui", action="store_true",
        help="Enable rich TUI dashboard (requires 'rich' package)",
    )
    args = parser.parse_args()

    if args.debug:
        os.environ["DEBUG_MODE"] = "1"

    # Set up logging.
    import logging
    if args.tui and _HAS_TUI:
        # In TUI mode, suppress console logging — the TUI handler captures
        # agent events directly and renders them in the Events panel.
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        # Ensure the agentic_afl logger still fires at INFO for the handler.
        logging.getLogger("agentic_afl").setLevel(logging.INFO)
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

    # Signal handling.
    def _sighandler(sig, frame):
        global _shutdown_requested
        _shutdown_requested = True

    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    asyncio.run(run_campaign(args))


if __name__ == "__main__":
    main()
