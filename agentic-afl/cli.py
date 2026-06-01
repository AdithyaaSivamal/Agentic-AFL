"""
cli.py — Subcommand-based CLI for Agentic-AFL.

Usage:
    agentic-afl fuzz ./harness -i ./seeds --duration 1h --tui
    agentic-afl plot ./results/campaign.json -o coverage.png

Architecture:
    Follows the git/docker/cargo pattern — subcommands that scale.
    Each subcommand is a function that receives parsed args.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path


def _parse_duration(s: str) -> int:
    """Parse '6h', '30m', '90s' into seconds."""
    s = s.strip().lower()
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    elif s.endswith("m"):
        return int(float(s[:-1]) * 60)
    elif s.endswith("s"):
        return int(float(s[:-1]))
    return int(s)


def _format_duration(seconds: float) -> str:
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    if h > 0:
        return f"{h}h{m:02d}m{s:02d}s"
    elif m > 0:
        return f"{m}m{s:02d}s"
    return f"{s}s"


# ═══════════════════════════════════════════════════════════════════════
#  SUBCOMMAND: fuzz
# ═══════════════════════════════════════════════════════════════════════

def cmd_fuzz(args: argparse.Namespace) -> None:
    """Run an Agentic-AFL fuzzing campaign."""
    from agentic_afl.campaign import CampaignRunner

    harness = Path(args.harness).resolve()
    seed_dir = Path(args.seeds).resolve()

    if not harness.exists():
        print(f"error: harness not found: {harness}", file=sys.stderr)
        sys.exit(1)
    if not seed_dir.exists():
        print(f"error: seed directory not found: {seed_dir}", file=sys.stderr)
        sys.exit(1)

    duration = _parse_duration(args.duration)
    custom_mutator = Path(args.custom_mutator) if args.custom_mutator else None
    log_dir = Path(args.log_dir) if args.log_dir else None

    # ── TUI setup ─────────────────────────────────────────────────
    use_tui = args.tui
    tui_obj = None
    tui_state = None
    tui_live = None

    if use_tui:
        try:
            from agentic_afl.tui import CampaignTUI, TUIState
        except ImportError:
            print("error: --tui requires 'rich' package (pip install rich)",
                  file=sys.stderr)
            sys.exit(1)

    # ── Logging ───────────────────────────────────────────────────
    if use_tui:
        # Suppress console logging — TUI captures events.
        logging.basicConfig(level=logging.WARNING,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        logging.getLogger("agentic_afl").setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # ── Banner ────────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  AGENTIC-AFL")
    print(f"  Target:   {harness.name}")
    print(f"  Seeds:    {seed_dir} ({len(list(seed_dir.iterdir()))} files)")
    print(f"  Duration: {_format_duration(duration)}")
    print(f"  Stall:    {args.stall_minutes}m threshold")
    if custom_mutator:
        print(f"  Mutator:  {custom_mutator.name}")
    if log_dir:
        print(f"  Logs:     {log_dir}")
    print(f"{'═' * 70}\n")

    # ── Build runner ──────────────────────────────────────────────
    runner = CampaignRunner(
        harness=harness,
        seed_dir=seed_dir,
        duration=duration,
        stall_minutes=args.stall_minutes,
        accept_marker=args.accept_marker,
        custom_mutator=custom_mutator,
        log_dir=log_dir,
        target_name=args.name or harness.stem,
    )

    # ── TUI callback ──────────────────────────────────────────────
    if use_tui:
        from agentic_afl.tui import CampaignTUI, TUIState

        tui_state = TUIState(
            target_name=args.name or harness.stem,
            target_desc=str(harness),
            duration_seconds=duration,
        )
        tui_obj = CampaignTUI(state=tui_state)

        # Log interceptor for pipeline stages.
        class _TUILogHandler(logging.Handler):
            def emit(self, record):
                msg = record.getMessage()
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
                    "restarted with CRC": ("mutator", "done"),
                }
                for pattern, (stage, status) in stage_map.items():
                    if pattern in msg:
                        tui_state.set_pipeline(stage, status)
                        tui_state.add_event(
                            msg[:80],
                            "success" if status == "done" else "info",
                        )
                        break

        handler = _TUILogHandler()
        handler.setLevel(logging.INFO)
        logging.getLogger("agentic_afl").addHandler(handler)

        def on_update(snap):
            import time as _t
            if tui_state.start_time == 0:
                tui_state.start_time = _t.monotonic() - snap.elapsed
            tui_state.edges = snap.edges
            tui_state.baseline_edges = snap.baseline_edges
            tui_state.execs = snap.execs
            tui_state.execs_per_sec = snap.execs_per_sec
            tui_state.corpus_count = snap.corpus_count
            tui_state.cycles_done = snap.cycles_done
            tui_state.pending_favs = snap.pending_favs
            tui_state.stalls_detected = snap.stalls_detected
            tui_state.stalls_solved = snap.stalls_solved
            tui_state.payloads_injected = snap.payloads_injected
            tui_state.llm_calls = snap.llm_calls
            tui_state.react_turns = snap.react_turns
            tui_state.edge_history = snap.edge_history
            tui_state.bypass_detected = snap.bypass_detected
            tui_state.bypass_time = snap.bypass_time
            tui_state.bypass_evidence = snap.bypass_evidence
            tui_state.mutator_deployed = snap.mutator_deployed
            tui_state.mutator_name = snap.mutator_name
            tui_obj.refresh()

        runner.on_update = on_update
    else:
        # Print-based dashboard callback.
        _last_print = [0.0]

        def on_update(snap):
            import time as _t
            now = _t.monotonic()
            if now - _last_print[0] < 25:
                return
            _last_print[0] = now
            status = "fuzzing"
            if snap.payloads_injected > 0:
                status = f"injected×{snap.payloads_injected}"
            elif snap.stalls_detected > 0:
                status = f"stall×{snap.stalls_detected}"
            print(
                f"  {_format_duration(snap.elapsed):>8s}  "
                f"{snap.edges:>6d}  {snap.execs:>10d}  "
                f"{snap.stalls_detected:>6d}  "
                f"{snap.payloads_injected:>6d}  "
                f"{status}"
            )

        runner.on_update = on_update
        print(f"  {'Time':>8s}  {'Edges':>6s}  {'Execs':>10s}  "
              f"{'Stalls':>6s}  {'Inject':>6s}  {'Status'}")
        print(f"  {'─' * 60}")

    # ── Signal handling ───────────────────────────────────────────
    def _sighandler(sig, frame):
        runner.request_shutdown()

    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    # ── Run ───────────────────────────────────────────────────────
    if use_tui:
        tui_live = tui_obj.live()
        tui_live.__enter__()

    try:
        result = asyncio.run(runner.run())
    finally:
        if use_tui and tui_live:
            tui_live.__exit__(None, None, None)

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  CAMPAIGN RESULTS — {result.target_name}")
    print(f"{'═' * 70}")
    print(f"  Duration:          {_format_duration(result.elapsed_seconds)}")
    print(f"  Baseline edges:    {result.baseline_edges}")
    print(f"  Final edges:       {result.final_edges}")
    print(f"  Edge gain:         +{result.edge_gain} ({result.edge_gain_pct:+.1f}%)")
    print(f"  Stalls detected:   {result.stalls_detected}")
    print(f"  Payloads injected: {result.payloads_injected}")
    print(f"  LLM calls:         {result.llm_calls}")
    print(f"  Math wall bypass:  {'✅ YES' if result.bypass_detected else '❌ NO'}")
    if result.bypass_evidence:
        print(f"  Evidence:          {result.bypass_evidence}")
    if result.mutator_deployed:
        print(f"  Custom mutator:    ✅ DEPLOYED")
    print(f"{'═' * 70}\n")


# ═══════════════════════════════════════════════════════════════════════
#  SUBCOMMAND: plot
# ═══════════════════════════════════════════════════════════════════════

def cmd_plot(args: argparse.Namespace) -> None:
    """Generate a coverage-over-time plot from campaign JSON results."""
    import importlib.util

    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"error: file not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    # Try to import the plot module from experiments.
    plot_script = Path(__file__).resolve().parents[1] / "experiments" / "tests" / "plot_coverage.py"
    if not plot_script.exists():
        # Fallback: inline minimal plotter.
        print("error: plot_coverage.py not found", file=sys.stderr)
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("plot_coverage", plot_script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    output = args.output or json_path.with_suffix(".png")
    mod.plot_campaign(str(json_path), str(output))
    print(f"✓ Plot saved: {output}")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentic-afl",
        description="Neuro-symbolic fuzzing orchestration for ICS/OT targets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── fuzz ──────────────────────────────────────────────────────
    fuzz_parser = subparsers.add_parser(
        "fuzz",
        help="Run an Agentic-AFL fuzzing campaign.",
        description=(
            "Launch AFL++ with the AgentLoop co-process. "
            "The harness must be pre-compiled with afl-cc."
        ),
    )
    fuzz_parser.add_argument(
        "harness",
        help="Path to AFL++-instrumented harness binary.",
    )
    fuzz_parser.add_argument(
        "-i", "--seeds", required=True,
        help="Directory containing initial seed corpus.",
    )
    fuzz_parser.add_argument(
        "--duration", default="1h",
        help="Campaign duration (e.g., '6h', '30m', '90s'). Default: 1h",
    )
    fuzz_parser.add_argument(
        "--stall-minutes", type=int, default=5,
        help="Minutes of edge plateau before triggering agent. Default: 5",
    )
    fuzz_parser.add_argument(
        "--accept-marker", default="ACCEPT",
        help="Stdout marker indicating math wall bypass. Default: ACCEPT",
    )
    fuzz_parser.add_argument(
        "--custom-mutator", default=None,
        help="Path to Python custom mutator script for post-solve deployment.",
    )
    fuzz_parser.add_argument(
        "--log-dir", default=None,
        help="Directory for JSON result files.",
    )
    fuzz_parser.add_argument(
        "--name", default=None,
        help="Campaign name (default: harness filename).",
    )
    fuzz_parser.add_argument(
        "--tui", action="store_true",
        help="Enable rich TUI dashboard.",
    )
    fuzz_parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging.",
    )

    # ── plot ──────────────────────────────────────────────────────
    plot_parser = subparsers.add_parser(
        "plot",
        help="Generate coverage-over-time plot from campaign results.",
    )
    plot_parser.add_argument(
        "json_file",
        help="Path to campaign JSON result file.",
    )
    plot_parser.add_argument(
        "-o", "--output", default=None,
        help="Output image path (default: same name as JSON with .png).",
    )

    args = parser.parse_args()

    if args.command == "fuzz":
        cmd_fuzz(args)
    elif args.command == "plot":
        cmd_plot(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
