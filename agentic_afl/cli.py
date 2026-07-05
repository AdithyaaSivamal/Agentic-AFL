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
    log_dir = Path(args.log_dir) if args.log_dir else None

    # Validate QEMU sysroot.
    qemu_sysroot = None
    if args.qemu_sysroot:
        qemu_sysroot = Path(args.qemu_sysroot).resolve()
        if not qemu_sysroot.is_dir():
            print(
                f"error: QEMU sysroot not found: {qemu_sysroot}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Validate QEMU preload shim.
    qemu_preload = None
    if args.qemu_preload:
        qemu_preload = Path(args.qemu_preload).resolve()
        if not qemu_preload.exists():
            print(
                f"error: QEMU preload shim not found: {qemu_preload}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Validate custom mutator path before printing the banner.
    # Resolve relative to CWD so the error shows the absolute path the
    # user actually needs to provide.
    custom_mutator = None
    if args.custom_mutator:
        custom_mutator = Path(args.custom_mutator).resolve()
        if not custom_mutator.exists():
            print(
                f"error: custom mutator not found: {custom_mutator}\n"
                f"  (given: {args.custom_mutator})\n"
                f"  Use an absolute path or a path relative to your current directory.",
                file=sys.stderr,
            )
            sys.exit(1)

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
    if args.qemu:
        print(f"  Mode:     QEMU user-mode (-Q)")
    if qemu_sysroot:
        print(f"  Sysroot:  {qemu_sysroot}")
    if qemu_preload:
        print(f"  Preload:  {qemu_preload.name}")
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
        qemu_mode=args.qemu,
        qemu_sysroot=qemu_sysroot,
        qemu_preload=qemu_preload,
        stall_address=getattr(args, 'stall_address', None),
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
#  SUBCOMMAND: check
# ═══════════════════════════════════════════════════════════════════════

def cmd_check(args: argparse.Namespace) -> None:
    """
    Run pre-flight diagnostics for Agentic-AFL.

    Validates all external dependencies (Ghidra, LLM API key, PostgreSQL)
    and reports their status. This is the same logic that runs at the start
    of every 'agentic-afl fuzz' campaign, exposed as a standalone diagnostic.

    Usage:
        agentic-afl check          # Check all dependencies
        agentic-afl check --fix    # Show how to fix each issue
    """
    from agentic_afl.config import settings
    from agentic_afl.orchestrator.agent_loop import AgentLoop

    # Configure logging.
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    agent = AgentLoop(
        afl_output_dir="/tmp/agentic_afl_check",
        afl_sync_dir="/tmp/agentic_afl_check_sync",
        register_signals=False,
    )

    print(f"\n{'═' * 60}")
    print(f"  AGENTIC-AFL PRE-FLIGHT CHECK")
    print(f"{'═' * 60}\n")

    all_ok = True

    # ── 1. Ghidra ────────────────────────────────────────────────
    try:
        agent._validate_ghidra()
        print(f"  ✅ Ghidra          — found")
    except RuntimeError as e:
        all_ok = False
        print(f"  ❌ Ghidra          — NOT FOUND")
        if args.fix:
            for line in str(e).strip().split("\n"):
                print(f"     {line}")

    # ── 2. LLM API Key ──────────────────────────────────────────
    try:
        asyncio.run(_check_llm_key(agent))
        print(f"  ✅ LLM API key     — validated ({settings.llm_api_provider})")
    except RuntimeError as e:
        all_ok = False
        print(f"  ❌ LLM API key     — INVALID ({settings.llm_api_provider})")
        if args.fix:
            for line in str(e).strip().split("\n"):
                print(f"     {line}")

    # ── 3. PostgreSQL ────────────────────────────────────────────
    # The connect + close MUST happen inside a SINGLE asyncio.run() call:
    # an asyncpg connection is bound to the event loop that created it, so
    # closing it from a second asyncio.run() (a fresh loop) raises
    # "RuntimeError: Event loop is closed" and falsely flips all_ok=False
    # even when PostgreSQL is perfectly healthy.
    try:
        used_fallback = asyncio.run(_check_postgres(agent))
        if used_fallback:
            print(f"  ⚠️  PostgreSQL     — unavailable (in-memory fallback)")
        else:
            print(f"  ✅ PostgreSQL      — connected")
    except Exception as e:
        all_ok = False
        print(f"  ❌ PostgreSQL      — ERROR: {e}")

    # ── 4. Z3 Solver ─────────────────────────────────────────────
    try:
        import z3
        print(f"  ✅ Z3 solver       — v{z3.get_version_string()}")
    except ImportError:
        all_ok = False
        print(f"  ❌ Z3 solver       — NOT INSTALLED")
        if args.fix:
            print(f"     pip install z3-solver")

    # ── 5. AFL++ ─────────────────────────────────────────────────
    import shutil
    afl_fuzz = shutil.which("afl-fuzz")
    if afl_fuzz:
        print(f"  ✅ AFL++           — {afl_fuzz}")
    else:
        print(f"  ⚠️  AFL++           — not on PATH (needed for 'agentic-afl fuzz')")

    print(f"\n{'═' * 60}")
    if all_ok:
        print(f"  All checks passed. Ready to fuzz.")
    else:
        print(f"  Some checks failed. Run with --fix for remediation steps.")
    print(f"{'═' * 60}\n")

    sys.exit(0 if all_ok else 1)


async def _check_llm_key(agent):
    """Async wrapper for LLM key validation."""
    await agent._validate_llm_api_key()


async def _check_postgres(agent) -> bool:
    """Connect to the spec store and close it within one event loop.

    Returns True if the in-memory fallback was used (PostgreSQL
    unavailable), False if a real PostgreSQL connection succeeded.

    Connect + close happen in the same coroutine (hence the same event
    loop) so the asyncpg connection can be torn down cleanly — see the
    caller for why this matters.
    """
    from agentic_afl.database.memory_store import InMemorySpecStore

    store = await agent._initialize_store()
    used_fallback = isinstance(store, InMemorySpecStore)
    try:
        await store.close()
    except Exception:
        # Best-effort cleanup; a close failure must not mask a successful
        # connection in the diagnostic result.
        pass
    return used_fallback


# ═══════════════════════════════════════════════════════════════════════
#  SUBCOMMAND: analyze
# ═══════════════════════════════════════════════════════════════════════

def cmd_analyze(args: argparse.Namespace) -> None:
    """
    Run the extraction pipeline on a binary WITHOUT fuzzing.

    This is a diagnostic command that exercises the same code paths
    as the full fuzzing campaign, but stops after constraint profiling.

    Workflow:
        1. Validate Ghidra installation.
        2. Run P-Code slicer on the target binary at the given address.
        3. Profile the slice (ConstraintProfiler).
        4. Print the structural tags, metrics, and strategy hint.

    Usage:
        agentic-afl analyze ./binary --address 0x0000d7e4
    """
    from agentic_afl.config import settings

    binary = Path(args.binary).resolve()
    if not binary.exists():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        sys.exit(1)

    # Configure logging.
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s %(name)s: %(message)s")

    asyncio.run(_run_analyze(binary, args.address, args.depth, args.arch))


async def _run_analyze(binary: Path, address: str, depth: int, arch: str) -> None:
    """Execute the extraction + profiling pipeline."""
    from agentic_afl.extractor.pcode_slicer import PCodeSlicer
    from agentic_afl.extractor.constraint_profiler import ConstraintProfiler
    from agentic_afl.constants import Architecture

    print(f"\n{'═' * 60}")
    print(f"  AGENTIC-AFL STATIC ANALYSIS")
    print(f"{'═' * 60}")
    print(f"  Binary:   {binary}")
    print(f"  Address:  {address}")
    print(f"  Arch:     {arch}")
    print(f"{'─' * 60}\n")

    # Step 1: Slice.
    print("  [1/3] Running Ghidra P-Code extraction...")
    slicer = PCodeSlicer()
    try:
        pcode_slice = slicer.extract_slice(
            binary_path=binary,
            stall_address=address,
            taint_source="stdin",
        )
    except Exception as e:
        print(f"\n  ❌ Extraction failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"        ✓ {pcode_slice.instruction_count} P-Code instructions extracted")
    print(f"        ✓ Function: {pcode_slice.function_name} @ {pcode_slice.function_entry}")
    print(f"        ✓ Slice depth: {pcode_slice.slice_depth} basic blocks")
    if pcode_slice.truncated:
        print(f"        ⚠ Slice was truncated (token budget)")

    # Step 2: Profile.
    print("\n  [2/3] Running constraint profiler...")
    profiler = ConstraintProfiler()
    profile = profiler.analyze(pcode_slice)

    tag_names = sorted(t.name for t in profile.tags)
    print(f"        ✓ Tags detected: {len(profile.tags)}")
    for tag in tag_names:
        print(f"          • {tag}")

    # Step 3: Print metrics.
    print(f"\n  [3/3] Structural metrics:")
    print(f"        Bitwise density:     {profile.bitwise_density:.4f}")
    print(f"        Arithmetic density:  {profile.arithmetic_density:.4f}")
    print(f"        Loop depth:          {profile.loop_depth}")
    print(f"        Register count:      {profile.register_count}")
    print(f"        Estimated complexity: {profile.estimated_complexity}/100")

    # Strategy hint based on tags.
    print(f"\n{'─' * 60}")
    print(f"  STRATEGY HINT:")
    if not profile.tags:
        print(f"    No structural tags detected — likely a simple comparison.")
    else:
        from agentic_afl.constants import ConstraintTag
        if ConstraintTag.BITWISE_LOOP in profile.tags:
            print(f"    → CRC/hash-like: Unroll loop, model as GF(2) polynomial")
        if ConstraintTag.INDEXED_LOOKUP in profile.tags:
            print(f"    → Table lookup: Inline table values as Array() in Z3")
        if ConstraintTag.CONSTANT_EQUALITY in profile.tags:
            print(f"    → Magic number check: Direct BitVec equality constraint")
        if ConstraintTag.BITMASK_CHECK in profile.tags:
            print(f"    → Bitmask: Extract/Assert specific bit patterns")
        if ConstraintTag.CALLEE_DEPENDENCY in profile.tags:
            print(f"    → Callee: May need to inline called function's semantics")

    # Print P-Code slice.
    if pcode_slice.decompiled_c:
        print(f"\n{'─' * 60}")
        print(f"  DECOMPILED C:")
        for line in pcode_slice.decompiled_c.split("\n")[:30]:
            print(f"    {line}")
        if pcode_slice.decompiled_c.count("\n") > 30:
            print(f"    ... ({pcode_slice.decompiled_c.count(chr(10)) - 30} more lines)")

    print(f"\n{'═' * 60}\n")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser.

    Extracted from main() so the CLI surface can be unit-tested without
    executing any subcommand (health-review: cli.py was at 0% coverage).
    """
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
    fuzz_parser.add_argument(
        "--qemu", action="store_true",
        help="Enable QEMU user-mode (-Q) for cross-architecture firmware targets.",
    )
    fuzz_parser.add_argument(
        "--qemu-sysroot", default=None,
        help="Path to firmware root filesystem (sets QEMU_LD_PREFIX).",
    )
    fuzz_parser.add_argument(
        "--qemu-preload", default=None,
        help="Path to ARM-compiled LD_PRELOAD shim (sets AFL_PRELOAD).",
    )
    fuzz_parser.add_argument(
        "--stall-address", default=None,
        help="Override stall address (hex, e.g. 0x0000d7e4) for stripped binaries "
             "where nm/GDB cannot discover frontier functions.",
    )

    # ── check ─────────────────────────────────────────────────────
    check_parser = subparsers.add_parser(
        "check",
        help="Validate environment: Ghidra, LLM API key, PostgreSQL, Z3, AFL++.",
        description=(
            "Run pre-flight diagnostics to verify all external dependencies "
            "are properly configured. Exit code 0 = all critical checks pass."
        ),
    )
    check_parser.add_argument(
        "--fix", action="store_true",
        help="Show remediation instructions for each failed check.",
    )
    check_parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging.",
    )

    # ── analyze ───────────────────────────────────────────────────
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run static analysis (P-Code extraction + profiling) on a binary.",
        description=(
            "Extract a P-Code backward slice from a binary at a given address, "
            "run the constraint profiler, and print structural tags + strategy hints. "
            "Does NOT launch AFL++ — useful for pre-campaign investigation."
        ),
    )
    analyze_parser.add_argument(
        "binary",
        help="Path to the target binary.",
    )
    analyze_parser.add_argument(
        "--address", required=True,
        help="Target address (hex, e.g. 0x0000d7e4).",
    )
    analyze_parser.add_argument(
        "--depth", type=int, default=20,
        help="Maximum backward slice depth (basic blocks). Default: 20",
    )
    analyze_parser.add_argument(
        "--arch", default="x86_64",
        help="Target architecture (arm32, arm64, x86, x86_64, mips32). Default: x86_64",
    )
    analyze_parser.add_argument(
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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "fuzz":
        cmd_fuzz(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "plot":
        cmd_plot(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

