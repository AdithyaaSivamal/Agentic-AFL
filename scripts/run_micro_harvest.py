#!/usr/bin/env python3
"""
run_micro_harvest.py — Run AutoHarvest on existing generalization matrix targets.

This is Step 2 of the CARM bootstrap sequence:
  Step 1: IndusCP ETL      → DONE (149 seed entries)
  Step 2: Micro-Harvest    → THIS SCRIPT
  Step 3: Protocol Siege   → grbl / lib60870

For each target, this script:
  1. Compiles the target with afl-cc
  2. Launches AFL++ for a baseline period
  3. Starts AgentLoop with harvest_mode=True
  4. When a stall is detected → zero-shot solve → verify via edge delta
  5. If verified → auto-commits (P-Code, Tags, Z3) triplet to PostgreSQL

Usage:
    # Run all targets (custom_hash + arithmetic):
    python scripts/run_micro_harvest.py

    # Run a specific target:
    python scripts/run_micro_harvest.py custom_hash
    python scripts/run_micro_harvest.py arithmetic

    # With custom timeouts:
    python scripts/run_micro_harvest.py --baseline 60 --agent-timeout 300
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Add project root.
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from agentic_afl.orchestrator.agent_loop import AgentLoop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("harvest")

# ── Paths ──────────────────────────────────────────────────────────────
TARGETS_DIR = ROOT_DIR / "experiments" / "test_targets"
HARVEST_DIR = ROOT_DIR / "experiments" / "harvest_runs"

# ── Target Definitions (subset of test_generalization_matrix.py) ──────
HARVEST_TARGETS = {
    "custom_hash": {
        "name": "Custom Hash",
        "source": "custom_hash_target.c",
        "binary": "custom_hash_harness",
        "stall_func": "check_hash",
        "seed": b"\xAA\x10\x00\x00\x00\x00\x00\x01",
        "description": "Rotate-XOR-accumulate hash (novel, not in any corpus)",
    },
    "arithmetic": {
        "name": "Arithmetic",
        "source": "arithmetic_constraint_target.c",
        "binary": "arithmetic_harness",
        "stall_func": "check_linear",
        "seed": b"\x01\x50\x00\x30\x00\x00\x00",
        "description": "Pure linear arithmetic (a*7 + b*13)",
    },
    "lib60870": {
        "name": "lib60870 APCI Parser",
        "source": None,  # Uses build script, not single-file compilation
        "binary": "lib60870_harness",
        "build_script": "build_lib60870_harness.sh",
        "stall_func": "checkSequenceNumber",
        "seed_dir": "lib60870_seeds",  # Directory of seed files
        "seed": b"\x68\x04\x07\x00\x00\x00",  # Fallback: STARTDT_ACT
        "description": "IEC 60870-5-104 APCI frame parser (real-world)",
    },
}


async def compile_target(name: str, target: dict) -> Path:
    """Compile target with afl-cc (single-file) or a build script."""
    out = TARGETS_DIR / target["binary"]

    if target.get("build_script"):
        # Complex target with custom build script
        script = TARGETS_DIR / target["build_script"]
        logger.info("Compiling %s with build script...", name)
        proc = await asyncio.create_subprocess_exec(
            "bash", str(script), "afl-cc",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error("Build script failed:\n%s\n%s", stdout.decode(), stderr.decode())
            sys.exit(1)
    elif target.get("source"):
        # Simple single-file target
        src = TARGETS_DIR / target["source"]
        logger.info("Compiling %s with afl-cc...", name)
        proc = await asyncio.create_subprocess_exec(
            "afl-cc", "-O1", "-g", "-no-pie", str(src), "-o", str(out),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error("Compilation failed: %s", stderr.decode())
            sys.exit(1)
    else:
        if not out.exists():
            logger.error("No source or build script, and binary %s not found", out)
            sys.exit(1)

    logger.info("✓ Compiled %s", out)
    return out


def resolve_symbol(binary: Path, symbol: str) -> str:
    """Find the address of a symbol via nm (supports both global and local symbols)."""
    result = subprocess.run(["nm", str(binary)], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        # nm format: "address type name" — match both T (global) and t (local)
        if len(parts) >= 3 and parts[2] == symbol and parts[1].lower() == "t":
            return f"0x{parts[0]}"
    logger.warning("Could not resolve %s — using 0x000000", symbol)
    return "0x000000"


def read_edges(afl_out: Path) -> int:
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


def cleanup_afl_state(run_dir: Path):
    """
    Clean up stale AFL++ state from previous runs.

    Removes:
      - The entire harvest run directory (output, queue, stats)
      - OLD e2e_run directories from test_generalization_matrix.py
        (these contain solved payloads that AFL++ syncs from, causing
        phantom baseline edge inflation)
      - Stale AFL++ lock files and SHM segments in /tmp
      - Leftover Ghidra project dirs in /tmp

    Also kills any stale afl-fuzz processes from previous aborted runs.
    """
    # SIGKILL stale afl-fuzz processes. SIGTERM (-q) is insufficient
    # because orphaned AFL++ processes may ignore it and continue
    # writing stale queue entries that cause phantom edge inflation.
    try:
        result = subprocess.run(
            ["killall", "-9", "-q", "afl-fuzz"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            logger.info("SIGKILL'd stale afl-fuzz processes")
            # Give OS time to reclaim SHM and release locks.
            time.sleep(2)
    except Exception:
        pass

    # Remove this target's harvest run directory.
    if run_dir.exists():
        logger.info("Cleaning up stale run directory: %s", run_dir)
        shutil.rmtree(run_dir)

    # Remove OLD e2e_run directories from test_generalization_matrix.py.
    # These contain previously solved payloads that AFL++ can discover
    # via sync, causing the "phantom sync" edge inflation.
    e2e_dir = ROOT_DIR / "experiments" / "tests" / "e2e_run"
    if e2e_dir.exists():
        logger.info("Cleaning up stale e2e_run: %s", e2e_dir)
        shutil.rmtree(e2e_dir)

    # Remove stale AFL++ lock files and SHM segments.
    for lock in Path("/tmp").glob(".afl_*"):
        try:
            lock.unlink()
            logger.info("Removed stale lock: %s", lock)
        except OSError:
            pass
    for shm in Path("/dev/shm").glob("afl_*"):
        try:
            shm.unlink()
            logger.info("Removed stale SHM: %s", shm)
        except OSError:
            pass

    # Remove leftover Ghidra project dirs.
    ghidra_proj = Path("/tmp/ghidra_projects")
    if ghidra_proj.exists():
        shutil.rmtree(ghidra_proj, ignore_errors=True)


async def harvest_target(
    key: str,
    baseline_secs: int = 60,
    agent_timeout_secs: int = 300,
) -> dict:
    """Run one harvest cycle for a single target."""
    target = HARVEST_TARGETS[key]
    run_dir = HARVEST_DIR / key
    afl_in = run_dir / "in"
    afl_out = run_dir / "out"

    # CRITICAL: Create a fake "agentic" secondary instance directory.
    # AFL++ with `-M default` auto-syncs from sibling instance queues:
    #   afl_out/default/queue/   ← AFL++ owns this, does NOT re-import from it
    #   afl_out/agentic/queue/   ← We write here, AFL++ discovers via sync cycle
    # Writing directly into default/queue/ was the cause of the verification
    # failure: AFL++ never re-scanned its own queue for externally added files.
    afl_sync = afl_out / "agentic" / "queue"

    print(f"\n{'═' * 60}")
    print(f"  HARVEST: {target['name']}")
    print(f"  {target['description']}")
    print(f"{'═' * 60}\n")

    # ── Cleanup stale state from previous runs ────────────────────
    cleanup_afl_state(run_dir)
    afl_in.mkdir(parents=True)
    # Support both single seed bytes and seed directories
    if target.get("seed_dir"):
        seed_src = TARGETS_DIR / target["seed_dir"]
        for seed_file in seed_src.glob("*"):
            shutil.copy(seed_file, afl_in / seed_file.name)
        logger.info("Copied %d seed files from %s", len(list(afl_in.iterdir())), seed_src)
    else:
        (afl_in / "seed1").write_bytes(target["seed"])

    # Pre-create the agentic sync directory so PayloadInjector can write to it.
    afl_sync.mkdir(parents=True, exist_ok=True)

    # Compile.
    binary = await compile_target(target["name"], target)
    stall_addr = resolve_symbol(binary, target["stall_func"])

    # ── Phase 1: AFL++ Baseline ──────────────────────────────────
    print(f"\n[HARVEST] ═══ Phase 1: AFL++ Baseline ({baseline_secs}s) ═══")

    env = os.environ.copy()
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_SKIP_CPUFREQ"] = "1"
    # Disable auto-import during baseline to prevent phantom edge inflation
    # from any external files. AFL++ should explore ONLY from the seed.
    env["AFL_IMPORT_FIRST"] = "0"
    env["AFL_NO_UI"] = "1"
    # Force AFL++ to check foreign sync directories frequently.
    # Default is ~30 minutes; we need it every ~1 minute for harvest.
    env["AFL_SYNC_TIME"] = "1"

    afl_proc = await asyncio.create_subprocess_exec(
        "afl-fuzz", "-M", "default",
        "-F", str(afl_sync),  # Foreign fuzzer dir — AFL++ actively imports from here
        "-i", str(afl_in), "-o", str(afl_out),
        "--", str(binary), "@@",
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.sleep(5)

    for i in range(0, baseline_secs - 5, 10):
        edges = read_edges(afl_out)
        print(f"[HARVEST]   Baseline t={i+5:3d}s: edges={edges}")
        await asyncio.sleep(10)

    baseline_edges = read_edges(afl_out)
    print(f"[HARVEST]   Baseline final: edges={baseline_edges}")

    # ── Phase 2: AgentLoop with harvest_mode=True ────────────────
    print(f"\n[HARVEST] ═══ Phase 2: Harvest Mode ({agent_timeout_secs}s timeout) ═══")
    print("[HARVEST] CARM retrieval DISABLED — zero-shot LLM generation only")
    print("[HARVEST] Verified solves will be auto-committed to PostgreSQL")
    print(f"[HARVEST] Sync dir: {afl_sync} (fake secondary instance)\n")

    agent = AgentLoop(
        afl_output_dir=afl_out,
        afl_sync_dir=afl_sync,
        target_binary=binary,
        stall_address_override=stall_addr,
        min_stall_cycles=10,
        harvest_mode=True,   # ← THE KEY FLAG
    )
    await agent.setup()
    agent_task = asyncio.create_task(agent.run())

    start = time.monotonic()
    injection_time: float | None = None  # Track WHEN injection happened

    result = {
        "target": target["name"],
        "baseline_edges": baseline_edges,
        "final_edges": 0,
        "payloads_injected": 0,
        "harvest_verified": 0,
        "harvest_committed": 0,
    }

    while time.monotonic() - start < agent_timeout_secs:
        await asyncio.sleep(5)
        elapsed = int(time.monotonic() - start)
        current_edges = read_edges(afl_out)
        m = agent._metrics

        print(
            f"[HARVEST]   t={elapsed:3d}s: edges={current_edges} "
            f"stalls={m['stalls_detected']} "
            f"injected={m['payloads_injected']} "
            f"verified={m['harvest_verified']} "
            f"committed={m['harvest_committed']}"
        )

        # Stop early if we got a verified commit.
        if m["harvest_committed"] > 0:
            print("[HARVEST]   ✓ Verified commit detected — stopping.")
            await asyncio.sleep(3)
            break

        # Track when injection happens so we can give verification
        # enough time. The agent's wait_for_edge_delta() runs for 90s
        # inside _process_stall — we must NOT cancel the task during
        # that window.
        if m["payloads_injected"] > 0 and injection_time is None:
            injection_time = time.monotonic()
            print("[HARVEST]   → Payload injected, waiting for edge verification (up to 120s)...")

        # Only exit after injection if we've waited long enough for:
        #   1. wait_for_edge_delta() to complete (90s)
        #   2. AFL++ to process the file and update stats (~30s buffer)
        if injection_time is not None:
            secs_since_inject = time.monotonic() - injection_time
            if secs_since_inject > 120:
                print(f"[HARVEST]   → {secs_since_inject:.0f}s since injection, stopping.")
                break

    # ── Graceful Shutdown ─────────────────────────────────────────
    # Signal the agent to stop after its current iteration completes.
    # Do NOT cancel the task — let _process_stall finish naturally
    # (including wait_for_edge_delta).
    await agent.shutdown()

    # Give the agent up to 10s to finish current work before forcing.
    try:
        await asyncio.wait_for(asyncio.shield(agent_task), timeout=10)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass

    # Collect final metrics.
    final_edges = read_edges(afl_out)
    m = agent._metrics
    result.update({
        "final_edges": final_edges,
        "payloads_injected": m["payloads_injected"],
        "harvest_verified": m["harvest_verified"],
        "harvest_committed": m["harvest_committed"],
    })

    # Kill AFL++.
    afl_proc.terminate()
    try:
        await asyncio.wait_for(afl_proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        afl_proc.kill()

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  HARVEST RESULT: {target['name']}")
    print(f"  Baseline edges:    {result['baseline_edges']}")
    print(f"  Final edges:       {result['final_edges']}")
    print(f"  Edge delta:        +{result['final_edges'] - result['baseline_edges']}")
    print(f"  Payloads injected: {result['payloads_injected']}")
    print(f"  Verified solves:   {result['harvest_verified']}")
    print(f"  Templates committed: {result['harvest_committed']}")

    if result["harvest_committed"] > 0:
        print(f"\n  ✅ SUCCESS — Template auto-committed to CARM corpus!")
    elif result["payloads_injected"] > 0:
        print(f"\n  ⚠  Payload injected but not verified (no new edges)")
    else:
        print(f"\n  ✗ No payloads generated within timeout")
    print(f"{'═' * 60}\n")

    return result


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run micro-harvest on test targets.")
    parser.add_argument("target", nargs="?", default=None,
                        help="Target key (custom_hash, arithmetic). Default: run all.")
    parser.add_argument("--baseline", type=int, default=60,
                        help="AFL++ baseline seconds (default: 60)")
    parser.add_argument("--agent-timeout", type=int, default=300,
                        help="Agent loop timeout seconds (default: 300)")
    args = parser.parse_args()

    targets = [args.target] if args.target else list(HARVEST_TARGETS.keys())

    results = []
    for key in targets:
        if key not in HARVEST_TARGETS:
            logger.error("Unknown target: %s (available: %s)",
                         key, list(HARVEST_TARGETS.keys()))
            sys.exit(1)
        r = await harvest_target(key, args.baseline, args.agent_timeout)
        results.append(r)

    # Final summary.
    print(f"\n{'═' * 60}")
    print("  MICRO-HARVEST SUMMARY")
    print(f"{'═' * 60}")
    total_committed = sum(r["harvest_committed"] for r in results)
    for r in results:
        status = "✅" if r["harvest_committed"] > 0 else "✗"
        print(f"  {status} {r['target']:20s} committed={r['harvest_committed']} verified={r['harvest_verified']}")
    print(f"\n  Total templates committed: {total_committed}")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    asyncio.run(main())
