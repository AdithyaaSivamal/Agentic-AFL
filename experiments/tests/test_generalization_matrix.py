"""
test_generalization_matrix.py — Generalization Matrix E2E Tests.

Tests Agentic-AFL against structurally distinct targets to prove the pipeline
generalizes beyond CRC-16/Modbus. Each target produces a different set of
ConstraintTags, forcing the pipeline to adapt dynamically.

Usage:
    python test_generalization_matrix.py                     # Run all targets
    python test_generalization_matrix.py opendnp3            # Run one target
    python test_generalization_matrix.py opendnp3 --debug    # With debug artifacts
"""
import asyncio
import logging
import os
import signal
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.orchestrator.agent_loop import AgentLoop
from agentic_afl.config import settings

# ── Paths ─────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[2]
TARGETS_DIR = ROOT_DIR / "experiments" / "test_targets"
TESTS_DIR = ROOT_DIR / "experiments" / "tests"

BASELINE_SECONDS = 60
# Real-world targets (lib60870) can take 2+ minutes for Ghidra headless
# import alone. 180s was calibrated for synthetic targets only.
AGENT_TIMEOUT = 600

# Global flag for graceful Ctrl+C shutdown.
_shutdown_requested = False


# ── Target Definitions ────────────────────────────────────────────────

@dataclass
class TargetSpec:
    """Defines a test target for the generalization matrix."""
    name: str
    source_file: str | None       # None if using build_script
    binary_name: str
    stall_function: str           # Symbol name to resolve via nm
    seed_bytes: bytes             # Initial AFL seed (valid header, bad checksum)
    description: str
    build_script: str | None = None   # Shell script for multi-file builds
    seed_dir: str | None = None       # Directory of seed files (overrides seed_bytes)
    accept_marker: str = "ACCEPT"     # Output marker indicating wall bypass
    custom_mutator: str | None = None # Python custom mutator module name

TARGETS = {
    "modbus": TargetSpec(
        name="Modbus CRC-16",
        source_file="modbus_rtu_slave.c",
        binary_name="libmodbus_harness",
        stall_function="check_crc",
        # Valid MBAP header, invalid CRC
        seed_bytes=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x00",
        description="Industry-standard CRC-16/Modbus with polynomial 0xA001",
    ),
    "custom_hash": TargetSpec(
        name="Custom Hash",
        source_file="custom_hash_target.c",
        binary_name="custom_hash_harness",
        stall_function="check_hash",
        # Valid magic + command, invalid hash
        seed_bytes=b"\xAA\x10\x00\x00\x00\x00\x00\x01",
        description="Novel rotate-XOR-accumulate hash (NOT in any training corpus)",
    ),
    "arithmetic": TargetSpec(
        name="Arithmetic",
        source_file="arithmetic_constraint_target.c",
        binary_name="arithmetic_harness",
        stall_function="check_linear",
        # a=0x0150 (in range), b=0x0030, wrong expected + checkbyte
        seed_bytes=b"\x01\x50\x00\x30\x00\x00\x00",
        description="Pure linear arithmetic (a*7 + b*13), no loops or bitwise ops",
    ),
    "iec104": TargetSpec(
        name="IEC 104",
        source_file="iec104_apci_parser.c",
        binary_name="iec104_harness",
        stall_function="check_sequence_number",
        # Valid start (0x68), valid length (4), passes format check (I-format),
        # but SSN = (0xFE | 0xFF<<8) >> 1 & 0x7FFF = 0x7FFF ≠ expected 0x0000
        seed_bytes=b"\x68\x04\xFE\xFF\x00\x00",
        description="IEC 60870-5-104 APCI — bit-field extraction + sequence number",
    ),
    "state_machine": TargetSpec(
        name="State Machine",
        source_file="modbus_state_machine.c",
        binary_name="modbus_state_harness",
        stall_function="transition_auth_challenge",
        # Multi-packet: [len][pkt1][len][pkt2]
        # Pkt1 (4 bytes): magic=0x4D42, cmd=0x01, pad=0x00 → passes T1
        # Pkt2 (6 bytes): header + WRONG challenge response → stalls at T2
        # Pipeline must solve: response == 0xDEADBEEF ^ 0xCAFEBABE = 0x14530451
        seed_bytes=b"\x04\x4D\x42\x01\x00\x06\x4D\x42\x00\x00\x00\x00",
        description="Multi-state FSM with XOR challenge-response authentication",
    ),
    "lib60870": TargetSpec(
        name="lib60870 APCI",
        source_file=None,
        binary_name="lib60870_harness",
        stall_function="checkSequenceNumber",
        seed_bytes=b"\x68\x04\x07\x00\x00\x00",
        description="IEC 60870-5-104 APCI frame parser (REAL-WORLD ICS library)",
        build_script="build_lib60870_harness.sh",
        seed_dir="lib60870_seeds",
        accept_marker="Bypassed sequence number validation",
    ),
    "opendnp3": TargetSpec(
        name="OpenDNP3 Outstation",
        source_file=None,
        binary_name="opendnp3_outstation_harness",
        stall_function="_ZN8opendnp315LinkLayerParser10ReadHeaderEv",
        seed_bytes=b"\x05\x64\x05\xC0\x01\x00\x03\x00\x00\x00",
        description="DNP3 (IEEE-1815) outstation CRC-16/DNP3 math wall (REAL-WORLD SCADA library)",
        build_script="build_opendnp3_harness.sh",
        seed_dir="opendnp3_seeds",
        accept_marker="FRAME_ACCEPTED",
    ),
    "cfs": TargetSpec(
        name="NASA cFS Checksum",
        source_file=None,
        binary_name="cfs_checksum_harness",
        stall_function="CFE_MSG_ValidateChecksum",
        seed_bytes=b"\x18\x01\xC0\x00\x00\x01\x00\x00",
        description="CCSDS (NASA cFS) XOR additive checksum with multi-guard header validation (REAL-WORLD aerospace)",
        build_script="build_cfs_harness.sh",
        seed_dir="cfs_seeds",
        accept_marker="APDU_VALIDATED",
    ),
    "libmodbus": TargetSpec(
        name="Libmodbus RTU",
        source_file=None,
        binary_name="libmodbus_harness",
        stall_function="crc16",
        seed_bytes=b"\x01\x03\x00\x00\x00\x0A\x00\x00",
        description="Modbus RTU CRC-16 (polynomial 0xA001) math wall (REAL-WORLD ICS library)",
        build_script="build_libmodbus_harness.sh",
        seed_dir="libmodbus_seeds",
        accept_marker="MODBUS_FRAME_VALID",
    ),
    "ics_crc32": TargetSpec(
        name="ICS CRC-32",
        source_file=None,
        binary_name="ics_crc32_harness",
        stall_function="crc32_calc",
        seed_bytes=b"\xA5\x5A\x01\x01\x05\x00\x01\x00\x00\x05\x00\xDE\xAD\xBE\xEF",
        description="CRC-32/IEEE 802.3 (PROFINET/EtherCAT polynomial) with deep ICS state machine (245 edges)",
        build_script="build_ics_crc32.sh",
        seed_dir="ics_crc32_seeds",
        accept_marker="ICS_FRAME_ACCEPTED",
        custom_mutator="crc32_fixup_mutator",
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────

async def compile_target(spec: TargetSpec) -> Path:
    """Compile the target with afl-cc or a build script."""
    binary = TARGETS_DIR / spec.binary_name

    if spec.build_script:
        script = TARGETS_DIR / spec.build_script
        print(f"[E2E] Compiling {spec.name} with build script...")
        proc = await asyncio.create_subprocess_exec(
            "bash", str(script), "afl-cc",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            print(f"[E2E] ✗ Build failed:\n{stdout.decode()}\n{stderr.decode()}")
            sys.exit(1)
    elif spec.source_file:
        source = TARGETS_DIR / spec.source_file
        print(f"[E2E] Compiling {spec.name} with afl-cc -no-pie...")
        proc = await asyncio.create_subprocess_exec(
            "afl-cc", "-O1", "-g", "-no-pie", str(source), "-o", str(binary),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            print(f"[E2E] ✗ Compilation failed:\n{stderr.decode()}")
            sys.exit(1)
    else:
        if not binary.exists():
            print(f"[E2E] ✗ No source/build script and binary not found: {binary}")
            sys.exit(1)

    print("[E2E] ✓ Compiled successfully")
    return binary


def resolve_symbol(binary: Path, symbol: str) -> str:
    """Find the address of a symbol in the compiled binary via nm.
    Supports both global (T) and local (t) text symbols."""
    result = subprocess.run(
        ["nm", str(binary)], capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol and parts[1].lower() == "t":
            addr = parts[0]
            print(f"[E2E] ✓ Resolved {symbol} @ 0x{addr}")
            return f"0x{addr}"
    print(f"[E2E] ⚠ Could not resolve {symbol} — using 0x000000")
    return "0x000000"


def read_edges(afl_out: Path) -> int:
    """Read the current edges_found from fuzzer_stats."""
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


def check_for_accept(afl_out: Path, binary: Path, accept_marker: str = "ACCEPT") -> str | None:
    """Check if any queue entry produces the target-specific bypass marker.

    Each target defines its own accept_marker string that indicates the math
    wall was successfully bypassed. This generalizes across targets:
      - lib60870: "Bypassed sequence number validation"
      - opendnp3: "FRAME_ACCEPTED" (CRC-16 wall passed)
      - synthetics: "ACCEPT"

    Skips original unmodified seeds (time:0,execs:0) to avoid false positives
    from seeds that already contain valid checksums.
    """
    queue_dir = afl_out / "default" / "queue"
    if queue_dir.exists():
        for f in sorted(queue_dir.iterdir()):
            if not f.is_file():
                continue
            # Check both AFL queue entries (id:*) and injected payloads (agentic_*)
            if not (f.name.startswith("id:") or f.name.startswith("agentic_")):
                continue
            # Skip original unmodified seeds — these were never mutated by
            # AFL++ or Agentic-AFL. If they pass, it's a false positive.
            if "time:0,execs:0" in f.name:
                continue
            try:
                # Try argv[1] mode first (lib60870, opendnp3).
                result = subprocess.run(
                    [str(binary), str(f)],
                    capture_output=True, text=True, timeout=5,
                )
                combined = result.stdout + result.stderr
                if accept_marker in combined:
                    return f.name
            except Exception:
                pass
            try:
                # Fallback: stdin mode (cFS and stdin-based harnesses).
                with open(f, 'rb') as fh:
                    result = subprocess.run(
                        [str(binary)],
                        stdin=fh,
                        capture_output=True, text=True, timeout=5,
                    )
                combined = result.stdout + result.stderr
                if accept_marker in combined:
                    return f.name
            except Exception:
                continue
    return None


def check_partial_bypass(afl_out: Path, binary: Path, stall_func: str) -> str | None:
    """Check if any queue entry or injected payload gets PAST the stall function.

    This detects cases where the math wall is solved but a later wall
    still blocks (e.g., CRC solved but session token wrong).
    """
    # Map stall function to rejection messages AFTER it
    bypass_indicators = {
        "check_crc": "Bad session token",
        "check_hash": "Bad sequence counter",
        "check_linear": "Modular checkbyte failed",
        "check_frame_format": "Sequence number mismatch",
        "transition_auth_challenge": "AUTH_CHALLENGE",
        # OpenDNP3: CRC_HEADER_PASS = header CRC solved but body may fail
        "_ZN8opendnp315LinkLayerParser10ReadHeaderEv": "CRC_HEADER_PASS",
        # check_sequence_number has no indicator — it's the last wall,
        # so bypassing it produces ACCEPT (caught by check_for_accept).
    }
    indicator = bypass_indicators.get(stall_func)
    if not indicator:
        return None

    queue_dir = afl_out / "default" / "queue"
    if not queue_dir.exists():
        return None
    for f in sorted(queue_dir.iterdir()):
        if not f.is_file():
            continue
        if not (f.name.startswith("id:") or f.name.startswith("agentic_")):
            continue
        try:
            # Try argv[1] mode first.
            result = subprocess.run(
                [str(binary), str(f)],
                capture_output=True, text=True, timeout=5,
            )
            combined = result.stdout + result.stderr
            if indicator in combined or "ACCEPT" in combined:
                return f.name
        except Exception:
            pass
        try:
            # Fallback: stdin mode.
            with open(f, 'rb') as fh:
                result = subprocess.run(
                    [str(binary)],
                    stdin=fh,
                    capture_output=True, text=True, timeout=5,
                )
            combined = result.stdout + result.stderr
            if indicator in combined or "ACCEPT" in combined:
                return f.name
        except Exception:
            continue
    return None


async def run_afl(binary: Path, afl_in: Path, afl_out: Path, afl_sync: Path) -> asyncio.subprocess.Process:
    """Start AFL++ fuzzer with foreign sync directory."""
    env = os.environ.copy()
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_NO_UI"] = "1"
    # Force AFL++ to check foreign sync directories every ~1 minute.
    env["AFL_SYNC_TIME"] = "1"

    proc = await asyncio.create_subprocess_exec(
        "afl-fuzz", "-M", "default",
        "-F", str(afl_sync),  # Foreign fuzzer dir — AFL++ actively imports from here
        "-i", str(afl_in), "-o", str(afl_out),
        "--", str(binary), "@@",
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return proc


def _safe_terminate(proc: asyncio.subprocess.Process) -> None:
    """Terminate a subprocess, ignoring ProcessLookupError if already dead."""
    try:
        proc.terminate()
    except ProcessLookupError:
        pass


# ── Main Test Runner ──────────────────────────────────────────────────

async def run_target_test(target_key: str) -> dict:
    """Run the full E2E test for a single target. Returns results dict."""
    spec = TARGETS[target_key]
    test_dir = TESTS_DIR / "e2e_run"
    afl_in = test_dir / "in"
    afl_out = test_dir / "out"
    # Use a separate "agentic" secondary instance directory for sync.
    # Writing directly into default/queue/ does NOT work — AFL++ never
    # re-scans its own queue for externally added files.
    afl_sync = afl_out / "agentic" / "queue"

    print(f"\n{'═' * 60}")
    print(f"  TARGET: {spec.name}")
    print(f"  {spec.description}")
    print(f"{'═' * 60}\n")

    # ── Cleanup stale state from previous runs ────────────────────
    # Kill any zombie afl-fuzz processes to prevent SHM contamination.
    try:
        subprocess.run(
            ["pkill", "-9", "-f", "afl-fuzz"],
            capture_output=True, timeout=5,
        )
        import time as _time
        _time.sleep(2)
    except Exception:
        pass
    if test_dir.exists():
        shutil.rmtree(test_dir)
    afl_in.mkdir(parents=True)
    # Support both single seed bytes and seed directories
    if spec.seed_dir:
        seed_src = TARGETS_DIR / spec.seed_dir
        for seed_file in seed_src.glob("*"):
            if seed_file.is_file():
                shutil.copy(seed_file, afl_in / seed_file.name)
        print(f"[E2E] Loaded {len(list(afl_in.iterdir()))} seed files from {spec.seed_dir}")
    else:
        (afl_in / "seed1").write_bytes(spec.seed_bytes)

    # Pre-create the agentic sync directory so PayloadInjector can write to it.
    afl_sync.mkdir(parents=True, exist_ok=True)

    binary = await compile_target(spec)
    stall_addr = resolve_symbol(binary, spec.stall_function)

    # ── Phase 1: AFL++ Baseline ───────────────────────────────────
    print(f"\n[E2E] ═══ Phase 1: AFL++ Baseline ({BASELINE_SECONDS}s) ═══")
    print("[E2E] Running AFL++ ALONE to prove it cannot bypass the math wall...")

    afl_proc = await run_afl(binary, afl_in, afl_out, afl_sync)
    await asyncio.sleep(5)

    for i in range(0, BASELINE_SECONDS - 5, 5):
        edges = read_edges(afl_out)
        print(f"[E2E]   Baseline t={i+5:3d}s: edges={edges}")
        await asyncio.sleep(5)

    baseline_edges = read_edges(afl_out)
    print(f"\n[E2E] ═══ Baseline Result ═══")
    print(f"[E2E]   Final edges: {baseline_edges}")

    # ── Phase 2: Enable Agentic-AFL ──────────────────────────────
    print(f"\n[E2E] ═══ Phase 2: Agentic-AFL ({AGENT_TIMEOUT}s timeout) ═══")
    print("[E2E] Starting AgentLoop to detect stall and inject bypass...")

    agent = AgentLoop(
        afl_output_dir=afl_out,
        afl_sync_dir=afl_sync,
        target_binary=binary,
        stall_address_override=stall_addr,
        min_stall_cycles=10,
        register_signals=False,  # Test script handles SIGINT/SIGTERM
    )
    await agent.setup()
    agent_task = asyncio.create_task(agent.run())

    start = time.monotonic()
    result = {
        "target": spec.name,
        "baseline_edges": baseline_edges,
        "final_edges": 0,
        "payloads_injected": 0,
        "react_turns": 0,
        "llm_calls": 0,
        "math_wall_bypassed": False,
        "full_accept": False,
        "bypass_evidence": None,
    }

    success = False
    while time.monotonic() - start < AGENT_TIMEOUT:
        if _shutdown_requested:
            print(f"\n[E2E] ⚡ Ctrl+C received — ending run early...")
            break
        await asyncio.sleep(5)
        elapsed = int(time.monotonic() - start)
        current_edges = read_edges(afl_out)
        metrics = agent._metrics

        print(
            f"[E2E]   t={elapsed:3d}s: edges={current_edges} "
            f"stalls_detected={metrics['stalls_detected']} "
            f"payloads_injected={metrics['payloads_injected']}"
        )

        if metrics["payloads_injected"] > 0 and not success:
            # Give AFL++ time to absorb the payload and discover new
            # coverage before checking results.  For multi-wall targets
            # (e.g., DNP3 header CRC → body block CRCs), the fuzzer
            # needs time to hit the next wall so the agent can solve it.
            await asyncio.sleep(5)
            final_edges = read_edges(afl_out)
            accept_entry = check_for_accept(afl_out, binary, spec.accept_marker)
            partial = check_partial_bypass(afl_out, binary, spec.stall_function)

            result.update({
                "final_edges": final_edges,
                "payloads_injected": metrics["payloads_injected"],
                "react_turns": metrics["react_turns_total"],
                "llm_calls": metrics["llm_calls_total"],
                "full_accept": bool(accept_entry),
                "math_wall_bypassed": bool(accept_entry or partial),
                "bypass_evidence": accept_entry or partial,
            })

            if accept_entry:
                # Full accept — we're done!
                print(f"\n[E2E] ═══ Results ═══")
                print(f"[E2E]   Baseline edges:     {baseline_edges}")
                print(f"[E2E]   Final edges:        {final_edges}")
                print(f"[E2E]   Payloads injected:  {metrics['payloads_injected']}")
                print(f"[E2E]   LLM calls:          {metrics['llm_calls_total']}")
                print(f"[E2E]   ReAct turns:        {metrics['react_turns_total']}")
                print(f"[E2E]   Math wall bypassed: YES")
                print(f"[E2E]   Full ACCEPT:        YES — {accept_entry}")
                print(f"\n{'═' * 60}")
                print(f"  ✅ SUCCESS: {spec.name} — FULL ACCEPT")
                print(f"{'═' * 60}")
                success = True
                break

            # Not a full accept yet — log partial bypass and continue.
            # The agent loop will detect the next stall and solve it.
            if partial and elapsed % 30 == 0:  # Log every 30s to avoid spam
                print(f"[E2E]   ↳ partial bypass: {partial} (continuing for next wall...)")

    if not success:
        # ── Grace period for in-flight agent work ─────────────────
        # The agent may be in the middle of Ghidra extraction or LLM
        # calls when the timeout fires. Give it up to 120s to finish
        # any in-flight work before declaring failure.
        if _shutdown_requested:
            print(f"\n[E2E] Skipping grace period (user requested shutdown)")
        else:
            print(f"\n[E2E] Timeout reached — waiting up to 120s for in-flight agent work...")
        grace_start = time.monotonic()
        grace_seconds = 0 if _shutdown_requested else 120
        while time.monotonic() - grace_start < grace_seconds:
            await asyncio.sleep(5)
            metrics = agent._metrics
            if metrics["payloads_injected"] > 0:
                await asyncio.sleep(5)  # Let AFL++ import the payload
                final_edges = read_edges(afl_out)
                accept_entry = check_for_accept(afl_out, binary, spec.accept_marker)
                partial = check_partial_bypass(afl_out, binary, spec.stall_function)

                result.update({
                    "final_edges": final_edges,
                    "payloads_injected": metrics["payloads_injected"],
                    "react_turns": metrics["react_turns_total"],
                    "llm_calls": metrics["llm_calls_total"],
                    "full_accept": bool(accept_entry),
                    "math_wall_bypassed": bool(accept_entry or partial),
                    "bypass_evidence": accept_entry or partial,
                })

                print(f"\n[E2E] ═══ Results (captured during grace period) ═══")
                print(f"[E2E]   Baseline edges:     {baseline_edges}")
                print(f"[E2E]   Final edges:        {final_edges}")
                print(f"[E2E]   Payloads injected:  {metrics['payloads_injected']}")
                print(f"[E2E]   Math wall bypassed: {'YES' if result['math_wall_bypassed'] else 'NO'}")
                print(f"[E2E]   Full ACCEPT:        {'YES — ' + accept_entry if accept_entry else 'NO'}")

                if accept_entry:
                    print(f"\n{'═' * 60}")
                    print(f"  ✅ SUCCESS: {spec.name} — FULL ACCEPT (late arrival)")
                    print(f"{'═' * 60}")

                success = True
                break

        if not success:
            final_edges = read_edges(afl_out)
            metrics = agent._metrics
            accept_entry = check_for_accept(afl_out, binary, spec.accept_marker)
            partial = check_partial_bypass(afl_out, binary, spec.stall_function)
            result.update({
                "final_edges": final_edges,
                "payloads_injected": metrics.get("payloads_injected", 0),
                "react_turns": metrics.get("react_turns_total", 0),
                "llm_calls": metrics.get("llm_calls_total", 0),
                "full_accept": bool(accept_entry),
                "math_wall_bypassed": bool(accept_entry or partial),
                "bypass_evidence": accept_entry or partial,
            })

            print(f"\n[E2E] ═══ Results (timeout) ═══")
            print(f"[E2E]   Baseline edges:     {baseline_edges}")
            print(f"[E2E]   Final edges:        {final_edges}")
            print(f"[E2E]   Payloads injected:  {metrics.get('payloads_injected', 0)}")
            print(f"[E2E]   LLM calls:          {metrics.get('llm_calls_total', 0)}")
            print(f"[E2E]   ReAct turns:        {metrics.get('react_turns_total', 0)}")
            print(f"[E2E]   Math wall bypassed: {'YES' if result['math_wall_bypassed'] else 'NO'}")
            print(f"[E2E]   Full ACCEPT:        {'YES — ' + accept_entry if accept_entry else 'NO'}")
            if accept_entry:
                print(f"\n{'═' * 60}")
                print(f"  ✅ SUCCESS: {spec.name} — FULL ACCEPT (late arrival)")
                print(f"{'═' * 60}")
                success = True
            elif partial:
                print(f"\n[E2E] ✓ Math wall bypassed (partial — blocked by next wall)")
                print(f"[E2E]   Evidence: {partial}")
            else:
                print(f"\n[E2E] ✗ Timeout — no bypass achieved")
            print(f"[E2E]   Metrics: {metrics}")

    # ── Cleanup ───────────────────────────────────────────────────
    print("[E2E] Cleaning up...")
    _safe_terminate(afl_proc)
    await agent.shutdown()
    agent_task.cancel()
    await asyncio.gather(agent_task, return_exceptions=True)
    # Wait for AFL to actually exit.
    try:
        await asyncio.wait_for(afl_proc.wait(), timeout=5)
    except (asyncio.TimeoutError, ProcessLookupError):
        pass
    print("[E2E] ✓ Cleanup complete")

    return result


async def main():
    global _shutdown_requested

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # ── Register signal handler for graceful Ctrl+C ──────────────
    loop = asyncio.get_running_loop()

    def _handle_shutdown(sig: int) -> None:
        global _shutdown_requested
        if _shutdown_requested:
            # Second Ctrl+C — force exit.
            print("\n[E2E] Second interrupt — forcing exit.")
            sys.exit(1)
        _shutdown_requested = True
        sig_name = signal.Signals(sig).name
        print(f"\n[E2E] ⚡ {sig_name} received — finishing current phase and cleaning up...")
        print("[E2E]   (press Ctrl+C again to force-quit)")

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_shutdown, sig)

    # Parse arguments.
    debug = "--debug" in sys.argv
    target_args = [k for k in sys.argv[1:] if not k.startswith("--")]

    if debug:
        settings.debug_mode = True
        print("[E2E] Debug mode ON — artifacts will be saved to /tmp/agentic_afl_debug/")

    # Determine which targets to run.
    if target_args:
        target_keys = [k for k in target_args if k in TARGETS]
        if not target_keys:
            print(f"Unknown target(s): {target_args}. Available: {list(TARGETS.keys())}")
            sys.exit(1)
    else:
        target_keys = list(TARGETS.keys())

    results = []
    for key in target_keys:
        result = await run_target_test(key)
        results.append(result)
        if _shutdown_requested:
            print(f"[E2E] Skipping remaining targets due to shutdown request.")
            break

    # ── Print Generalization Matrix ───────────────────────────────
    print(f"\n\n{'═' * 70}")
    print("  GENERALIZATION MATRIX — RESULTS SUMMARY")
    print(f"{'═' * 70}")
    print(f"{'Target':<20} {'Edges':>8} {'Injected':>10} {'Turns':>7} {'Wall':>6} {'Accept':>8}")
    print(f"{'─' * 20} {'─' * 8} {'─' * 10} {'─' * 7} {'─' * 6} {'─' * 8}")
    for r in results:
        wall = "✅" if r["math_wall_bypassed"] else "❌"
        accept = "✅" if r["full_accept"] else "❌"
        print(
            f"{r['target']:<20} {r['final_edges']:>8} {r['payloads_injected']:>10} "
            f"{r['react_turns']:>7} {wall:>6} {accept:>8}"
        )
    print(f"{'═' * 70}\n")


if __name__ == "__main__":
    asyncio.run(main())
