"""
test_live_e2e.py — Stage 3: Live AFL++ End-to-End Integration Test.

This script:
1. Recompiles the math_wall_x86 test binary with afl-cc.
2. Sets up a temporary AFL++ environment (in/out directories).
3. Spawns afl-fuzz in the background.
4. Spawns the AgentLoop daemon.
5. Monitors the fuzzer to see it bypass the magic number wall.
"""
import asyncio
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.orchestrator.agent_loop import AgentLoop

async def build_afl_target(target_c: Path, target_bin: Path):
    print(f"[E2E] Compiling {target_c.name} with afl-cc...")
    proc = await asyncio.create_subprocess_exec(
        "afl-cc", "-O1", "-g", "-Wall", str(target_c), "-o", str(target_bin),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError("Failed to compile target with afl-cc")

async def monitor_afl(afl_dir: Path):
    """Monitor AFL fuzzer stats to detect when it bypasses the wall."""
    stats_file = afl_dir / "default" / "fuzzer_stats"
    while True:
        if stats_file.exists():
            try:
                content = stats_file.read_text()
                edges = 0
                for line in content.splitlines():
                    if line.startswith("edges_found"):
                        edges = int(line.split(":")[-1].strip())
                print(f"[E2E] Fuzzer edges found: {edges}")
                if edges > 5: # 5 is the plateau for the first wall
                    print("[E2E] => Magic Number wall bypassed!")
                    return True
            except Exception:
                pass
        await asyncio.sleep(2)

async def main():
    root_dir = Path(__file__).resolve().parents[2]
    target_c = root_dir / "experiments" / "test_targets" / "math_wall_test.c"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        target_bin = tmpdir / "math_wall_afl"
        afl_in = tmpdir / "in"
        afl_out = tmpdir / "afl_output"
        
        afl_in.mkdir()
        (afl_in / "seed1").write_bytes(b"\x00\x00")
        
        await build_afl_target(target_c, target_bin)
        
        print("[E2E] Starting AFL++ fuzzer...")
        env = os.environ.copy()
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        
        afl_proc = await asyncio.create_subprocess_exec(
            "afl-fuzz", "-M", "default", "-i", str(afl_in), "-o", str(afl_out), "--", str(target_bin), "@@",
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        print("[E2E] Starting AgentLoop...")
        os.environ["AFL_OUTPUT_DIR"] = str(afl_out)
        os.environ["AFL_SYNC_DIR"] = str(afl_out / "sync_dir")
        os.environ["STALL_DETECTION_CYCLES"] = "5"
        
        agent = AgentLoop()
        await agent.setup()
        
        # Run agent and monitor concurrently
        agent_task = asyncio.create_task(agent.run())
        monitor_task = asyncio.create_task(monitor_afl(afl_out))
        
        try:
            # We wait until the monitor tells us we bypassed the wall, or timeout
            done, pending = await asyncio.wait(
                [monitor_task],
                timeout=120  # Max 2 minutes for E2E
            )
            
            if monitor_task in done and monitor_task.result() is True:
                print("\n=======================================================")
                print("SUCCESS: AFL++ bypassed the stall via Agentic-AFL!")
                print("=======================================================\n")
            else:
                print("\n[E2E] Timeout reached or failed to bypass wall.")
                
        finally:
            print("[E2E] Cleaning up...")
            afl_proc.terminate()
            await agent.shutdown()
            await asyncio.gather(agent_task, return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(main())
