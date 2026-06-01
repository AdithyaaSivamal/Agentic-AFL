"""
stall_detector.py — AFL++ Coverage Stall Detection.

This module monitors AFL++'s output directory for coverage stalls —
addresses where the fuzzer has exhausted its mutation strategy and
stopped discovering new edges.

Inputs:
    - AFL++ output directory (config.afl_output_dir)

Outputs:
    - list[StallReport]  — New stalls detected since last poll.

Reference: HyLLfuzz §3.1 — Coverage analyzer with "interestingness" scoring.

Key Design Decisions:
    1. FILESYSTEM-BASED MONITORING: We parse AFL++'s fuzzer_stats,
       plot_data, and queue/ directory. No shared memory or IPC.
       This maintains the fully asynchronous, decoupled architecture.

    2. INTERESTINGNESS SCORING: Not all stalls are equal. A stall at
       a crypto check blocking 50% of the program is more critical
       than a stall at a debug branch. Severity is computed from:
       - Cycles with no new coverage at this address.
       - Cyclomatic complexity of the stalled basic block.
       - Number of downstream basic blocks blocked.

    3. DEDUPLICATION: The same stall address is only reported once.
       Subsequent polls skip known stalls unless they've been resolved.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.constants import StallSeverity
from agentic_afl.models import StallReport

logger = logging.getLogger(__name__)

# AFL++ fuzzer_stats keys of interest.
_STATS_KEYS = frozenset({
    "start_time",
    "last_update",
    "cycles_done",
    "execs_done",
    "execs_per_sec",
    "corpus_count",
    "corpus_found",
    "pending_favs",
    "pending_total",
    "edges_found",
    "max_depth",
    "cur_item",
    "saved_crashes",
})

# Pattern for AFL++ queue filenames:
#   id:000042,src:000023,time:1234567,execs:42,op:havoc,rep:4
_QUEUE_ID_RE = re.compile(r"id:(\d+)")


class StallDetector:
    """
    Monitors AFL++ for coverage stalls.

    Usage:
        detector = StallDetector()
        new_stalls = await detector.detect()
        for stall in new_stalls:
            print(f"Stall at {stall.stall_address}, severity: {stall.severity}")
    """

    def __init__(
        self,
        afl_output_dir: Path = settings.afl_output_dir,
        min_stall_cycles: int = settings.min_stall_cycles,
        target_binary: Path | None = None,
        stall_address_override: str | None = None,
        min_stall_time_seconds: int = settings.min_stall_time_seconds,
    ) -> None:
        self.afl_output_dir = Path(afl_output_dir)
        self.min_stall_cycles = min_stall_cycles
        # If provided, use this binary path instead of parsing from AFL++ cmdline.
        self._target_binary = Path(target_binary) if target_binary else None
        # If provided, always report this address as the stall instead of
        # synthesizing one from queue item IDs (which are NOT binary addresses).
        self._stall_address_override = stall_address_override
        # Time-based stall threshold: when > 0, triggers stall detection
        # based on wall-clock time with no new edges (for E2E campaigns).
        self._min_stall_time_seconds = min_stall_time_seconds

        # Track known stalls to avoid re-reporting.
        self._known_stalls: set[str] = set()
        # Permanently resolved stalls — never re-discover or re-report.
        self._resolved_stalls: set[str] = set()
        # Track cycle counts per address for interestingness scoring.
        self._stall_cycle_counts: dict[str, int] = {}
        # Track edge count at each poll for plateau detection.
        self._last_edges_found: int = 0
        self._plateau_cycles: int = 0
        # Wall-clock time when the last new edge was discovered.
        self._last_new_edge_time: float = time.monotonic()
        # Previous stats snapshot for diffing.
        self._prev_stats: dict[str, str] = {}
        # Cache for frontier function discovery results.
        # Maps seed content hash -> discovered function address.
        self._frontier_cache: dict[str, str] = {}
        # Track frontier discovery attempts to avoid infinite retries.
        self._frontier_discovery_attempts: int = 0
        self._frontier_discovery_max_attempts: int = 3

    async def detect(self) -> list[StallReport]:
        """
        Poll AFL++ for new coverage stalls.

        Returns:
            List of NEW StallReports since the last call.
            Returns empty list if no new stalls are found.

        Algorithm:
            1. Parse AFL++ fuzzer_stats for current cycle/edge counts.
            2. Detect edge-count plateau (no new edges for min_stall_cycles).
            3. Identify stall addresses from plot_data.
            4. For each new stall, compute severity and create StallReport.
            5. Return only stalls not previously reported.
        """
        # Step 1: Parse fuzzer_stats.
        stats = self._parse_fuzzer_stats()
        if not stats:
            logger.warning("Could not parse fuzzer_stats at %s", self.afl_output_dir)
            return []

        current_cycles = int(stats.get("cycles_done", "0"))
        current_edges = int(stats.get("edges_found", "0"))

        # Step 2: Detect global coverage plateau.
        if current_edges == self._last_edges_found:
            self._plateau_cycles += 1
        else:
            self._plateau_cycles = 0
            self._last_edges_found = current_edges
            self._last_new_edge_time = time.monotonic()

        # Time-based stall detection (for E2E campaigns).
        if self._min_stall_time_seconds > 0:
            time_stalled = time.monotonic() - self._last_new_edge_time
            if time_stalled < self._min_stall_time_seconds:
                logger.debug(
                    "Time-based stall: %.0f/%ds (edges=%d)",
                    time_stalled, self._min_stall_time_seconds, current_edges,
                )
                self._prev_stats = stats
                return []
        else:
            # Cycle-based stall detection (original mode).
            if self._plateau_cycles < self.min_stall_cycles:
                logger.debug(
                    "Plateau cycles: %d/%d (edges=%d)",
                    self._plateau_cycles, self.min_stall_cycles, current_edges,
                )
                self._prev_stats = stats
                return []

        # Step 3: Identify stall addresses from plot_data.
        stall_addresses = self._identify_stalls(stats)

        # Step 4: Build StallReports for NEW stalls only.
        binary_path = self._get_binary_path()
        new_stalls: list[StallReport] = []

        for addr in stall_addresses:
            if addr in self._known_stalls:
                continue

            # Count how many cycles this address has been stalled.
            self._stall_cycle_counts[addr] = (
                self._stall_cycle_counts.get(addr, 0) + self._plateau_cycles
            )

            severity = self._compute_severity(
                addr, self._stall_cycle_counts[addr], current_edges,
            )
            seed_path = self._find_closest_seed(addr)
            seed_bytes = seed_path.read_bytes() if seed_path.exists() else b""

            report = StallReport(
                stall_address=addr,
                binary_path=binary_path,
                severity=severity,
                cycles_stalled=self._stall_cycle_counts[addr],
                seed_input=seed_bytes,
                seed_input_path=seed_path,
            )
            new_stalls.append(report)
            self._known_stalls.add(addr)

        if new_stalls:
            logger.info(
                "Detected %d new stall(s) at cycle %d (edges=%d, plateau=%d)",
                len(new_stalls), current_cycles, current_edges, self._plateau_cycles,
            )

        self._prev_stats = stats
        return new_stalls

    def _parse_fuzzer_stats(self) -> dict[str, str]:
        """
        Parse AFL++'s fuzzer_stats file.

        Located at: {afl_output_dir}/default/fuzzer_stats
        Contains key-value pairs like:
            cycles_done        : 42
            execs_per_sec      : 10000.00
            pending_favs       : 5

        Returns:
            Dict of stat_name -> value_string.
        """
        # AFL++ uses "default" as the fuzzer instance name by default.
        # Multi-instance setups use "fuzzer01", "fuzzer02", etc.
        stats_candidates = [
            self.afl_output_dir / "default" / "fuzzer_stats",
            self.afl_output_dir / "fuzzer_stats",
        ]
        # Also check for numbered instances.
        if self.afl_output_dir.is_dir():
            for child in sorted(self.afl_output_dir.iterdir()):
                if child.is_dir() and (child / "fuzzer_stats").exists():
                    stats_candidates.insert(0, child / "fuzzer_stats")

        for stats_path in stats_candidates:
            if stats_path.exists():
                return self._parse_stats_file(stats_path)

        return {}

    @staticmethod
    def _parse_stats_file(path: Path) -> dict[str, str]:
        """Parse a single fuzzer_stats file into a dict."""
        stats: dict[str, str] = {}
        try:
            for line in path.read_text().splitlines():
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key:
                    stats[key] = value
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse %s: %s", path, e)
        return stats

    def _identify_stalls(self, stats: dict[str, str]) -> list[str]:
        """
        Identify stall addresses from AFL++'s coverage data.

        Strategy: Parse plot_data for edges-over-time. Addresses where the
        edge count plateaus are candidate stalls.

        For the MVP, we use a heuristic: if the global edge count has
        plateaued, the "stall address" is the current queue item's target.
        In production, this would integrate with AFL++'s bitmap diffing
        or QEMU instrumentation to identify specific stalling branch addresses.

        IMPORTANT: In afl-cc mode (non-QEMU), plot_data only contains queue
        item indices — NOT binary addresses. If stall_address_override was
        set in the constructor, we use that instead.
        """
        # If the caller explicitly specified a stall address (e.g., from
        # static analysis of the binary), use it directly.
        if self._stall_address_override:
            return [self._stall_address_override]

        stall_addrs: list[str] = []

        # In autonomous mode (no override), use frontier function discovery
        # to find the actual blocking function via GDB depth tracing.
        # NOTE: _parse_plot_data_stalls only reports queue item indices,
        # NOT binary addresses, so it's useless for the Ghidra pipeline.
        #
        # Guard against infinite retries: after max_attempts rounds of
        # failed frontier discovery, stop trying.
        if self._frontier_discovery_attempts >= self._frontier_discovery_max_attempts:
            logger.debug(
                "Frontier discovery exhausted (%d/%d attempts) — skipping",
                self._frontier_discovery_attempts,
                self._frontier_discovery_max_attempts,
            )
            return stall_addrs

        pending = int(stats.get("pending_favs", "0"))
        if pending == 0:
            binary = self._get_binary_path()
            # Try multiple seeds — some may not reach the math wall.
            seed_candidates = self._find_seed_candidates(max_seeds=5)
            for seed_path in seed_candidates:
                if not seed_path.exists():
                    continue
                frontier = self._discover_frontier_function_sync(
                    binary, seed_path,
                )
                if frontier:
                    if frontier in self._resolved_stalls:
                        logger.debug(
                            "Frontier discovery: %s already resolved, skipping",
                            frontier,
                        )
                    else:
                        stall_addrs.append(frontier)
                        logger.info(
                            "Frontier discovery: %s from seed %s",
                            frontier, seed_path.name,
                        )
                    # Reset retry counter on success.
                    self._frontier_discovery_attempts = 0
                    break
            else:
                if seed_candidates:
                    self._frontier_discovery_attempts += 1
                    logger.warning(
                        "Frontier discovery failed on %d seeds (attempt %d/%d)",
                        len(seed_candidates),
                        self._frontier_discovery_attempts,
                        self._frontier_discovery_max_attempts,
                    )

        return stall_addrs

    def _find_plot_data(self) -> Path | None:
        """Find the plot_data file in the AFL++ output directory."""
        candidates = [
            self.afl_output_dir / "default" / "plot_data",
            self.afl_output_dir / "plot_data",
        ]
        if self.afl_output_dir.is_dir():
            for child in sorted(self.afl_output_dir.iterdir()):
                if child.is_dir() and (child / "plot_data").exists():
                    candidates.insert(0, child / "plot_data")

        for p in candidates:
            if p.exists():
                return p
        return None

    def _parse_plot_data_stalls(self, plot_data_path: Path) -> list[str]:
        """
        Parse AFL++'s plot_data for stall evidence.

        plot_data format (TSV):
            # relative_time, cycles_done, cur_item, corpus_count, pending_total,
            # pending_favs, max_depth, edges_found, ...

        We look for edge-count plateaus in the last N entries.
        """
        stall_addrs: list[str] = []
        try:
            lines = plot_data_path.read_text().splitlines()
            data_lines = [l for l in lines if l and not l.startswith("#")]

            if len(data_lines) < 2:
                return stall_addrs

            # Parse last N entries to detect plateaus.
            recent = data_lines[-min(50, len(data_lines)):]
            edge_counts: list[int] = []
            for line in recent:
                fields = line.split(",")
                if len(fields) >= 8:
                    try:
                        edge_counts.append(int(fields[7].strip()))
                    except (ValueError, IndexError):
                        pass

            if not edge_counts:
                return stall_addrs

            # If the last N edge counts are all the same → plateau.
            plateau_window = min(self.min_stall_cycles, len(edge_counts))
            tail = edge_counts[-plateau_window:]
            if len(set(tail)) == 1 and len(tail) >= plateau_window:
                # Parse the current item from the latest entry as the stall address.
                last_fields = data_lines[-1].split(",")
                if len(last_fields) >= 3:
                    cur_item = last_fields[2].strip()
                    stall_addrs.append(f"0x{int(cur_item):08x}")

        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse plot_data: %s", e)

        return stall_addrs

    def _discover_frontier_function_sync(
        self,
        binary: Path,
        seed_path: Path,
        timeout_seconds: float = 30.0,
    ) -> str | None:
        """Discover the frontier function using GDB 'last-hit' tracing.

        Strategy:
          1. Extract all function symbols from the binary using ``nm``.
          2. Write a GDB Python script that sets a silent breakpoint on each
             function and tracks the last one hit.
          3. Run the binary with the seed under GDB.
          4. When the binary exits, print the last function hit.

        The last function executed before the rejection path begins is the
        math wall — the function that the LLM must solve.

        Results are cached by seed content hash to avoid redundant GDB runs
        during long campaigns where AFL++ triggers multiple stall detections
        on the same blocking function.

        Returns:
            Hex address string (e.g., ``0x00401234``) or None if discovery fails.
        """
        # Check cache first.
        seed_data = seed_path.read_bytes()
        seed_hash = hashlib.sha256(seed_data).hexdigest()[:16]
        if seed_hash in self._frontier_cache:
            cached = self._frontier_cache[seed_hash]
            logger.debug(
                "Frontier cache hit: %s → %s (seed=%s)",
                seed_hash, cached, seed_path.name,
            )
            return cached

        # Step 1: Extract function symbols from the binary.
        try:
            nm_result = subprocess.run(
                ["nm", "--defined-only", "--print-size", str(binary)],
                capture_output=True, text=True, timeout=10,
            )
            if nm_result.returncode != 0:
                logger.warning("nm failed: %s", nm_result.stderr.strip())
                return None
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("nm error: %s", e)
            return None

        # Parse nm output: filter for text-section functions (T/t).
        # Exclude compiler-generated and library stubs.
        _EXCLUDE_PREFIXES = (
            "__", "_start", "_fini", "_init", "frame_dummy",
            "register_tm", "deregister_tm", "__libc", "__afl",
            "__sanitizer", "__sancov", "sancov",
            # HAL / utility functions that appear at deep depths
            # during initialization but are not the math wall.
            "Memory_", "Hal_", "Socket_", "Thread_", "Semaphore_",
            "Tls_", "malloc", "calloc", "realloc", "free",
            "fopen", "fclose", "fread", "fwrite", "fprintf", "printf",
            "memcpy", "memset", "memmove", "strlen", "strcmp", "strncmp",
            "setup_", "main", "exit", "abort",
        )
        functions: list[tuple[str, str]] = []  # (file_offset_addr, name)
        for line in nm_result.stdout.splitlines():
            parts = line.split()
            # nm output: "address [size] type name" or "address type name"
            if len(parts) < 3:
                continue
            if len(parts) == 4:
                addr, _size, sym_type, name = parts
            else:
                addr, sym_type, name = parts[0], parts[-2], parts[-1]
            if sym_type not in ("T", "t"):
                continue
            if any(name.startswith(p) for p in _EXCLUDE_PREFIXES):
                continue
            functions.append((addr, name))

        if not functions:
            logger.warning("No text-section functions found in %s", binary)
            return None

        logger.info(
            "Frontier discovery: tracing %d functions in %s with seed %s",
            len(functions), binary.name, seed_path.name,
        )

        # Step 2: Build a GDB Python script that tracks the function
        # at maximum call stack depth. The math wall is always deeper
        # than main() — deeper than cleanup functions like free().
        #
        # IMPORTANT: We use SYMBOL NAMES for breakpoints, not raw addresses.
        # AFL++ compiles PIE binaries, so nm addresses are file offsets that
        # differ from runtime virtual addresses. GDB resolves symbol names
        # correctly regardless of ASLR/PIE.
        #
        # Strategy: on each breakpoint hit, measure the current stack
        # depth via len(gdb.execute("bt", to_string=True).splitlines()).
        # If this depth is deeper than the recorded maximum, update the
        # frontier. This ensures we capture CRC::IsCorrectCRC (depth=6)
        # rather than LinkLayerParser::ReadHeader (depth=4).

        # Build function name list for GDB Python (use symbol names, not addresses).
        func_list_str = ", ".join(
            f'("{name}",)' for _addr, name in functions
        )

        gdb_script = "\n".join([
            "set pagination off",
            "set confirm off",
            "set debuginfod enabled off",
            "set print address on",
            # Use Python for all breakpoint logic.
            "python",
            "import gdb",
            "",
            "max_depth = 0",
            'deepest_func = "NONE"',
            'deepest_name = "unknown"',
            "",
            f"func_list = [{func_list_str}]",
            "",
            "class FrontierBreakpoint(gdb.Breakpoint):",
            "    def __init__(self, sym_name):",
            # Use symbol name directly — GDB resolves PIE at runtime.
            '        super().__init__(sym_name, internal=True)',
            "        self.silent = True",
            "        self.sym_name = sym_name",
            "",
            "    def stop(self):",
            "        global max_depth, deepest_func, deepest_name",
            "        try:",
            '            bt = gdb.execute("bt", to_string=True)',
            "            depth = len([l for l in bt.splitlines() if l.startswith('#')])",
            "            if depth > max_depth:",
            "                max_depth = depth",
            "                deepest_func = self.sym_name",
            "                deepest_name = self.sym_name",
            "        except:",
            "            pass",
            "        return False  # Don't stop, continue execution",
            "",
            "for (sym_name,) in func_list:",
            "    try:",
            "        FrontierBreakpoint(sym_name)",
            "    except:",
            "        pass",
            "",
            "end",
            # Run with the seed file.
            f"run {seed_path}",
            # After exit, resolve the runtime address of the deepest function.
            # We need the address for Ghidra's P-Code extraction.
            "python",
            "runtime_addr = 'NONE'",
            "if deepest_func != 'NONE':",
            "    try:",
            "        info = gdb.execute(f'info address {deepest_func}', to_string=True)",
            "        # Parse: 'Symbol \"foo\" is at 0x5555555551a0 ...'",
            "        import re",
            "        m = re.search(r'0x[0-9a-fA-F]+', info)",
            "        if m:",
            "            runtime_addr = m.group(0)",
            "    except:",
            "        pass",
            'print(f"FRONTIER_FUNC={runtime_addr} {deepest_name}")',
            "end",
            "quit",
        ]) + "\n"

        gdb_script_path = Path(
            tempfile.mktemp(suffix=".gdb", prefix="frontier_")
        )
        gdb_script_path.write_text(gdb_script)

        # Step 3: Run GDB.
        try:
            proc = subprocess.run(
                [
                    "gdb", "--batch", "--nx",
                    "-x", str(gdb_script_path),
                    str(binary),
                ],
                capture_output=True, text=True,
                timeout=timeout_seconds,
            )
            output = proc.stdout
        except subprocess.TimeoutExpired:
            logger.warning(
                "Frontier discovery: GDB timed out after %.0fs", timeout_seconds,
            )
            return None
        except FileNotFoundError:
            logger.warning("Frontier discovery: GDB not found")
            return None
        finally:
            gdb_script_path.unlink(missing_ok=True)

        # Step 4: Parse the FRONTIER_FUNC output.
        # The GDB script may output a runtime (PIE-relocated) address.
        # We need to map back to the file-offset address for Ghidra.
        # Build a name→file_offset lookup from the nm functions list.
        name_to_offset = {name: f"0x{addr}" for addr, name in functions}

        for line in output.splitlines():
            if "FRONTIER_FUNC=" in line:
                _, _, payload = line.partition("FRONTIER_FUNC=")
                payload = payload.strip()
                if not payload:
                    logger.warning("Frontier discovery: empty output")
                    return None
                parts = payload.split(None, 1)
                addr_str = parts[0]
                func_name = parts[1] if len(parts) > 1 else "unknown"
                # GDB script initializes with "NONE" when no function was hit.
                if addr_str == "NONE" or func_name == "unknown":
                    logger.info(
                        "Frontier discovery: no function hit via seed %s",
                        seed_path.name,
                    )
                    return None
                # Map the function name back to its nm file-offset address.
                # This is needed because GDB outputs PIE-relocated runtime
                # addresses, but Ghidra loads binaries at its own base.
                file_offset = name_to_offset.get(func_name)
                if file_offset:
                    addr_str = file_offset
                    logger.info(
                        "Frontier discovered: %s (%s) via seed %s "
                        "(mapped from runtime to file offset)",
                        addr_str, func_name, seed_path.name,
                    )
                else:
                    logger.info(
                        "Frontier discovered: %s (%s) via seed %s "
                        "(using runtime addr — no nm mapping found)",
                        addr_str, func_name, seed_path.name,
                    )
                # Cache the result.
                self._frontier_cache[seed_hash] = addr_str
                return addr_str

        logger.warning(
            "Frontier discovery: FRONTIER_FUNC not found in GDB output"
        )
        return None

    def _compute_severity(
        self,
        stall_address: str,
        cycles_stalled: int,
        total_edges: int,
    ) -> StallSeverity:
        """
        Compute the severity of a stall based on interestingness.

        Factors:
          - Cycles stalled (more cycles = higher severity)
          - Total edges found (fewer edges = more constrained = higher severity)

        Thresholds are tuned for typical ICS firmware fuzz campaigns.
        """
        if cycles_stalled >= self.min_stall_cycles * 4:
            return StallSeverity.CRITICAL
        elif cycles_stalled >= self.min_stall_cycles * 2:
            return StallSeverity.HIGH
        elif cycles_stalled >= self.min_stall_cycles:
            return StallSeverity.MEDIUM
        else:
            return StallSeverity.LOW

    def _find_closest_seed(self, stall_address: str) -> Path:
        """
        Find the seed input in AFL++'s queue that best represents the stall.

        Strategy:
          1. Prefer the ORIGINAL corpus seed (AFL marks these with 'orig:'
             in the filename). This preserves the correct protocol frame size.
          2. Fall back to the longest seed that's <= 1024 bytes. This avoids
             both AFL-trimmed seeds (too short, missing protocol fields) and
             AFL havoc-bloated seeds (too long, confuses the LLM prompt).

        In production, this would use AFL++'s coverage bitmap to find the
        seed with the closest edge-set to the stall address.

        Returns:
            Path to the closest seed file. May not exist if queue is empty.
        """
        queue_candidates = [
            self.afl_output_dir / "default" / "queue",
            self.afl_output_dir / "queue",
        ]
        if self.afl_output_dir.is_dir():
            for child in sorted(self.afl_output_dir.iterdir()):
                if child.is_dir() and (child / "queue").exists():
                    queue_candidates.insert(0, child / "queue")

        for queue_dir in queue_candidates:
            if queue_dir.is_dir():
                seeds = [
                    f for f in queue_dir.iterdir()
                    if f.is_file() and f.name.startswith("id:")
                ]
                if not seeds:
                    continue

                # Priority 1: prefer original corpus seeds.
                orig_seeds = [f for f in seeds if "orig:" in f.name]
                if orig_seeds:
                    return max(orig_seeds, key=lambda f: f.stat().st_size)

                # Priority 2: longest seed that's <= 1024 bytes.
                MAX_SEED_SIZE = 1024
                reasonable = [
                    f for f in seeds if f.stat().st_size <= MAX_SEED_SIZE
                ]
                if reasonable:
                    return max(reasonable, key=lambda f: f.stat().st_size)

                # Priority 3: if all seeds are huge, pick the smallest.
                return min(seeds, key=lambda f: f.stat().st_size)

        # Fallback: return a path that won't exist (handled by caller).
        return self.afl_output_dir / "queue" / "id:000000,orig:seed"

    def _find_seed_candidates(self, max_seeds: int = 5) -> list[Path]:
        """Return up to max_seeds queue entries, sorted by size (largest first).

        Larger seeds are more likely to reach deeper protocol paths and
        exercise the math wall function. Original corpus seeds are
        prioritized over AFL++-generated seeds.
        """
        queue_candidates = [
            self.afl_output_dir / "default" / "queue",
            self.afl_output_dir / "queue",
        ]
        if self.afl_output_dir.is_dir():
            for child in sorted(self.afl_output_dir.iterdir()):
                if child.is_dir() and (child / "queue").exists():
                    queue_candidates.insert(0, child / "queue")

        all_seeds: list[Path] = []
        for queue_dir in queue_candidates:
            if queue_dir.is_dir():
                seeds = [
                    f for f in queue_dir.iterdir()
                    if f.is_file() and f.name.startswith("id:")
                       and f.stat().st_size <= 1024
                ]
                all_seeds.extend(seeds)

        if not all_seeds:
            return []

        # Sort: original seeds first, then by size descending.
        def seed_key(f: Path) -> tuple[int, int]:
            is_orig = 0 if "orig:" in f.name else 1
            return (is_orig, -f.stat().st_size)

        all_seeds.sort(key=seed_key)
        return all_seeds[:max_seeds]

    def _get_binary_path(self) -> Path:
        """
        Extract the binary path from AFL++'s fuzzer_stats or cmdline file.
        """
        # If a target binary was explicitly provided, use it.
        if self._target_binary:
            return self._target_binary

        # Try reading from the cmdline file.
        cmdline_candidates = [
            self.afl_output_dir / "default" / "cmdline",
            self.afl_output_dir / "cmdline",
        ]
        for cmdline_path in cmdline_candidates:
            if cmdline_path.exists():
                try:
                    parts = cmdline_path.read_text().strip().split()
                    if parts:
                        return Path(parts[0])
                except (OSError, UnicodeDecodeError):
                    pass

        # Fallback from fuzzer_stats command_line key.
        stats = self._parse_fuzzer_stats()
        cmd_line = stats.get("command_line", "")
        if cmd_line:
            parts = cmd_line.split()
            # Find the binary after the last -- or the first non-flag argument.
            for i, part in enumerate(parts):
                if part == "--":
                    if i + 1 < len(parts):
                        return Path(parts[i + 1])
                elif not part.startswith("-") and "/" in part:
                    return Path(part)

        return Path("unknown_binary")

    def resolve_stall(self, stall_address: str) -> None:
        """
        Mark a stall as resolved (payload was successfully injected).

        The address is KEPT in _known_stalls so the detector never
        re-reports it. It is also added to _resolved_stalls for
        explicit tracking.
        """
        # Keep in _known_stalls to suppress re-detection.
        self._known_stalls.add(stall_address)
        self._resolved_stalls.add(stall_address)
        self._stall_cycle_counts.pop(stall_address, None)
        logger.info("Resolved stall at %s (permanently suppressed)", stall_address)

    def get_status(self) -> dict:
        """Return current detector status for diagnostics."""
        return {
            "known_stalls": len(self._known_stalls),
            "stall_addresses": sorted(self._known_stalls),
            "plateau_cycles": self._plateau_cycles,
            "last_edges": self._last_edges_found,
        }
