"""
agent_loop.py — The Main Asynchronous Orchestration Daemon.

This is the CENTRAL COORDINATOR of the runtime pipeline. It watches for
AFL++ stalls, orchestrates the full Extract → Translate → Solve → Inject
cycle, and manages the ReAct self-correction loop.

This module ties together ALL other components:
  - fuzzer_bridge/stall_detector.py   → Detects stalls
  - extractor/pcode_slicer.py         → Extracts P-Code slices
  - extractor/constraint_profiler.py  → Profiles constraints
  - extractor/spec_exporter.py        → Persists specs to PostgreSQL
  - orchestrator/retrieval_carm.py    → Retrieves templates
  - orchestrator/llm_client.py        → Generates Z3 scripts
  - orchestrator/z3_sandbox.py        → Executes Z3 scripts
  - fuzzer_bridge/payload_injector.py → Injects solved payloads

Reference: HyLLfuzz §3.1-3.4 — Parallel plugin architecture.
Reference: SAILOR §4 — Iterative compile-execute-refine loop.
Reference: TDD_v2 §5 — Phase 2 runtime loop.

Key Design Decisions:
    1. FULLY ASYNCHRONOUS: The agent loop runs as an asyncio daemon.
       It NEVER blocks AFL++'s execution. All communication is through
       the filesystem (sync directory) — no shared memory, no blocking IPC.

    2. REACT LOOP: When Z3 fails (UNSAT/TIMEOUT/ERROR), the agent does
       NOT immediately give up. It enters a ReAct loop:
         Thought: "The Z3 script failed because of [error]."
         Action:  Feed the error back to the LLM for repair.
         Observation: "The repaired script returned [verdict]."
       Up to config.max_react_turns (default 5) iterations.

    3. GRACEFUL DEGRADATION: If all ReAct turns fail, the stall is
       deferred back to AFL++ for probabilistic mutation. The agent
       records the failure in the VulnerabilitySpec's correction_history
       for future learning.

    4. PRIORITY QUEUE: Stalls are processed in severity order (CRITICAL
       first). This ensures the most impactful stalls are attacked first.
"""

from __future__ import annotations

import asyncio
import logging
import re
import signal
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.constants import ARCH_REGISTER_WIDTH, StallSeverity, Z3Verdict
from agentic_afl.models import (
    CorrectionEntry,
    SolvedPayload,
    StallReport,
    VulnerabilitySpec,
    Z3GenerationRequest,
    Z3Result,
    Z3Script,
)

logger = logging.getLogger(__name__)


class AgentLoop:
    """
    The main orchestration daemon.

    Lifecycle:
        1. Initialize all sub-components.
        2. Enter the main loop: poll for stalls → process stalls → inject payloads.
        3. Shut down gracefully on signal (SIGINT/SIGTERM).

    Usage:
        loop = AgentLoop()
        await loop.run()  # Runs until interrupted
    """

    def __init__(
        self,
        afl_output_dir: Path | str | None = None,
        afl_sync_dir: Path | str | None = None,
        target_binary: Path | str | None = None,
        stall_address_override: str | None = None,
        min_stall_cycles: int | None = None,
        harvest_mode: bool = False,
        register_signals: bool = True,
    ) -> None:
        import typing
        # Explicit directory overrides (test scripts pass these directly).
        # Falls back to settings (which reads from .env / os.environ).
        self._afl_output_dir = Path(afl_output_dir) if afl_output_dir else settings.afl_output_dir
        self._afl_sync_dir = Path(afl_sync_dir) if afl_sync_dir else settings.afl_sync_dir
        self._target_binary = Path(target_binary) if target_binary else None
        self._stall_address_override = stall_address_override
        self._min_stall_cycles = min_stall_cycles if min_stall_cycles is not None else settings.min_stall_cycles

        # Harvest mode: disable CARM retrieval, verify solves via edge
        # deltas, and auto-commit verified templates to the corpus.
        # Reference: Implementation Plan — Strategy 1 (AutoHarvest).
        self._harvest_mode = harvest_mode

        # When False, the caller is responsible for signal handling.
        # This prevents the agent's handler from overwriting the caller's.
        self._register_signals = register_signals

        # Lazy imports to avoid circular dependencies at module level.
        # These will be initialized in setup().
        self._slicer: typing.Any = None          # PCodeSlicer
        self._profiler: typing.Any = None        # ConstraintProfiler
        self._exporter: typing.Any = None        # SpecExporter
        self._store: typing.Any = None           # SpecStore
        self._retriever: typing.Any = None       # CARMRetriever
        self._llm_client: typing.Any = None      # LLMClient
        self._sandbox: typing.Any = None         # Z3Sandbox
        self._stall_detector: typing.Any = None  # StallDetector
        self._injector: typing.Any = None        # PayloadInjector

        # Priority queue of stalls to process.
        self._stall_queue: asyncio.PriorityQueue[tuple[int, StallReport]] = (
            asyncio.PriorityQueue()
        )

        # Track which stalls are currently being processed (by address).
        self._active_stalls: set[str] = set()

        # Permanently suppress stalls that have been successfully solved.
        # Once a payload is injected for an address, we never re-process it.
        self._solved_stalls: set[str] = set()

        # Shutdown flag.
        self._running = False

        # Runtime metrics.
        self._metrics = {
            "stalls_detected": 0,
            "stalls_processed": 0,
            "payloads_injected": 0,
            "react_turns_total": 0,
            "llm_calls_total": 0,
            # Harvest-mode specific metrics.
            "harvest_verified": 0,
            "harvest_committed": 0,
        }

    async def setup(self) -> None:
        """
        Initialize all sub-components.

        Called once before the main loop starts. This is where we:
          - Instantiate the slicer, profiler, exporter, retriever, etc.
          - Initialize the PostgreSQL spec store and CARM retriever.
          - Validate configuration (Ghidra path, API key, etc.).
        """
        from agentic_afl.database.spec_store import SpecStore
        from agentic_afl.extractor.constraint_profiler import ConstraintProfiler
        from agentic_afl.extractor.pcode_slicer import PCodeSlicer
        from agentic_afl.extractor.spec_exporter import SpecExporter
        from agentic_afl.fuzzer_bridge.payload_injector import PayloadInjector
        from agentic_afl.fuzzer_bridge.stall_detector import StallDetector
        from agentic_afl.orchestrator.llm_client import LLMClient
        from agentic_afl.orchestrator.retrieval_carm import CARMRetriever
        from agentic_afl.orchestrator.z3_sandbox import Z3Sandbox

        # PostgreSQL spec store + CARM retriever.
        self._store = SpecStore(dsn=settings.postgres_dsn)
        await self._store.initialize()

        # Extractor pipeline.
        self._slicer = PCodeSlicer()
        self._profiler = ConstraintProfiler()
        self._exporter = SpecExporter(store=self._store)

        # Orchestrator pipeline.
        self._retriever = CARMRetriever(store=self._store)
        self._llm_client = LLMClient()
        self._sandbox = Z3Sandbox()

        # Fuzzer bridge — use explicit parameters passed to __init__.
        self._stall_detector = StallDetector(
            afl_output_dir=self._afl_output_dir,
            min_stall_cycles=self._min_stall_cycles,
            target_binary=self._target_binary,
            stall_address_override=self._stall_address_override,
        )
        self._injector = PayloadInjector(sync_dir=self._afl_sync_dir)

        logger.info(
            "Agent loop initialized (provider=%s, model=%s, K=%d, max_turns=%d)",
            settings.llm_api_provider,
            settings.llm_model_name,
            settings.k_vote_count,
            settings.max_react_turns,
        )

    async def run(self) -> None:
        """
        Main daemon loop. Runs until self._running is set to False.

        Flow per iteration:
          1. Poll for new stalls from the stall detector.
          2. For each new stall, add to priority queue.
          3. Dequeue the highest-priority stall.
          4. Process it through the full pipeline.
          5. Sleep for config.stall_poll_interval.
        """
        self._running = True

        # Register signal handlers for graceful shutdown (only if not
        # managed by an external caller like test_generalization_matrix.py).
        if self._register_signals:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info("Agent loop started — polling every %.1fs", settings.stall_poll_interval)

        while self._running:
            try:
                # Step 1: Detect new stalls.
                new_stalls = await self._stall_detector.detect()
                for stall in new_stalls:
                    if (stall.stall_address not in self._active_stalls
                            and stall.stall_address not in self._solved_stalls):
                        priority = self._stall_priority(stall.severity)
                        await self._stall_queue.put((priority, stall))
                        self._metrics["stalls_detected"] += 1
                        logger.info(
                            "Queued stall: %s (severity=%s, queue_size=%d)",
                            stall.stall_address,
                            stall.severity.name,
                            self._stall_queue.qsize(),
                        )
                    elif stall.stall_address in self._solved_stalls:
                        logger.debug(
                            "Skipping solved stall: %s", stall.stall_address,
                        )

                # Step 2: Process the highest-priority stall.
                if not self._stall_queue.empty():
                    _, stall = await self._stall_queue.get()
                    self._active_stalls.add(stall.stall_address)
                    try:
                        success = await self._process_stall(stall)
                        self._metrics["stalls_processed"] += 1
                        if success:
                            # Mark as permanently solved — never re-process.
                            self._solved_stalls.add(stall.stall_address)
                            logger.info(
                                "Stall %s marked as SOLVED — suppressing future detections",
                                stall.stall_address,
                            )
                            self._stall_detector.resolve_stall(stall.stall_address)

                            # Diverse payload injection: generate valid
                            # frames for ALL protocol types to maximize
                            # post-bypass coverage exploration.
                            try:
                                from agentic_afl.fuzzer_bridge.diversity_generator import (
                                    DiversityGenerator,
                                )
                                div_gen = DiversityGenerator(
                                    sync_dir=self._injector.sync_dir,
                                )
                                div_count = await div_gen.generate_ics_crc32_variants(
                                    stall_address=stall.stall_address,
                                )
                                if div_count > 0:
                                    self._metrics["payloads_injected"] += div_count
                                    logger.info(
                                        "Diverse injection: %d additional frame variants",
                                        div_count,
                                    )
                            except Exception as div_err:
                                logger.debug(
                                    "Diversity generator skipped: %s", div_err,
                                )
                    except Exception as e:
                        logger.error(
                            "Failed to process stall %s: %s",
                            stall.stall_address, e,
                            exc_info=True,
                        )
                    finally:
                        self._active_stalls.discard(stall.stall_address)

                # Step 3: Sleep before next poll.
                await asyncio.sleep(settings.stall_poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unhandled error in agent loop: %s", e, exc_info=True)
                await asyncio.sleep(settings.stall_poll_interval)

        # Cleanup.
        if self._store:
            await self._store.close()
        logger.info("Agent loop stopped. Metrics: %s", self._metrics)

    async def _process_stall(self, stall: StallReport) -> bool:
        """
        Process a single stall through the full pipeline.

        This is the core logic:
          1. Extract P-Code slice from the binary at the stall address.
          2. Profile the constraint types.
          3. Export/update the VulnerabilitySpec.
          4. Query CARM for similar templates.
          5. Generate Z3 scripts (K-way voting).
          6. Execute scripts in the sandbox.
          7. If SAT: extract payload and inject into AFL++.
          8. If FAIL: enter ReAct self-correction loop.

        Args:
            stall: The StallReport to process.

        Returns:
            True if a payload was successfully injected, False otherwise.
        """
        logger.info(
            "Processing stall at %s (severity=%s, cycles=%d)",
            stall.stall_address, stall.severity.name, stall.cycles_stalled,
        )

        # Step 1: Extract P-Code slice.
        # The taint source is the register carrying the input buffer pointer.
        # On x86_64, the first argument to process_modbus_packet(buf, n)
        # is passed in RDI. The slicer uses this to prune LOAD operations
        # that dereference pointers NOT derived from the input buffer.
        taint_source = "RDI"  # x86_64 System V ABI: 1st arg register
        pcode_slice = self._slicer.extract_slice(
            binary_path=stall.binary_path,
            stall_address=stall.stall_address,
            taint_source=taint_source,
        )

        # Step 2: Profile constraints.
        profile = self._profiler.analyze(pcode_slice)
        logger.info(
            "Profile: tags=%s, complexity=%d",
            [t.name for t in profile.tags],
            profile.estimated_complexity,
        )

        # Step 3: Export spec to PostgreSQL.
        spec = await self._exporter.export(pcode_slice, profile)

        # Step 4: Retrieve similar templates from CARM.
        # In harvest_mode, CARM is intentionally disabled to force zero-shot
        # generation. This ensures that any successful solve is genuinely novel
        # and worth committing to the corpus.
        if self._harvest_mode:
            retrieval_results = []
            templates = []
            logger.info("CARM: DISABLED (harvest_mode=True, zero-shot generation)")
        else:
            retrieval_results = await self._retriever.query(
                query_profile=profile,
                architecture=pcode_slice.architecture,
            )
            templates = [r.z3_template for r in retrieval_results if r.z3_template]
            logger.info(
                "CARM: %d results, %d with templates",
                len(retrieval_results), len(templates),
            )

        # Step 4.5: Discover input pointer base offset (REDQUEEN-style probe).
        # This determines where in the file the constraint function's `input`
        # pointer actually starts, preventing byte offset mismatch.
        from agentic_afl.extractor.offset_probe import (
            discover_base_offset,
            extract_arg_memory,
        )
        base_offset = await discover_base_offset(
            binary=stall.binary_path,
            seed=stall.seed_input,
            stall_address=stall.stall_address,
            function_name=pcode_slice.function_name,
        )
        if base_offset > 0:
            logger.info(
                "Offset probe: input[0] = byte_%d of file", base_offset,
            )

        # Step 4.6: Extract runtime state at function arguments via GDB.
        # Multi-seed probe: try up to 5 seeds from the AFL queue until
        # one hits the breakpoint. Different seeds exercise different code
        # paths — e.g., S-frame seeds reach checkSequenceNumber while
        # I-frame seeds may fail at an earlier check in checkMessage.
        runtime_state: dict[str, str] = {}
        probe_seeds = self._gather_probe_seeds(stall)
        for i, probe_seed in enumerate(probe_seeds):
            runtime_state = await extract_arg_memory(
                binary=stall.binary_path,
                seed=probe_seed,
                stall_address=stall.stall_address,
                function_name=pcode_slice.function_name,
            )
            if runtime_state:
                logger.info(
                    "Arg memory probe: hit on seed %d/%d",
                    i + 1, len(probe_seeds),
                )
                break
        if not runtime_state:
            logger.info(
                "Arg memory probe: no seed hit breakpoint (%d tried) — "
                "LLM will rely on caller C for struct constants",
                len(probe_seeds),
            )

        # Step 5: Build generation request.
        request = Z3GenerationRequest(
            vuln_spec=spec,
            seed_input=stall.seed_input,
            retrieved_templates=templates,
            correction_history=list(spec.correction_history),
            k_vote_count=settings.k_vote_count,
            base_offset=base_offset,
            runtime_state=runtime_state,
        )

        # Step 6: Generate and solve (with ReAct loop).
        result = await self._generate_and_solve(request, spec)

        # Step 7: Inject if successful.
        if result is not None:
            payload, winning_script = result

            # Record edge count BEFORE injection for harvest verification.
            pre_inject_edges = 0
            if self._harvest_mode:
                from agentic_afl.orchestrator.harvest_mode import read_edges_from_stats
                pre_inject_edges = await read_edges_from_stats(self._afl_output_dir)

            await self._injector.inject(payload)
            await self._retriever.update_template(spec.spec_id, winning_script)
            self._metrics["payloads_injected"] += 1
            logger.info(
                "✓ Payload injected for %s (%d bytes, confidence=%.2f)",
                stall.stall_address, len(payload.raw_bytes), payload.confidence,
            )

            # Harvest mode: verify the solve via AFL++ edge coverage.
            if self._harvest_mode:
                from agentic_afl.orchestrator.harvest_mode import (
                    commit_verified_template,
                    wait_for_edge_delta,
                )
                edge_delta = await wait_for_edge_delta(
                    afl_output_dir=self._afl_output_dir,
                    baseline_edges=pre_inject_edges,
                    timeout_seconds=90.0,
                )
                if edge_delta > 0:
                    self._metrics["harvest_verified"] += 1
                    # Auto-commit the verified triplet.
                    from agentic_afl.database.spec_store import SpecStore
                    tag_ints = SpecStore.tags_to_int_array(profile.tags)
                    await commit_verified_template(
                        store=self._store,
                        pcode_text=pcode_slice.pcode_text,
                        constraint_tags=tag_ints,
                        z3_script=winning_script,
                        binary_path=str(stall.binary_path),
                        function_name=pcode_slice.function_name,
                        stall_address=stall.stall_address,
                        architecture=spec.architecture,
                    )
                    self._metrics["harvest_committed"] += 1
                    logger.info(
                        "✓ HARVEST: Verified solve committed to CARM "
                        "(+%d edges, total_committed=%d)",
                        edge_delta, self._metrics["harvest_committed"],
                    )
                else:
                    logger.warning(
                        "✗ HARVEST: Solve NOT verified — no new edges after injection"
                    )

            return True

        logger.warning(
            "✗ All ReAct turns exhausted for %s — deferring to AFL++",
            stall.stall_address,
        )
        return False

    async def _generate_and_solve(
        self,
        request: Z3GenerationRequest,
        spec: VulnerabilitySpec,
    ) -> tuple[SolvedPayload, str] | None:
        """
        Generate Z3 scripts, execute them, and enter the ReAct loop on failure.

        This method implements the K-way voting (LINC) + self-repair (LLM-Sym)
        + ReAct turn budget (SAILOR) strategy.

        Algorithm:
          For each ReAct turn (up to max_react_turns):
            1. Generate K Z3 scripts via LLM (K-way voting).
            2. Execute all K scripts in parallel via sandbox.
            3. If any script returns SAT:
               - Extract the model as a byte payload.
               - Record the winning script as a template.
               - Return (payload, winning_script_text).
            4. If all K scripts fail:
               - Select the "best" failure (prefer UNSAT over ERROR).
               - Feed the error back to the LLM for repair.
               - Update the request with correction history.
               - Continue to next ReAct turn.

        Returns:
            (SolvedPayload, winning_script_text) if successful, None if all turns exhausted.
        """
        for turn in range(settings.max_react_turns):
            logger.info(
                "ReAct turn %d/%d for %s",
                turn + 1, settings.max_react_turns, spec.stall_address,
            )
            self._metrics["react_turns_total"] += 1

            # K-way generation.
            if turn == 0:
                scripts = await self._llm_client.generate_z3_scripts(request)
            else:
                # On subsequent turns, repair the best-failing script
                # and also generate fresh candidates.
                scripts = await self._llm_client.generate_z3_scripts(request)

            self._metrics["llm_calls_total"] += 1

            # Parallel execution in sandbox.
            results: list[Z3Result] = await asyncio.gather(*[
                self._sandbox.execute(script) for script in scripts
            ])

            # Debug: save scripts and results for post-mortem analysis.
            if settings.debug_mode:
                debug_dir = Path("/tmp/agentic_afl_debug")
                debug_dir.mkdir(exist_ok=True)
                for idx, (script, result) in enumerate(zip(scripts, results)):
                    stem = f"turn{turn+1}_k{idx}_{result.verdict.value}"
                    (debug_dir / f"{stem}.py").write_text(script.script_text)
                    (debug_dir / f"{stem}.txt").write_text(
                        f"verdict={result.verdict.value}\n"
                        f"model={result.model}\n"
                        f"error={result.error_message}\n"
                    )

            # Check for SAT — accept partial models if they cover enough
            # constraint-critical bytes.  _model_to_payload() will merge
            # solved bytes onto the original seed, so uncovered bytes
            # retain their original seed values (not zeroed).
            #
            # Minimum acceptance threshold: at least 8 byte vars OR
            # at least 50% of the input length, whichever is smaller.
            # This allows the LLM to solve just the protocol header
            # (e.g., 10-byte DNP3 header) without needing to constrain
            # 500+ bytes of body data.
            sat_results = [
                r for r in results
                if r.verdict == Z3Verdict.SAT and r.model
            ]
            if sat_results:
                input_len = len(request.seed_input) if request.seed_input else 0

                def _byte_var_count(r: Z3Result) -> int:
                    """Count byte_N variables in a model."""
                    if not r.model:
                        return 0
                    return sum(
                        1 for name in r.model
                        if re.match(r"(?:byte_?|b_)\d+", name)
                    )

                # Sort by byte coverage (descending), pick the most complete.
                sat_results.sort(key=_byte_var_count, reverse=True)
                best_sat = sat_results[0]
                n_vars = _byte_var_count(best_sat)

                # Minimum threshold: 8 bytes or 50% of input, whichever
                # is smaller.  For short inputs (< 16 bytes) accept any SAT.
                min_required = min(8, max(input_len // 2, 1)) if input_len > 0 else 1

                if n_vars < min_required:
                    # Trivially incomplete — reject and feed correction.
                    logger.warning(
                        "SAT model rejected: only %d/%d byte vars covered "
                        "(need at least %d)",
                        n_vars, input_len, min_required,
                    )
                    missing = sorted(
                        set(range(min(input_len, 16))) - {
                            int(m.group(1))
                            for name in (best_sat.model or {})
                            if (m := re.match(r"(?:byte_?|b_)(\d+)", name))
                        }
                    )
                    correction = CorrectionEntry(
                        error_message=(
                            f"INCOMPLETE MODEL: Your script only constrained "
                            f"{n_vars} byte variables (need at least {min_required}). "
                            f"Missing critical bytes: "
                            f"{['byte_' + str(i) for i in missing[:10]]}. "
                            f"You MUST model the hash/checksum computation to "
                            f"constrain the CRC/checksum field bytes."
                        ),
                        corrected_script=best_sat.script.script_text,
                    )
                    request.correction_history.append(correction)
                    if self._store:
                        await self._store.append_correction(
                            spec_id=spec.spec_id,
                            error_message=correction.error_message,
                            corrected_script=correction.corrected_script,
                        )
                    continue  # → next ReAct turn

                # Accept partial model — _model_to_payload merges solved
                # bytes with original seed bytes for uncovered positions.

                payload = self._model_to_payload(best_sat, spec, seed_input=request.seed_input, base_offset=request.base_offset)
                winning_script = best_sat.script.script_text
                logger.info(
                    "SAT found on turn %d (script %d, %d/%d byte vars): %s",
                    turn + 1,
                    best_sat.script.generation_idx,
                    n_vars,
                    input_len,
                    best_sat.model,
                )
                return (payload, winning_script)

            # All K scripts failed — select best failure for repair.
            best_failure = self._select_best_failure(results)
            if best_failure is None:
                logger.warning("No results to repair from")
                break

            logger.info(
                "Turn %d failed: best=%s, error=%s",
                turn + 1,
                best_failure.verdict.value,
                (best_failure.error_message or "")[:100],
            )

            # Record correction entry.
            correction = CorrectionEntry(
                error_message=best_failure.error_message or "Unknown error",
                corrected_script=best_failure.script.script_text,
            )
            request.correction_history.append(correction)

            # Persist the correction in PostgreSQL for future learning.
            if self._store:
                await self._store.append_correction(
                    spec_id=spec.spec_id,
                    error_message=correction.error_message,
                    corrected_script=correction.corrected_script,
                )

        logger.warning(
            "All %d ReAct turns exhausted for %s",
            settings.max_react_turns, spec.stall_address,
        )
        return None

    def _gather_probe_seeds(self, stall: StallReport, max_seeds: int = 5) -> list[bytes]:
        """Gather candidate seeds for multi-seed GDB probing.

        Different seeds exercise different code paths. For example, S-frame
        seeds may reach checkSequenceNumber while I-frame seeds fail at an
        earlier check. We prioritize by file size (larger = deeper paths)
        and always include the stall detector's chosen seed.

        Returns:
            Up to max_seeds byte strings to probe, ordered by priority.
        """
        candidates: list[bytes] = []

        # Priority 1: The stall detector's chosen seed (closest to stall).
        if stall.seed_input:
            candidates.append(stall.seed_input)

        # Priority 2: Other seeds from the AFL queue, sorted by size descending
        # (larger files tend to reach deeper code paths).
        try:
            queue_dir = self._afl_output_dir / "default" / "queue"
            if queue_dir.exists():
                queue_files = sorted(
                    (f for f in queue_dir.iterdir() if f.is_file() and f.name.startswith("id:")),
                    key=lambda f: f.stat().st_size,
                    reverse=True,
                )
                for qf in queue_files:
                    if len(candidates) >= max_seeds:
                        break
                    seed_bytes = qf.read_bytes()
                    # Skip if identical to an already-added seed.
                    if seed_bytes not in candidates:
                        candidates.append(seed_bytes)
        except Exception as e:
            logger.debug("Could not read AFL queue for probe seeds: %s", e)

        # Priority 3: Original seed directory (if queue is empty or small).
        try:
            seed_dir = self._afl_output_dir.parent / "seeds"
            if not seed_dir.exists():
                # Try the input directory configured for AFL
                seed_dir = Path(str(self._afl_output_dir).replace("/out", "/in"))
            if seed_dir.exists():
                seed_files = sorted(seed_dir.iterdir())
                for sf in seed_files:
                    if len(candidates) >= max_seeds:
                        break
                    if sf.is_file():
                        seed_bytes = sf.read_bytes()
                        if seed_bytes not in candidates:
                            candidates.append(seed_bytes)
        except Exception as e:
            logger.debug("Could not read seed dir for probe seeds: %s", e)

        logger.info(
            "Gathered %d probe seed candidates (sizes: %s)",
            len(candidates),
            [len(s) for s in candidates],
        )
        return candidates

    def _model_to_payload(
        self,
        result: Z3Result,
        spec: VulnerabilitySpec,
        seed_input: bytes = b"",
        base_offset: int = 0,
    ) -> SolvedPayload:
        """
        Convert a Z3 model (dict of variable assignments) into raw bytes.

        The model may contain:
          A) Byte-indexed variables: byte_0, byte_1, ..., byte_N
             These directly map to positions in the input buffer.
          B) Register/memory variables: reg_0, CF, DL, unique_0x23b00
             These are raw register values without position information.

        Strategy:
          - If byte-indexed variables are present, overlay them onto the seed
            input (which serves as the template for the rest of the packet).
          - If only register variables are present, concatenate them by name
            order, but pad to at least the seed input length.

        Returns:
            SolvedPayload with raw_bytes ready for sync directory injection.
        """
        import re

        model = result.model or {}
        register_width = ARCH_REGISTER_WIDTH.get(spec.architecture, 32)
        register_bytes = register_width // 8

        # Get the seed input as the base template.
        seed = seed_input or b""

        # Compute confidence from K-way voting agreement.
        confidence = 1.0  # Single SAT = full confidence

        # Check if model contains byte-indexed variables (byte_0, byte_1, etc.)
        byte_vars: dict[int, int] = {}
        reg_vars: dict[str, int] = {}
        for name, value in model.items():
            # Match byte_N, b_N, or byte_NN patterns.
            m = re.match(r"(?:byte_?|b_)(\d+)", name)
            if m:
                byte_vars[int(m.group(1))] = value
            else:
                reg_vars[name] = value

        if byte_vars:
            # Strategy A: Seed Splicing with Conditional Padding.
            # 1. Start with the original seed as the base template.
            # 2. Overlay Z3-solved byte values at their positions.
            # 3. Preserve the seed's tail bytes beyond the solved region.
            # 4. Conditionally append synthetic padding: ONLY when the LLM
            #    solved a partial region (offset > 0), meaning there's a
            #    multi-packet structure and the fuzzer needs "fuel" to
            #    explore post-constraint states.
            #    Do NOT pad when the LLM solved ALL bytes (byte_0 through
            #    byte_{N-1}), because the input length is semantically
            #    meaningful — padding would corrupt hashes/checksums
            #    computed over the full buffer.
            max_pos = max(byte_vars.keys()) + 1

            # Determine whether padding is appropriate.
            # Use the offset probe result: if base_offset > 0, this is a
            # multi-packet/interprocedural target where the function
            # receives a sub-buffer (e.g., buf+6). Padding gives AFL++
            # mutation fuel to explore post-constraint states.
            # Do NOT pad when base_offset == 0 — the input length is
            # semantically meaningful (hashes/checksums over full buffer).
            _SYNTHETIC_PAD = 32
            needs_padding = base_offset > 0
            pad_amount = _SYNTHETIC_PAD if needs_padding else 0

            buf_len = max(max_pos, len(seed)) + pad_amount
            payload = bytearray(seed.ljust(buf_len, b"\x00"))
            for pos, val in byte_vars.items():
                if pos < len(payload):
                    payload[pos] = val & 0xFF
            raw_bytes = bytes(payload)

            logger.info(
                "Payload built from %d byte-indexed Z3 vars "
                "(seed=%d bytes, solved_max=byte_%d, payload=%d bytes%s)",
                len(byte_vars), len(seed), max_pos - 1,
                len(raw_bytes),
                f" [+{pad_amount} pad]" if pad_amount else "",
            )
        else:
            # Strategy B: Concatenate register values.
            # This is a fallback for when the LLM uses register-style naming.
            raw_parts: list[bytes] = []
            for name in sorted(reg_vars.keys()):
                value = reg_vars[name]
                if any(name.startswith(p) for p in ("byte", "b_", "char")):
                    raw_parts.append(value.to_bytes(1, byteorder="big"))
                elif name.endswith("_lo") or name.endswith("_hi"):
                    raw_parts.append(value.to_bytes(1, byteorder="big"))
                else:
                    byte_len = max(1, (value.bit_length() + 7) // 8)
                    byte_len = min(byte_len, register_bytes)
                    raw_parts.append(value.to_bytes(byte_len, byteorder="big"))

            raw_bytes = b"".join(raw_parts)

            # If seed is longer, pad the payload with seed bytes after the model data.
            if len(raw_bytes) < len(seed):
                raw_bytes = raw_bytes + seed[len(raw_bytes):]

            logger.info(
                "Payload built from %d register vars (concatenated=%d bytes, seed=%d bytes)",
                len(reg_vars), len(raw_bytes), len(seed),
            )

        return SolvedPayload(
            raw_bytes=raw_bytes,
            source_spec_id=spec.spec_id,
            stall_address=spec.stall_address,
            z3_model=model,
            confidence=confidence,
        )

    def _select_best_failure(self, results: list[Z3Result]) -> Z3Result | None:
        """
        Select the "best" failure for self-repair feedback.

        Preference order (most informative for repair):
          1. UNSAT — the logic compiled but is unsatisfiable (structural error)
          2. RUNTIME_ERROR — the script ran but hit a Python exception
          3. SYNTAX_ERROR — the Z3 code didn't parse
          4. TIMEOUT — Z3 couldn't solve in time (may need concretization)
          5. UNKNOWN — Z3 returned unknown

        Returns:
            The Z3Result to use for repair, or None if no results.
        """
        if not results:
            return None

        preference = {
            Z3Verdict.UNSAT: 0,
            Z3Verdict.RUNTIME_ERROR: 1,
            Z3Verdict.SYNTAX_ERROR: 2,
            Z3Verdict.TIMEOUT: 3,
            Z3Verdict.UNKNOWN: 4,
        }

        # Filter out SAT results (shouldn't be here, but just in case).
        failures = [r for r in results if r.verdict != Z3Verdict.SAT]
        if not failures:
            return None

        # Sort by preference (lower = better for repair).
        failures.sort(
            key=lambda r: preference.get(r.verdict, 99)
        )
        return failures[0]

    @staticmethod
    def _stall_priority(severity: StallSeverity) -> int:
        """
        Map StallSeverity to a priority integer for the queue.

        Lower number = higher priority (processed first).
        """
        return {
            StallSeverity.CRITICAL: 0,
            StallSeverity.HIGH: 1,
            StallSeverity.MEDIUM: 2,
            StallSeverity.LOW: 3,
        }[severity]

    def get_metrics(self) -> dict:
        """Return runtime metrics."""
        return {
            **self._metrics,
            "queue_size": self._stall_queue.qsize(),
            "active_stalls": len(self._active_stalls),
        }

    async def shutdown(self) -> None:
        """Gracefully shut down the agent loop."""
        logger.info("Agent loop shutting down...")
        self._running = False
