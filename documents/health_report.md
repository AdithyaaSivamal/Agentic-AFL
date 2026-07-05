# Agentic-AFL — Health & Resilience Report

**Original review:** 2026-07-04
**Follow-up pass:** 2026-07-05 — all items from §8 "Suggested Next Steps" implemented and verified, except the key-rotation decision (see the update note in §6).
**Scope:** Full test-suite execution (offline + live LLM/Ghidra/AFL++), new regression tests for previously-untested modules, static tech-debt audit, fixes for the top Critical findings, and a full follow-up pass addressing every remaining prioritized finding.
**Environment:** Python 3.14.5 venv at `Agentic-AFL-dev/venv`, Ghidra + AFL++ + PostgreSQL all present and working on the host, live Gemini API access.

---

## 0. Follow-Up Pass Summary (2026-07-05)

Everything in the original §8 next-steps list has been implemented and verified, except key rotation (user's explicit call — see §6):

| # | Item | Status |
|---|---|---|
| 1 | Rotate exposed Gemini key | **Declined by user** — key removed from `.env.example` and replaced with a placeholder; repo has never been pushed publicly, so rotation was judged unnecessary. See §6. |
| 2 | Fix 3 stale `ConstraintTag` references | **Done** — verified live: `test_phase2_integration.py` 9/9, `test_ics_validation.py` 9/9 (no longer crashes on import) |
| 3 | Harden `ConstraintTag[name]` lookup in `spec_store.py` | **Done** — wrapped in try/except, drops+logs unknown tags instead of crashing; verified live via `test_phase3_carm.py` 12/12 |
| 4 | Fix double-`asyncio.run()` Postgres false-negative in `cli.py` | **Done** — verified live: `agentic-afl check` now reports "All checks passed" against the same healthy Postgres instance that previously false-negatived |
| 5 | Resolve `run_e2e_campaign.py` duplication (M6) | **Done** — deduplicated shared AFL launch/terminate/cleanup helpers by importing from `campaign.py` instead of reimplementing; this also fixed an unscoped `pkill -9 -f afl-fuzz` that had regressed back into the duplicate copy (see §4.5) |
| 6 | Extend coverage to `cli.py`, `retrieval_carm.py`, `spec_exporter.py`, `diversity_generator.py`, `offset_probe.py` | **Done** — all 5 now covered (see §2.1); `offset_probe.py` reached 99% |
| 7 | Address H3, H5, M8 | **Done** — see §3 for the H3/H5/M8 write-ups, now marked fixed |

**Net result:** offline suite grew from 145 → **214 tests**, overall coverage from 39% → **51%**. All previously-failing/crashing experiment scripts (`test_phase2_integration.py`, `test_ics_validation.py`, `test_phase3_carm.py`) now pass cleanly. `run_e2e_campaign.py` was smoke-tested end-to-end after the refactor (full ACCEPT on the `arithmetic` target, no regressions).

Remaining open items are only the lower-priority M7 (god-file decomposition), M9/M10 (minor UX papercuts), and the two still-0%-coverage modules not in the original explicit list (`tui.py`, `harvest_mode.py`) — see the updated §5 and §8.

---

## 1. Executive Summary

The core pipeline **works end-to-end and was proven live during this review**: a bounded run of `test_generalization_matrix.py` against the `arithmetic` target showed AFL++ alone plateau at 7 edges for 60s, then Agentic-AFL detect the stall, run Ghidra → Z3/Gemini → sandbox → inject, and AFL++ go on to a **full ACCEPT** (12 edges, wall bypassed) in ~127s. The live LLM integration test also passed 3/3, including a real CRC constraint solve. The architecture is sound and the "hard" parts (Ghidra bridge, Z3 sandbox, sync-dir injection) are well-engineered.

The problems were concentrated in **two places**: (1) two genuinely dangerous unbounded-wait bugs in the exact class the user said was "recently fixed" (LLM retry loops) — these were still present as unbounded *waits*, not retries; and (2) a **large, silent test-coverage gap** on the modules that matter most for unattended operation (`llm_client.py` and `pcode_slicer.py` had 0% coverage before this review). Both classes of problem are now resolved — see §0 above for the full follow-up disposition.

**What changed across both passes:**
- Offline suite grew from **84 → 214 tests**, all green.
- Coverage on the previously-blind modules: `llm_client.py` 0% → 49%, `pcode_slicer.py` 0% → 79%, `agent_loop.py` 22% → 39%, `campaign.py` 0% → 33%, `offset_probe.py` 0% → 99%, plus `cli.py`, `retrieval_carm.py`, `spec_exporter.py`, `diversity_generator.py` all brought up from 0%.
- Overall repo coverage: 26% → 51%.
- 3 Critical/High findings fixed and proven with tests in pass 1 (C1, C2, H4); 4 more (stale enums, `spec_store.py` hardening, the CLI preflight bug, `run_e2e_campaign.py` dedup) plus H3/H5/M8 fixed in the follow-up pass.
- 1 live security exposure discovered; user made an informed decision not to rotate (§6).

---

## 2. Test Coverage Summary

### 2.1 Offline suite (`pytest tests/`)

| Original review | Follow-up pass |
|---|---|
| 84 tests, 26% overall coverage | **214 tests, 51% overall coverage** |

Per-module coverage, original → final:

| Module | Original | Final | Notes |
|---|---|---|---|
| `orchestrator/llm_client.py` | 0% | **49%** | `tests/test_llm_client.py` (13 tests) |
| `extractor/pcode_slicer.py` | 0% | **79%** | `tests/test_pcode_slicer.py` (25 tests) |
| `extractor/offset_probe.py` | 0% | **99%** | `tests/test_offset_probe.py` (18 tests) — mocks `asyncio.create_subprocess_exec` to simulate GDB output, no real GDB/binary needed |
| `orchestrator/agent_loop.py` | 22% | **39%** | `tests/test_agent_loop_recovery.py` (9 tests) |
| `campaign.py` | 0% | **33%** | `tests/test_campaign.py` (10 tests) |
| `cli.py` | 0% | **18%** | `tests/test_cli.py` (12 tests) — the low % reflects that most subcommands need live Ghidra/AFL/Postgres to exercise fully; the preflight-check logic itself is covered |
| `orchestrator/retrieval_carm.py` | 0% | **98%** | `tests/test_retrieval_carm.py` (7 tests) |
| `extractor/spec_exporter.py` | 0% | **75%** | `tests/test_spec_exporter.py` (9 tests) |
| `fuzzer_bridge/diversity_generator.py` | 0% | **95%** | `tests/test_diversity_generator.py` (15 tests) — verifies CRC correctness of every emitted protocol frame |
| `orchestrator/z3_sandbox.py` | 79% | 83% | +2 timeout tests |
| `fuzzer_bridge/payload_injector.py` | 96% | 96% | +2 edge-case tests |
| `database/spec_store.py` | 35% | 31%* | *Denominator grew (added the try/except hardening branch); the hardening itself is exercised live via `test_phase3_carm.py`, not the offline suite (needs Postgres) |
| `tui.py`, `orchestrator/harvest_mode.py` | 0% | 0% | **Still untested** — not in the original explicit next-steps list; UI/display code and an auxiliary strategy mode respectively. See §8. |

Run: `pytest tests/ --cov=agentic_afl --cov-report=term-missing` — 214 passed, 0 failed, ~22s.

### 2.2 Collectable/standalone experiment scripts (`experiments/tests/`)

These are excluded from default `pytest` discovery (`testpaths=["tests"]` in `pyproject.toml`) and mostly run as `__main__` scripts, not pytest functions.

| Script | Original result | Final result (after follow-up pass) |
|---|---|---|
| `test_phase2_integration.py` | 8/9 pass, 1 fail (stale `FUNCTION_CODE_DISPATCH`, §4.1) | **9/9 pass** |
| `test_agent_loop_unit.py` | 9/9 pass | 9/9 pass (no regression from any fix) |
| `test_phase4_bridge.py` | 12/14 pass | 12/14 pass — the 2 remaining failures are the pre-existing stale-fixture issue in §4.2, intentionally left as-is (needs a real compiled binary fixture, out of scope for this pass) |
| `test_phase3_carm.py` | Failed immediately (`KeyError: 'CRC_CHECKSUM'`, §4.1) | **12/12 pass** |
| `test_ics_validation.py` | Crashed on import (§4.1) | **9/9 pass** |
| `run_e2e_campaign.py` (after M6 dedup) | n/a (fix landed in follow-up pass) | Smoke-tested against `arithmetic` target end-to-end — full ACCEPT, no import/runtime errors from the refactor |

### 2.3 Live tests (user opted into full execution incl. real API cost)

| Test | Result |
|---|---|
| `test_live_ghidra.py` | **PASS** — real Ghidra headless extraction of `math_wall_x86`, correct P-Code (`INT_EQUAL` against `0x5a01`) |
| `test_live_llm.py` | **PASS 3/3** — real Gemini calls; 3/3 SAT on Modbus TID and IEC 104 start-byte, 2/3 SAT on a real CRC/bitwise-loop constraint. K=3 calls took 44–74s each in the wild |
| `test_generalization_matrix.py arithmetic` (bounded run) | **PASS — full ACCEPT** | AFL++ alone: 7 edges/60s plateau. Agentic-AFL: detected stall at t=72s, solved + injected at t=127s, final 12 edges, wall bypassed |

The full 11-target matrix was not run to completion (each target needs a 60s baseline + up to 600s agent timeout — a full run is multi-hour and largely re-validates the same pipeline already proven live above). This is a explicit scope decision, not a silent truncation: **10 of 11 targets in `TARGETS` were not exercised in this pass** (`modbus`, `custom_hash`, `iec104`, `state_machine`, `lib60870`, `opendnp3`, `cfs`, `libmodbus`, `ics_crc32`, and the two remaining ones already covered by unit fixtures).

---

## 3. Fixes Applied This Pass (Critical findings, test-proven)

All three fixes below are TDD-proven: a regression test was written that **fails against the pre-fix code** and **passes against the post-fix code**, with the failure/pass distinguished by actual elapsed wall-clock time (not just "an exception was raised"), so the tests cannot pass vacuously.

### C1 — LLM provider calls had no timeout (Critical)
**Files:** `agentic_afl/orchestrator/llm_client.py`, `agentic_afl/config.py`

Before: `OpenAIProvider.generate()` and `GeminiProvider.generate()` awaited the HTTP client directly with no timeout. A stuck connection would hang the coroutine — and with it, the AgentLoop's single stall-processing consumer — **forever**. This is the same failure family as the "infinite LLM retry loop" already fixed, but one layer deeper: an infinite *wait*, not an infinite *retry*.

Fix: added `settings.llm_timeout_seconds` (default 120s, env `LLM_TIMEOUT_SECONDS`) and a new `LLMClient._call_provider()` wrapper that bounds every provider call with `asyncio.wait_for`, raising a catchable `LLMClientError` on timeout — mirroring the pattern `Z3Sandbox.execute()` already used for the same class of risk.

Proof: `tests/test_llm_client.py::TestProviderTimeout` — against a `HangingProvider` that never resolves, `generate_z3_scripts()`/`repair_z3_script()` now return in ~0.2s (the monkeypatched timeout) instead of hanging; before the fix, the test suite took 30s per run (hitting the test's own generous backstop) and after the fix takes 0.45s total for all 13 tests in the file.

### C2 — Sandbox `asyncio.gather` had no outer bound (defense-in-depth)
**File:** `agentic_afl/orchestrator/agent_loop.py:872`

`Z3Sandbox.execute()` already bounds itself internally (confirmed by reading `z3_sandbox.py` — it never raises on timeout, it returns a `TIMEOUT`-verdict `Z3Result`), so this was **not actively hanging in the current code** — but the `asyncio.gather` at the call site had no independent bound, so a future regression in that internal guard (or an exception raised before it, e.g. a disk error writing the temp script) would hang the same single-consumer loop with no safety net.

Fix: wrapped the gather in `asyncio.wait_for` with a computed bound `(sandbox.timeout_seconds + 10) * n_scripts`, degrading to an empty result list (which the existing `_select_best_failure(results) is None → break` path already handles gracefully) on timeout.

Proof: `tests/test_agent_loop_recovery.py::TestSandboxGatherTimeout` — against a `HangingSandbox` whose `execute()` never resolves, `_generate_and_solve()` now returns `None` in ~11s (matching the computed bound) instead of hanging indefinitely, verified via an elapsed-time assertion.

### H4 — Stale-instance cleanup killed every afl-fuzz process on the host (High)
**File:** `agentic_afl/campaign.py`

Before: `CampaignRunner.run()` called `pkill -9 -f afl-fuzz` at startup to clean up orphaned instances from a crashed prior run. This pattern matches by process name only — it kills **every** afl-fuzz process on the machine, including unrelated concurrent campaigns against different targets. This is a realistic risk on a shared research box (multiple students/targets on one VM is the project's own stated setup in several test scripts).

Fix: extracted `_stale_afl_pkill_pattern(afl_out)`, which anchors the `pkill -f` regex on `-o <afl_out>` — AFL++'s own command line always includes this flag, and `afl_out` is unique per campaign (derived from the harness path). Two concurrent campaigns now produce non-overlapping patterns and can no longer kill each other.

Proof: `tests/test_campaign.py::TestStaleAflPkillPattern` — 4 tests, including one that explicitly constructs two campaign paths and asserts neither pattern matches the other's output directory.

### Follow-up pass fixes (2026-07-05)

**Stale `ConstraintTag` references (§4.1)** — `FUNCTION_CODE_DISPATCH` renamed to `MULTI_WAY_BRANCH` (or, where the profiler actually emits `RANGE_BOUND` for that structural pattern, updated to match reality rather than guessed) and `CRC_CHECKSUM` renamed to `BITWISE_LOOP` across `test_phase2_integration.py`, `test_ics_validation.py`, `test_phase3_carm.py`, and `experiments/test_profiler.py`. Each corrected assertion was verified against the profiler's actual live output before editing, not just pattern-matched against the rename.

**`spec_store.py:288` unhandled `ConstraintTag[name]` lookup** — wrapped in try/except; unknown tag names are now logged (`"Dropping unknown constraint tag %r ... (ontology may have been renamed since this tag was stored)"`) and dropped rather than crashing `save_spec()`. This is the schema-versioning gap flagged in the original §4.1 — not a full migration system, but the persistent store can no longer be bricked by a future ontology rename.

**`cli.py` double-`asyncio.run()` Postgres false-negative (§4.3)** — the connect-check-close sequence was consolidated so the connect and close happen inside the same `asyncio.run()` call (a single async function returns whether the fallback store was used; the caller only prints based on that boolean). Verified live: `agentic-afl check` against the same healthy Postgres instance that previously reported `❌ ERROR: Event loop is closed` now correctly reports `✅ PostgreSQL — connected` and `All checks passed`.

**H3 — hardcoded `/tmp/agentic_afl_debug`** — introduced `settings.debug_dir` (env-overridable, defaults preserved) and both `llm_client.py` and `agent_loop.py` now read it instead of hardcoding the path inline.

**H5 — tempfile leak on write failure** — `PayloadInjector.inject()` now wraps the write in try/except; on any exception the partially-written temp file is explicitly unlinked before re-raising, instead of being silently orphaned in the sync directory. `tests/test_payload_injector.py::TestTempfileLeakOnWriteFailure` was updated from "documents the leak" to asserting the leak is gone.

**M8 — settings read at import time as parameter defaults** — `PayloadInjector`, `LLMClient`, and `Z3Sandbox` `__init__` signatures changed from `param: Path = settings.x` (frozen at class-definition/import time) to `param: Path | None = None` with `settings.x` read inside the method body when `param is None`. This means `monkeypatch.setattr(settings, "x", ...)` now actually takes effect for code constructing these objects after the patch, closing the "latent trap for future test-writers" called out in the original report.

**M6 — `run_e2e_campaign.py` / `campaign.py` duplication** — `run_e2e_campaign.py`'s local reimplementations of `_format_duration`, `_safe_terminate`, and `run_afl` (AFL++ launch) were deleted and replaced with imports from `agentic_afl.campaign` (`_start_afl` aliased as `run_afl` for call-site compatibility — its signature is a strict superset of the old local function). This surfaced a concrete instance of the drift risk the finding predicted: `run_e2e_campaign.py`'s stale-instance cleanup still had the **unscoped** `pkill -9 -f afl-fuzz` (the exact H4 bug) even though `campaign.py`'s copy had already been fixed — the two files had already drifted apart on a security-relevant fix. Now both call the same `_stale_afl_pkill_pattern()` helper, so there is one source of truth. Smoke-tested end-to-end post-refactor: full ACCEPT on the `arithmetic` target, no errors.

**offset_probe.py test coverage** — `tests/test_offset_probe.py` (18 tests) covers `discover_base_offset()` and `extract_arg_memory()` by monkeypatching `asyncio.create_subprocess_exec` with a fake process emitting scripted GDB stdout, exercising: empty-seed short-circuit, GDB-not-found, timeout (with process-kill verification), breakpoint-not-hit, single- and multi-register offset matching, low-confidence-match fallback, and malformed/`FAIL:`-prefixed GDB output. No real GDB or compiled binary needed.

---

## 4. Bugs Discovered by Actually Running the Suite

These were not found by static analysis — they only surfaced by executing code paths that are apparently rarely run.

### 4.1 Constraint ontology renames silently break 3 test files/paths (High) — ✅ FIXED 2026-07-05
`agentic_afl/constants.py`'s `ConstraintTag` enum has been renamed at least twice without updating all call sites:
- `FUNCTION_CODE_DISPATCH` → consolidated into `MULTI_WAY_BRANCH`
- `CRC_CHECKSUM` → consolidated into `BITWISE_LOOP`

Confirmed via a full-repo grep: exactly these 2 stale names are referenced, breaking:
- `experiments/tests/test_phase2_integration.py::test_profiler_wall3` (`AttributeError`)
- `experiments/tests/test_ics_validation.py` (crashes on **import**, 0% of the file's tests run)
- `experiments/tests/test_phase3_carm.py` (crashes inside `save_spec()` — see below)

**More seriously:** `agentic_afl/database/spec_store.py:278` does `ConstraintTag[name].value for name in tag_names` with **no try/except**, converting a stored string tag name back into the enum on every `save_spec()`/load call. This is a real production fragility, not just a test-staleness issue: PostgreSQL is a persistent store, so **any row written under an old tag name before a future ontology rename will crash `save_spec`/load with an unhandled `KeyError`** the next time it's touched. There is currently no schema versioning or migration path for the constraint ontology. Recommend: (a) fix the 3 stale references above (mechanical, low-risk), (b) wrap the `ConstraintTag[name]` lookup in a try/except that logs and drops unknown tags rather than crashing, (c) consider a `tag_aliases` table or migration script for future renames.

### 4.2 `test_phase4_bridge.py` StallDetector tests are stale against autonomous frontier discovery (Medium)
Two of 14 tests fail: `detect stalls (plateau detection)` and `resolve and re-detect`, both because the test manually presets `_plateau_cycles` against a placeholder binary path (`modbus_rtu_x86`) that doesn't exist on disk. Since `StallDetector.detect()` now runs full autonomous GDB frontier discovery when no `stall_address_override` is set, `nm` correctly reports "no symbols found" against the nonexistent binary and returns 0 stalls — this is **correct behavior given the stale test fixture**, not a StallDetector bug. The test predates the autonomous-discovery feature and needs a real compiled binary fixture to be meaningful again.

### 4.3 CLI preflight check reports a false-negative Postgres failure (Medium) — ✅ FIXED 2026-07-05
`agentic_afl/cli.py:382,388` (`cmd_check`) calls `asyncio.run(_check_postgres(agent))` and then `asyncio.run(store.close())` as **two separate top-level `asyncio.run()` calls**. Each spins up and tears down its own event loop. The asyncpg connection created in the first loop cannot be closed from the second — this raises `RuntimeError: Event loop is closed`, caught by the surrounding `except Exception as e` and reported as `❌ PostgreSQL — ERROR: Event loop is closed`, immediately **after** printing `✅ PostgreSQL — connected` for the same check. Confirmed live: `agentic-afl check` against a genuinely healthy, connected PostgreSQL instance still reports overall failure (`all_ok = False`) and exits as if something were broken. This will confuse anyone debugging a real Postgres outage, since the tool cries wolf even when Postgres is fine. Fix: run both calls inside a single `asyncio.run()` (wrap connect+use+close in one async function), matching the pattern already used correctly elsewhere in the file.

### 4.4 `.env.example` contains a live, working Gemini API key (Critical — security) — ⚠️ PARTIALLY ADDRESSED
See §6 for the user's decision.

### 4.5 `run_e2e_campaign.py` had regressed the H4 pkill fix independently — ✅ FIXED 2026-07-05
Discovered while implementing the M6 dedup: `experiments/tests/run_e2e_campaign.py:162` (pre-fix line numbers) had its own copy of the stale-instance cleanup, still using the **unscoped** `pkill -9 -f afl-fuzz` — the exact H4 bug, in the exact form it existed in `campaign.py` before that fix landed. This is concrete, observed proof of the M6 finding's core claim: two copies of the same logic *will* drift, and a fix applied to one silently fails to protect the other. Resolved as part of the M6 dedup (§3, follow-up pass).

---

## 5. Prioritized Remaining Findings (updated 2026-07-05)

Everything from the original C1/C2/H4/H3/H5/M6/M8 set, plus §4.1/§4.3/§4.5, is now fixed (see §3 and §0). What's left:

### Critical
- ~~§4.4 Exposed API key~~ — **user decision, not a defect**: removed from `.env.example` and replaced with a placeholder; not rotated because the repo has never been pushed to a public or shared remote. Revisit rotation if the repo is ever pushed anywhere (see §6).

### High
- **H2 (from the original static review, not yet re-verified with tests):** `campaign.py` has several `except Exception: pass` blocks (`_read_edges`, `_read_fuzzer_stats`, `_check_for_accept`) that silently degrade to zero/None on malformed state. Combined with the edge-gain gate in `agent_loop.py`, a malformed `fuzzer_stats` file could mask real coverage progress. Recommend logging at `debug` level instead of silently swallowing. **Still open** — lower urgency than the items fixed this pass since it requires an actually-malformed AFL++ stats file to trigger, not a normal-operation risk.

### Medium
- **M7:** God files — `agent_loop.py` (1275 lines), `extract_pcode.py` (853), `stall_detector.py` (835), `llm_client.py` (846), `cli.py` (703), `tui.py` (651). Low cohesion, high change-risk. `agent_loop.py` in particular mixes queue management, ReAct orchestration, payload construction, and probe-seed gathering in one class — candidates for extraction: `PayloadBuilder` (the `_model_to_payload` logic), `ProbeSeedGatherer` (`_gather_probe_seeds`). **Still open** — a structural refactor, deliberately out of scope for a health-fix pass; do this as a deliberate, reviewed change, not an incidental one.
- **M9:** Empty/malformed LLM completions degrade quietly through `_extract_z3_code`'s three-tier fallback, wasting a full ReAct turn + K API calls before the sandbox reports `SYNTAX_ERROR`. Confirmed working-as-designed via `tests/test_llm_client.py::TestExtractZ3Code`, but there's no fast-path short-circuit for a clearly-empty completion before spending a sandbox round-trip. **Still open** — minor cost optimization, not a correctness issue.
- **M10:** `LocalProvider` raises `NotImplementedError` only on first `generate()` call, not at `LLMClient` construction time when `llm_api_provider="local"` is configured. Fails late instead of fast. **Still open** — low impact since `local` isn't the default provider and isn't used in the live-validated path.
- **New:** `tui.py` (651 lines) and `orchestrator/harvest_mode.py` (69 lines) remain at 0% coverage. Neither was in the original explicit next-steps list (§8 named 5 specific modules, all now covered). `tui.py` is interactive terminal-UI code — lower value to unit test, higher value to smoke-test visually. `harvest_mode.py` is a smaller, more tractable gap if pursued next.

### Low
- `z3_sandbox.py:420 validate_equivalence()` is dead code (`NotImplementedError`, no callers) — either implement the WARP bidirectional-equivalence check it's meant for, or remove it. **Still open.**
- `rate_limiter.py:87 while True` is safe (bounded by refill logic) — no action needed, noted only for completeness.

---

## 6. Security

**`Agentic-AFL-dev/.env.example:16`** contained `GEMINI_API_KEY=AIzaSy...` — a value matching Google's live API key format, not a placeholder. This was independently confirmed twice during the original review: once by direct inspection of the file, and once when a test failure's exception traceback repr'd the full `settings` object and printed the same key in cleartext into this session's transcript.

**Update 2026-07-05 — user decision:** the key has been removed from `.env.example` and replaced with a genuine placeholder. The user opted **not** to rotate the key, on the basis that this repository (also confirmed: not a git repo at all at the time of this review — `git status` fails with "not a git repository") has never been pushed to any public or shared remote, so the exposure window was local-only. This is a reasonable call given that context, and is recorded here as an informed decision rather than an oversight.

**Still worth doing if circumstances change:**
1. If this directory is ever turned into a git repo and pushed anywhere (even a private remote), rotate the key first — a `git init` + `git add .` at this point would commit the key's prior presence into history if it's ever restored from a backup or shared before rotation.
2. Consider a pre-commit hook or `gitleaks`/`trufflehog` check before the first `git push`, given a real key already made it into a template file once.

---

## 7. What's Genuinely Working Well

Worth stating plainly so fixes aren't misread as "the pipeline is broken":

- The Ghidra bridge, Z3 sandbox, and payload injector all have solid engineering: subprocess isolation, `RLIMIT_AS`, import blocklists, atomic writes, and (in `Z3Sandbox`) a timeout pattern that the rest of the codebase should have copied sooner.
- The full pipeline was proven live end-to-end during this review, not just in unit tests — a real math wall was bypassed and AFL++ reached full ACCEPT.
- The existing 84-test offline suite was accurate and all passed cleanly before any of this review's additions — the team's unit-testing discipline on `constraint_profiler.py`, `memory_store.py`, `rate_limiter.py`, and `z3_sandbox.py` is genuinely good (93-99% coverage on those files already).
- `_select_best_failure`'s UNSAT-preferred repair ranking and the ReAct correction-history feedback loop behave exactly as documented under adversarial (all-failing) test conditions — no infinite loop, clean deferral after `max_react_turns`.
- Every fix applied in the follow-up pass was smoke-tested against the real pipeline where practical, not just unit-tested in isolation: the CLI preflight check was re-run live against real Postgres, and `run_e2e_campaign.py` was re-run end-to-end against the `arithmetic` target post-refactor. Nothing in this pass is "tests pass but I didn't check it actually works."

---

## 8. Next Steps (updated 2026-07-05 — all original items complete)

All 7 items from the original list are done (see §0 for disposition of each, including the key-rotation decision). What's left, in priority order:

1. **H2** — replace the silent `except Exception: pass` blocks in `campaign.py` (`_read_edges`, `_read_fuzzer_stats`, `_check_for_accept`) with debug-level logging, so a malformed `fuzzer_stats` file doesn't masquerade as "zero edges" during a real campaign.
2. **M7** — decompose `agent_loop.py` (1275 lines) as a deliberate refactor: extract `PayloadBuilder` (`_model_to_payload`) and `ProbeSeedGatherer` (`_gather_probe_seeds`) into their own modules with dedicated tests. Do this as its own reviewed change, not folded into an unrelated fix.
3. Extend coverage to `harvest_mode.py` (0%, 69 lines — tractable) and consider a smoke/visual test approach for `tui.py` (0%, 651 lines — interactive terminal UI, lower value from unit tests).
4. **M9/M10** — minor: fast-path an empty LLM completion before a wasted sandbox round-trip; fail fast on `LocalProvider` misconfiguration at `LLMClient` construction time instead of first use.
5. If this directory is ever turned into a git repo and pushed anywhere, rotate the Gemini key first (§6).
