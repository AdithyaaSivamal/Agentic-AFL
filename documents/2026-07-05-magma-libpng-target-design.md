# Design: Magma/libpng Target Integration

**Date:** 2026-07-05
**Status:** Approved by user, pending implementation plan
**Author:** Claude (design session with user)

## Context

The user is writing an academic paper (for college credit) on Agentic-AFL's approach to bypassing "math walls" (CRC/checksum/hash constraints) during coverage-guided fuzzing. The paper needs evaluation targets that are recognized in the academic fuzzing literature, with genuine checksum/CRC walls that traditional fuzzers (vanilla AFL++, and eventually concolic tools like SymCC/QSYM) struggle with.

The project's own prior analysis (`documents/testing_infrastructure.md`) had already evaluated LAVA-M vs. Magma as evaluation corpora and concluded Magma is the better fit: LAVA-M's injected bugs are synthetic magic-byte comparisons with no real checksums or structured parsing, while Magma uses real CVEs in real, widely-used libraries (libpng, libxml2, poppler) and is the modern academic-standard successor to LAVA-M.

This design scopes the **first concrete step**: getting libpng's CRC-32 wall (`png_crc_finish()`, guarding each PNG chunk's trailing CRC) running as a target under Agentic-AFL, using the project's existing target-integration pattern. It deliberately does NOT cover:
- Installing/integrating SymCC or QSYM as comparison baselines (separate future design — neither tool exists on this machine yet, and both have nontrivial installation risk).
- Adopting Magma's full framework (its own build pipeline, injected-bug oracles, ground-truth CVE-reachability tracking). The user chose the lighter-weight option: pull libpng source only, write our own minimal harness, and measure success via AFL++ coverage (edges) rather than Magma's bug oracles.
- Running the actual paper-grade comparative campaigns (baseline vs. Agentic-AFL over hours, statistical significance, etc.) — this design only covers building and validating that the target works at all.

## Goal

Add libpng as a new entry in the existing `TARGETS` dict (`experiments/tests/test_generalization_matrix.py`), following the exact same pattern as the project's existing real-world targets (`libmodbus`, `opendnp3`, `lib60870`, `cfs`), such that:
1. AFL++ alone, run against a seed with a corrupted IHDR CRC-32, plateaus (cannot guess a 32-bit CRC via random mutation).
2. Agentic-AFL, run in the same autonomous mode as the existing targets, detects the stall, extracts `png_crc_finish` via Ghidra, generates a correct Z3 CRC-32 script, injects a valid payload, and AFL++ subsequently gains coverage past the IHDR chunk boundary.

## Non-Goals

- Full Magma framework integration (bug oracles, CVE-reachability metrics) — explicitly deferred.
- SymCC/QSYM baseline setup — explicitly deferred to a separate design.
- Any change to core `agentic_afl/` pipeline code. This is purely a new evaluation target, using the existing extraction/orchestration/injection machinery as-is.

## Architecture

No changes to `agentic_afl/` core code. This follows the established target-integration pattern used by every existing real-world target:

1. **Harness source** (`experiments/test_targets/magma_libpng_harness.c`) — a small C harness adapted from OSS-Fuzz's canonical `libpng_read_fuzzer.cc`, ported to plain C and changed to read the input file path from `argv[1]` (matching AFL++'s `@@` convention) instead of libFuzzer's in-memory buffer API. It calls libpng's standard read-and-decode path (`png_read_png` or equivalent) against the input file. On a clean decode with no error, it prints the target's `accept_marker` to stdout.

   **Error handling:** libpng reports errors (including a CRC mismatch triggering `png_chunk_error`) via `longjmp` back into the caller — it does not use return codes. The harness must call `setjmp(png_jmpbuf(png_ptr))` immediately after creating `png_ptr`/`info_ptr` and *before* calling `png_read_png()`. If `setjmp` returns non-zero (i.e., we're back here via a `longjmp` from a libpng error), the harness cleans up (`png_destroy_read_struct`) and exits without printing the accept marker — a corrupted CRC is expected to land here. If `png_read_png()` returns normally instead, decoding succeeded and the harness prints the accept marker. Without this, a real decode error crashes the harness process itself rather than being caught cleanly.

2. **Build script** (`experiments/test_targets/build_magma_libpng_harness.sh`) — follows the existing `build_libmodbus_harness.sh` convention:
   - Fetches libpng source pinned to a specific tag (`v1.6.58`, matching this environment's system libpng version for consistency — see Open Questions).
   - Builds libpng from source with `afl-cc -O0 -g` (no inlining, so `png_crc_finish` survives as a resolvable symbol for Ghidra/`nm` — same rationale as the existing convention's comment on `-O0 -fno-inline`).
   - Links against **system zlib** (uninstrumented is fine — reaching the IHDR CRC check requires zero zlib/IDAT decompression calls, so zlib coverage isn't part of what we're measuring).
   - Compiles and links the harness against the freshly-built, instrumented libpng.
   - Verifies (via `nm`, mirroring the existing script's symbol-check pattern) that `png_crc_finish` is present and not inlined/stripped.

3. **Seed** — a minimal valid PNG (~100 bytes: signature + IHDR + minimal required chunks + IEND) with **all 4 bytes** of the IHDR chunk's trailing CRC-32 deliberately wrong (e.g. `\xDE\xAD\xBE\xEF`, matching the placeholder style `ics_crc32` already uses for its CRC-32 field — confirmed by checking the actual seed: `ics_crc32`'s trailing 4 bytes are exactly `\xDE\xAD\xBE\xEF`, and `modbus`'s trailing bytes are zeroed, so this project's existing convention already fully invalidates the checksum field rather than flipping a single bit). This matters because AFL++'s havoc mutator can and does try random values at random byte offsets — a single near-miss byte would be a 1-in-256 guess a normal campaign could plausibly stumble onto by chance, whereas a fully-wrong 4-byte value is a genuine 1-in-2³² problem for random mutation, matching what "math wall" is supposed to mean. Inlined directly as `seed_bytes` in the `TargetSpec` (following the `ics_crc32` convention — a single ~100-byte seed doesn't need a `seed_dir`, which is reserved for targets needing multiple seed files).

4. **TargetSpec entry** in `TARGETS` (`experiments/tests/test_generalization_matrix.py`):
   ```python
   "magma_libpng": TargetSpec(
       name="Magma libpng",
       source_file=None,
       binary_name="magma_libpng_harness",
       stall_function="png_crc_finish",
       seed_bytes=b"\x89PNG\r\n\x1a\n...\xDE\xAD\xBE\xEF...",  # minimal valid PNG, all 4 IHDR CRC-32 bytes wrong
       description="libpng IHDR chunk CRC-32 validation (real CVE-bearing library, Magma benchmark)",
       build_script="build_magma_libpng_harness.sh",
       accept_marker="PNG_DECODE_OK",
   ),
   ```

## Key Technical Assumption (verify first)

The design assumes libpng's default chunk-CRC handling treats a CRC mismatch on IHDR — a critical/required chunk — as a hard, parse-halting error (`png_chunk_error`, which triggers libpng's `longjmp`-based error path), not a skippable warning. This is what makes it a genuine coverage "wall" rather than something libpng just shrugs off and continues past. This behavior is configurable in libpng via `png_set_crc_action()`, but the *default* is believed to be hard-fail for critical chunks.

**This must be verified against the actual vendored libpng 1.6.58 source (`pngrutil.c`) as the first implementation step**, before writing the rest of the harness/build script around it. If the assumption is wrong (e.g., IHDR CRC mismatches only warn by default in this version), the design needs a small adjustment: either call `png_set_crc_action(png_ptr, PNG_CRC_CRITICAL_USE, PNG_CRC_ERROR_QUIT)` explicitly in the harness to force the intended behavior, or target a different, harder-gated chunk.

## Validation Plan

Mirror the exact methodology already proven in the health-report phase (the `arithmetic` and `ics_crc32` targets):
1. Run AFL++ alone for a baseline period; confirm it plateaus (coverage flat, cannot solve the CRC by mutation).
2. Run the existing `test_generalization_matrix.py magma_libpng` flow (fully autonomous — no `stall_address_override`, matching how all other real-world targets already run) and confirm:
   - `StallDetector` discovers `png_crc_finish` as the frontier function via GDB.
   - `PCodeSlicer`/Ghidra successfully extracts a P-Code slice.
   - `ConstraintProfiler` tags it `BITWISE_LOOP` (standard CRC pattern).
   - Since libpng's CRC-32 is the standard zlib/IEEE-802.3 polynomial, this should trigger the existing CRC-32 reference-template fast path in `llm_client.py` (the same one that made `arithmetic`/`ics_crc32` solve quickly) — worth confirming this fires rather than falling back to a slower from-scratch LLM derivation.
   - A valid payload is injected and AFL++ subsequently gains coverage past the IHDR boundary (edge count increases).
3. Record the same kind of before/after edge-count evidence used in the health report's `arithmetic` target proof.

## Open Questions / Risks

- **libpng version pin**: recommend `v1.6.58` (matches system-installed version in this environment for easy cross-referencing), but any recent 1.6.x branch works — not tied to a specific CVE for this design since we're using coverage/CRC-bypass as the success metric, not Magma's bug-oracle reachability.
- **Network access**: fetching libpng source requires outbound network access from the build environment. This worked for `pip install` during the health-review session; assumed to also work for `git clone`/`curl`, but not yet confirmed.

~~Harness correctness (setjmp/longjmp)~~ — **resolved during design review**: the harness will call `setjmp(png_jmpbuf(png_ptr))` before `png_read_png()`, per the "Error handling" note in the Architecture section above. This is the standard, correct libpng error-handling pattern (the same mechanism OSS-Fuzz's own harness uses under the hood), so no longer an open risk — just needs to be implemented correctly, which the implementation plan should verify with an explicit test (feed the harness a deliberately-corrupted seed and confirm it exits cleanly without the accept marker, rather than crashing).
