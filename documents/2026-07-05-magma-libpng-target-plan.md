# Magma libpng Target Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add libpng's IHDR CRC-32 chunk validation (`png_crc_finish`) as a new evaluation target in Agentic-AFL's generalization-matrix harness, so it can be shown that AFL++ alone plateaus against it while Agentic-AFL autonomously bypasses it.

**Architecture:** Follows the project's existing real-world-target pattern exactly (see `libmodbus`/`opendnp3`/`lib60870` entries in `experiments/tests/test_generalization_matrix.py`): a small hand-written C harness reads a file via `argv[1]`, calls into a real external library (libpng) rebuilt from source with AFL++ instrumentation, and prints an accept marker on success. No changes to core `agentic_afl/` pipeline code — this is purely a new target.

**Tech Stack:** C, libpng 1.6.x (built from source), system zlib, afl-cc, GDB/nm (existing project tooling).

## Global Constraints

- libpng pinned to tag `v1.6.58` (matches this environment's system-installed libpng version, for easy cross-referencing).
- Build libpng from source with `afl-cc -O0 -g` (no inlining) — required so `png_crc_finish` survives as a resolvable symbol for Ghidra/`nm`, matching the project's existing convention (see `build_libmodbus_harness.sh`'s `-O0 -fno-inline` rationale).
- Link against **system zlib** — acceptable to leave uninstrumented since reaching the IHDR CRC check requires zero zlib/IDAT decompression calls.
- Harness reads the input file path from `argv[1]` (matches AFL++'s `@@` convention used by every existing target).
- `accept_marker` string is exactly `PNG_DECODE_OK`.
- Seed must have **all 4 bytes** of the IHDR chunk's trailing CRC-32 deliberately wrong (not a single-byte near-miss) — this is what makes AFL++ havoc mutation unable to stumble onto the correct value by chance.
- No changes to any file under `agentic_afl/`.

---

## File Structure

- Create: `experiments/test_targets/libpng/` — git-cloned libpng source at `v1.6.58` (external dependency, not hand-authored).
- Create: `experiments/test_targets/magma_libpng_harness.c` — the fuzzing harness.
- Create: `experiments/test_targets/build_magma_libpng_harness.sh` — build script (compiles libpng from source + the harness, following the `build_libmodbus_harness.sh`/`build_opendnp3_harness.sh` convention).
- Modify: `experiments/tests/test_generalization_matrix.py` — add one new `TargetSpec` entry to the `TARGETS` dict.

---

### Task 1: Verify libpng's CRC-handling behavior and fuzzing-mode macros

**Files:**
- Create: `experiments/test_targets/libpng/` (git clone, read-only reference material — not modified)

**Interfaces:**
- Produces: a documented answer (in the task's commit message / a short note) to two questions that gate every later task: (a) does libpng's default chunk-CRC handling hard-fail on IHDR CRC mismatch, and (b) does libpng's source reference `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` anywhere (which `afl-cc` auto-defines, and which the project's `opendnp3` harness had to explicitly undefine because OpenDNP3's own code used it to bypass its CRC check).

- [ ] **Step 1: Clone libpng at the pinned tag**

```bash
cd experiments/test_targets
git clone --branch v1.6.58 --depth 1 https://github.com/pnggroup/libpng.git libpng
```

Expected: a `libpng/` directory containing `png.c`, `pngrutil.c`, `png.h`, etc. If the clone fails because the tag or org doesn't exist under `pnggroup`, retry against the long-standing mirror: `https://github.com/glennrp/libpng.git`.

- [ ] **Step 2: Inspect IHDR's CRC-check code path**

```bash
grep -n "png_crc_finish\|png_crc_error\|PNG_CRC_" experiments/test_targets/libpng/pngrutil.c | head -40
grep -n "PNG_CRC_DEFAULT\|crc_action" experiments/test_targets/libpng/pngrutil.c experiments/test_targets/libpng/png.c | head -40
```

Read the surrounding code for `png_handle_IHDR` and `png_crc_finish`/`png_crc_error` in `pngrutil.c`. Confirm whether a CRC mismatch on IHDR (a critical, required chunk) results in a call to `png_chunk_error` (hard `longjmp`-based failure) under libpng's *default* `crc_action`, with no extra configuration needed.

**Decision point:** If IHDR CRC mismatch is a hard failure by default (expected outcome) — proceed to Task 2 with no changes needed. If it is NOT a hard failure by default — the harness in Task 3 must add an explicit call: `png_set_crc_action(png_ptr, PNG_CRC_CRITICAL_USE, PNG_CRC_ERROR_QUIT);` immediately after `png_create_read_struct`. Record which case applies in the Task 1 commit message so Task 3 knows whether to include this call.

- [ ] **Step 3: Check for FUZZING_BUILD_MODE references**

```bash
grep -rn "FUZZING_BUILD_MODE" experiments/test_targets/libpng/
```

Expected: no matches (stock libpng is not written with fuzzing-mode bypasses, unlike OpenDNP3). If this returns any matches, read the surrounding code — if it disables any validation logic relevant to CRC checking, Task 4's build script must add `-UFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (mirroring `build_opendnp3_harness.sh`'s existing defensive pattern) to force it off.

- [ ] **Step 4: Commit the clone**

```bash
cd experiments/test_targets
git add libpng
git commit -m "chore: vendor libpng v1.6.58 source for Magma-style CRC-32 fuzzing target"
```

---

### Task 2: Write the harness source

**Files:**
- Create: `experiments/test_targets/magma_libpng_harness.c`

**Interfaces:**
- Consumes: `png.h` (libpng's public API — `png_create_read_struct`, `png_create_info_struct`, `png_jmpbuf`, `png_init_io`, `png_read_png`, `png_destroy_read_struct`).
- Produces: an executable that takes one argument (a file path), prints `PNG_DECODE_OK\n` to stdout and exits 0 on a clean decode, or exits non-zero with no `PNG_DECODE_OK` output on any decode failure (including a CRC mismatch).

- [ ] **Step 1: Write the harness**

```c
/*
 * magma_libpng_harness.c — AFL++ harness for libpng's IHDR CRC-32 wall.
 *
 * Reads a PNG file from argv[1] and attempts a full decode via libpng.
 * Prints PNG_DECODE_OK only if the decode completes without error —
 * in particular, a CRC-32 mismatch on the IHDR chunk triggers libpng's
 * longjmp-based error path (see png_crc_finish / png_chunk_error in
 * pngrutil.c), caught here via setjmp(png_jmpbuf(png_ptr)).
 *
 * Adapted from OSS-Fuzz's libpng_read_fuzzer, using libpng's standard
 * FILE*-based I/O (png_init_io) instead of a custom in-memory read
 * callback, since input arrives as a file path (AFL++'s @@ convention)
 * rather than an in-memory buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include "png.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <png_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }

    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fclose(fp);
        return 1;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return 1;
    }

    /* libpng reports errors via longjmp, not return codes. Any error
     * during png_read_png() — including an IHDR CRC-32 mismatch —
     * jumps back to here with a non-zero setjmp return. We must not
     * print the accept marker in that case. */
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return 1;
    }

    png_init_io(png_ptr, fp);
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);

    printf("PNG_DECODE_OK\n");
    return 0;
}
```

If Task 1 Step 2 determined that IHDR CRC mismatch is NOT a hard failure by default, insert this line immediately after the `if (!png_ptr)` check (before `png_create_info_struct`):
```c
    png_set_crc_action(png_ptr, PNG_CRC_CRITICAL_USE, PNG_CRC_ERROR_QUIT);
```

- [ ] **Step 2: Commit**

```bash
cd experiments/test_targets
git add magma_libpng_harness.c
git commit -m "feat: add libpng CRC-32 fuzzing harness (magma_libpng)"
```

(This cannot be compiled or tested yet — the build script in Task 3 is required first. That's the next task's deliverable.)

---

### Task 3: Write the build script and produce a working binary

**Files:**
- Create: `experiments/test_targets/build_magma_libpng_harness.sh`

**Interfaces:**
- Consumes: `experiments/test_targets/libpng/` (Task 1), `experiments/test_targets/magma_libpng_harness.c` (Task 2).
- Produces: `experiments/test_targets/magma_libpng_harness` — an executable binary with `png_crc_finish` present as a resolvable, non-inlined symbol.

- [ ] **Step 1: Write the build script**

```bash
#!/usr/bin/env bash
# build_magma_libpng_harness.sh — Compile the libpng CRC-32 harness with AFL++
#
# Builds libpng from source (NOT the system package) with afl-cc so that
# AFL++'s coverage instrumentation lands inside libpng's own code —
# linking against the pre-built system libpng.so would give zero
# coverage feedback inside png_crc_finish, defeating the whole point.
#
# Usage: ./build_magma_libpng_harness.sh [compiler]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${1:-afl-cc}"
LIBPNG="${SCRIPT_DIR}/libpng"
HARNESS="${SCRIPT_DIR}/magma_libpng_harness.c"
OUTPUT="${SCRIPT_DIR}/magma_libpng_harness"

if [ ! -d "${LIBPNG}" ]; then
    echo "[ERROR] libpng source not found at ${LIBPNG}"
    echo "        Clone: git clone --branch v1.6.58 --depth 1 https://github.com/pnggroup/libpng.git ${LIBPNG}"
    exit 1
fi

echo "[BUILD] Preparing libpng library config..."
# libpng needs a generated pnglibconf.h before it can compile standalone.
# The prebuilt default config (shipped in the repo) is the standard
# shortcut used for exactly this kind of direct-compile fuzzing setup
# (this is what OSS-Fuzz's own libpng build.sh does).
cp "${LIBPNG}/scripts/pnglibconf.h.prebuilt" "${LIBPNG}/pnglibconf.h"

echo "[BUILD] Compiling libpng + harness with ${CC}..."
# Glob every core libpng*.c file at the repo root (png.c, pngerror.c,
# pngget.c, pngmem.c, pngread.c, pngrio.c, pngrtran.c, pngrutil.c,
# pngset.c, pngtrans.c, pngwio.c, pngwrite.c, pngwtran.c, pngwutil.c),
# excluding pngtest.c (libpng's own self-test tool, which has a
# conflicting main()). Platform SIMD-optimized subdirectories
# (arm/, intel/, mips/, powerpc/, loongarch/) are excluded implicitly
# by not being matched by this glob; the -D...OPT=0 flags below make
# sure libpng's own headers don't expect those files to be linked in.
LIBPNG_SRCS=()
for f in "${LIBPNG}"/png*.c; do
    base="$(basename "$f")"
    if [ "$base" != "pngtest.c" ]; then
        LIBPNG_SRCS+=("$f")
    fi
done
echo "[BUILD] Compiling ${#LIBPNG_SRCS[@]} libpng source files..."

"${CC}" \
    -O0 \
    -g \
    -fno-inline \
    -Wall \
    -DPNG_ARM_NEON_OPT=0 \
    -DPNG_INTEL_SSE_OPT=0 \
    -DPNG_MIPS_MSA_OPT=0 \
    -DPNG_POWERPC_VSX_OPT=0 \
    -UFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
    -I"${LIBPNG}" \
    "${HARNESS}" \
    "${LIBPNG_SRCS[@]}" \
    -lz \
    -o "${OUTPUT}"

echo "[BUILD] ✓ Compiled: ${OUTPUT}"
echo "[BUILD]   Size: $(stat -c%s "${OUTPUT}" 2>/dev/null || stat -f%z "${OUTPUT}") bytes"

# Verify the CRC function symbol is present and not inlined.
ADDR=$(nm "${OUTPUT}" | awk '$3 == "png_crc_finish" {print $1; exit}' || true)
if [ -n "${ADDR}" ]; then
    echo "[BUILD]   png_crc_finish @ 0x${ADDR}"
else
    echo "[BUILD]   WARNING: png_crc_finish symbol not found — may be inlined or stripped"
fi
```

- [ ] **Step 2: Run the build**

```bash
chmod +x experiments/test_targets/build_magma_libpng_harness.sh
experiments/test_targets/build_magma_libpng_harness.sh
```

Expected: `[BUILD] ✓ Compiled: .../magma_libpng_harness` followed by `[BUILD]   png_crc_finish @ 0x<address>` (not the WARNING line). If linking fails with undefined references to zlib symbols (`inflate`, `crc32`, etc.), confirm `zlib.h`/`libz.so` are present (`pkg-config --libs zlib` or `ls /usr/lib/libz.so*`) — this environment already has zlib installed per the earlier health-review session.

If the WARNING line appears instead of an address, `png_crc_finish` was inlined or stripped despite `-fno-inline` — stop and investigate before proceeding (check for `-flto` or optimization flags being injected elsewhere, e.g. via `AFL_CC_COMPILER`/`AFL_LLVM_*` environment variables left over from a previous session).

- [ ] **Step 3: Commit**

```bash
cd experiments/test_targets
git add build_magma_libpng_harness.sh
git commit -m "feat: add build script for the libpng CRC-32 harness"
```

---

### Task 4: Harness correctness check (both directions)

**Files:**
- No new files. Verification-only task using the binary produced by Task 3.

**Interfaces:**
- Consumes: `experiments/test_targets/magma_libpng_harness` (Task 3).
- Produces: confidence that the harness's `setjmp`/`longjmp` error handling actually works — a corrupted CRC exits cleanly (no crash, no accept marker) and a valid PNG prints the accept marker. This must be verified with real files *before* ever running AFL++ against it, so a harness bug isn't mistaken for "AFL++ successfully found the wall."

- [ ] **Step 1: Construct a minimal valid PNG and confirm the harness accepts it**

```bash
python3 -c "
import struct, zlib

def chunk(tag, data):
    c = tag + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)

sig = b'\x89PNG\r\n\x1a\n'
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)  # 1x1, 8-bit grayscale
ihdr = chunk(b'IHDR', ihdr_data)
idat = chunk(b'IDAT', zlib.compress(b'\x00\x00'))  # 1 filter byte + 1 pixel byte
iend = chunk(b'IEND', b'')

open('/tmp/valid.png', 'wb').write(sig + ihdr + idat + iend)
"
experiments/test_targets/magma_libpng_harness /tmp/valid.png
```

Expected output: `PNG_DECODE_OK`. If this fails, the harness itself has a bug (unrelated to the CRC wall) — fix before proceeding.

- [ ] **Step 2: Corrupt the IHDR CRC-32 (all 4 bytes) and confirm clean rejection**

```bash
python3 -c "
data = bytearray(open('/tmp/valid.png', 'rb').read())
# IHDR CRC is the 4 bytes immediately after the 13-byte IHDR data field,
# which starts at offset 8 (signature) + 8 (length+type) = 16.
crc_offset = 16 + 13
data[crc_offset:crc_offset+4] = b'\xDE\xAD\xBE\xEF'
open('/tmp/corrupted.png', 'wb').write(bytes(data))
"
experiments/test_targets/magma_libpng_harness /tmp/corrupted.png; echo "exit code: $?"
```

Expected: no `PNG_DECODE_OK` printed, non-zero exit code, and critically **no crash** (no segfault, no `Illegal instruction`, no core dump message) — a clean, controlled failure. If the process crashes instead of exiting cleanly, the `setjmp`/`longjmp` setup is wrong (double-check `png_jmpbuf(png_ptr)` is called before `png_init_io`/`png_read_png`, and that `png_ptr`/`info_ptr` aren't used after `png_destroy_read_struct`).

- [ ] **Step 3: Document the verified seed offset**

Note the confirmed `crc_offset = 16 + 13 = 29` (relative to the start of this specific minimal 1x1 grayscale PNG layout) for reuse in Task 5 — this is only valid for this exact minimal IHDR (1x1, 8-bit grayscale, no interlacing); a different image geometry would shift the offset.

---

### Task 5: Construct the seed and add the TargetSpec entry

**Files:**
- Modify: `experiments/tests/test_generalization_matrix.py`

**Interfaces:**
- Consumes: the corrupted-PNG construction logic verified in Task 4, the `TargetSpec` dataclass already defined in this file (fields: `name`, `source_file`, `binary_name`, `stall_function`, `seed_bytes`, `description`, `build_script`, `seed_dir`, `accept_marker`, `custom_mutator`).
- Produces: a `"magma_libpng"` key in the `TARGETS` dict, usable by the existing `compile_target`/`resolve_symbol`/`run_target_test` machinery with no further code changes.

- [ ] **Step 1: Verify the seed bytes (already computed and checked below)**

The exact seed — a minimal valid 1x1 grayscale PNG with all 4 IHDR CRC-32 bytes replaced by `\xDE\xAD\xBE\xEF` — was computed and verified during plan-writing:

```bash
python3 -c "
import struct, zlib

def chunk(tag, data, corrupt_crc=False):
    c = tag + data
    if corrupt_crc:
        crc = b'\xDE\xAD\xBE\xEF'
    else:
        crc = struct.pack('>I', zlib.crc32(c) & 0xFFFFFFFF)
    return struct.pack('>I', len(data)) + c + crc

sig = b'\x89PNG\r\n\x1a\n'
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)
ihdr = chunk(b'IHDR', ihdr_data, corrupt_crc=True)
idat = chunk(b'IDAT', zlib.compress(b'\x00\x00'))
iend = chunk(b'IEND', b'')

seed = sig + ihdr + idat + iend
assert seed[29:33] == b'\xde\xad\xbe\xef'  # confirms Task 4's verified crc_offset=29
print(repr(seed))
"
```

Expected output (this is the literal used in Step 2 below):
```
b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82'
```

- [ ] **Step 2: Add the TargetSpec entry**

In `experiments/tests/test_generalization_matrix.py`, add this entry to the `TARGETS` dict (alongside the existing `"ics_crc32"` entry — same file, same dict, no other code changes needed):

```python
    "magma_libpng": TargetSpec(
        name="Magma libpng",
        source_file=None,
        binary_name="magma_libpng_harness",
        stall_function="png_crc_finish",
        seed_bytes=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82',
        description="libpng IHDR chunk CRC-32 validation (real CVE-bearing library, Magma benchmark family)",
        build_script="build_magma_libpng_harness.sh",
        accept_marker="PNG_DECODE_OK",
    ),
```

- [ ] **Step 3: Confirm the target compiles through the existing harness**

```bash
cd Agentic-AFL-dev
./venv/bin/python -c "
import asyncio, sys
sys.path.insert(0, 'experiments/tests')
from test_generalization_matrix import TARGETS, compile_target, resolve_symbol
spec = TARGETS['magma_libpng']
binary = asyncio.run(compile_target(spec))
addr = resolve_symbol(binary, spec.stall_function)
print(f'Compiled: {binary}, {spec.stall_function} @ {addr}')
"
```

Expected: `Compiled: .../magma_libpng_harness, png_crc_finish @ 0x<address>` with no exceptions. This confirms the new target is wired into the existing harness correctly before attempting a full campaign.

- [ ] **Step 4: Commit**

```bash
git add experiments/tests/test_generalization_matrix.py
git commit -m "feat: register magma_libpng as a generalization-matrix target"
```

---

### Task 6: Validate — AFL++ baseline plateaus

**Files:**
- No new files. Live validation run.

**Interfaces:**
- Consumes: the `magma_libpng` target (Task 5).
- Produces: observed evidence that AFL++ alone cannot bypass the CRC-32 wall — the baseline half of the comparison this whole target exists to demonstrate.

- [ ] **Step 1: Run the existing generalization-matrix script against just this target**

```bash
cd Agentic-AFL-dev
timeout 120 ./venv/bin/python experiments/tests/test_generalization_matrix.py magma_libpng
```

This runs the existing `run_target_test` flow, which starts with a 60-second AFL++-alone baseline period before Agentic-AFL engages (same methodology already proven for the `arithmetic` and `ics_crc32` targets in the health-report phase).

- [ ] **Step 2: Confirm the plateau**

In the output, confirm the baseline edge count is flat across the 60s baseline window (matching the pattern already seen for `arithmetic`: `Baseline t=5s: edges=N`, `t=10s: edges=N`, ... unchanged through `t=55s`). If edges are still climbing at the end of the baseline window, AFL++ hasn't plateaued yet — this specific target may need a longer baseline period, or (less likely, given the 2³² corruption) there may be an issue with the seed. Do not proceed to Task 7 until the baseline is confirmed flat.

---

### Task 7: Validate — Agentic-AFL autonomously bypasses the wall

**Files:**
- No new files. Live validation run (continuation of Task 6's same invocation).

**Interfaces:**
- Consumes: the `magma_libpng` target, AgentLoop running in fully autonomous mode (no `stall_address_override` — matching how `test_generalization_matrix.py` already runs every other real-world target).
- Produces: the core result this design exists to produce — full-pipeline evidence that Agentic-AFL detects, solves, and bypasses a real libpng CRC-32 wall.

- [ ] **Step 1: Let the same run from Task 6 continue past the baseline**

Increase the timeout so the AgentLoop has room to work (mirror the `arithmetic` target's proof, which took ~127s total):

```bash
cd Agentic-AFL-dev
timeout 300 ./venv/bin/python experiments/tests/test_generalization_matrix.py magma_libpng
```

- [ ] **Step 2: Confirm each pipeline stage fires, in the log output**

Check for, in order:
- `Detected 1 new stall(s)` — StallDetector found the plateau and (via GDB frontier discovery) identified `png_crc_finish` as the blocking function.
- `Extracted slice: png_crc_finish @ 0x...` — Ghidra/PCodeSlicer succeeded.
- `Profiled png_crc_finish ...: tags={'BITWISE_LOOP', ...}` — ConstraintProfiler correctly tagged it as a CRC-style pattern.
- `Generating N Z3 scripts for png_crc_finish` followed by a `verdict=sat` result — the LLM produced a working Z3 script. Note whether the log shows the CRC-32 reference-template injection firing (search for `Injected crc32_ieee reference template` in the log) — this is a soft check, not a hard requirement: the spec already anticipated this template match might not trigger if Ghidra's decompiled-C slice doesn't expose the literal `0xedb88320` polynomial constant, in which case the LLM derives the CRC-32 script from scratch instead. Either path is an acceptable success.
- `Injected payload for 0x...` — PayloadInjector wrote the solved payload to the sync directory.

- [ ] **Step 3: Confirm coverage gain past the baseline**

Compare the final edge count to the Task 6 baseline edge count — it must be strictly higher, demonstrating AFL++ made progress past the IHDR chunk boundary after the payload injection (same "before/after edge count" evidence format used for the `arithmetic` target in the health report).

- [ ] **Step 4: Record the result**

Append a short results note to `documents/2026-07-05-magma-libpng-target-design.md` (a new "## Result" section) recording: baseline edges, final edges, whether the CRC-32 template fast path fired, and total wall-clock time from stall detection to successful injection. This is the evidence the paper's evaluation section will eventually cite.

- [ ] **Step 5: Commit**

```bash
git add documents/2026-07-05-magma-libpng-target-design.md
git commit -m "docs: record magma_libpng validation results"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 covers the spec's "Key Technical Assumption (verify first)" section and the setjmp/longjmp resolution; Tasks 2-3 cover Architecture items 1-2 (harness, build script); Task 5 covers Architecture items 3-4 (seed, TargetSpec entry) and the seed-corruption refinement from the design review; Task 4 covers the explicit harness-correctness test the user's design review asked for; Tasks 6-7 cover the full Validation Plan section end-to-end. All spec sections have a corresponding task.
- **No placeholders:** every code/command block above is complete and runnable as written; no TBD/TODO remains.
- **Type/name consistency:** `stall_function="png_crc_finish"` (Task 5) matches the symbol name checked in Task 3's build script and Task 1's source inspection. `accept_marker="PNG_DECODE_OK"` (Task 5) matches the exact string printed by the harness in Task 2. `binary_name="magma_libpng_harness"` (Task 5) matches `OUTPUT` in Task 3's build script.
