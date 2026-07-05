# libpng CRC-handling & fuzzing-mode verification (Task 1)

Pinned reference: `libpng` v1.6.58 (tag `v1.6.58`, resolved commit
`3061454d980de7d53608f594194cfac722721d2a`), cloned from
`https://github.com/pnggroup/libpng.git`.

The clone lives at `experiments/test_targets/libpng/` on disk for reference
by later tasks but is **not committed** — it is already listed in
`.gitignore` (same convention as `opendnp3/`, `libmodbus/`, `cfe/`, etc.:
"regenerable via `git clone`, not hand-authored, and large"). Re-fetch with:

```bash
cd experiments/test_targets
git clone --branch v1.6.58 --depth 1 https://github.com/pnggroup/libpng.git libpng
```

## Q1: Does IHDR CRC mismatch hard-fail under libpng's default crc_action?

**Yes — no extra configuration needed.**

- `png.h` defines `PNG_CRC_DEFAULT 0` as "error/quit" for critical chunks
  (IHDR is critical) and "warn/discard" only for ancillary chunks.
- `pngrutil.c`, `png_handle_IHDR` calls `png_crc_read()` + `png_crc_finish()`
  unconditionally after reading the 13-byte IHDR payload.
- `png_crc_finish()` -> `png_crc_finish_critical()` -> `png_crc_error()`: for
  a critical chunk, unless `PNG_FLAG_CRC_CRITICAL_USE` was explicitly set
  (it is not, by default — default flags are all zero), a CRC mismatch takes
  the `else` branch and calls `png_chunk_error(png_ptr, "CRC error")`.
- `pngerror.c`: `png_chunk_error` is declared `PNG_NORETURN` and calls
  `png_error()`, libpng's standard hard-error path (`longjmp` via
  `png_ptr->jmp_buf`) — i.e. parsing aborts immediately.

**Decision for Task 3:** the harness does **not** need to call
`png_set_crc_action(png_ptr, PNG_CRC_CRITICAL_USE, PNG_CRC_ERROR_QUIT)` —
default behavior already hard-fails on IHDR CRC mismatch. This differs from
OpenDNP3, which required the harness to explicitly force CRC enforcement.

**Caveat / bonus finding for Task 3-4:** libpng's own official OSS-Fuzz
harness, `contrib/oss-fuzz/libpng_read_fuzzer.cc:142`, explicitly *disables*
CRC enforcement via
`png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE)`. Task 3's
harness must **not** copy this pattern (it would remove the CRC "math wall"
the project exists to test) — leave `crc_action` at its library default.

## Q2: Does libpng reference `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`?

**No matches.** `grep -rn "FUZZING_BUILD_MODE" experiments/test_targets/libpng/`
returns zero results (grep exit code 1). Stock libpng v1.6.58 contains no
fuzzing-mode bypass macros, unlike OpenDNP3. Task 4's build script does
**not** need the `-UFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` defensive flag
that `build_opendnp3_harness.sh` uses.
