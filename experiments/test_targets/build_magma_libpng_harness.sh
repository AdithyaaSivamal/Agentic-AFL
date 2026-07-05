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
    -lm \
    -o "${OUTPUT}"

echo "[BUILD] Compiled: ${OUTPUT}"
echo "[BUILD]   Size: $(stat -c%s "${OUTPUT}" 2>/dev/null || stat -f%z "${OUTPUT}") bytes"

# Verify the CRC function symbol is present and not inlined.
ADDR=$(nm "${OUTPUT}" | awk '$3 == "png_crc_finish" {print $1; exit}' || true)
if [ -n "${ADDR}" ]; then
    echo "[BUILD]   png_crc_finish @ 0x${ADDR}"
else
    echo "[BUILD]   WARNING: png_crc_finish symbol not found — may be inlined or stripped"
fi
