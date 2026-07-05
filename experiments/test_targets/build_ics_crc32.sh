#!/usr/bin/env bash
# build_ics_crc32.sh — Compile ICS CRC-32 harness with AFL++
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/ics_crc32"
OUT="${SCRIPT_DIR}/ics_crc32_harness"

# Accept compiler from arg or env (matches other build scripts)
CC="${1:-${CC:-afl-cc}}"
CFLAGS="-O0 -fno-inline -g -Wall -Wextra"

echo "[build] Compiling ICS CRC-32 harness..."
$CC $CFLAGS -I"${SRC_DIR}" "${SRC_DIR}/harness.c" -o "$OUT"
echo "[build] ✓ Built: $OUT"

# Extract stall function address (|| true to prevent SIGPIPE exit)
FUNC_NAME="crc32_calc"
ADDR=$(nm "$OUT" 2>/dev/null | grep -w "$FUNC_NAME" | awk '{print "0x"$1; exit}' || true)
if [ -n "$ADDR" ]; then
    echo "[build]   ${FUNC_NAME} @ ${ADDR}"
else
    echo "[build]   ⚠ ${FUNC_NAME} not found (may be inlined)"
fi
