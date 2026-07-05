#!/usr/bin/env bash
# build_libmodbus_harness.sh — Compile the libmodbus CRC-16 harness with AFL++
#
# Links directly against the CRC tables embedded in the harness
# (copied from libmodbus/src/modbus-rtu.c). No external library needed.
#
# Flags:
#   -O0 -fno-inline:  Prevent compiler from optimizing away the CRC function,
#                     ensuring 100% instrumentation accuracy.
#   -g:               Debug symbols for GDB probing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="${SCRIPT_DIR}/libmodbus_harness.c"
OUTPUT="${SCRIPT_DIR}/libmodbus_harness"

echo "[build] Compiling libmodbus CRC-16 harness with afl-cc..."

afl-cc \
    -O0 \
    -fno-inline \
    -g \
    -Wall -Wextra \
    "${HARNESS}" \
    -o "${OUTPUT}"

echo "[build] ✓ Built: ${OUTPUT}"
echo "[build]   Size: $(stat -c%s "${OUTPUT}" 2>/dev/null || stat -f%z "${OUTPUT}") bytes"

# Verify the CRC function symbol is present and not inlined
ADDR=$(nm "${OUTPUT}" | awk '$3 == "crc16" {print $1; exit}' || true)
if [ -n "${ADDR}" ]; then
    echo "[build]   crc16 @ 0x${ADDR}"
else
    echo "[build]   WARNING: crc16 symbol not found — may be inlined"
fi
