#!/bin/bash
# build_lib60870_harness.sh — Compile lib60870 AFL++ harness
#
# Usage: ./build_lib60870_harness.sh [compiler]
#   compiler: "afl-cc" (default) or "gcc" (for debugging)
#
# This script compiles the lib60870 APCI parser harness against
# the actual lib60870 source code with HAL stubs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB60870="/home/adi/Projects/PLAGUE-V/lib60870/lib60870-C"
HARNESS="${SCRIPT_DIR}/lib60870_harness.c"
OUTPUT="${SCRIPT_DIR}/lib60870_harness"

CC="${1:-afl-cc}"

echo "[BUILD] Compiling lib60870 harness with ${CC}..."
echo "[BUILD] Source: ${HARNESS}"
echo "[BUILD] lib60870: ${LIB60870}"

# Verify lib60870 source exists
if [ ! -d "${LIB60870}/src" ]; then
    echo "[ERROR] lib60870 source not found at ${LIB60870}"
    echo "        Clone from: https://github.com/mz-automation/lib60870"
    exit 1
fi

# The harness #includes cs104_connection.c directly (to access static
# functions), so we do NOT compile cs104_connection.c separately.
# We only compile the transitive dependencies.
${CC} -O1 -g -no-pie \
    -DCONFIG_USE_THREADS=0 \
    -DCONFIG_USE_SEMAPHORES=0 \
    -DCONFIG_CS104_SUPPORT_TLS=0 \
    -DCONFIG_DEBUG_OUTPUT=0 \
    -I"${LIB60870}/config" \
    -I"${LIB60870}/src/inc/api" \
    -I"${LIB60870}/src/inc/internal" \
    -I"${LIB60870}/src/hal/inc" \
    -I"${LIB60870}/src/common/inc" \
    -I"${LIB60870}/src/iec60870" \
    -I"${LIB60870}/src/iec60870/cs104" \
    -I"${LIB60870}/src/iec60870/cs101" \
    "${HARNESS}" \
    "${LIB60870}/src/iec60870/cs104/cs104_frame.c" \
    "${LIB60870}/src/iec60870/cs101/cs101_asdu.c" \
    "${LIB60870}/src/iec60870/cs101/cs101_information_objects.c" \
    "${LIB60870}/src/iec60870/lib60870_common.c" \
    "${LIB60870}/src/iec60870/apl/cpXXtime2a.c" \
    "${LIB60870}/src/iec60870/frame.c" \
    "${LIB60870}/src/hal/memory/lib_memory.c" \
    -o "${OUTPUT}" \
    -lm

echo "[BUILD] ✓ Compiled: ${OUTPUT}"

# Verify the stall function symbol is resolvable
echo ""
echo "[BUILD] Checking symbols..."
if nm -C "${OUTPUT}" | grep -q "checkMessage"; then
    ADDR=$(nm -C "${OUTPUT}" | grep " checkMessage$" | head -1 | awk '{print $1}')
    echo "[BUILD] ✓ checkMessage @ 0x${ADDR}"
else
    echo "[BUILD] ⚠ checkMessage not found (static, may be inlined)"
fi

if nm -C "${OUTPUT}" | grep -q "checkSequenceNumber"; then
    ADDR=$(nm -C "${OUTPUT}" | grep " checkSequenceNumber$" | head -1 | awk '{print $1}')
    echo "[BUILD] ✓ checkSequenceNumber @ 0x${ADDR}"
else
    echo "[BUILD] ⚠ checkSequenceNumber not found (static, may be inlined)"
fi

echo ""
echo "[BUILD] Test with: ${OUTPUT} <input_file>"
echo "[BUILD] Fuzz with: afl-fuzz -i seeds/ -o out/ -- ${OUTPUT} @@"
