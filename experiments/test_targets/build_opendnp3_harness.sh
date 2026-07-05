#!/usr/bin/env bash
# build_opendnp3_harness.sh — Compile OpenDNP3 AFL++ harness
#
# Usage: ./build_opendnp3_harness.sh [compiler]
#
# This script compiles the OpenDNP3 outstation harness against the actual
# OpenDNP3 source code with CRC validation ENABLED. The harness targets
# the data link layer CRC-16/DNP3 math wall.
#
# Default compiler: afl-clang-fast++ (falls back to g++)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CXX="${1:-afl-clang-fast++}"

# Paths
OPENDNP3="${SCRIPT_DIR}/opendnp3"
SER4CPP="${SCRIPT_DIR}/opendnp3_deps/ser4cpp"
HARNESS="${SCRIPT_DIR}/opendnp3_outstation_harness.cpp"
OUTPUT="${SCRIPT_DIR}/opendnp3_outstation_harness"

echo "[BUILD] Compiling OpenDNP3 outstation harness with ${CXX}..."
echo "[BUILD] OpenDNP3: ${OPENDNP3}"
echo "[BUILD] ser4cpp:  ${SER4CPP}"

# Verify sources exist
if [ ! -d "${OPENDNP3}/cpp/lib/src" ]; then
    echo "[ERROR] OpenDNP3 source not found at ${OPENDNP3}"
    echo "        Clone: git clone --branch release --depth 1 https://github.com/dnp3/opendnp3.git ${OPENDNP3}"
    exit 1
fi

if [ ! -d "${SER4CPP}/src" ]; then
    echo "[ERROR] ser4cpp not found at ${SER4CPP}"
    echo "        Clone: git clone --depth 1 https://github.com/automatak/ser4cpp.git ${SER4CPP}"
    exit 1
fi

# OpenDNP3 source files needed for the link layer parser
LINK_SRCS=(
    "${OPENDNP3}/cpp/lib/src/link/CRC.cpp"
    "${OPENDNP3}/cpp/lib/src/link/LinkLayerParser.cpp"
    "${OPENDNP3}/cpp/lib/src/link/LinkFrame.cpp"
    "${OPENDNP3}/cpp/lib/src/link/LinkHeader.cpp"
    "${OPENDNP3}/cpp/lib/src/link/LinkHeaderFields.cpp"
    "${OPENDNP3}/cpp/lib/src/link/Addresses.cpp"
    "${OPENDNP3}/cpp/lib/src/link/ShiftableBuffer.cpp"
)

# Logging source files (minimal — needed for Logger class)
LOG_SRCS=(
    "${OPENDNP3}/cpp/lib/src/logging/LogLevels.cpp"
)

# Gen source files (for link function enum string conversions)
GEN_SRCS=()
for f in "${OPENDNP3}/cpp/lib/src/gen/"*.cpp; do
    if [ -f "$f" ]; then
        GEN_SRCS+=("$f")
    fi
done

# Include directories
INCLUDES=(
    -I"${OPENDNP3}/cpp/lib/src"
    -I"${OPENDNP3}/cpp/lib/include"
    -I"${SER4CPP}/src"
)

echo "[BUILD] Compiling ${#LINK_SRCS[@]} link + ${#LOG_SRCS[@]} log + ${#GEN_SRCS[@]} gen sources..."

# Compile — FORCEFULLY UNDEFINE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION.
# afl-clang-fast++ auto-defines this macro, which causes OpenDNP3's
# CRC::IsCorrectCRC() to return true unconditionally (line 78-79 of CRC.cpp).
# We MUST keep the CRC wall active — that's the entire point of this harness.
${CXX} \
    -std=c++14 \
    -O2 \
    -g \
    -Wall \
    -Wno-unused-variable \
    -Wno-sign-compare \
    -UFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
    -include "${SCRIPT_DIR}/opendnp3_force_crc.h" \
    "${INCLUDES[@]}" \
    "${HARNESS}" \
    "${LINK_SRCS[@]}" \
    "${LOG_SRCS[@]}" \
    "${GEN_SRCS[@]}" \
    -o "${OUTPUT}" \
    -lstdc++ \
    -lm

echo "[BUILD] ✓ Compiled: ${OUTPUT}"
echo "[BUILD]   Size: $(stat --printf='%s' "${OUTPUT}" 2>/dev/null || stat -f%z "${OUTPUT}" 2>/dev/null) bytes"

# Quick sanity check
if [ -x "${OUTPUT}" ]; then
    echo "[BUILD] ✓ Binary is executable"

    # Test with random input (should be rejected)
    TMPFILE=$(mktemp)
    dd if=/dev/urandom bs=32 count=1 of="${TMPFILE}" 2>/dev/null
    RESULT=$(${OUTPUT} "${TMPFILE}" 2>&1 || true)
    rm -f "${TMPFILE}"

    if echo "${RESULT}" | grep -q "REJECT"; then
        echo "[BUILD] ✓ Random input correctly rejected"
    else
        echo "[BUILD] ⚠ Random input result: ${RESULT}"
    fi
fi
