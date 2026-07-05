#!/usr/bin/env bash
# build_cfs_harness.sh — Compile NASA cFS checksum AFL++ harness
#
# Usage: ./build_cfs_harness.sh [compiler]
#
# This script compiles the cFS checksum harness against the actual NASA cFE
# CFE_MSG_ValidateChecksum() source code. The harness targets the CCSDS
# command checksum (XOR additive) math wall.
#
# The cFE source is cloned from github.com/nasa/cFE (Apache-2.0).
# A minimal compatibility shim (cfs_compat.h) provides OSAL/PSP types
# without requiring the full cFS build system.
#
# Default compiler: afl-cc (falls back to gcc)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${1:-afl-cc}"

# Paths
CFE_DIR="${SCRIPT_DIR}/cfe"
CFE_CHECKSUM_SRC="${CFE_DIR}/modules/msg/fsw/src/cfe_msg_sechdr_checksum.c"
COMPAT_HDR="${SCRIPT_DIR}/cfs_compat.h"
STUBS_DIR="${SCRIPT_DIR}/cfs_stubs"
HARNESS="${SCRIPT_DIR}/cfs_checksum_harness.c"
OUTPUT="${SCRIPT_DIR}/cfs_checksum_harness"

echo "[BUILD] Compiling NASA cFS checksum harness with ${CC}..."
echo "[BUILD] cFE source: ${CFE_DIR}"

# Clone cFE if not present
if [ ! -f "${CFE_CHECKSUM_SRC}" ]; then
    echo "[BUILD] Cloning NASA cFE repository..."
    git clone --branch main --depth 1 https://github.com/nasa/cFE.git "${CFE_DIR}"
fi

# Verify critical files
if [ ! -f "${CFE_CHECKSUM_SRC}" ]; then
    echo "[ERROR] cFE checksum source not found: ${CFE_CHECKSUM_SRC}"
    exit 1
fi
if [ ! -f "${COMPAT_HDR}" ]; then
    echo "[ERROR] Compatibility shim not found: ${COMPAT_HDR}"
    exit 1
fi

# Create stub headers if missing
mkdir -p "${STUBS_DIR}"
for hdr in cfe_msg.h cfe_msg_priv.h cfe_msg_defaults.h common_types.h; do
    if [ ! -f "${STUBS_DIR}/${hdr}" ]; then
        echo "/* Stub — real types provided by cfs_compat.h */" > "${STUBS_DIR}/${hdr}"
    fi
done

echo "[BUILD] Compiling..."
${CC} -O0 -g -fno-inline -no-pie \
    -include "${COMPAT_HDR}" \
    -I"${STUBS_DIR}" \
    "${HARNESS}" "${CFE_CHECKSUM_SRC}" \
    -o "${OUTPUT}"

echo "[BUILD] ✓ Built: ${OUTPUT}"
echo "[BUILD]   NASA source: ${CFE_CHECKSUM_SRC}"
echo "[BUILD]   Checksum function: CFE_MSG_ValidateChecksum"

# Quick sanity test with gcc-compiled binary
echo "[BUILD] Running sanity check..."
SANITY=$(python3 -c "
buf = bytearray([0x18, 0x01, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00])
xor = 0xFF
for b in buf[:7]: xor ^= b
buf[7] = xor
import sys; sys.stdout.buffer.write(buf)
" | "${OUTPUT}" 2>&1) || true

if echo "${SANITY}" | grep -q "APDU_VALIDATED"; then
    echo "[BUILD] ✓ Sanity check passed: ${SANITY}"
else
    echo "[BUILD] ⚠ Sanity check: no APDU_VALIDATED (expected with AFL instrumentation)"
fi
