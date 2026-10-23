#!/usr/bin/env bash
# setup_symcc.sh — Build SymCC via Docker and validate it against the
# `arithmetic` evaluation target, as a baseline comparison tool for
# Agentic-AFL's RQ2 evaluation.
#
# Scope (deliberately narrow — see documents/ for the full design):
#   1. Build SymCC's own Docker image (default Z3-only backend, not the
#      QSYM-hybrid backend — simpler, fewer moving parts).
#   2. Run SymCC's own bundled self-test inside the container, to prove
#      the build works in isolation before touching our code at all.
#   3. Compile experiments/test_targets/arithmetic_constraint_target.c
#      with SymCC's compiler wrapper and run it once, to prove SymCC can
#      handle a real target from this project.
#
# Explicitly OUT of scope: actual comparison campaigns against
# Agentic-AFL, QSYM, any target other than `arithmetic`. Those are
# separate, later tasks.
#
# SymCC version specifics (input/output env vars, exact CLI flags) can
# drift across releases. Where this script isn't 100% certain of the
# current convention, it checks the tool's own --help/README output
# and tells you what to look for rather than guessing silently.
#
# Versioning: SymCC has no tagged GitHub releases, so there's no release
# tag to pin to. Instead, this script clones the default branch and then
# records the exact commit SHA it got (Step 2) — that SHA IS the pin.
# Write it down (or better, into documents/ alongside this setup) so a
# future re-run or a different machine can reproduce the exact same
# SymCC build via:
#   git clone https://github.com/eurecom-s3/symcc.git && cd symcc && git checkout <sha>
#
# Usage:
#   chmod +x setup_symcc.sh
#   ./setup_symcc.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYMCC_DIR="${SCRIPT_DIR}/experiments/tools/symcc"
SYMCC_IMAGE="agentic-afl-symcc"
ARITH_SRC="${SCRIPT_DIR}/experiments/test_targets/arithmetic_constraint_target.c"

echo "=== SymCC Setup (Docker) ==="
echo ""

# ── Step 1: Preflight — Docker present and daemon reachable ───────────

echo "[1/5] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "[ERROR] docker not found on PATH."
    echo "        Install it first: sudo apt install -y docker.io docker-compose-plugin"
    echo "        Then: sudo systemctl enable --now docker"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "[ERROR] Docker daemon not reachable. Is it running, and are you in the docker group?"
    echo "        Try:  sudo systemctl start docker"
    echo "        And:  sudo usermod -aG docker \$USER   (then log out/in)"
    exit 1
fi
echo "  -> Docker OK: $(docker --version)"

# ── Step 2: Clone SymCC (no tagged releases exist — pin by commit SHA) ─

echo ""
echo "[2/5] Fetching SymCC (default branch — no tagged releases exist upstream)..."
mkdir -p "$(dirname "${SYMCC_DIR}")"
if [ -d "${SYMCC_DIR}" ]; then
    echo "  -> ${SYMCC_DIR} already exists, skipping clone (delete it first to re-fetch)"
else
    git clone --depth 1 --recurse-submodules \
        https://github.com/eurecom-s3/symcc.git "${SYMCC_DIR}"
    echo "  -> Cloned to ${SYMCC_DIR}"
fi

if [ ! -f "${SYMCC_DIR}/Dockerfile" ]; then
    echo "[ERROR] No Dockerfile found at ${SYMCC_DIR}/Dockerfile."
    echo "        SymCC's repo layout may have changed since this script was written —"
    echo "        check https://github.com/eurecom-s3/symcc for the current build instructions."
    exit 1
fi

# Record the exact commit as the reproducibility pin, since there's no
# release tag to reference instead. Written to a file (not just echoed)
# so it survives past this terminal session.
SYMCC_COMMIT_SHA="$(git -C "${SYMCC_DIR}" rev-parse HEAD)"
echo "${SYMCC_COMMIT_SHA}" > "${SYMCC_DIR}/../SYMCC_COMMIT_SHA.txt"
echo "  -> Pinned commit: ${SYMCC_COMMIT_SHA}"
echo "     (recorded in experiments/tools/SYMCC_COMMIT_SHA.txt — keep this,"
echo "      it's the only way to reproduce this exact build later since"
echo "      SymCC has no release tags)"

# ── Step 3: Build the Docker image ──────────────────────────────────────

echo ""
echo "[3/5] Building SymCC Docker image (this compiles LLVM + the symbolic"
echo "      runtime — expect this to take a while, easily 10-20+ minutes"
echo "      on modest hardware)..."
docker build -t "${SYMCC_IMAGE}" "${SYMCC_DIR}"
echo "  -> Built image: ${SYMCC_IMAGE}"

# ── Step 4: Self-check — SymCC's own example, independent of our code ──

echo ""
echo "[4/5] Running SymCC's self-check inside the container..."
echo "      (Looking for a bundled example/test — reporting what's found"
echo "      rather than assuming an exact path, since this can vary by"
echo "      release.)"

SELF_CHECK_LOG=$(mktemp)
if docker run --rm "${SYMCC_IMAGE}" bash -c '
    set -e
    echo "--- symcc/sym++ presence ---"
    which symcc sym++ 2>&1 || echo "(not on PATH — check the Dockerfile for the actual binary location/name)"
    echo "--- example/test directories in the image ---"
    find / -maxdepth 4 -iname "*example*" -o -iname "*test*" 2>/dev/null | grep -iv "^/proc\|^/sys\|/usr/lib\|/usr/share/doc" | head -20
' > "${SELF_CHECK_LOG}" 2>&1; then
    cat "${SELF_CHECK_LOG}"
    echo "  -> Container runs and responds. Review the output above manually:"
    echo "     confirm 'symcc'/'sym++' resolved to a real path, not the 'not found' fallback."
else
    echo "[ERROR] Self-check container run failed. Full output:"
    cat "${SELF_CHECK_LOG}"
    rm -f "${SELF_CHECK_LOG}"
    exit 1
fi
rm -f "${SELF_CHECK_LOG}"

# ── Step 5: Compile + run the arithmetic target through SymCC ──────────

echo ""
echo "[5/5] Compiling experiments/test_targets/arithmetic_constraint_target.c"
echo "      with SymCC and running it once..."

if [ ! -f "${ARITH_SRC}" ]; then
    echo "[ERROR] ${ARITH_SRC} not found. Are you running this from the repo root?"
    exit 1
fi

# Build a valid packet matching arithmetic_constraint_target.c's format
# (see its own header comment): a=0x0150 (in [0x100,0x200]), b=0x0005,
# expected=(a*7+b*13)&0xFFFF, checkbyte=(a+b)&0xFF. Computed with Python
# for correctness rather than hand-arithmetic.
TEST_INPUT=$(mktemp)
python3 -c "
import struct
a, b = 0x0150, 0x0005
expected = (a * 7 + b * 13) & 0xFFFF
checkbyte = (a + b) & 0xFF
data = struct.pack('>HHHB', a, b, expected, checkbyte)
open('${TEST_INPUT}', 'wb').write(data)
"
# mktemp defaults to mode 0600, owner-only. The SymCC image's container
# process runs as a non-root 'ubuntu' user (uid 1000) regardless of what
# UID this script itself runs as on the host -- if that's root (uid 0,
# as it commonly is on a fresh VM), the container can't read a 0600
# root-owned file at all (bind mounts don't translate ownership). The
# file only ever holds non-sensitive test input bytes, so making it
# world-readable is a safe, minimal fix rather than fighting UID
# mismatches or changing how you run this script.
chmod 644 "${TEST_INPUT}"

docker run --rm \
    -v "${SCRIPT_DIR}/experiments/test_targets:/target:ro" \
    -v "$(dirname "${TEST_INPUT}"):/testdata" \
    "${SYMCC_IMAGE}" bash -c "
        set -e
        cd /tmp
        cp /target/arithmetic_constraint_target.c .
        echo '--- compiling with symcc ---'
        symcc -O1 -g -o arithmetic_target_symcc arithmetic_constraint_target.c
        echo '--- running against a known-valid input ---'
        ./arithmetic_target_symcc '/testdata/$(basename "${TEST_INPUT}")'
        echo '--- exit code: '\$?' ---'
    "

rm -f "${TEST_INPUT}"

echo ""
echo "=== SymCC Setup Complete ==="
echo ""
echo "If step 5 printed 'ACCEPT: Valid packet' above, SymCC compiled and ran"
echo "a real project target correctly — the tool is validated."
echo ""
echo "What this script deliberately does NOT do yet:"
echo "  - Actually drive SymCC's symbolic exploration loop to solve the"
echo "    constraints from a BAD input (that needs SYMCC_INPUT_FILE / the"
echo "    output-directory env var for generated test cases — check"
echo "    '${SYMCC_DIR}/README.md' or 'symcc --help' inside the container"
echo "    for the current names, since these can drift across releases)."
echo "  - Any comparison against Agentic-AFL. That's a separate, later task."
