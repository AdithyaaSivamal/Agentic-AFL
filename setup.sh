#!/usr/bin/env bash
# setup.sh — Environment preparation for Agentic-AFL.
#
# This script installs system-level dependencies that cannot be handled
# by pip (Z3 native library, Ghidra, AFL++).
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Prerequisites:
#   - Arch Linux / CachyOS (pacman-based)
#   - Python 3.11+
#   - yay or paru for AUR packages

set -euo pipefail

echo "=== Agentic-AFL Environment Setup ==="

# ── System Dependencies ─────────────────────────────────────────────────

echo "[1/4] Installing system packages..."
# z3: SMT solver (native library + Python bindings)
# ghidra: Binary analysis framework (Headless mode)
# aflplusplus: Coverage-guided fuzzer
# python-z3-solver: Python bindings for Z3 (also available via pip)

# Uncomment the appropriate package manager:
# sudo pacman -S --nocheck z3 ghidra
# yay -S aflplusplus

echo "  → Skipping system package installation (uncomment lines above for your distro)"

# ── Python Virtual Environment ──────────────────────────────────────────

echo "[2/4] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "  → Created .venv"
else
    echo "  → .venv already exists"
fi

source .venv/bin/activate

# ── PostgreSQL (Spec Store) ─────────────────────────────────────────────

echo "[3/5] Starting PostgreSQL via Docker..."
if command -v docker &> /dev/null; then
    if docker compose ps --services --filter "status=running" 2>/dev/null | grep -q postgres; then
        echo "  → PostgreSQL already running"
    else
        docker compose up -d
        echo "  → PostgreSQL container started (agentic_afl_db)"
        echo "  → Waiting for health check..."
        sleep 3
    fi
else
    echo "  ⚠ Docker not found. Install Docker or provision PostgreSQL manually."
    echo "    Connection string: postgresql://agentic_afl:agentic_afl@localhost:5432/agentic_afl"
fi

# ── Python Dependencies ─────────────────────────────────────────────────

echo "[4/5] Installing Python dependencies..."
pip install -e ".[dev]" --quiet

# ── Directory Structure ─────────────────────────────────────────────────

echo "[5/5] Creating runtime directories..."
mkdir -p logs
mkdir -p experiments/{plague_v_iec104,baseline_modbus}

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Activate the environment:  source .venv/bin/activate"
echo "Run tests:                 pytest"
echo "Type check:                mypy agentic_afl/"
echo "Lint:                      ruff check agentic_afl/"
echo ""
echo "Required environment variables:"
echo "  LLM_API_KEY          — Your OpenAI/Anthropic API key"
echo "  GHIDRA_INSTALL_DIR   — Path to Ghidra installation (default: /opt/ghidra)"
echo "  AFL_OUTPUT_DIR       — Path to AFL++ output directory"
echo "  POSTGRES_DSN         — PostgreSQL connection (default: postgresql://agentic_afl:agentic_afl@localhost:5432/agentic_afl)"

