#!/usr/bin/env fish
#
# setup_ghidra_python.fish -- Enable Python 3 scripting in Ghidra 12.
#
# Ghidra 12 ships with PyGhidra built-in, but it requires the `pyghidra`
# pip package to be installed. Once installed, you launch Ghidra via
# `pyghidraRun` instead of `ghidraRun`, and all .py scripts in the
# Script Manager run as Python 3.
#
# Usage:
#   chmod +x setup_ghidra_python.fish
#   ./setup_ghidra_python.fish

echo "=== Ghidra Python 3 Setup ==="
echo ""

# ── Step 1: Find Ghidra Installation ───────────────────────────────────

set -l ghidra_dir ""

# Check common locations
for candidate in /opt/ghidra /usr/share/ghidra /usr/local/share/ghidra $HOME/ghidra
    if test -f "$candidate/ghidraRun"
        set ghidra_dir $candidate
        break
    end
end

# Fallback: find it via the `ghidra` command
if test -z "$ghidra_dir"
    set -l ghidra_bin (which ghidra 2>/dev/null)
    if test -n "$ghidra_bin"
        # Resolve symlinks to find the actual install dir
        set -l resolved (readlink -f "$ghidra_bin" 2>/dev/null; or echo "$ghidra_bin")
        set ghidra_dir (dirname "$resolved")
        # ghidraRun is usually in the install root, not support/
        if not test -f "$ghidra_dir/ghidraRun"
            set ghidra_dir (dirname "$ghidra_dir")
        end
    end
end

if test -z "$ghidra_dir"; or not test -f "$ghidra_dir/ghidraRun"
    echo "[ERROR] Could not find Ghidra installation."
    echo "  Checked: /opt/ghidra, /usr/share/ghidra, \$HOME/ghidra"
    echo "  Set GHIDRA_INSTALL_DIR manually and re-run."
    exit 1
end

echo "[1/5] Found Ghidra at: $ghidra_dir"

# ── Step 2: Verify PyGhidra launcher exists ────────────────────────────

set -l pyghidra_run "$ghidra_dir/support/pyghidraRun"
if not test -f "$pyghidra_run"
    echo "[ERROR] pyghidraRun not found at: $pyghidra_run"
    echo "  Your Ghidra build may not include PyGhidra."
    echo "  Ghidra 12+ should have it. Check your installation."
    exit 1
end

echo "[2/5] Found PyGhidra launcher: $pyghidra_run"

# ── Step 3: Check Python 3 ────────────────────────────────────────────

set -l python_bin (which python3 2>/dev/null)
if test -z "$python_bin"
    echo "[ERROR] Python 3 not found. Install python3 first."
    exit 1
end

set -l py_version (python3 --version 2>&1)
echo "[3/5] Using Python: $python_bin ($py_version)"

# ── Step 4: Install pyghidra pip package ───────────────────────────────

echo "[4/5] Installing pyghidra pip package..."

# Check if already installed
if pip show pyghidra >/dev/null 2>&1
    set -l installed_version (pip show pyghidra 2>/dev/null | grep "^Version:" | awk '{print $2}')
    echo "  -> pyghidra already installed (v$installed_version)"
else
    pip install pyghidra
    if test $status -ne 0
        echo "[ERROR] Failed to install pyghidra."
        echo "  Try: pip install --user pyghidra"
        exit 1
    end
    echo "  -> pyghidra installed successfully"
end

# ── Step 5: Copy extract_pcode.py to Ghidra scripts dir ───────────────

echo "[5/5] Setting up Ghidra scripts directory..."

set -l ghidra_scripts_dir "$HOME/ghidra_scripts"
mkdir -p "$ghidra_scripts_dir"

set -l script_src (dirname (status filename))"/agentic_afl/extractor/ghidra_scripts/extract_pcode.py"

# Fallback if running from a different directory
if not test -f "$script_src"
    set script_src (dirname (status filename 2>/dev/null; or echo "."))"/../agentic_afl/extractor/ghidra_scripts/extract_pcode.py"
end

if not test -f "$script_src"
    # Try the known absolute path
    set script_src "/home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/extractor/ghidra_scripts/extract_pcode.py"
end

if test -f "$script_src"
    cp "$script_src" "$ghidra_scripts_dir/extract_pcode.py"
    echo "  -> Copied extract_pcode.py to $ghidra_scripts_dir/"
else
    echo "  -> [WARN] Could not find extract_pcode.py to copy."
    echo "    Copy it manually to: $ghidra_scripts_dir/"
end

# ── Done ───────────────────────────────────────────────────────────────

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To launch Ghidra WITH Python 3 support:"
echo ""
echo "  $pyghidra_run"
echo ""
echo "  Or create a fish alias:"
echo "  alias ghidra-py '$pyghidra_run'"
echo ""
echo "Once Ghidra opens:"
echo "  1. Window > Script Manager"
echo "  2. Find extract_pcode.py (search 'extract')"
echo "  3. Click Run -- you'll get three input dialogs"
echo ""
echo "NOTE: You MUST launch via pyghidraRun, not ghidraRun."
echo "      The regular ghidraRun does NOT have Python support."
