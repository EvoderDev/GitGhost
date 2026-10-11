#!/usr/bin/env bash
# =====================================================================
#  GitGhost: PR Review & Security Scanner Action - Setup (Linux / macOS)
# =====================================================================
set -e

echo "====================================================================="
echo " GitGhost: PR Review & Security Scanner Action - Setup (Linux / macOS)"
echo "====================================================================="

# 1. Check Python installation (prefer python3)
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[ERROR] Python 3 is not installed or not in PATH."
    echo "Please install Python 3.9 or higher."
    exit 1
fi

# 2. Check Python version (>= 3.9)
$PYTHON_BIN -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null || {
    echo "[ERROR] Python 3.9 or higher is required."
    echo "Current version: $($PYTHON_BIN --version 2>&1)"
    exit 1
}
echo "[OK] Detected $($PYTHON_BIN --version 2>&1)"

# 3. Create virtual environment (.venv) if missing
if [ ! -f ".venv/bin/activate" ]; then
    echo "[*] Creating virtual environment in .venv ..."
    $PYTHON_BIN -m venv .venv
    echo "[OK] Virtual environment created successfully."
else
    echo "[OK] Existing virtual environment found in .venv."
fi

# 4. Activate virtual environment
echo "[*] Activating virtual environment..."
source .venv/bin/activate

# 5. Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip --quiet

# 6. Install requirements
echo "[*] Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# 7. Install package in editable mode
echo "[*] Installing GitGhost in editable development mode (pip install -e .)..."
pip install -e .

# 8. Verify installation
echo "[*] Verifying installation..."
gitghost --version || python -m gitghost --version

echo "====================================================================="
echo " [SUCCESS] GitGhost setup completed successfully!"
echo "====================================================================="
echo "To start using GitGhost:"
echo "  1. Activate virtual environment: source .venv/bin/activate"
echo "  2. Scan staged Git changes:      gitghost scan --staged"
echo "  3. Scan a directory or file:     gitghost scan --file src/"
echo "  4. Auto-generate patches:        gitghost fix --staged"
echo "  5. Autonomous LLM review:        gitghost review"
echo "  6. GitHub Action CI mode:        gitghost ci --fail-on high"
echo "====================================================================="
