#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -x "$SCRIPT_DIR/venv/bin/python3" ]; then
  PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
else
  PYTHON_BIN="python3"
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/witness_signer_gui_macos.py"
