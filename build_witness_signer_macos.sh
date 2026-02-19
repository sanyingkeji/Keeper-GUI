#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -x ".venv-build/bin/python3" ]; then
  echo "[INFO] Creating build venv..."
  python3 -m venv .venv-build
fi

source .venv-build/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements.packaging.txt

rm -rf build dist

echo "[INFO] Building macOS app with PyInstaller..."
pyinstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name "NAIOWitnessSigner" \
  --collect-all eth_account \
  --collect-all eth_abi \
  --collect-all eth_utils \
  --collect-all eth_keys \
  --collect-all hexbytes \
  --collect-all rlp \
  --collect-all parsimonious \
  witness_signer_gui_macos.py

APP_PATH="dist/NAIOWitnessSigner.app"
if [ ! -d "$APP_PATH" ]; then
  echo "[ERROR] App bundle not found: $APP_PATH"
  exit 1
fi

DMG_ROOT="dist/dmg_root"
DMG_PATH="dist/NAIOWitnessSigner.dmg"
rm -rf "$DMG_ROOT" "$DMG_PATH"
mkdir -p "$DMG_ROOT"
cp -R "$APP_PATH" "$DMG_ROOT/"
ln -s /Applications "$DMG_ROOT/Applications"

echo "[INFO] Building DMG..."
hdiutil create \
  -volname "NAIOWitnessSigner" \
  -srcfolder "$DMG_ROOT" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "[OK] DMG generated: $DMG_PATH"
