@echo off
setlocal enableextensions enabledelayedexpansion

cd /d "%~dp0"

if not exist ".venv-build\Scripts\python.exe" (
  echo [INFO] Creating build venv...
  where python >nul 2>nul
  if %errorlevel%==0 (
    python -m venv .venv-build
  ) else (
    py -3.11 -m venv .venv-build
  )
  if errorlevel 1 (
    echo [ERROR] Failed to create venv. Ensure Python 3.11 is installed.
    exit /b 1
  )
)

call ".venv-build\Scripts\activate.bat"
if errorlevel 1 (
  echo [ERROR] Failed to activate venv.
  exit /b 1
)

python --version
if errorlevel 1 exit /b 1

python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

pip install -r requirements.txt -r requirements.packaging.txt
if errorlevel 1 exit /b 1

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [INFO] Building EXE with PyInstaller...
pyinstaller ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --onefile ^
  --name "NAIOWitnessSigner" ^
  --collect-all eth_account ^
  --collect-all eth_abi ^
  --collect-all eth_utils ^
  --collect-all eth_keys ^
  --collect-all hexbytes ^
  --collect-all rlp ^
  --collect-all parsimonious ^
  witness_signer_gui_windows.py
if errorlevel 1 (
  echo [ERROR] Build failed.
  exit /b 1
)

echo [OK] EXE generated: dist\NAIOWitnessSigner.exe
endlocal
