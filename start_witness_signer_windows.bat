@echo off
setlocal enableextensions enabledelayedexpansion

cd /d "%~dp0"

if exist ".venv-build\Scripts\python.exe" (
  set "PYTHON_BIN=.venv-build\Scripts\python.exe"
) else (
  set "PYTHON_BIN=python"
)

"%PYTHON_BIN%" witness_signer_gui_windows.py
endlocal
