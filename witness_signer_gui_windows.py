#!/usr/bin/env python3
"""
Windows launcher for witness signer GUI.

Usage:
    python witness_signer_gui_windows.py
"""

import argparse
import os

from witness_signer_gui import main as start_gui


def default_windows_config_file() -> str:
    appdata = os.getenv("APPDATA", "").strip()
    if not appdata:
        appdata = os.path.expanduser("~")
    base = os.path.join(appdata, "NAIOWitnessSigner")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "config.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config-file",
        default=default_windows_config_file(),
        help="path to GUI config JSON",
    )
    parser.add_argument("--title", default="NAIO Witness Signer (Windows)", help="window title")
    args = parser.parse_args()
    start_gui(config_file=args.config_file, app_title=args.title)


if __name__ == "__main__":
    main()
