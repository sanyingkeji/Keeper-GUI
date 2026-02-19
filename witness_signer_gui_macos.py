#!/usr/bin/env python3
"""
macOS launcher for witness signer GUI.

Usage:
    python witness_signer_gui_macos.py
"""

import argparse
import os

from witness_signer_gui import main as start_gui


def default_macos_config_file() -> str:
    base = os.path.expanduser("~/Library/Application Support/NAIOWitnessSigner")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "config.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config-file",
        default=default_macos_config_file(),
        help="path to GUI config JSON",
    )
    parser.add_argument("--title", default="NAIO Witness Signer (macOS)", help="window title")
    args = parser.parse_args()
    start_gui(config_file=args.config_file, app_title=args.title)


if __name__ == "__main__":
    main()
