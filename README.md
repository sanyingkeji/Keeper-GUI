# Keeper GUI

Standalone GUI signer client for NAIO witness-signature flow.

This repo contains only the client-side GUI and packaging pipeline (EXE/DMG).

## Features

- Configure signer private key locally (stored on client machine)
- Configure server endpoint and API key
- Pull pending witness tasks and submit signatures automatically
- Cross-platform launcher:
  - Windows: `witness_signer_gui_windows.py`
  - macOS: `witness_signer_gui_macos.py`

## Runtime Requirements

- Python 3.10+ (recommended 3.11)
- Tkinter (usually bundled in official Python installers)

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

## Local Run

Windows:

```bat
python witness_signer_gui_windows.py
```

macOS:

```bash
python witness_signer_gui_macos.py
```

## Local Packaging

Windows EXE (run on Windows):

```bat
build_witness_signer_windows.bat
```

Output:
- `dist/NAIOWitnessSigner.exe`

macOS DMG (run on macOS):

```bash
chmod +x build_witness_signer_macos.sh
./build_witness_signer_macos.sh
```

Output:
- `dist/NAIOWitnessSigner.dmg`

## GitHub Actions Packaging

Workflow file:
- `.github/workflows/build-packages.yml`

Triggers:
- Manual: `workflow_dispatch`
- Tag push: `v*` (e.g. `v1.0.0`)

Behavior:
- Build Windows EXE on `windows-latest`
- Build macOS DMG on `macos-latest`
- Upload both as workflow artifacts
- On tag push, publish GitHub Release with EXE + DMG assets

## Security Notes

- Private key is stored in client config file on local machine.
- For production distribution, add platform code-signing:
  - Windows Authenticode signing
  - Apple Developer signing + notarization
