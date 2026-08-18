# ARGUS Forensics — Desktop build (Tauri + Python sidecar)

## Prerequisites

| Tool | Install |
|------|---------|
| **Rust (MSVC)** | [rustup.rs](https://rustup.rs/) then `rustup default stable-x86_64-pc-windows-msvc` |
| **Visual Studio Build Tools 2022** | Workload: *Desktop development with C++* (provides `link.exe`) |
| **Tauri CLI** | `cargo install tauri-cli --version "^2.0" --locked` |
| **Python 3.10+** | For dev runs and bundling the embeddable runtime |
| **WebView2** | Pre-installed on Windows 11; [Evergreen runtime](https://developer.microsoft.com/microsoft-edge/webview2/) on Windows 10 |

> **Note:** The repo pins `stable-x86_64-pc-windows-msvc` via `src-tauri/rust-toolchain.toml`.
> GNU/MinGW toolchains are not supported for Tauri on Windows.

## Quick dev launch

Double-click **`ARGUS-Desktop.bat`** or:

```powershell
cd argus-forensics
cargo tauri dev
```

This starts the Python sidecar and opens a native WebView2 window at the workbench URL.

## Bundle embedded Python (production)

```powershell
.\scripts\bundle-python.ps1
```

Creates `src-tauri/resources/`:

```
resources/
  python/python.exe          # embeddable CPython 3.12
  python/Lib/site-packages/argus/
  argus_app.py
```

Optional office/EXIF/crypto deps:

```powershell
.\scripts\bundle-python.ps1 -WithOptionalDeps
```

## Production installer

```powershell
.\scripts\build-desktop.ps1
```

Output:

- `src-tauri/target/release/bundle/msi/*.msi`
- `src-tauri/target/release/bundle/nsis/*.exe`

Skip re-bundling Python during iterative Rust work:

```powershell
.\scripts\build-desktop.ps1 -SkipPythonBundle
```

## Architecture

```
ARGUS Forensics.exe  (Tauri / Rust)
  ├── System tray + single-instance focus
  ├── WebView2 → http://127.0.0.1:<port>/#token=...
  └── Python sidecar (argus_app.py --ready-json)
        └── 50+ /api/* routes, all acquisition/analysis intact
```

Full requirements: [PRD-TAURI-DESKTOP.md](./PRD-TAURI-DESKTOP.md)

## Icons

```powershell
python tools/make_icon.py
# or from a logo PNG:
cargo tauri icon path/to/logo.png
```

## Tests

```powershell
python -m unittest tests.test_desktop_sidecar -v
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `link.exe` not found | Install VS Build Tools with C++ workload; restart terminal |
| `dlltool.exe` not found | You are on GNU toolchain — run `rustup default stable-x86_64-pc-windows-msvc` |
| Sidecar timeout | Run `python argus_app.py --ready-json --no-browser` manually |
| Blank window | Confirm WebView2 runtime; check sidecar printed `{"event":"ready",...}` |
| Close button hides app | By design — use tray **Quit** to exit; **Show ARGUS** to restore |
