@echo off
REM ARGUS Forensics — native desktop window (Tauri + Python sidecar)
setlocal
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

cd /d "%~dp0src-tauri"
where cargo >nul 2>&1 || (
  echo Rust is not installed. Install from https://rustup.rs/ then run:
  echo   rustup default stable-x86_64-pc-windows-msvc
  pause
  exit /b 1
)

where cargo-tauri >nul 2>&1 || (
  echo Installing Tauri CLI...
  cargo install tauri-cli --version "^2.0" --locked
)

cd ..
cargo tauri dev --manifest-path src-tauri\Cargo.toml
endlocal
