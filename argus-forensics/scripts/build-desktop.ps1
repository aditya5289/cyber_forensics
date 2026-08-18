#Requires -Version 5.1
<#
.SYNOPSIS
  Build ARGUS Forensics Windows desktop installer (Tauri + embedded Python).
#>
param(
    [switch]$SkipPythonBundle,
    [switch]$SkipTests,
    [string]$PythonVersion = "3.12.7"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path

Write-Host "==> ARGUS Forensics desktop build" -ForegroundColor Cyan

foreach ($cmd in @("cargo", "python")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "$cmd not found on PATH. Install Rust (rustup) and Python 3.10+ first."
    }
}

if (-not (Get-Command "cargo-tauri" -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing tauri-cli..." -ForegroundColor Yellow
    cargo install tauri-cli --version "^2.0" --locked
}

# --- Icon ---
$Icon = Join-Path $Root "src-tauri\icons\icon.ico"
if (-not (Test-Path $Icon)) {
    Write-Host "==> Generating application icon..." -ForegroundColor Cyan
    python (Join-Path $Root "tools\make_icon.py")
}

# --- Bundle Python ---
if (-not $SkipPythonBundle) {
    & (Join-Path $Root "scripts\bundle-python.ps1") -PythonVersion $PythonVersion
}

# --- Tests ---
if (-not $SkipTests) {
    Write-Host "==> Running Python acceptance tests..." -ForegroundColor Cyan
    python -m pytest tests/test_progress.py tests/test_batch.py tests/test_mtp.py -q
    if ($LASTEXITCODE -ne 0) {
        throw "Python tests failed."
    }
}

# --- Tauri build (GNU toolchain — matches default rustup host) ---
Write-Host "==> cargo tauri build" -ForegroundColor Cyan
Set-Location (Join-Path $Root "src-tauri")
cargo tauri build

Write-Host ""
Write-Host "==> Done. Installers:" -ForegroundColor Green
Get-ChildItem "target\release\bundle" -Recurse -Include *.msi,*.exe -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "    $($_.FullName)" }
