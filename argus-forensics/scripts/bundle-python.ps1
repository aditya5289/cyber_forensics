#Requires -Version 5.1
<#
.SYNOPSIS
  Download and stage embeddable CPython + ARGUS package for Tauri bundling.

.DESCRIPTION
  Produces src-tauri/resources/ with:
    python/python.exe          (embeddable CPython)
    python/python312._pth      (configured for site-packages)
    python/Lib/site-packages/  (argus package + optional deps)
    argus_app.py

.EXAMPLE
  .\scripts\bundle-python.ps1
  .\scripts\bundle-python.ps1 -PythonVersion 3.12.7 -WithOptionalDeps
#>
param(
    [string]$PythonVersion = "3.12.7",
    [switch]$WithOptionalDeps,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ResDir = Join-Path $Root "src-tauri\resources"
$PyDir = Join-Path $ResDir "python"
$Site = Join-Path $PyDir "Lib\site-packages"
$Cache = Join-Path $Root ".cache\python-embed"

$MajorMinor = ($PythonVersion -split '\.')[0..1] -join '.'
$ZipName = "python-$PythonVersion-embed-amd64.zip"
$Url = "https://www.python.org/ftp/python/$PythonVersion/$ZipName"

function Write-Step($msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

Write-Step "ARGUS Python bundle → $ResDir"

if ((Test-Path $PyDir) -and -not $Force) {
    $existing = Join-Path $PyDir "python.exe"
    if (Test-Path $existing) {
        Write-Host "    Embed already present ($PyDir). Use -Force to rebuild." -ForegroundColor DarkGray
    }
}

New-Item -ItemType Directory -Force -Path $Cache, $ResDir, $Site | Out-Null

# --- Download embeddable CPython ---
$ZipPath = Join-Path $Cache $ZipName
if (-not (Test-Path $ZipPath) -or $Force) {
    Write-Step "Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
}

if (Test-Path $PyDir) { Remove-Item $PyDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $PyDir | Out-Null
Expand-Archive -Path $ZipPath -DestinationPath $PyDir -Force

# --- Enable site-packages in embeddable distro ---
$PthFile = Get-ChildItem $PyDir -Filter "python*._pth" | Select-Object -First 1
if ($PthFile) {
    $pth = Get-Content $PthFile.FullName
    $pth = $pth | ForEach-Object { $_ -replace '^#import site', 'import site' }
    if ($pth -notcontains 'import site') {
        $pth += 'import site'
    }
    if ($pth -notcontains 'Lib\site-packages') {
        $pth += 'Lib\site-packages'
    }
    if ($pth -notcontains '..') {
        $pth += '..'
    }
    Set-Content -Path $PthFile.FullName -Value $pth -Encoding ASCII
    Write-Host "    Configured $($PthFile.Name) for site-packages"
}

# --- pip bootstrap ---
$GetPip = Join-Path $Cache "get-pip.py"
if (-not (Test-Path $GetPip)) {
    Write-Step "Downloading get-pip.py"
    Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $GetPip -UseBasicParsing
}

$PythonExe = Join-Path $PyDir "python.exe"
& $PythonExe $GetPip --no-warn-script-location 2>&1 | Out-Null

# --- Copy ARGUS package into site-packages (no wheel build needed) ---
Write-Step "Copying argus package into embeddable site-packages"
$DestArgus = Join-Path $Site "argus"
if (Test-Path $DestArgus) { Remove-Item $DestArgus -Recurse -Force }
Copy-Item (Join-Path $Root "argus") $DestArgus -Recurse -Force

# Optional third-party deps (report formats, EXIF, crypto)
if ($WithOptionalDeps) {
    Write-Step "Installing optional dependencies"
    & $PythonExe -m pip install --no-warn-script-location --target $Site `
        "pillow>=10.0" "openpyxl>=3.1" "python-docx>=1.1" "reportlab>=4.0" "pycryptodome>=3.19"
}

# --- Stage sidecar launcher beside python/ ---
Copy-Item (Join-Path $Root "argus_app.py") $ResDir -Force

# --- Verify ---
Write-Step "Verifying embedded runtime"
$check = & $PythonExe -c "import argus; print(argus.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Embedded Python cannot import argus: $check"
}
Write-Host "    argus $check" -ForegroundColor Green

$readyTest = @"
import subprocess, json, sys, os
root = r'$ResDir'
proc = subprocess.Popen(
    [sys.executable, os.path.join(root, 'argus_app.py'),
     '--no-browser', '--quiet', '--ready-json', '--port', '0'],
    stdout=subprocess.PIPE, text=True, cwd=root)
line = proc.stdout.readline()
evt = json.loads(line)
assert evt['event'] == 'ready', evt
proc.terminate()
print('ready-json OK on port', evt['port'])
"@
& $PythonExe -c $readyTest
if ($LASTEXITCODE -ne 0) { throw "Sidecar ready-json verification failed" }

Write-Step "Done"
Write-Host "    Python:  $PythonExe"
Write-Host "    Sidecar: $(Join-Path $ResDir 'argus_app.py')"
Write-Host "    Next:    cargo tauri build" -ForegroundColor Yellow
