# Check-Phone.ps1 — why is my handset not being detected?
#
# Standalone. Needs no ARGUS install, no Python, no modules. Paste it, run it,
# and it will say what is actually attached and what is wrong.
#
#   powershell -ExecutionPolicy Bypass -File .\Check-Phone.ps1

$ErrorActionPreference = 'SilentlyContinue'

function Section($text) {
    Write-Host ""
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("-" * $text.Length) -ForegroundColor DarkGray
}

# USB vendor IDs are assigned by USB-IF and stable, so a match is a fact about
# the hardware rather than a guess from a product string.
$vendors = @{
    '22d9' = 'Oppo';        '2a70' = 'OnePlus';   '2717' = 'Xiaomi'
    '04e8' = 'Samsung';     '18d1' = 'Google';    '22b8' = 'Motorola'
    '12d1' = 'Huawei';      '0bb4' = 'HTC';       '19d2' = 'ZTE'
    '0fce' = 'Sony';        '1004' = 'LG';        '05ac' = 'Apple'
    '2d95' = 'Vivo';        '1782' = 'Unisoc';    '2916' = 'Android ADB'
    '05c6' = 'Qualcomm';    '0e8d' = 'MediaTek'
}

Write-Host ""
Write-Host "  ARGUS handset connection check" -ForegroundColor White
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────── 1. USB hardware
Section "1. USB devices"

$found = @()
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB*' } |
  ForEach-Object {
    if ($_.InstanceId -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
        $vid = $Matches[1].ToLower()
        $pid = $Matches[2].ToLower()
        if ($vendors.ContainsKey($vid)) {
            $found += [PSCustomObject]@{
                Vendor = $vendors[$vid]
                VID    = $vid
                PID    = $pid
                Name   = $_.FriendlyName
                Status = $_.Status
            }
        }
    }
  }

if ($found.Count -gt 0) {
    $found | Sort-Object Vendor -Unique | Format-Table -AutoSize
    Write-Host "  Handset hardware IS attached. The cable and port work." -ForegroundColor Green

    # A device that enumerated but whose driver did not bind is the single most
    # common cause of "the phone is plugged in and nothing sees it".
    $broken = $found | Where-Object { $_.Status -ne 'OK' }
    if ($broken) {
        Write-Host ""
        Write-Host "  DRIVER PROBLEM — these enumerated but did not bind:" -ForegroundColor Yellow
        $broken | Format-Table Vendor, Name, Status -AutoSize
        Write-Host "  Fix in Device Manager: right-click the flagged device," -ForegroundColor Yellow
        Write-Host "  Update driver, Browse, Let me pick, MTP USB Device." -ForegroundColor Yellow
    }
} else {
    Write-Host "  No handset-vendor hardware on the bus." -ForegroundColor Red
    Write-Host "  Most likely a charge-only cable — they look identical to data"
    Write-Host "  cables and are the usual culprit. Try a different cable first."
}

# ───────────────────────────────────────────── 2. Mounted (MTP) handsets
Section "2. Handsets mounted in This PC (file-transfer mode)"

$shell = New-Object -ComObject Shell.Application
$mtp = @()
$known = @('Desktop','Documents','Downloads','Music','Pictures','Videos','3D Objects')
foreach ($item in $shell.NameSpace(17).Items()) {
    if ($item.IsFolder -and -not ($item.Path -match '^[A-Z]:\\$') -and
        $known -notcontains $item.Name) {
        $mtp += $item.Name
    }
}

if ($mtp.Count -gt 0) {
    $mtp | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
    Write-Host ""
    Write-Host "  This is a route to evidence RIGHT NOW — no USB debugging needed." -ForegroundColor Green
    Write-Host "  Open This PC -> the handset -> Internal shared storage, and copy"
    Write-Host "  it to a local folder. That reaches photos, video, downloads and"
    Write-Host "  app media under Android/media. It cannot reach /data/data."
} else {
    Write-Host "  None mounted." -ForegroundColor Yellow
    Write-Host "  On the handset: pull down the notification shade, tap the USB"
    Write-Host "  notification, and choose File transfer / MTP. Most vendors"
    Write-Host "  default to charge-only, which exposes nothing."
}

# ──────────────────────────────────────────────────────────── 3. adb
Section "3. adb"

$adbPaths = @(
    'adb',
    'C:\platform-tools\adb.exe',
    'C:\platform-tools-latest-windows\platform-tools\adb.exe',
    "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Links\adb.exe"
)
$adb = $null
foreach ($candidate in $adbPaths) {
    $resolved = (Get-Command $candidate -ErrorAction SilentlyContinue)
    if ($resolved) { $adb = $resolved.Source; break }
    if (Test-Path $candidate) { $adb = $candidate; break }
}

if (-not $adb) {
    Write-Host "  Not installed." -ForegroundColor Yellow
    Write-Host "  Only needed for live acquisition. Importing an extraction that"
    Write-Host "  already exists on disk does not need it."
} else {
    Write-Host "  Found: $adb" -ForegroundColor Green
    $devices = & $adb devices -l 2>&1 | Select-Object -Skip 1 |
               Where-Object { $_ -match '\S' }
    if (-not $devices) {
        Write-Host "  adb sees no handset." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  If section 1 or 2 found your phone, the hardware is fine and"
        Write-Host "  this is USB debugging. On ColorOS (Oppo/realme):" -ForegroundColor White
        Write-Host "    Settings > About device > Version > tap Build number 7 times"
        Write-Host "    Settings > Additional settings > Developer options"
        Write-Host "      - USB debugging                ON"
        Write-Host "      - Disable permission monitoring ON   <- the one everyone misses"
        Write-Host "    Then replug and accept the prompt on the screen."
    } else {
        foreach ($line in $devices) {
            $state = 'unknown'
            if ($line -match '^\S+\s+(no permissions|\w+)') { $state = $Matches[1] }
            $colour = if ($state -eq 'device') { 'Green' } else { 'Yellow' }
            Write-Host "  $line" -ForegroundColor $colour
            switch ($state) {
                'device'       { Write-Host "    Ready." -ForegroundColor Green }
                'unauthorized' { Write-Host "    Unlock the screen and accept the USB debugging prompt." -ForegroundColor Yellow
                                 Write-Host "    On ColorOS also enable 'Disable permission monitoring'." -ForegroundColor Yellow }
                'offline'      { Write-Host "    Set USB mode to File transfer, then: adb kill-server" -ForegroundColor Yellow }
                'recovery'     { Write-Host "    In recovery. Reboot to the system." -ForegroundColor Yellow }
                default        { Write-Host "    State '$state' - see adb documentation." -ForegroundColor Yellow }
            }
        }
    }
}

# ──────────────────────────────────────────────────────────── verdict
Section "What to do next"

if ($mtp.Count -gt 0) {
    Write-Host "  Your handset is browsable. Copy its Internal shared storage to a" -ForegroundColor Green
    Write-Host "  local folder and import that folder. You do not need to solve the" -ForegroundColor Green
    Write-Host "  USB debugging problem to start work." -ForegroundColor Green
} elseif ($found.Count -gt 0) {
    Write-Host "  The hardware is attached and working. Switch the USB mode on the" -ForegroundColor Yellow
    Write-Host "  handset to File transfer (MTP), then run this script again." -ForegroundColor Yellow
} else {
    Write-Host "  Nothing detected at any level. Try a different cable, then a" -ForegroundColor Red
    Write-Host "  different USB port - ideally USB 2.0 rather than 3.x." -ForegroundColor Red
}
Write-Host ""
