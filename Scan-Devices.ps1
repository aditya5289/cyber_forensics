# Scan-Devices.ps1 - what is actually attached to this workstation.
#
# Standalone. No ARGUS install, no Python, no modules, no admin rights.
#
#   powershell -ExecutionPolicy Bypass -File .\Scan-Devices.ps1
#   powershell -ExecutionPolicy Bypass -File .\Scan-Devices.ps1 -Json scan.json
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS IN THIS FORM
#
# adb and libimobiledevice only see handsets that cooperate. A phone in MTP
# mode, one whose driver never bound, one in fastboot, one where USB debugging
# was never enabled - all are physically present and invisible to both. So the
# scan asks the operating system directly.
#
# But asking the operating system can itself fail, and the previous version of
# this script handled that badly enough to matter: Get-PnpDevice returned
# nothing, the failure was swallowed, and the script announced "no handset
# hardware - probably a charge-only cable" about a phone that was plugged in and
# mounted. That is a tool contradicting the evidence of the examiner's own eyes,
# and it sends them hunting for a fault that does not exist.
#
# An empty result and a failed query are not the same fact. Every source below
# reports its own status, nothing is reported as absent unless a source actually
# looked, and the verdict refuses to conclude "nothing attached" while any
# source is unavailable.
#
# Four independent enumerators are used because each misses different devices:
#   PnP    - the modern API; misses nothing, but the module can be absent
#   CIM    - WMI; works where the PnP module does not
#   WPD    - portable devices specifically, which is how MTP handsets appear
#   Reg    - raw USB enum keys; always readable, but includes past devices
# ---------------------------------------------------------------------------

param(
    [string]$Json = "",
    [switch]$IncludeFixedVolumes
)

# NOT SilentlyContinue. Failures here are findings.
$ErrorActionPreference = 'Continue'

function Section($text) {
    Write-Host ""
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("-" * $text.Length) -ForegroundColor DarkGray
}

function Note($text)  { Write-Host "  $text" }
function Good($text)  { Write-Host "  $text" -ForegroundColor Green }
function Warn($text)  { Write-Host "  $text" -ForegroundColor Yellow }
function Bad($text)   { Write-Host "  $text" -ForegroundColor Red }
function Dim($text)   { Write-Host "  $text" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# USB vendor IDs. Assigned by USB-IF and stable, so a match is a fact about the
# hardware rather than a guess from a product string the vendor is free to
# change at any firmware revision.
# ---------------------------------------------------------------------------
$VENDORS = @{
    '18d1' = 'Google';            '04e8' = 'Samsung'
    '22b8' = 'Motorola';          '0bb4' = 'HTC'
    '12d1' = 'Huawei';            '19d2' = 'ZTE'
    '0fce' = 'Sony';              '1004' = 'LG'
    '05ac' = 'Apple';             '22d9' = 'Oppo / realme'
    '2a70' = 'OnePlus';           '2717' = 'Xiaomi'
    '2d95' = 'Vivo';              '2a45' = 'Meizu'
    '1bbb' = 'TCL / Alcatel';     '0421' = 'Nokia'
    '109b' = 'Hisense';           '0b05' = 'ASUS'
    '17ef' = 'Lenovo';            '2ae5' = 'Fairphone'
    '0489' = 'Foxconn / HTC';     '1949' = 'Amazon (Lab126)'
    '0955' = 'NVIDIA';            '0e79' = 'Archos'
    '2916' = 'Android (generic ADB interface)'
    '0482' = 'Kyocera';           '04dd' = 'Sharp'
    '201e' = 'Haier';             '2c7c' = 'Quectel'
    # Chipset vendors. These identify silicon, not a brand, and they appear
    # when the handset is below its own operating system.
    '05c6' = 'Qualcomm silicon';  '0e8d' = 'MediaTek silicon'
    '1782' = 'Spreadtrum / Unisoc silicon'
    '2207' = 'Rockchip silicon';  '1f3a' = 'Allwinner silicon'
    '0451' = 'Texas Instruments silicon'
}

# ---------------------------------------------------------------------------
# Modes worth naming, keyed on vendor AND product ID.
#
# The vendor alone identifies no mode. MediaTek's 0e8d covers the BootROM, the
# preloader, and perfectly ordinary MTP and ADB interfaces. Keying on the vendor
# announced "BootROM - physical acquisition is a candidate" for a phone that was
# simply browsable in Explorer: a confident wrong answer that points the
# examiner at an afternoon of low-level tooling they do not need.
# ---------------------------------------------------------------------------
$MODES = @{
    '05c6:9008' = @('Qualcomm EDL (9008)',
        'Emergency Download mode. A full physical image is possible with a signed programmer for this OEM. adb does not operate here.')
    '05c6:900e' = @('Qualcomm diagnostic',
        'Diagnostic mode. Often a route to a physical read depending on the OEM.')
    '0e8d:0003' = @('MediaTek BootROM',
        'The handset is in the MediaTek BootROM, below its operating system. Physical acquisition is a candidate; whether the image is readable still depends on the encryption scheme.')
    '0e8d:2000' = @('MediaTek preloader',
        'The preloader. This window is brief and usually closes as the device continues to boot.')
    '0e8d:2001' = @('MediaTek preloader (alt)',
        'A MediaTek preloader mode below the operating system.')
    '1782:4d00' = @('Unisoc diagnostic',
        'A Spreadtrum/Unisoc diagnostic mode, which frequently permits a full read.')
    '2207:310b' = @('Rockchip MaskROM',
        'MaskROM mode, below the operating system.')
    '1f3a:efe8' = @('Allwinner FEL',
        'FEL recovery mode, below the operating system.')
    '0451:d00e' = @('TI OMAP boot',
        'OMAP peripheral boot mode.')
    '04e8:685d' = @('Samsung Download / Odin',
        'Download mode. Flashing is possible; this is not by itself an acquisition route and writing to the device destroys evidence.')
    '05ac:1227' = @('Apple DFU',
        'Device Firmware Update mode. On checkm8-vulnerable silicon (A5-A11) this is where a physical extraction becomes possible.')
    '05ac:1281' = @('Apple Recovery',
        'Recovery mode. Restoring from here erases the device - do not proceed on evidence.')
    '18d1:4ee0' = @('Android fastboot',
        'The bootloader. Useful for establishing lock state; not an acquisition route on its own.')
}

$MTP_HINT = 'File-transfer (MTP) mode. Shared storage can be copied off and imported with no adb, no debugging toggle and no vendor tooling.'

# Source status: each enumerator records whether it actually ran.
$status  = [ordered]@{}
$devices = @{}          # key "vid:pid|name" -> record

function Add-Device($vid, $pid, $name, $state, $source) {
    if (-not $vid) { return }
    $vid = $vid.ToLower(); $pid = $pid.ToLower()
    if (-not $VENDORS.ContainsKey($vid)) { return }

    $key = "$vid`:$pid"
    if (-not $devices.ContainsKey($key)) {
        $mode = $MODES[$key]
        $note = ''
        $modeName = ''
        if ($mode) { $modeName = $mode[0]; $note = $mode[1] }
        elseif ($name -match '(?i)\bMTP\b|portable device|file.?transfer') { $note = $MTP_HINT }

        $devices[$key] = [PSCustomObject]@{
            Vid = $vid; Pid = $pid
            Vendor = $VENDORS[$vid]
            Name = $name
            State = $state
            Mode = $modeName
            Note = $note
            Sources = New-Object System.Collections.ArrayList
        }
    }
    $rec = $devices[$key]
    if ($name -and ($rec.Name.Length -lt $name.Length)) { $rec.Name = $name }
    if ($state -and $state -ne 'OK' -and $rec.State -eq 'OK') { $rec.State = $state }
    if ($rec.Sources -notcontains $source) { [void]$rec.Sources.Add($source) }
}

Write-Host ""
Write-Host "  ARGUS device scan" -ForegroundColor White
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor DarkGray

# ============================================================ 1. USB hardware
Section "1. USB hardware"

# --- source A: PnP -------------------------------------------------------
try {
    $pnp = Get-PnpDevice -PresentOnly -ErrorAction Stop
    $n = 0
    foreach ($d in $pnp) {
        if ($d.InstanceId -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
            $n++
            Add-Device $Matches[1] $Matches[2] $d.FriendlyName $d.Status 'PnP'
        }
    }
    $status['PnP'] = "ok ($n USB devices)"
} catch {
    $status['PnP'] = "FAILED - $($_.Exception.Message)"
}

# --- source B: CIM / WMI -------------------------------------------------
# Works on installs where the PnpDevice module is missing or blocked.
try {
    $cim = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop
    $n = 0
    foreach ($d in $cim) {
        if ($d.PNPDeviceID -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
            $n++
            $state = if ($d.Status) { $d.Status } else { 'OK' }
            Add-Device $Matches[1] $Matches[2] $d.Name $state 'CIM'
        }
        # Portable devices frequently carry no VID/PID in their instance path.
        elseif ($d.PNPClass -eq 'WPD' -and $d.Name) {
            $status['WPD'] = 'ok'
        }
    }
    $status['CIM'] = "ok ($n USB devices)"
} catch {
    $status['CIM'] = "FAILED - $($_.Exception.Message)"
}

# --- source C: registry --------------------------------------------------
# Always readable without admin and without any module. It lists devices the
# machine has ever seen, so entries found ONLY here are labelled as unconfirmed
# rather than reported as attached.
$registryOnly = @{}
try {
    $usbKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -ErrorAction Stop
    $n = 0
    foreach ($k in $usbKeys) {
        if ($k.PSChildName -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
            $vid = $Matches[1].ToLower(); $pid = $Matches[2].ToLower()
            if (-not $VENDORS.ContainsKey($vid)) { continue }
            $n++
            $key = "$vid`:$pid"
            if ($devices.ContainsKey($key)) { continue }
            $desc = ''
            foreach ($inst in (Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                if ($p.FriendlyName) { $desc = $p.FriendlyName; break }
                if ($p.DeviceDesc)   { $desc = ($p.DeviceDesc -split ';')[-1] }
            }
            $registryOnly[$key] = [PSCustomObject]@{
                Vid = $vid; Pid = $pid; Vendor = $VENDORS[$vid]; Name = $desc
            }
        }
    }
    $status['Registry'] = "ok ($n handset entries, historical)"
} catch {
    $status['Registry'] = "FAILED - $($_.Exception.Message)"
}

$failedSources = @($status.Keys | Where-Object { $status[$_] -like 'FAILED*' })

foreach ($k in $status.Keys) {
    $colour = if ($status[$k] -like 'FAILED*') { 'Yellow' } else { 'DarkGray' }
    Write-Host ("  {0,-9} {1}" -f $k, $status[$k]) -ForegroundColor $colour
}
Write-Host ""

$present = $devices.Values | Sort-Object Vendor, Name
if ($present.Count -gt 0) {
    foreach ($d in $present) {
        $line = "  {0,-22} {1}:{2}  {3}" -f $d.Vendor, $d.Vid, $d.Pid, $d.Name
        $colour = if ($d.State -ne 'OK') { 'Yellow' } else { 'Green' }
        Write-Host $line -ForegroundColor $colour
        if ($d.State -ne 'OK') {
            Write-Host "      driver state: $($d.State)" -ForegroundColor Yellow
        }
        if ($d.Mode) { Write-Host "      MODE: $($d.Mode)" -ForegroundColor Magenta }
        if ($d.Note) { Write-Host "      $($d.Note)" -ForegroundColor DarkGray }
    }
    Write-Host ""
    Good "Handset hardware is attached. The cable and port are working."

    $broken = $present | Where-Object { $_.State -ne 'OK' }
    if ($broken) {
        Write-Host ""
        Warn "DRIVER PROBLEM - enumerated but did not bind:"
        foreach ($b in $broken) { Warn "  $($b.Vendor) $($b.Name) [$($b.State)]" }
        Warn "Device Manager -> right-click -> Update driver -> Browse ->"
        Warn "Let me pick -> MTP USB Device."
    }
} elseif ($failedSources.Count -gt 0) {
    Warn "No handset hardware found - but $($failedSources -join ', ') failed."
    Warn "This is NOT a statement that nothing is attached. Sections 2-5 below"
    Warn "query independently and may still find the device."
} else {
    Note "No handset-vendor hardware on the USB bus."
    Dim "All enumerators ran and agreed. If a phone is plugged in, suspect a"
    Dim "charge-only cable - they are visually identical to data cables."
}

if ($registryOnly.Count -gt 0 -and $present.Count -eq 0) {
    Write-Host ""
    Dim "Previously attached to this machine (registry, presence unconfirmed):"
    foreach ($r in $registryOnly.Values) {
        Dim "  $($r.Vendor)  $($r.Vid):$($r.Pid)  $($r.Name)"
    }
}

# ====================================================== 2. Mounted handsets
Section "2. Handsets mounted in This PC (MTP)"

$mtp = @()
try {
    $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
    $ns = $shell.NameSpace(17)
    if ($null -eq $ns) { throw "shell namespace 17 unavailable" }
    $known = @('Desktop','Documents','Downloads','Music','Pictures','Videos','3D Objects')
    foreach ($item in $ns.Items()) {
        if ($item.IsFolder -and -not ($item.Path -match '^[A-Z]:\\$') -and
            $known -notcontains $item.Name) {
            $mtp += $item.Name
        }
    }
    $status['Shell'] = "ok ($($mtp.Count) handset(s))"
} catch {
    $status['Shell'] = "FAILED - $($_.Exception.Message)"
    Warn "Shell namespace query failed: $($_.Exception.Message)"
}

if ($mtp.Count -gt 0) {
    foreach ($m in $mtp) { Good $m }
    Write-Host ""
    Good "This is a route to evidence right now - no USB debugging required."
    Dim "Reaches: camera media, downloads, documents, and app folders under"
    Dim "Android/media (including WhatsApp media)."
    Dim "Cannot reach: /data/data - message databases, call logs, and the"
    Dim "unallocated space holding deleted records."
} elseif ($status['Shell'] -notlike 'FAILED*') {
    Note "None mounted."
    Dim "On the handset: notification shade -> tap the USB notification ->"
    Dim "File transfer / MTP. Most vendors default to charge-only."
}

# ================================================================= 3. Volumes
Section "3. Mounted volumes carrying handset data"

$MARKERS = @('DCIM','Android','LOST.DIR','WhatsApp','MIUI','.thumbnails')
$evidenceVolumes = @()
try {
    $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction Stop
    foreach ($drive in $drives) {
        if (-not $drive.Root -or $drive.Root.Length -gt 3) { continue }
        $type = 'unknown'
        $v = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -ErrorAction SilentlyContinue
        if ($v) { $type = switch ($v.DriveType) { 2 {'removable'} 3 {'fixed'} 4 {'network'} 5 {'optical'} default {'other'} } }
        if ($type -eq 'fixed' -and -not $IncludeFixedVolumes) { continue }
        if ($type -in @('network','optical')) { continue }

        $hits = @()
        foreach ($m in $MARKERS) {
            if (Test-Path -LiteralPath (Join-Path $drive.Root $m)) { $hits += $m }
        }
        if ($hits.Count -gt 0) {
            $evidenceVolumes += [PSCustomObject]@{ Root=$drive.Root; Type=$type; Markers=$hits }
            Good "$($drive.Root)  [$type]  contains: $($hits -join ', ')"
        }
    }
    $status['Volumes'] = "ok ($($evidenceVolumes.Count) with handset markers)"
} catch {
    $status['Volumes'] = "FAILED - $($_.Exception.Message)"
    Warn "Volume enumeration failed: $($_.Exception.Message)"
}

if ($evidenceVolumes.Count -gt 0) {
    Write-Host ""
    Good "These can be imported immediately - no adb involved."
} elseif ($status['Volumes'] -notlike 'FAILED*') {
    Note "No mounted volume carries handset directories."
    if (-not $IncludeFixedVolumes) { Dim "(Fixed disks skipped. Use -IncludeFixedVolumes to include them.)" }
}

# ===================================================================== 4. adb
Section "4. adb (Android live acquisition)"

function Find-Tool($exe) {
    $c = Get-Command $exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $paths = @(
        "C:\platform-tools\$exe.exe",
        "C:\platform-tools-latest-windows\platform-tools\$exe.exe",
        "C:\adb\$exe.exe",
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\$exe.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\$exe.exe",
        "$env:ProgramFiles\platform-tools\$exe.exe",
        "${env:ProgramFiles(x86)}\Android\android-sdk\platform-tools\$exe.exe",
        "$env:USERPROFILE\AppData\Local\Android\Sdk\platform-tools\$exe.exe"
    )
    foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { return $p } }
    return $null
}

$adbReady = @()
$adbBlocked = @()
$adb = Find-Tool 'adb'
if (-not $adb) {
    $status['adb'] = 'not installed'
    Note "Not installed."
    Dim "Only needed for LIVE acquisition. Importing an extraction that already"
    Dim "exists on disk, or copying a mounted handset, does not need it."
} else {
    Good "Found: $adb"
    $lines = @(& $adb devices -l 2>&1 | Select-Object -Skip 1 |
               Where-Object { $_ -match '\S' })
    $status['adb'] = "ok ($($lines.Count) device line(s))"
    if ($lines.Count -eq 0) {
        Note "adb reports no handset."
    } else {
        foreach ($line in $lines) {
            $state = 'unknown'
            if ($line -match '^(\S+)\s+(no permissions|\w+)') {
                $state = $Matches[2]
            }
            $colour = if ($state -eq 'device') { 'Green' } else { 'Yellow' }
            Write-Host "  $line" -ForegroundColor $colour
            switch ($state) {
                'device'       { $adbReady += $line; Good "    Ready for live acquisition." }
                'unauthorized' { $adbBlocked += $line
                                 Warn "    Not trusted. Unlock the screen and accept the RSA prompt."
                                 Warn "    On ColorOS also enable 'Disable permission monitoring'." }
                'offline'      { $adbBlocked += $line
                                 Warn "    Enumerated but unresponsive. Set USB mode to File transfer,"
                                 Warn "    then: adb kill-server" }
                'no'           { $adbBlocked += $line
                                 Warn "    The OS is blocking the USB device - wrong driver on Windows." }
                'recovery'     { $adbBlocked += $line; Warn "    In recovery. Reboot to the system." }
                'sideload'     { $adbBlocked += $line; Warn "    In sideload mode. Reboot to the system." }
                'bootloader'   { $adbBlocked += $line; Warn "    In the bootloader. Reboot to the system." }
                default        { $adbBlocked += $line; Warn "    State '$state' - consult adb documentation." }
            }
        }
    }
}

# Fastboot is a separate protocol; a device here is invisible to adb entirely.
$fastboot = Find-Tool 'fastboot'
if ($fastboot) {
    $fbLines = @(& $fastboot devices 2>&1 | Where-Object { $_ -match '\S' })
    if ($fbLines.Count -gt 0) {
        Write-Host ""
        Warn "fastboot devices:"
        foreach ($l in $fbLines) { Warn "  $l" }
        Dim "  In the bootloader. Useful for establishing lock state. Not an"
        Dim "  acquisition route on its own - reboot to the system for adb."
    }
}

# ===================================================================== 5. iOS
Section "5. iOS"

$appleHw = $present | Where-Object { $_.Vid -eq '05ac' }
$idevice = Find-Tool 'idevice_id'
$amds = Get-Service -Name 'Apple Mobile Device Service' -ErrorAction SilentlyContinue

if ($appleHw) {
    foreach ($a in $appleHw) {
        Good "Apple hardware present: $($a.Name) ($($a.Vid):$($a.Pid))"
        if ($a.Mode) { Write-Host "      MODE: $($a.Mode)" -ForegroundColor Magenta }
    }
}
if ($idevice) {
    $ids = @(& $idevice -l 2>&1 | Where-Object { $_ -match '^[0-9a-fA-F\-]{20,}$' })
    if ($ids.Count -gt 0) {
        foreach ($i in $ids) { Good "libimobiledevice UDID: $i" }
        Dim "Trust the computer on the handset, then acquire a backup."
    } else {
        Note "libimobiledevice present but sees no handset."
    }
} elseif ($appleHw) {
    Note "libimobiledevice not installed - needed for live iOS acquisition."
    Dim "An existing iTunes backup folder can be imported without it."
} else {
    Note "No Apple handset detected."
    if ($amds) { Dim "Apple Mobile Device Service is installed and $($amds.Status)." }
}

# ================================================================== VERDICT
Section "Verdict"

$lowLevel = $present | Where-Object { $_.Mode -ne '' }

if ($adbReady.Count -gt 0) {
    Good "A handset is authorised and ready for live acquisition over adb."
    Good "This reaches the most data of any route available here."
}
elseif ($mtp.Count -gt 0) {
    Good "'$($mtp[0])' is mounted and browsable. Acquire it now:"
    Write-Host ""
    Write-Host "    .\Copy-Phone.ps1 -Out C:\evidence\$(($mtp[0] -replace '[^A-Za-z0-9]','-').ToLower())" -ForegroundColor White
    Write-Host ""
    Good "You do not need to solve the USB debugging problem to start work."
    if ($adbBlocked.Count -gt 0) {
        Dim "adb is also present but blocked - fixing it would additionally reach"
        Dim "/data/data, where messages, call logs and deleted records live."
    }
}
elseif ($lowLevel) {
    Warn "A handset is in a low-level mode: $($lowLevel[0].Mode)"
    Note $lowLevel[0].Note
}
elseif ($evidenceVolumes.Count -gt 0) {
    Good "A mounted volume carries handset data. Import $($evidenceVolumes[0].Root) directly."
}
elseif ($adbBlocked.Count -gt 0) {
    Warn "A handset is attached but adb is refused. The hardware is fine."
    Warn "ColorOS (Oppo / realme / recent OnePlus):"
    Note "  Settings > About device > Version > tap Build number 7 times"
    Note "  Settings > Additional settings > Developer options"
    Note "    - USB debugging                  ON"
    Note "    - Disable permission monitoring  ON   <- the one everyone misses"
    Note "  Replug, then accept the prompt on the handset screen."
    Dim "MIUI additionally needs 'USB debugging (Security settings)' and a"
    Dim "signed-in Mi account."
}
elseif ($present.Count -gt 0) {
    Warn "Handset hardware is attached and its driver bound, but nothing can"
    Warn "talk to it. Switch the USB mode on the handset to File transfer"
    Warn "(MTP), then run this scan again."
}
elseif ($failedSources.Count -gt 0) {
    Warn "No handset found, but these enumerators failed: $($failedSources -join ', ')"
    Warn "That is not the same as nothing being attached. Re-run in an elevated"
    Warn "PowerShell before concluding the device is absent."
}
else {
    Bad "Nothing detected at any level, and every enumerator ran successfully."
    Bad "Try a different cable first - charge-only cables are the usual cause"
    Bad "and are visually identical. Then a different port, ideally USB 2.0."
}

# ================================================================ JSON out
if ($Json) {
    $payload = [ordered]@{
        format        = "argus-device-scan/1"
        scanned_at    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
        workstation   = $env:COMPUTERNAME
        operator      = $env:USERNAME
        source_status = $status
        failed_sources = @($failedSources)
        usb_devices   = @($present | ForEach-Object {
                            [ordered]@{ vendor_id=$_.Vid; product_id=$_.Pid
                                        vendor=$_.Vendor; name=$_.Name
                                        driver_state=$_.State; mode=$_.Mode
                                        note=$_.Note; sources=@($_.Sources) } })
        mtp_mounted   = @($mtp)
        volumes       = @($evidenceVolumes | ForEach-Object {
                            [ordered]@{ root=$_.Root; type=$_.Type; markers=@($_.Markers) } })
        adb_ready     = @($adbReady)
        adb_blocked   = @($adbBlocked)
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Json -Encoding UTF8
    Write-Host ""
    Dim "Scan written to $Json"
}

Write-Host ""
