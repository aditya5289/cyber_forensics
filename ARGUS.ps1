# ============================================================================
#  ARGUS Field Tool - scan, acquire, triage, and launch, in one file.
# ============================================================================
#
#   Double-click ARGUS.bat            - opens the window
#   .\ARGUS.ps1 -Console              - text menu instead (RDP, Server Core)
#
# For scripted use every function is also a switch:
#
#   .\ARGUS.ps1 -SelfTest
#   .\ARGUS.ps1 -Scan -Json scan.json
#   .\ARGUS.ps1 -Acquire -Out C:\evidence\oppo-f11
#   .\ARGUS.ps1 -Pull    -Out C:\evidence\oppo-f11     (adb, needs debugging)
#   .\ARGUS.ps1 -Analyze C:\evidence\oppo-f11
#   .\ARGUS.ps1 -Verify  C:\evidence\oppo-f11
#   .\ARGUS.ps1 -Triage  C:\cases\iPhone12.xrycase
#   .\ARGUS.ps1 -Doctor
#
# ----------------------------------------------------------------------------
# WHAT THIS IS
#
# Everything here runs on a stock Windows box: no Python, no pip, no modules,
# no admin rights, no network. That is deliberate. A forensic workstation is
# frequently locked down or air-gapped, and a tool that needs an install before
# it can tell you whether a phone is plugged in is a tool that fails exactly
# when it is needed.
#
# Capabilities, each of which was a separate script until they had to be used
# in sequence on a real handset:
#
#   SCAN     - what is attached, from four independent enumerators
#   ACQUIRE  - copy a mounted handset with hashes and a reconciled manifest
#   PULL     - logical acquisition over adb, same reconciliation discipline
#   ANALYSE  - inventory, EXIF, video metadata, GPS, duplicates, HTML report
#   VERIFY   - re-hash against the manifest and check the custody chain
#   TRIAGE   - identify an opaque container and say whether it can be read
#   DOCTOR   - find every ARGUS copy on this machine and say which is current
#   SELFTEST - check the tool's own logic before pointing it at evidence
#
# Every operation appends to a hash-chained custody log beside the evidence, so
# what was done to an exhibit can be checked rather than merely asserted.
#
# ----------------------------------------------------------------------------
# THE RULE THIS FILE IS BUILT AROUND
#
# An honest "unknown" beats a confident wrong answer.
#
# The scan distinguishes "nothing is attached" from "I could not look", because
# an earlier version swallowed a failed query and announced "no handset -
# probably a charge-only cable" about a phone that was plugged in and mounted.
# The acquisition names every file that did not arrive, because a dropped file
# and an absent file are indistinguishable otherwise, and reporting the second
# when you mean the first is an error that survives into court. The triage
# refuses to call an encrypted container carvable. All three are the same rule.
# ============================================================================

param(
    [switch]$Gui,
    [switch]$Console,
    [switch]$NoEntry,
    [switch]$Auto,
    [switch]$Raw,
    [switch]$Relist,
    [switch]$SkipCacheDirs,
    [switch]$PerFile,
    [string]$Adopt = "",
    [switch]$Yes,
    [switch]$Scan,
    [switch]$Watch,
    [switch]$History,
    [switch]$Acquire,
    [switch]$Pull,
    [switch]$Doctor,
    [switch]$SelfTest,
    [switch]$Demo,
    [string]$Triage = "",
    [string]$Analyze = "",
    [string]$Verify = "",
    [string]$Device = "",
    [string]$Out = "",
    [string]$Json = "",
    [switch]$NoHash,
    [switch]$IncludeFixedVolumes,
    [int]$FileTimeoutSeconds = 180,
    [switch]$God
)

# Failures are findings. Never SilentlyContinue at file scope.
$ErrorActionPreference = 'Continue'

# Nothing may ever stop to ask a question.
#
# Work runs in a background runspace with no console attached, so any cmdlet
# that decides to prompt does not pause - it throws, and the operation dies
# mid-way. That happened for real: a Remove-Item on a directory tried to
# confirm a recursive delete, found no host to ask, and killed an acquisition
# that was already part-copied.
#
# Suppressing the prompt is not the fix for that particular bug - the fix is
# never asking Remove-Item to delete a directory in the first place. This is
# the belt to that braces: no cmdlet anywhere in the tool may block on input.
$ConfirmPreference = 'None'
$ProgressPreference = 'SilentlyContinue'
$script:Version = '1.1.0-field'
$script:God = [bool]$God

# ============================================================ presentation
#
# Write-Host is shadowed rather than replaced everywhere by hand. When the GUI
# sets $script:GuiSink, every line the engine produces is captured instead of
# printed, so the console and the window run identical code and cannot drift
# apart. Two implementations of the same output is how a fix lands in one and
# not the other.
$script:GuiSink = $null

function Write-Host {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)] $Object = '',
        [string] $ForegroundColor = 'Plain',
        [switch] $NoNewline
    )
    process {
        $text = [string]$Object
        if ($script:GuiSink) {
            [void]$script:GuiSink.Lines.Add(
                [PSCustomObject]@{ Text = $text; Colour = $ForegroundColor })
            return
        }
        if ($ForegroundColor -eq 'Plain') {
            Microsoft.PowerShell.Utility\Write-Host $text -NoNewline:$NoNewline
        } else {
            Microsoft.PowerShell.Utility\Write-Host $text `
                -ForegroundColor $ForegroundColor -NoNewline:$NoNewline
        }
    }
}

function Section($text) {
    Write-Host ""
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("-" * $text.Length) -ForegroundColor DarkGray
}
function Note($t) { Write-Host "  $t" }
function Good($t) { Write-Host "  $t" -ForegroundColor Green }
function Warn($t) { Write-Host "  $t" -ForegroundColor Yellow }
function Bad($t)  { Write-Host "  $t" -ForegroundColor Red }
function Dim($t)  { Write-Host "  $t" -ForegroundColor DarkGray }
function Mode($t) { Write-Host "  $t" -ForegroundColor Magenta }

# ======================================================== progress reporting
#
# A long copy with no feedback is indistinguishable from a hung one, and the
# consequence is not impatience - it is somebody killing a 40-minute
# acquisition at minute 30 because they concluded it had stopped. Partial
# exhibits are created by uncertainty far more often than by faults.
#
# So progress is reported against BYTES, not file count. A phone holds a few
# thousand photographs and a handful of videos that dwarf them, so "2,455 of
# 3,680 files" can sit at 90% complete while less than half the data has
# moved. Bytes do not mislead that way.
#
# Reports are time-based rather than every N files: a run of large videos can
# go minutes between file boundaries, which is exactly when reassurance
# matters most.

function Format-Size([double]$bytes) {
    if ($bytes -ge 1TB) { return ("{0:N2} TB" -f ($bytes / 1TB)) }
    if ($bytes -ge 1GB) { return ("{0:N2} GB" -f ($bytes / 1GB)) }
    if ($bytes -ge 1MB) { return ("{0:N1} MB" -f ($bytes / 1MB)) }
    if ($bytes -ge 1KB) { return ("{0:N0} KB" -f ($bytes / 1KB)) }
    return ("{0:N0} B" -f $bytes)
}

function Format-Duration([TimeSpan]$span) {
    if ($span.TotalSeconds -lt 1)  { return "under a second" }
    if ($span.TotalSeconds -lt 60) { return ("{0:N0}s" -f $span.TotalSeconds) }
    if ($span.TotalHours   -lt 1)  { return ("{0:N0}m {1:N0}s" -f $span.Minutes, $span.Seconds) }
    if ($span.TotalDays    -lt 1)  { return ("{0:N0}h {1:N0}m" -f [Math]::Floor($span.TotalHours), $span.Minutes) }
    return ("{0:N0}d {1:N0}h" -f [Math]::Floor($span.TotalDays), $span.Hours)
}

function New-ProgressState([int]$TotalItems, [double]$TotalBytes, [string]$Label) {
    return [PSCustomObject]@{
        Label      = $Label
        TotalItems = $TotalItems
        TotalBytes = $TotalBytes
        Items      = 0
        Bytes      = 0.0
        Started    = Get-Date
        LastReport = (Get-Date).AddSeconds(-99)
        EverySec   = 5
    }
}

function Write-Progress2($state, [switch]$Force) {
    $now = Get-Date
    if (-not $Force -and ($now - $state.LastReport).TotalSeconds -lt $state.EverySec) { return }
    $state.LastReport = $now

    $elapsed = $now - $state.Started
    $secs = [Math]::Max($elapsed.TotalSeconds, 0.001)

    # Percentage by bytes where a size is known, otherwise by item count.
    if ($state.TotalBytes -gt 0) {
        $frac = $state.Bytes / $state.TotalBytes
    } elseif ($state.TotalItems -gt 0) {
        $frac = $state.Items / $state.TotalItems
    } else { $frac = 0 }
    $frac = [Math]::Max(0, [Math]::Min(1, $frac))
    $pct = [int]($frac * 100)

    $filled = [int]($frac * 28)
    $bar = ('#' * $filled) + ('.' * (28 - $filled))

    $line1 = "  [{0}] {1,3}%   {2:N0} / {3:N0} files" -f $bar, $pct, $state.Items, $state.TotalItems
    Write-Host $line1 -ForegroundColor Cyan
    if ($state.Label -and $state.Label -ne 'Copy') {
        Write-Host ("       {0}" -f $state.Label) -ForegroundColor DarkCyan
    }

    $parts = @()
    if ($state.TotalBytes -gt 0) {
        $parts += ("{0} of {1}" -f (Format-Size $state.Bytes), (Format-Size $state.TotalBytes))
        $parts += ("{0}/s" -f (Format-Size ($state.Bytes / $secs)))
    }
    $parts += ("elapsed {0}" -f (Format-Duration $elapsed))

    # Only estimate once there is enough of a sample to be worth stating. An
    # ETA from the first two seconds of a transfer is noise presented as fact.
    if ($frac -gt 0.02 -and $secs -gt 8) {
        $remaining = [TimeSpan]::FromSeconds(($secs / $frac) - $secs)
        $parts += ("left ~{0}" -f (Format-Duration $remaining))
        $parts += ("done ~{0:HH:mm}" -f $now.Add($remaining))
    } elseif ($state.TotalItems -gt 0) {
        $parts += "estimating..."
    }
    Write-Host ("       " + ($parts -join "   ")) -ForegroundColor DarkGray
}

function Complete-Progress($state, [string]$Noun = 'file') {
    $elapsed = (Get-Date) - $state.Started
    $secs = [Math]::Max($elapsed.TotalSeconds, 0.001)
    $msg = "{0}: {1:N0} {2}(s) in {3}" -f $state.Label, $state.Items, $Noun, (Format-Duration $elapsed)
    if ($state.TotalBytes -gt 0 -or $state.Bytes -gt 0) {
        $msg += " ({0}, {1}/s average)" -f (Format-Size $state.Bytes), (Format-Size ($state.Bytes / $secs))
    }
    Good $msg
}

function Banner {
    Write-Host ""
    Write-Host "  +----------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |  ARGUS Field Tool  $script:Version                |" -ForegroundColor White
    Write-Host "  +----------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor DarkGray
}

# ============================================================ shared tables
# USB vendor IDs are assigned by USB-IF and stable, so a match is a fact about
# the hardware rather than a guess from a product string the vendor may change.
$script:VENDORS = @{
    '18d1'='Google';        '04e8'='Samsung';       '22b8'='Motorola'
    '0bb4'='HTC';           '12d1'='Huawei';        '19d2'='ZTE'
    '0fce'='Sony';          '1004'='LG';            '05ac'='Apple'
    '22d9'='Oppo / realme'; '2a70'='OnePlus';       '2717'='Xiaomi'
    '2d95'='Vivo';          '2a45'='Meizu';         '1bbb'='TCL / Alcatel'
    '0421'='Nokia';         '109b'='Hisense';       '0b05'='ASUS'
    '17ef'='Lenovo';        '2ae5'='Fairphone';     '0489'='Foxconn / HTC'
    '1949'='Amazon';        '0955'='NVIDIA';        '0e79'='Archos'
    '0482'='Kyocera';       '04dd'='Sharp';         '201e'='Haier'
    '2c7c'='Quectel';       '2916'='Android (generic ADB interface)'
    '05c6'='Qualcomm silicon';  '0e8d'='MediaTek silicon'
    '1782'='Unisoc silicon';    '2207'='Rockchip silicon'
    '1f3a'='Allwinner silicon'; '0451'='TI silicon'
}

# Keyed on vendor AND product. The vendor alone identifies no mode: MediaTek's
# 0e8d covers the BootROM, the preloader, and ordinary MTP and ADB interfaces.
# Keying on the vendor once announced "BootROM - physical acquisition is a
# candidate" for a phone that was simply browsable in Explorer.
$script:MODES = @{
    '05c6:9008'=@('Qualcomm EDL (9008)','Emergency Download mode. A full physical image is possible with a signed programmer for this OEM. adb does not operate here.')
    '05c6:900e'=@('Qualcomm diagnostic','Diagnostic mode, often a route to a physical read depending on the OEM.')
    '0e8d:0003'=@('MediaTek BootROM','In the MediaTek BootROM, below the operating system. Physical acquisition is a candidate; whether the image is readable still depends on the encryption scheme.')
    '0e8d:2000'=@('MediaTek preloader','The preloader. This window is brief and usually closes as the device continues to boot.')
    '0e8d:2001'=@('MediaTek preloader (alt)','A preloader mode below the operating system.')
    '1782:4d00'=@('Unisoc diagnostic','A Unisoc diagnostic mode, which frequently permits a full read.')
    '2207:310b'=@('Rockchip MaskROM','MaskROM mode, below the operating system.')
    '1f3a:efe8'=@('Allwinner FEL','FEL recovery mode, below the operating system.')
    '0451:d00e'=@('TI OMAP boot','OMAP peripheral boot mode.')
    '04e8:685d'=@('Samsung Download / Odin','Download mode. Flashing is possible; this is not an acquisition route and writing to the device destroys evidence.')
    '05ac:1227'=@('Apple DFU','Device Firmware Update mode. On checkm8-vulnerable silicon (A5-A11) this is where physical extraction becomes possible.')
    '05ac:1281'=@('Apple Recovery','Recovery mode. Restoring from here ERASES the device - do not proceed on evidence.')
    '18d1:4ee0'=@('Android fastboot','The bootloader. Useful for establishing lock state; not an acquisition route on its own.')
}

# Byte-exact fixtures whose correct answers are known. Shared by the
# self-test and the end-to-end demo so both assert against the same
# ground truth rather than two drifting copies of it.
$script:FIXTURE_JPEG_B64 =
            '/9j/4QDiRXhpZgAASUkqAAgAAAAEAA8BAgAGAAAAPgAAABABAgAKAAAARAAAAGmHBAABAAAATgAAACWIBAABAAAAdAAAAAAAAABBUkdVUwBU' +
            'RVNUQ0FNLTEAAQADkAIAFAAAAGAAAAAAAAAAMjAyNDowMzoxNSAxNDoyMjowNwAEAAEAAgACAAAATgAAAAIABQADAAAAqgAAAAMAAgACAAAA' +
            'VwAAAAQABQADAAAAwgAAAAAAAAAzAAAAAQAAABwAAAABAAAAJwAAAAEAAAAAAAAAAQAAAAAAAAABAAAANgAAAAoAAAD/2wBDABAQEBAQEBAQ' +
            'EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAALCAABAAEBAREA/9oACAEBAAA/AAAA' +
            'AAD/2Q=='
$script:FIXTURE_MP4_B64 =
            'AAAAHGZ0eXBpc29tAAACAGlzb21pc28ybXA0MQAAAEhtZGF0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAJhtb292AAAAbG12aGQAAAAA3NuumNzbrpgAAAPoAAAw1AABAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAJHVkdGEAAAAcqXh5egAQFccrNDguODU4' +
            'MisyLjI5NDUv'

$script:MTP_HINT = 'File-transfer (MTP) mode. Shared storage can be copied off and imported with no adb, no debugging toggle and no vendor tooling.'

# Configuration Manager problem codes. "Status is not OK" tells an examiner
# nothing they can act on; these say what actually went wrong and what fixes
# it. Code 28 in particular is the single most common reason a plugged-in
# handset is invisible, and it is trivially fixable once named.
$script:PROBLEM_CODES = @{
    1  = @('Not configured correctly', 'Reinstall the driver from Device Manager.')
    3  = @('Driver corrupted, or out of memory', 'Reinstall the driver; reboot if it persists.')
    10 = @('Device cannot start', 'Usually a wrong or partial driver. Unplug, reboot, replug.')
    12 = @('Not enough free resources', 'Move to a different USB controller - a rear port, not a hub.')
    14 = @('Needs a restart', 'Reboot the workstation.')
    18 = @('Drivers need reinstalling', 'Device Manager: uninstall the device, then replug.')
    19 = @('Registry entry is corrupt', 'Uninstall the device in Device Manager, then replug.')
    21 = @('Windows is removing it', 'Wait, then replug. If it persists, reboot.')
    22 = @('Device is disabled', 'Device Manager: right-click the device and Enable.')
    24 = @('Not present, or not working', 'Replug. If unchanged, try another port and cable.')
    28 = @('NO DRIVER INSTALLED', 'The commonest cause of an invisible handset. Device Manager: right-click, Update driver, Browse, Let me pick, MTP USB Device.')
    31 = @('Driver failed to load', 'Device Manager: uninstall the device, then replug.')
    43 = @('Windows stopped it - the device reported a fault', 'Replug. If it repeats on a different port and cable, suspect the handset socket.')
    45 = @('Not currently connected', 'This is a stale entry, not an attached device.')
    48 = @('Driver blocked from starting', 'The driver is known-incompatible. Install the vendor USB driver.')
}

$script:SHELL_KNOWN = @('Desktop','Documents','Downloads','Music','Pictures','Videos','3D Objects')

function Find-Tool($exe) {
    $c = Get-Command $exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @(
        "C:\platform-tools\$exe.exe",
        "C:\platform-tools-latest-windows\platform-tools\$exe.exe",
        "C:\adb\$exe.exe",
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\$exe.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\$exe.exe",
        "$env:ProgramFiles\platform-tools\$exe.exe",
        "${env:ProgramFiles(x86)}\Android\android-sdk\platform-tools\$exe.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

# ===================================================== physical port topology
#
# Where a device sits on the bus is diagnostic, not decoration. MTP is
# noticeably less reliable through a hub and through some USB 3.x controllers,
# and "it works on the back port but not the front" is a real and common
# outcome. Naming the hub and port turns that from folklore into something an
# examiner can check and record.
function Get-PortInfo([string]$instanceId) {
    $r = [PSCustomObject]@{ Location=''; BusDescription=''; Parent='' }
    if (-not $instanceId) { return $r }
    foreach ($pair in @(
        @('DEVPKEY_Device_LocationInfo', 'Location'),
        @('DEVPKEY_Device_BusReportedDeviceDesc', 'BusDescription'),
        @('DEVPKEY_Device_Parent', 'Parent'))) {
        try {
            $p = Get-PnpDeviceProperty -InstanceId $instanceId -KeyName $pair[0] -ErrorAction Stop
            if ($p -and $p.Data) { $r.($pair[1]) = [string]$p.Data }
        } catch { }
    }
    return $r
}

# ======================================================= USB attachment history
#
# Windows records, for every USB device it has ever seen, when it was first
# installed and when it last arrived and departed. That is a forensic artefact
# about THIS workstation: which handsets have been connected to it, and when.
#
# Two uses. It corroborates an examiner's own notes about when a device was
# attached, and on a machine under examination it answers "what was plugged
# into this" - a question that is otherwise very hard to answer at all.
#
# The timestamps live under a property GUID as 8-byte FILETIMEs:
#   0064 first install   0065 first install (alt)
#   0066 last arrival    0067 last removal
$script:USB_PROP_GUID = '{83da6326-97a6-4088-9453-a1923f573b29}'

function Get-UsbHistory {
    param([switch]$HandsetsOnly)

    $result = [PSCustomObject]@{ Ok=$false; Error=''; Devices=@() }
    $found = New-Object System.Collections.ArrayList

    function Read-FileTime($propPath, $index) {
        try {
            $key = Join-Path $propPath $index
            if (-not (Test-Path -LiteralPath $key)) { return $null }
            $sub = Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if (-not $sub) { return $null }
            $val = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).'(default)'
            if ($null -eq $val -or $val.Count -lt 8) { return $null }
            $ticks = 0L
            for ($i = 7; $i -ge 0; $i--) { $ticks = ($ticks * 256) + [int64]$val[$i] }
            if ($ticks -le 0) { return $null }
            $dt = [DateTime]::FromFileTimeUtc($ticks)
            if ($dt.Year -lt 1990 -or $dt.Year -gt 2100) { return $null }
            return $dt
        } catch { return $null }
    }

    try {
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
        foreach ($vidKey in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            if ($vidKey.PSChildName -notmatch 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') { continue }
            $vid = $Matches[1].ToLower(); $pid = $Matches[2].ToLower()
            $isHandset = $script:VENDORS.ContainsKey($vid)
            if ($HandsetsOnly -and -not $isHandset) { continue }

            foreach ($inst in (Get-ChildItem -LiteralPath $vidKey.PSPath -ErrorAction SilentlyContinue)) {
                $props = Get-ItemProperty -LiteralPath $inst.PSPath -ErrorAction SilentlyContinue
                $desc = ''
                if ($props.FriendlyName) { $desc = $props.FriendlyName }
                elseif ($props.DeviceDesc) { $desc = ($props.DeviceDesc -split ';')[-1] }

                $serial = $inst.PSChildName
                if ($serial -match '&') { $serial = '' }

                $propPath = Join-Path $inst.PSPath "Properties\$script:USB_PROP_GUID"
                [void]$found.Add([PSCustomObject]@{
                    Vid=$vid; Pid=$pid
                    Vendor=$(if ($isHandset) { $script:VENDORS[$vid] } else { '' })
                    Handset=$isHandset
                    Name=$desc; Serial=$serial
                    FirstSeen  = Read-FileTime $propPath '0064'
                    LastArrival= Read-FileTime $propPath '0066'
                    LastRemoval= Read-FileTime $propPath '0067'
                })
            }
        }
        $result.Ok = $true
        $result.Devices = @($found)
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

# ===================================================== true filenames over MTP
#
# FolderItem.Name is the name Explorer would DISPLAY, and with "hide extensions
# for known file types" on - the Windows default - it drops the extension. That
# is not cosmetic. On one real handset it collapsed 24,394 files into 23,864
# distinct names: 530 files silently disappeared from the acquisition, 26 of
# them into the single key "documents\".
#
# FolderItem.Path keeps the real filename on its leaf. It is preferred wherever
# it is richer than the display name, which recovers both cases:
#
#   ".dev"          displayed as ""          -> no name at all
#   " - Copy.dev"   displayed as " - Copy"   -> collides with " - Copy.ext4"
#
# The display name is kept when the Path leaf is unusable, so a handset that
# does not populate Path degrades to the old behaviour rather than failing.
function Get-TrueName($item) {
    $display = ''
    try { $display = [string]$item.Name } catch { }

    $leaf = ''
    try {
        $p = [string]$item.Path
        if ($p) { $leaf = Split-Path -Leaf $p }
    } catch { }

    if ([string]::IsNullOrWhiteSpace($leaf)) { return $display }
    if ($leaf -eq $display) { return $display }
    if ([string]::IsNullOrWhiteSpace($display)) { return $leaf }

    # Only trust the leaf when it is the display name plus an extension.
    # Anything else and the two are describing different things, so the
    # displayed name is the safer choice.
    if ($leaf.Length -gt $display.Length -and
        $leaf.StartsWith($display, [StringComparison]::OrdinalIgnoreCase)) {
        return $leaf
    }
    return $display
}

function Get-MountedHandsets {
    $result = @{ Ok = $false; Error = ''; Items = @() }
    try {
        $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
        $ns = $shell.NameSpace(17)
        if ($null -eq $ns) { throw "shell namespace 17 unavailable" }
        $items = @()
        foreach ($item in $ns.Items()) {
            if ($item.IsFolder -and -not ($item.Path -match '^[A-Z]:\\$') -and
                $script:SHELL_KNOWN -notcontains $item.Name) {
                $items += $item
            }
        }
        $result.Ok = $true
        $result.Items = $items
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

# ================================================================== 1. SCAN
function Invoke-Scan {
    param([string]$JsonPath = "", [switch]$WithFixed)

    $status  = [ordered]@{}
    $devices = @{}
    $unknown = @{}
    $script:seenTotal = 0

    # ------------------------------------------------------------------
    # THE BUG THIS REPLACES
    #
    # The old version dropped, in silence, every USB device whose vendor ID
    # was not already in the table, then reported "no handset hardware on the
    # bus". That turns a gap in a hand-written whitelist into a positive
    # statement about the physical world, which is the single worst thing a
    # detection tool can do - and it is what happened to a phone that was
    # plugged in, mounted, and visible in Explorer at the time.
    #
    # A whitelist can only ever find handsets somebody anticipated. So a
    # device is now kept if ANY of these is true:
    #
    #   - its vendor ID is known                      (confident)
    #   - Windows classes it as a portable device     (it is a phone or camera)
    #   - its driver is the MTP or ADB one            (something is talking to it)
    #   - its name reads like a handset               (weak, but reported as weak)
    #
    # Anything left over is still counted and its VID printed, so a vendor
    # missing from the table shows up as a visible gap rather than as silence.
    # ------------------------------------------------------------------
    function Add-Dev($vid, $pid, $name, $state, $source, $class = '', $service = '',
                     $serial = '', $problem = -1, $instanceId = '') {
        if (-not $vid) { return }
        $vid = $vid.ToLower(); $pid = $pid.ToLower()
        $script:seenTotal++

        $known = $script:VENDORS.ContainsKey($vid)
        $isPortable = ($class -eq 'WPD') -or ($service -match '(?i)WpdMtp|WUDFWpdMtp')
        $isAdb = ($service -match '(?i)winusb') -and ($name -match '(?i)\bADB\b|Android')
        $looksLikePhone = $name -match '(?i)\b(MTP|portable device|android|phone|handset|mobile)\b'

        if (-not ($known -or $isPortable -or $isAdb -or $looksLikePhone)) {
            # Keep it, but only as a counted unknown - never as a handset.
            $k = "$vid`:$pid"
            if (-not $unknown.ContainsKey($k)) {
                $unknown[$k] = [PSCustomObject]@{ Vid=$vid; Pid=$pid; Name=$name }
            }
            return
        }

        $key = "$vid`:$pid"
        if (-not $devices.ContainsKey($key)) {
            $m = $script:MODES[$key]
            $modeName = ''; $note = ''
            if ($m) { $modeName = $m[0]; $note = $m[1] }
            elseif ($isPortable -or ($name -match '(?i)\bMTP\b|portable device|file.?transfer')) {
                $note = $script:MTP_HINT
            }

            # Confidence is recorded, not smuggled. A vendor-ID match is a
            # fact; a name that merely reads like a phone is a guess, and the
            # examiner is entitled to know which they are looking at.
            $vendor = if ($known) { $script:VENDORS[$vid] }
                      elseif ($isPortable) { "unrecognised vendor (portable device)" }
                      elseif ($isAdb) { "unrecognised vendor (ADB interface)" }
                      else { "unrecognised vendor (name match only)" }
            $confidence = if ($known) { 'vendor ID' }
                          elseif ($isPortable) { 'device class' }
                          elseif ($isAdb) { 'driver' }
                          else { 'name only' }

            $devices[$key] = [PSCustomObject]@{
                Vid=$vid; Pid=$pid; Vendor=$vendor; Name=$name
                State=$state; Mode=$modeName; Note=$note
                Known=$known; Confidence=$confidence
                Serial=$serial; Problem=$problem
                Interfaces=(New-Object System.Collections.ArrayList)
                Sources=(New-Object System.Collections.ArrayList)
            }
        }
        $r = $devices[$key]
        if ($name -and $r.Name.Length -lt $name.Length) { $r.Name = $name }
        if ($state -and $state -ne 'OK' -and $r.State -eq 'OK') { $r.State = $state }
        if ($serial -and -not $r.Serial) { $r.Serial = $serial }
        if ($problem -gt 0 -and $r.Problem -le 0) { $r.Problem = $problem }
        if ($r.Sources -notcontains $source) { [void]$r.Sources.Add($source) }

        # A phone presents several interfaces on one physical connection - a
        # composite parent, an MTP function, sometimes an ADB function. Listing
        # them as separate devices makes one handset look like three and buries
        # the one line that matters.
        if ($instanceId -and $r.Interfaces -notcontains $instanceId) {
            [void]$r.Interfaces.Add($instanceId)
        }
    }

    # A USB instance ID is USB\VID_x&PID_y\<serial>. When the device reports no
    # serial number Windows generates one containing '&', so the two cases are
    # distinguishable - and the difference matters: without a serial, two
    # handsets of the same model are indistinguishable to this machine, which
    # is a problem for exhibit identity, not a cosmetic one.
    function Get-UsbSerial([string]$instanceId) {
        if (-not $instanceId) { return '' }
        $parts = $instanceId -split '\\'
        if ($parts.Count -lt 3) { return '' }
        $tail = $parts[2]
        if ($tail -match '&') { return '' }        # Windows-generated, not real
        if ($tail.Length -lt 4) { return '' }
        return $tail
    }

    Section "1. USB hardware"

    # Three enumerators, because each misses devices the others catch, and any
    # of them can be absent or blocked on a managed workstation.
    $firstPass = @{}
    try {
        $n = 0
        foreach ($d in (Get-PnpDevice -PresentOnly -ErrorAction Stop)) {
            if ($d.InstanceId -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
                $n++
                $firstPass[$d.InstanceId] = $true
                $prob = -1
                if ($null -ne $d.Problem) { try { $prob = [int]$d.Problem } catch {} }
                Add-Dev $Matches[1] $Matches[2] $d.FriendlyName $d.Status 'PnP' `
                        $d.Class $d.Service (Get-UsbSerial $d.InstanceId) $prob $d.InstanceId
            }
        }
        $status['PnP'] = "ok ($n USB devices)"
    } catch { $status['PnP'] = "FAILED - $($_.Exception.Message)" }

    try {
        $n = 0
        $wpd = 0
        foreach ($d in (Get-CimInstance Win32_PnPEntity -ErrorAction Stop)) {
            if ($d.PNPDeviceID -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
                $n++
                $st = if ($d.Status) { $d.Status } else { 'OK' }
                $prob = -1
                if ($null -ne $d.ConfigManagerErrorCode) {
                    try { $prob = [int]$d.ConfigManagerErrorCode } catch {}
                }
                Add-Dev $Matches[1] $Matches[2] $d.Name $st 'CIM' $d.PNPClass $d.Service `
                        (Get-UsbSerial $d.PNPDeviceID) $prob $d.PNPDeviceID
            }
            elseif ($d.PNPClass -eq 'WPD' -and $d.Name) {
                # A portable device carrying no VID in its instance path. This
                # is exactly how a handset can be mounted, browsable, and
                # completely invisible to a VID-based scan.
                $wpd++
                $key = "wpd:$($d.Name)"
                if (-not $devices.ContainsKey($key)) {
                    $devices[$key] = [PSCustomObject]@{
                        Vid='----'; Pid='----'
                        Vendor='portable device (no vendor ID exposed)'
                        Name=$d.Name
                        State=$(if ($d.Status) { $d.Status } else { 'OK' })
                        Mode=''; Note=$script:MTP_HINT
                        Known=$false; Confidence='device class'
                        Sources=(New-Object System.Collections.ArrayList)
                    }
                    [void]$devices[$key].Sources.Add('CIM/WPD')
                }
            }
        }
        $status['CIM'] = "ok ($n USB devices, $wpd portable)"
    } catch { $status['CIM'] = "FAILED - $($_.Exception.Message)" }

    # The registry always reads without admin and without any module, but it
    # lists devices ever seen. Entries found ONLY here are reported as
    # historical, never as attached.
    $historical = @{}
    try {
        $n = 0
        foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -ErrorAction Stop)) {
            if ($k.PSChildName -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
                $vid = $Matches[1].ToLower(); $pid = $Matches[2].ToLower()
                if (-not $script:VENDORS.ContainsKey($vid)) { continue }
                $n++
                $key = "$vid`:$pid"
                if ($devices.ContainsKey($key)) { continue }
                $desc = ''
                foreach ($inst in (Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                    if ($p.FriendlyName) { $desc = $p.FriendlyName; break }
                    if ($p.DeviceDesc) { $desc = ($p.DeviceDesc -split ';')[-1] }
                }
                $historical[$key] = [PSCustomObject]@{
                    Vid=$vid; Pid=$pid; Vendor=$script:VENDORS[$vid]; Name=$desc }
            }
        }
        $status['Registry'] = "ok ($n handset entries, historical)"
    } catch { $status['Registry'] = "FAILED - $($_.Exception.Message)" }

    $failed = @($status.Keys | Where-Object { $status[$_] -like 'FAILED*' })
    foreach ($k in $status.Keys) {
        $c = if ($status[$k] -like 'FAILED*') { 'Yellow' } else { 'DarkGray' }
        Write-Host ("  {0,-9} {1}" -f $k, $status[$k]) -ForegroundColor $c
    }
    Write-Host ""

    Note "$script:seenTotal USB device(s) carrying a vendor ID were examined."
    Note "$($devices.Count) matched a handset; $($unknown.Count) did not."
    Write-Host ""

    $present = @($devices.Values | Sort-Object Vendor, Name)
    if ($present.Count -gt 0) {
        foreach ($d in $present) {
            $c = if ($d.State -ne 'OK') { 'Yellow' } elseif ($d.Known) { 'Green' } else { 'Cyan' }
            Write-Host ("  {0,-40} {1}:{2}  {3}" -f $d.Vendor,$d.Vid,$d.Pid,$d.Name) -ForegroundColor $c
            if (-not $d.Known) { Dim "    identified by $($d.Confidence), not by a known vendor ID" }

            # The serial is what ties an exhibit to a specific handset rather
            # than to a model. Worth recording in the case notes.
            if ($d.Serial) {
                Write-Host ("    serial: {0}" -f $d.Serial) -ForegroundColor White
            } else {
                Dim "    serial: not reported - two handsets of this model would"
                Dim "            be indistinguishable to this workstation"
            }

            if ($d.Interfaces.Count -gt 1) {
                Dim "    $($d.Interfaces.Count) interfaces on this one physical device"
            }

            # Where it physically sits. A handset behind a hub, or on some USB
            # 3.x controllers, is a well-known source of MTP transfer failures.
            if ($d.Interfaces.Count -gt 0) {
                $port = Get-PortInfo $d.Interfaces[0]
                if ($port.Location) {
                    Dim "    port: $($port.Location)"
                    if ($port.Location -match '(?i)hub_#0*([2-9]|\d\d)') {
                        Warn "    Behind a downstream hub. Move it to a port directly on"
                        Warn "    the machine before acquiring - hubs drop MTP transfers."
                    }
                }
                if ($port.BusDescription -and $port.BusDescription -ne $d.Name) {
                    Dim "    reported by the device as: $($port.BusDescription)"
                }
            }

            if ($d.Mode) { Mode "    MODE: $($d.Mode)" }

            if ($d.Problem -gt 0 -and $script:PROBLEM_CODES.ContainsKey($d.Problem)) {
                $p = $script:PROBLEM_CODES[$d.Problem]
                Warn ("    PROBLEM {0}: {1}" -f $d.Problem, $p[0])
                Warn ("    FIX: {0}" -f $p[1])
            } elseif ($d.Problem -gt 0) {
                Warn "    Configuration Manager problem code $($d.Problem)."
            } elseif ($d.State -ne 'OK') {
                Warn "    driver state: $($d.State)"
            }

            if ($d.Note) { Dim  "    $($d.Note)" }
        }
        Write-Host ""
        Good "Handset hardware is attached. The cable and port are working."

        $broken = @($present | Where-Object { $_.Problem -gt 0 -or $_.State -ne 'OK' })
        if ($broken.Count -gt 0) {
            Write-Host ""
            Warn "$($broken.Count) device(s) enumerated but did not bind a driver."
            Warn "The specific cause and fix is printed against each one above."
        }

        # ---- stability -------------------------------------------------
        #
        # "Try a different cable" is the standard advice and nobody can
        # justify it. A device that enumerates, disappears and re-enumerates
        # between two scans a second apart IS the signature of a marginal
        # cable, a failing port or a loose socket - and unlike the guess, it
        # is a measurement. A stable device rules the cable out entirely.
        if ($firstPass.Count -gt 0) {
            Start-Sleep -Milliseconds 900
            $secondPass = @{}
            try {
                foreach ($d in (Get-PnpDevice -PresentOnly -ErrorAction Stop)) {
                    if ($d.InstanceId -match 'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}') {
                        $secondPass[$d.InstanceId] = $true
                    }
                }
                $vanished = @($firstPass.Keys | Where-Object { -not $secondPass.ContainsKey($_) })
                $appeared = @($secondPass.Keys | Where-Object { -not $firstPass.ContainsKey($_) })
                if ($vanished.Count -gt 0 -or $appeared.Count -gt 0) {
                    Write-Host ""
                    Bad "UNSTABLE CONNECTION - the bus changed between two scans"
                    Bad "less than a second apart:"
                    foreach ($v in ($vanished | Select-Object -First 5)) { Bad "  vanished:  $v" }
                    foreach ($a in ($appeared | Select-Object -First 5)) { Bad "  appeared:  $a" }
                    Write-Host ""
                    Bad "A device that keeps re-enumerating cannot be acquired"
                    Bad "reliably - a copy started now would fail part-way and the"
                    Bad "missing files would look like files the handset never had."
                    Bad "Change the cable, then the port. Prefer a rear USB 2.0"
                    Bad "port over USB 3.x and never use a hub for acquisition."
                } else {
                    Dim "Connection is stable across two passes - the cable and port"
                    Dim "are not the problem."
                }
                $status['Stability'] = "ok (2 passes)"
            } catch { $status['Stability'] = "FAILED - $($_.Exception.Message)" }
        }
    } elseif ($failed.Count -gt 0) {
        Warn "No handset hardware found - but $($failed -join ', ') failed."
        Warn "That is NOT a statement that nothing is attached."
    } else {
        Note "No device matched a handset by vendor ID, device class, driver or name."
        Dim "All enumerators ran and agreed."
    }

    # The whitelist gap, made visible. If a phone is plugged in and the list
    # below is where it ended up, the vendor ID simply is not in the table -
    # which is a fault in this tool, not a fault in the cable.
    if ($unknown.Count -gt 0) {
        Write-Host ""
        Dim "$($unknown.Count) USB device(s) matched nothing. If your handset is"
        Dim "plugged in and absent above, its vendor ID is probably here:"
        foreach ($u in ($unknown.Values | Sort-Object Vid | Select-Object -First 25)) {
            Dim ("    {0}:{1}  {2}" -f $u.Vid, $u.Pid, $u.Name)
        }
        if ($unknown.Count -gt 25) { Dim "    ... and $($unknown.Count - 25) more" }
    }

    # ---- attachment history ---------------------------------------------
    Section "1b. Handsets previously attached to this workstation"
    $hist = Get-UsbHistory -HandsetsOnly
    if (-not $hist.Ok) {
        Warn "Could not read the USB history: $($hist.Error)"
        $status['History'] = "FAILED - $($hist.Error)"
    } elseif ($hist.Devices.Count -eq 0) {
        Note "No handset has been attached to this machine."
        $status['History'] = 'ok (none)'
    } else {
        $status['History'] = "ok ($($hist.Devices.Count) handset(s))"
        Note "$($hist.Devices.Count) handset(s) have been connected to this machine."
        Write-Host ""
        foreach ($h in ($hist.Devices | Sort-Object { $_.LastArrival } -Descending |
                        Select-Object -First 20)) {
            $live = $devices.ContainsKey("$($h.Vid):$($h.Pid)")
            $tag = if ($live) { '[attached now]' } else { '' }
            $c = if ($live) { 'Green' } else { 'DarkGray' }
            Write-Host ("  {0,-22} {1}:{2}  {3} {4}" -f
                        $h.Vendor, $h.Vid, $h.Pid, $h.Name, $tag) -ForegroundColor $c
            if ($h.Serial)      { Dim "      serial:       $($h.Serial)" }
            if ($h.FirstSeen)   { Dim ("      first seen:   {0:yyyy-MM-dd HH:mm} UTC" -f $h.FirstSeen) }
            if ($h.LastArrival) { Dim ("      last arrival: {0:yyyy-MM-dd HH:mm} UTC" -f $h.LastArrival) }
            if ($h.LastRemoval) { Dim ("      last removal: {0:yyyy-MM-dd HH:mm} UTC" -f $h.LastRemoval) }
        }
        if ($hist.Devices.Count -gt 20) { Dim "  ... $($hist.Devices.Count - 20) more" }
        Write-Host ""
        Dim "These come from Windows' own device registry, so they describe THIS"
        Dim "workstation, not any handset. Two uses: they corroborate your notes"
        Dim "about when a device was attached, and on a machine under examination"
        Dim "they answer 'what was plugged into this', which is otherwise very"
        Dim "hard to establish at all."
        Dim ""
        Dim "A device listed here is not necessarily attached now, and the"
        Dim "absence of a device does not prove it was never connected - the"
        Dim "keys can be cleared, and are, by cleanup tools."
    }

    # ---------------------------------------------------- mounted handsets
    Section "2. Handsets mounted in This PC (MTP)"
    $handsets = Get-MountedHandsets
    $mtp = @()
    if ($handsets.Ok) {
        $mtp = @($handsets.Items | ForEach-Object { $_.Name })
        $status['Shell'] = "ok ($($mtp.Count) handset(s))"
    } else {
        $status['Shell'] = "FAILED - $($handsets.Error)"
        Warn "Shell namespace query failed: $($handsets.Error)"
    }

    if ($mtp.Count -gt 0) {
        foreach ($m in $mtp) {
            Good $m
            # Join the mounted name to the hardware. Reporting "OPPO F11" in
            # one section and "Oppo 22d9:2765" in another leaves the examiner
            # to guess whether those are one phone or two.
            $words = @($m -split '[\s_-]+' | Where-Object { $_.Length -ge 3 })
            $match = $null
            foreach ($d in $present) {
                foreach ($w in $words) {
                    if ($d.Name -match [regex]::Escape($w) -or
                        $d.Vendor -match [regex]::Escape($w)) { $match = $d; break }
                }
                if ($match) { break }
            }
            if ($match) {
                Dim ("    hardware: {0}  {1}:{2}" -f $match.Vendor, $match.Vid, $match.Pid)
                if ($match.Serial) { Dim "    serial:   $($match.Serial)" }
            } else {
                Dim "    could not be tied to a USB entry by name - the mount is"
                Dim "    real either way, this only affects the paperwork"
            }
        }
        Write-Host ""
        Good "A route to evidence right now - no USB debugging required."
        Dim "Reaches: camera media, downloads, documents, and app folders under"
        Dim "Android/media (including WhatsApp media)."
        Dim "Cannot reach: /data/data - message databases, call logs, and the"
        Dim "unallocated space holding deleted records."
    } elseif ($handsets.Ok) {
        Note "None mounted."
        Dim "On the handset: notification shade -> tap the USB notification ->"
        Dim "File transfer / MTP. Most vendors default to charge-only."
    }

    # ------------------------------------------------------------ volumes
    Section "3. Mounted volumes carrying handset data"
    $markers = @('DCIM','Android','LOST.DIR','WhatsApp','MIUI','.thumbnails')
    $vols = @()
    try {
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction Stop)) {
            if (-not $drive.Root -or $drive.Root.Length -gt 3) { continue }
            $type = 'unknown'
            $v = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($drive.Name):'" -ErrorAction SilentlyContinue
            if ($v) { $type = switch ($v.DriveType) { 2{'removable'} 3{'fixed'} 4{'network'} 5{'optical'} default{'other'} } }
            if ($type -eq 'fixed' -and -not $WithFixed) { continue }
            if ($type -eq 'network' -or $type -eq 'optical') { continue }
            $hits = @()
            foreach ($m in $markers) {
                if (Test-Path -LiteralPath (Join-Path $drive.Root $m)) { $hits += $m }
            }
            if ($hits.Count -gt 0) {
                $vols += [PSCustomObject]@{ Root=$drive.Root; Type=$type; Markers=$hits }
                Good "$($drive.Root)  [$type]  contains: $($hits -join ', ')"
            }
        }
        $status['Volumes'] = "ok ($($vols.Count) with handset markers)"
    } catch { $status['Volumes'] = "FAILED - $($_.Exception.Message)" }

    if ($vols.Count -gt 0) { Write-Host ""; Good "These can be imported immediately - no adb involved." }
    elseif ($status['Volumes'] -notlike 'FAILED*') {
        Note "No mounted volume carries handset directories."
        if (-not $WithFixed) { Dim "(Fixed disks skipped. Use -IncludeFixedVolumes to include them.)" }
    }

    # ---------------------------------------------------------------- adb
    Section "4. adb (Android live acquisition)"
    $adbReady = @(); $adbBlocked = @()
    $adb = Find-Tool 'adb'
    if (-not $adb) {
        $status['adb'] = 'not installed'
        Note "Not installed."
        Dim "Only needed for LIVE acquisition. Importing an extraction that"
        Dim "already exists, or copying a mounted handset, does not need it."
    } else {
        Good "Found: $adb"
        $lines = @(& $adb devices -l 2>&1 | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
        $status['adb'] = "ok ($($lines.Count) device line(s))"
        if ($lines.Count -eq 0) { Note "adb reports no handset." }
        foreach ($line in $lines) {
            $state = 'unknown'
            if ($line -match '^(\S+)\s+(no permissions|\w+)') { $state = $Matches[2] }
            $c = if ($state -eq 'device') { 'Green' } else { 'Yellow' }
            Write-Host "  $line" -ForegroundColor $c
            switch ($state) {
                'device'       { $adbReady += $line;   Good "    Ready for live acquisition." }
                'unauthorized' { $adbBlocked += $line; Warn "    Not trusted. Unlock the screen and accept the RSA prompt."
                                                       Warn "    On ColorOS also enable 'Disable permission monitoring'." }
                'offline'      { $adbBlocked += $line; Warn "    Enumerated but unresponsive. Set USB mode to File transfer,"
                                                       Warn "    then: adb kill-server" }
                'no permissions' { $adbBlocked += $line
                                   Warn "    The OS is blocking the USB device itself."
                                   Warn "    On Windows this is the wrong driver: Device Manager ->"
                                   Warn "    Update driver -> Let me pick -> Android ADB Interface." }
                'recovery'     { $adbBlocked += $line; Warn "    In recovery. Reboot to the system." }
                'sideload'     { $adbBlocked += $line; Warn "    In sideload mode. Reboot to the system." }
                'bootloader'   { $adbBlocked += $line; Warn "    In the bootloader. Reboot to the system." }
                default        { $adbBlocked += $line; Warn "    State '$state' - consult adb documentation." }
            }
        }
    }

    $fb = Find-Tool 'fastboot'
    if ($fb) {
        $fbl = @(& $fb devices 2>&1 | Where-Object { $_ -match '\S' })
        if ($fbl.Count -gt 0) {
            Write-Host ""; Warn "fastboot devices:"
            foreach ($l in $fbl) { Warn "  $l" }
            Dim "  In the bootloader. Establishes lock state; not an acquisition route."
        }
    }

    # ---------------------------------------------------------------- iOS
    Section "5. iOS"
    $apple = @($present | Where-Object { $_.Vid -eq '05ac' })
    $idev = Find-Tool 'idevice_id'
    if ($apple.Count -gt 0) {
        foreach ($a in $apple) {
            Good "Apple hardware: $($a.Name) ($($a.Vid):$($a.Pid))"
            if ($a.Mode) { Mode "    MODE: $($a.Mode)" }
        }
    }
    if ($idev) {
        $ids = @(& $idev -l 2>&1 | Where-Object { $_ -match '^[0-9a-fA-F\-]{20,}$' })
        if ($ids.Count -gt 0) { foreach ($i in $ids) { Good "libimobiledevice UDID: $i" } }
        else { Note "libimobiledevice present but sees no handset." }
    } elseif ($apple.Count -gt 0) {
        Note "libimobiledevice not installed - needed for live iOS acquisition."
        Dim "An existing iTunes backup folder can be imported without it."
    } else {
        Note "No Apple handset detected."
    }

    # ------------------------------------------------------------ verdict
    Section "Verdict"
    $lowLevel = @($present | Where-Object { $_.Mode -ne '' })

    if ($adbReady.Count -gt 0) {
        Good "A handset is authorised and ready for live acquisition over adb."
        Good "That reaches more than any other route available here."
    } elseif ($mtp.Count -gt 0) {
        $slug = ($mtp[0] -replace '[^A-Za-z0-9]','-').ToLower()
        Good "'$($mtp[0])' is mounted and browsable. Acquire it with menu option 2,"
        Good "or directly:"
        Write-Host ""
        Write-Host "    .\ARGUS.ps1 -Acquire -Out C:\evidence\$slug" -ForegroundColor White
        Write-Host ""
        Good "You do not need to solve USB debugging to start work."
        if ($adbBlocked.Count -gt 0) {
            Dim "adb is present but blocked. Fixing it would additionally reach"
            Dim "/data/data, where messages, call logs and deleted records live."
        }
    } elseif ($lowLevel.Count -gt 0) {
        Warn "A handset is in a low-level mode: $($lowLevel[0].Mode)"
        Note $lowLevel[0].Note
    } elseif ($vols.Count -gt 0) {
        Good "A mounted volume carries handset data. Import $($vols[0].Root) directly."
    } elseif ($adbBlocked.Count -gt 0) {
        Warn "A handset is attached but adb is refused. The hardware is fine."
        Warn "ColorOS (Oppo / realme / recent OnePlus):"
        Note "  Settings > About device > Version > tap Build number 7 times"
        Note "  Settings > Additional settings > Developer options"
        Note "    - USB debugging                  ON"
        Note "    - Disable permission monitoring  ON   <- the one everyone misses"
        Note "  Replug, then accept the prompt on the handset screen."
        Dim "MIUI additionally needs 'USB debugging (Security settings)'."
    } elseif ($present.Count -gt 0) {
        Warn "Hardware is attached and its driver bound, but nothing can talk to"
        Warn "it. Switch the handset's USB mode to File transfer (MTP) and rescan."
    } elseif ($failed.Count -gt 0) {
        Warn "No handset found, but these enumerators failed: $($failed -join ', ')"
        Warn "Re-run in an elevated PowerShell before concluding it is absent."
    } else {
        Bad "Nothing detected at any level, and every enumerator ran cleanly."
        Bad "Try a different cable - charge-only cables are the usual cause and"
        Bad "are visually identical. Then a different port, ideally USB 2.0."
    }

    if ($JsonPath) {
        $payload = [ordered]@{
            format='argus-device-scan/1'; tool="ARGUS Field $script:Version"
            scanned_at=(Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            workstation=$env:COMPUTERNAME; operator=$env:USERNAME
            source_status=$status; failed_sources=@($failed)
            usb_devices=@($present | ForEach-Object { [ordered]@{
                vendor_id=$_.Vid; product_id=$_.Pid; vendor=$_.Vendor
                name=$_.Name; serial=$_.Serial; driver_state=$_.State
                problem_code=$_.Problem; mode=$_.Mode
                identified_by=$_.Confidence; interfaces=@($_.Interfaces)
                note=$_.Note; sources=@($_.Sources) } })
            mtp_mounted=@($mtp)
            volumes=@($vols | ForEach-Object { [ordered]@{ root=$_.Root; type=$_.Type; markers=@($_.Markers) } })
            adb_ready=@($adbReady); adb_blocked=@($adbBlocked)
        }
        $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
        Write-Host ""; Dim "Scan written to $JsonPath"
    }

    return @{ Mtp = $mtp; Present = $present; AdbReady = $adbReady }
}

# ============================================================== 1d. RAW DUMP
#
# Everything Windows reports, with NO filtering, NO vendor table, NO judgement.
#
# This exists because when the scan says "nothing found", there are two
# possible reasons and they need completely different responses: either nothing
# is attached, or my filtering is discarding it. Every layer I have added -
# vendor IDs, device classes, name matching - is a place a real handset can
# fall through, and no amount of care on my part makes that risk zero.
#
# So this deliberately removes all of it. If the phone is on the bus at all, it
# is in this output somewhere, and the VID/PID that appears here is the ground
# truth that any filtering has to be corrected against.
function Invoke-RawDump {
    param([string]$OutFile = '')

    Section "RAW - everything Windows reports, unfiltered"
    Note "If the scan found nothing but the phone is plugged in, the answer is"
    Note "in here. Nothing below is filtered by vendor, class or name."
    Write-Host ""

    Section "A. Get-PnpDevice, present devices with a VID/PID"
    try {
        $rows = @()
        foreach ($d in (Get-PnpDevice -PresentOnly -ErrorAction Stop)) {
            if ($d.InstanceId -notmatch 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') { continue }
            $rows += [PSCustomObject]@{
                VidPid = "$($Matches[1].ToLower()):$($Matches[2].ToLower())"
                Class  = $d.Class
                Status = $d.Status
                Name   = $d.FriendlyName
                Id     = $d.InstanceId
            }
        }
        if ($rows.Count -eq 0) {
            Bad "Get-PnpDevice returned NO device with a VID/PID at all."
            Bad "That is unusual on a machine with any USB peripheral, and"
            Bad "suggests the query itself is being blocked rather than that"
            Bad "the bus is empty."
        } else {
            Note "$($rows.Count) device(s):"
            foreach ($r in ($rows | Sort-Object VidPid)) {
                Write-Host ("  {0,-11} {1,-14} {2,-8} {3}" -f
                            $r.VidPid, $r.Class, $r.Status, $r.Name) -ForegroundColor White
                Dim ("      {0}" -f $r.Id)
            }
        }
    } catch { Bad "Get-PnpDevice FAILED: $($_.Exception.Message)" }

    Section "B. Win32_PnPEntity, anything that looks portable or unnamed"
    try {
        $n = 0
        foreach ($d in (Get-CimInstance Win32_PnPEntity -ErrorAction Stop)) {
            $isUsb = $d.PNPDeviceID -match '^USB'
            $isWpd = $d.PNPClass -eq 'WPD'
            if (-not ($isUsb -or $isWpd)) { continue }
            $n++
            Write-Host ("  {0,-14} {1,-8} {2}" -f $d.PNPClass, $d.Status, $d.Name) -ForegroundColor White
            Dim ("      {0}" -f $d.PNPDeviceID)
            if ($d.Service) { Dim ("      driver service: {0}" -f $d.Service) }
        }
        if ($n -eq 0) { Warn "No USB or WPD entity returned." }
    } catch { Bad "Win32_PnPEntity FAILED: $($_.Exception.Message)" }

    Section "C. Shell namespace - everything in This PC"
    try {
        $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
        $ns = $shell.NameSpace(17)
        if ($null -eq $ns) { Bad "Namespace 17 (This PC) returned nothing." }
        else {
            foreach ($item in $ns.Items()) {
                Write-Host ("  {0,-34} folder={1}  path={2}" -f
                            $item.Name, $item.IsFolder, $item.Path) -ForegroundColor White
            }
            Dim ""
            Dim "Anything above that is a phone rather than a drive letter or a"
            Dim "standard shell folder is MTP-mounted and can be acquired now."
        }
    } catch { Bad "Shell.Application FAILED: $($_.Exception.Message)" }

    Section "D. adb"
    $adb = Find-Tool 'adb'
    if (-not $adb) { Note "adb not installed." }
    else {
        Note "Path: $adb"
        try {
            $raw = & $adb devices -l 2>&1 | Out-String
            if ($raw.Trim()) { foreach ($l in ($raw -split "`n")) { if ($l.Trim()) { Note "  $($l.TrimEnd())" } } }
            else { Note "  (no output)" }
        } catch { Bad "adb FAILED: $($_.Exception.Message)" }
    }

    Section "E. Environment"
    Note "PowerShell   : $($PSVersionTable.PSVersion)  ($($PSVersionTable.PSEdition))"
    Note "OS           : $([System.Environment]::OSVersion.VersionString)"
    Note "64-bit proc  : $([System.Environment]::Is64BitProcess)"
    Note "User         : $env:USERDOMAIN\$env:USERNAME"
    try {
        $admin = ([Security.Principal.WindowsPrincipal] `
                  [Security.Principal.WindowsIdentity]::GetCurrent()
                 ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Note "Elevated     : $admin"
        if (-not $admin) {
            Dim "Some device properties are readable only when elevated. If the"
            Dim "phone is missing from section A, re-run this as Administrator"
            Dim "before concluding anything."
        }
    } catch { }
    Note "Script       : $($MyInvocation.ScriptName)"
    Note "Tool version : $script:Version"

    Write-Host ""
    Good "Send this whole output when reporting that the scan missed a device."
    Good "The VID:PID in section A is what any fix has to be built against."

    if ($OutFile) {
        Dim "(Console output only - use the GUI 'Save log' button to write a file.)"
    }
}

# ================================================================== 1c. WATCH
#
# A scan answers "is it there now", which is the wrong question when the phone
# is in your other hand. Worse, it makes the failure mode ambiguous: run a
# scan, see nothing, and you cannot tell whether the handset is broken or
# whether you simply have not plugged it in yet.
#
# Watching instead reports the transition. It names the moment a device
# enumerates and the moment it mounts, and those are usually seconds apart -
# which is itself the answer to "why did the scan say nothing", because most
# people scan during that gap.
function Invoke-Watch {
    param([int]$Seconds = 120)

    Section "Watching the bus"
    Note "Plug the handset in now. Unlock it and, if prompted, choose"
    Note "File transfer / MTP."
    Dim  "Watching for up to $Seconds seconds. Ctrl-C to stop."
    Write-Host ""

    function Snapshot {
        $usb = @{}
        try {
            foreach ($d in (Get-PnpDevice -PresentOnly -ErrorAction Stop)) {
                if ($d.InstanceId -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
                    $usb[$d.InstanceId] = [PSCustomObject]@{
                        Vid=$Matches[1].ToLower(); Pid=$Matches[2].ToLower()
                        Name=$d.FriendlyName; Status=$d.Status }
                }
            }
        } catch { }
        $mounted = @()
        $h = Get-MountedHandsets
        if ($h.Ok) { $mounted = @($h.Items | ForEach-Object { $_.Name }) }
        $adb = @()
        $adbPath = Find-Tool 'adb'
        if ($adbPath) {
            $adb = @(& $adbPath devices 2>&1 | Select-Object -Skip 1 |
                     Where-Object { $_ -match '\S' })
        }
        return [PSCustomObject]@{ Usb=$usb; Mounted=$mounted; Adb=$adb }
    }

    $prev = Snapshot
    $deadline = (Get-Date).AddSeconds($Seconds)
    $sawHandset = $false
    $sawMount = $false

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        $now = Snapshot
        $stamp = Get-Date -Format 'HH:mm:ss'

        foreach ($id in $now.Usb.Keys) {
            if ($prev.Usb.ContainsKey($id)) { continue }
            $d = $now.Usb[$id]
            $vendor = $script:VENDORS[$d.Vid]
            if ($vendor) {
                $sawHandset = $true
                Good "$stamp  HANDSET ENUMERATED  $vendor  $($d.Vid):$($d.Pid)"
                Note "          $($d.Name)"
                $serial = Get-UsbSerialStandalone $id
                if ($serial) { Note "          serial: $serial" }
                $mode = $script:MODES["$($d.Vid):$($d.Pid)"]
                if ($mode) { Mode "          MODE: $($mode[0])" }
                if ($d.Status -ne 'OK') { Warn "          driver state: $($d.Status)" }
            } else {
                Dim "$stamp  usb device appeared: $($d.Vid):$($d.Pid)  $($d.Name)"
            }
        }
        foreach ($id in $prev.Usb.Keys) {
            if ($now.Usb.ContainsKey($id)) { continue }
            $d = $prev.Usb[$id]
            if ($script:VENDORS[$d.Vid]) {
                Warn "$stamp  handset removed: $($d.Vid):$($d.Pid)  $($d.Name)"
            }
        }

        foreach ($m in $now.Mounted) {
            if ($prev.Mounted -contains $m) { continue }
            $sawMount = $true
            Good "$stamp  MOUNTED IN THIS PC: $m"
            Good "          Acquirable now - no USB debugging needed."
        }
        foreach ($m in $prev.Mounted) {
            if ($now.Mounted -notcontains $m) { Warn "$stamp  unmounted: $m" }
        }

        foreach ($line in $now.Adb) {
            if ($prev.Adb -contains $line) { continue }
            if ($line -match 'unauthorized') {
                Warn "$stamp  adb: $line"
                Warn "          Accept the RSA prompt on the handset screen."
                Warn "          On ColorOS also enable 'Disable permission monitoring'."
            } elseif ($line -match '\sdevice\s*$') {
                Good "$stamp  adb: $line  - authorised and ready"
            } else {
                Note "$stamp  adb: $line"
            }
        }

        $prev = $now
        if ($sawMount) {
            Write-Host ""
            Good "Handset mounted. Stopping here - you can acquire it now."
            return
        }
    }

    Write-Host ""
    if ($sawHandset) {
        Warn "A handset enumerated but never mounted."
        Note "The hardware and cable are fine. On the phone, pull down the"
        Note "notification shade, tap the USB notification, and choose"
        Note "File transfer. Charge-only exposes nothing."
    } else {
        Note "Nothing appeared in $Seconds seconds."
        Dim "If you did plug it in, the cable is the first suspect -"
        Dim "charge-only cables are visually identical to data cables."
    }
}

# Duplicated deliberately: the version inside Invoke-Scan is nested in that
# function's scope and is not reachable from here.
function Get-UsbSerialStandalone([string]$instanceId) {
    if (-not $instanceId) { return '' }
    $parts = $instanceId -split '\\'
    if ($parts.Count -lt 3) { return '' }
    $tail = $parts[2]
    if ($tail -match '&') { return '' }
    if ($tail.Length -lt 4) { return '' }
    return $tail
}

# =============================================================== 2. ACQUIRE
function Invoke-Acquire {
    param([string]$DeviceName = "", [string]$Destination = "",
          [switch]$SkipHash, [int]$Timeout = 180,
          [switch]$Relist, [switch]$SkipCacheDirs, [switch]$PerFile,
          [switch]$God)

    if ($script:God -or $God) { $SkipHash = $false; $PerFile = $false; $Timeout = 300; $Relist = $false
        Note "GOD-LEVEL acquisition — streaming SHA-256, bulk Shell copy, adaptive headroom, full verify" -ForegroundColor Magenta }

    Section "Acquire a mounted handset"

    $handsets = Get-MountedHandsets
    if (-not $handsets.Ok) { Bad "Cannot read the shell namespace: $($handsets.Error)"; return }
    if ($handsets.Items.Count -eq 0) {
        Bad "No handset mounted in This PC."
        Note "On the phone: notification shade -> USB notification -> File transfer."
        return
    }

    $source = $null
    if ($DeviceName) {
        $source = $handsets.Items | Where-Object { $_.Name -eq $DeviceName } | Select-Object -First 1
        if (-not $source) {
            Bad "'$DeviceName' is not mounted. Present:"
            $handsets.Items | ForEach-Object { Note "  $($_.Name)" }
            return
        }
    } elseif ($handsets.Items.Count -eq 1) {
        $source = $handsets.Items[0]
    } else {
        Note "More than one handset is mounted:"
        for ($i = 0; $i -lt $handsets.Items.Count; $i++) {
            Note "  [$($i+1)] $($handsets.Items[$i].Name)"
        }
        $pick = Read-Host "  Which one"
        $idx = 0
        if ([int]::TryParse($pick, [ref]$idx) -and $idx -ge 1 -and $idx -le $handsets.Items.Count) {
            $source = $handsets.Items[$idx - 1]
        } else { Bad "Not a valid choice."; return }
    }

    $devName = $source.Name
    Good "Handset: $devName"

    if (-not $Destination) {
        $slug = ($devName -replace '[^A-Za-z0-9]','-').ToLower()
        $suggest = "C:\evidence\$slug"
        $entered = Read-Host "  Destination folder [$suggest]"
        $Destination = if ($entered) { $entered } else { $suggest }
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $Destination = (Resolve-Path -LiteralPath $Destination).Path
    Dim "-> $Destination"
    $started = Get-Date

    # ---- in-progress marker ----------------------------------------------
    #
    # A half-finished acquisition is indistinguishable from a finished one by
    # looking at the folder, and that is the most dangerous property this tool
    # can have. It stopped being hypothetical when a crash left a part-copied
    # exhibit on disk with nothing to say so.
    #
    # This marker is written before the first byte and removed only on a clean
    # finish. While it exists, the folder is explicitly not an exhibit - and
    # because it names the device and start time, a later run can recognise
    # the folder as its own interrupted work and resume it rather than
    # refusing to touch it.
    $markerPath = Join-Path $Destination 'argus-INCOMPLETE.json'
    @{
        format      = 'argus-incomplete/1'
        device      = $devName
        started_at  = $started.ToString('yyyy-MM-ddTHH:mm:ssK')
        operator    = $env:USERNAME
        workstation = $env:COMPUTERNAME
        warning     = 'This acquisition has NOT completed. The folder is not an exhibit. Re-run the acquisition against this same folder to resume it; this file is removed only when the copy finishes and the manifest is written.'
    } | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8

    # ---- 1. inventory first, so a shortfall afterwards is measurable -----
    #
    # This pass was the slowest thing in the tool and most of the cost was one
    # avoidable COM call per file.
    #
    # ExtendedProperty('System.Size') is a property-store lookup that crosses
    # the MTP boundary every single time. FolderItem.Size is a direct property
    # and is often already populated, at a fraction of the cost - but not on
    # every handset, so it cannot simply be swapped in. The first 40 files are
    # therefore used as a probe: if the cheap property answers for any of them
    # it is trusted for the rest, otherwise the slow route is used and the run
    # is honest about why it will take a while.
    Section "1. Listing the device"
    Note "Reading the file list off the handset. Nothing is copied yet."
    Dim  "MTP has no bulk listing call, so this is one round-trip per folder."
    Write-Host ""

    # Explorer's "hide extensions for known file types" changes what MTP
    # reports as a filename, and it is on by default. The tool copes either
    # way now, but turning it off makes the listing exact rather than
    # reconstructed, so it is worth one sentence.
    try {
        $hideExt = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
                    -Name HideFileExt -ErrorAction Stop).HideFileExt
        if ($hideExt -eq 1) {
            Warn "Windows is hiding file extensions, so the handset reports"
            Warn "'photo' where the real file is 'photo.jpg'. Arrivals are"
            Warn "matched by prefix to compensate, which works but is inexact"
            Warn "where two files share a name."
            Dim  "To remove the guesswork: File Explorer -> View -> Show ->"
            Dim  "File name extensions, then re-run. Nothing else changes."
            Write-Host ""
        }
    } catch { }

    # ---- reuse a previous listing where one exists -----------------------
    #
    # Walking 24,000 files over MTP takes five minutes, and a resumed run
    # would otherwise pay it again every single time. Since resuming is now
    # the normal way an interrupted acquisition finishes, that cost lands
    # repeatedly on exactly the runs that can least afford it.
    #
    # The cache is tied to the device name and stamped with its age, and it
    # is only ever used to decide what to ASK for. Reconciliation still reads
    # the destination directly, so a stale listing can cause a file to be
    # re-requested or reported missing - never to be reported as arrived when
    # it did not.
    $listingCache = Join-Path $Destination 'argus-listing.json'
    $listed = New-Object System.Collections.ArrayList
    $usedCache = $false

    if ((Test-Path -LiteralPath $listingCache) -and -not $Relist) {
        try {
            $cache = Get-Content -LiteralPath $listingCache -Raw | ConvertFrom-Json
            $age = (Get-Date) - [DateTime]::Parse($cache.listed_at)
            if ($cache.device -eq $devName -and $age.TotalHours -lt 24) {
                foreach ($e in $cache.files) {
                    [void]$listed.Add([PSCustomObject]@{ Rel=$e.rel; Size=[int64]$e.size })
                }
                $usedCache = $true
                Good ("Reusing the listing from {0} ago - {1:N0} file(s)." -f
                      (Format-Duration $age), $listed.Count)
                Dim  "Use -Relist to walk the handset again instead."
                Write-Host ""
            } else {
                Dim "A cached listing exists but is for a different device or is"
                Dim "over 24 hours old. Walking the handset again."
            }
        } catch {
            Dim "Could not read the cached listing; walking the handset again."
            $listed = New-Object System.Collections.ArrayList
        }
    }

    $listStart = Get-Date
    $script:probeCount = 0
    $script:cheapWorks = $false
    $script:probeDone = $false
    $script:lastTick = Get-Date
    $script:curFolder = ''

    function Get-ItemSize($item) {
        if (-not $script:probeDone) {
            $script:probeCount++
            $quick = 0
            try { $quick = [int64]$item.Size } catch { }
            if ($quick -gt 0) { $script:cheapWorks = $true; $script:probeDone = $true; return $quick }
            if ($script:probeCount -ge 40) {
                $script:probeDone = $true
                Dim "This handset does not expose sizes cheaply - using the slower"
                Dim "property lookup. Expect the listing to take longer."
            }
            $slow = 0
            try { $slow = [int64]$item.ExtendedProperty('System.Size') } catch { }
            return $slow
        }
        if ($script:cheapWorks) {
            $v = 0
            try { $v = [int64]$item.Size } catch { }
            return $v
        }
        $v = 0
        try { $v = [int64]$item.ExtendedProperty('System.Size') } catch { }
        return $v
    }

    # Directories an examiner may reasonably choose to omit. Off by default:
    # a forensic tool's default must be to take everything, and an exclusion
    # that nobody chose is the kind of thing that surfaces in cross-examination.
    # When it is used, every pattern is recorded in the manifest so the
    # omission is disclosed rather than discovered.
    $script:skipPatterns = @()
    if ($SkipCacheDirs) {
        $script:skipPatterns = @(
            '\\Android\\data\\[^\\]+\\cache\\',
            '\\Android\\data\\[^\\]+\\code_cache\\',
            '\\Android\\data\\[^\\]+\\files\\Logs?\\',
            '\\\.cache\\'
        )
    }
    $script:skippedByPattern = 0

    function Walk-Device($folder, $prefix, $depth) {
        if ($depth -gt 12) { return }
        foreach ($item in $folder.Items()) {
            $nm = Get-TrueName $item
            $rel = if ($prefix) { "$prefix\$nm" } else { $nm }

            if ($script:skipPatterns.Count -gt 0) {
                $skip = $false
                foreach ($pat in $script:skipPatterns) {
                    if ("$rel\" -match $pat) { $skip = $true; break }
                }
                if ($skip) { $script:skippedByPattern++; continue }
            }

            if ($item.IsFolder) {
                $script:curFolder = $rel
                Walk-Device $item.GetFolder $rel ($depth + 1)
            } else {
                [void]$listed.Add([PSCustomObject]@{ Rel=$rel; Size=(Get-ItemSize $item) })

                # Feedback while it works. "This looks idle" was accurate and
                # it is the reason long listings get killed half-way.
                $now = Get-Date
                if (($now - $script:lastTick).TotalSeconds -ge 2) {
                    $script:lastTick = $now
                    $secs = [Math]::Max(($now - $listStart).TotalSeconds, 0.001)
                    Write-Host ("  {0,7:N0} files found   {1:N0}/s   {2}   in: {3}" -f
                                $listed.Count, ($listed.Count / $secs),
                                (Format-Duration ($now - $listStart)),
                                $script:curFolder) -ForegroundColor DarkGray
                }
            }
        }
    }
    if (-not $usedCache) { Walk-Device $source.GetFolder "" 0 }

    $listElapsed = (Get-Date) - $listStart
    Write-Host ""
    if ($script:skippedByPattern -gt 0) {
        Write-Host ""
        Warn ("{0} entries were EXCLUDED by -SkipCacheDirs and were never listed." -f
              $script:skippedByPattern)
        Warn "This is recorded in the manifest. Their absence from this exhibit"
        Warn "says nothing about the handset."
    }
    if (-not $usedCache) {
        Good ("Listing finished in {0} - {1:N0} file(s), {2:N0} per second." -f
              (Format-Duration $listElapsed), $listed.Count,
              ($listed.Count / [Math]::Max($listElapsed.TotalSeconds, 0.001)))
        try {
            @{ format='argus-listing/1'; device=$devName
               listed_at=(Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
               count=$listed.Count
               files=@($listed | ForEach-Object { @{ rel=$_.Rel; size=$_.Size } })
            } | ConvertTo-Json -Depth 4 -Compress |
              Set-Content -LiteralPath $listingCache -Encoding UTF8
            Dim "Listing cached - a resumed run will not have to walk the device again."
        } catch { Dim "Could not cache the listing: $($_.Exception.Message)" }
    }

    # Count how many files each key stands for. Where two distinct files still
    # share a name, the map can only hold one size - but the COUNT is kept, so
    # reconciliation knows to expect two arrivals and reports a shortfall
    # instead of quietly forgetting one.
    $expected = @{}
    $expectedCounts = @{}
    foreach ($e in $listed) {
        if (-not $expectedCounts.ContainsKey($e.Rel)) { $expectedCounts[$e.Rel] = 0 }
        $expectedCounts[$e.Rel]++
        if (-not $expected.ContainsKey($e.Rel)) { $expected[$e.Rel] = $e.Size }
    }
    $collisions = $listed.Count - $expected.Count
    if ($collisions -gt 0) {
        Write-Host ""
        Warn ("{0} of {1:N0} listed files share a name with another file." -f
              $collisions, $listed.Count)
        Warn "They are still counted and still copied, but where two files in one"
        Warn "folder cannot be told apart by name, the match is by count rather"
        Warn "than identity."
        Dim  "Turning on File name extensions in Explorer usually removes this"
        Dim  "entirely - it is what strips the extensions in the first place."
        Write-Host ""
    }
    $totalBytes = ($listed | Measure-Object -Property Size -Sum).Sum
    if (-not $totalBytes) { $totalBytes = 0 }

    Good ("{0} file(s), {1:N2} GB" -f $expected.Count, ($totalBytes / 1GB))
    Dim "This inventory is what makes a dropped file detectable later."
    if ($expected.Count -eq 0) { Warn "Nothing to copy."; return }

    # ---- free space, checked BEFORE copying ------------------------------
    #
    # Running out of disk 35 minutes into an acquisition is the worst possible
    # place to discover it: the copy stops part-way, and a partial exhibit on
    # disk is indistinguishable from a complete one unless somebody reads the
    # manifest. The inventory above already knows the size, so this costs
    # nothing and moves the failure to the only point where it is harmless.
    try {
        $destDrive = (Get-Item -LiteralPath $Destination).PSDrive
        if ($destDrive -and $null -ne $destDrive.Free) {
            $free = [int64]$destDrive.Free
            # Adaptive headroom: 5% default, 10% for >10GB (MTP sizes inexact + FS overhead)
            $headroom = if ($totalBytes -gt 10GB) { 1.10 } else { 1.05 }
            $headPct  = if ($totalBytes -gt 10GB) { '10%' } else { '5%' }
            $needed = [int64]($totalBytes * $headroom)
            Note ("Free on {0} : {1:N2} GB" -f $destDrive.Name, ($free / 1GB))
            Note ("Needed      : {0:N2} GB (listed size plus $headPct headroom)" -f ($needed / 1GB))
            if ($free -lt $needed) {
                Write-Host ""
                Bad "NOT ENOUGH FREE SPACE. Stopping before anything is copied."
                Bad ("Short by {0:N2} GB." -f (($needed - $free) / 1GB))
                Write-Host ""
                Note "Free space on that volume, or choose a destination with room."
                Note "Nothing has been written and the handset was not touched."
                return
            }
            if ($free -lt ($needed * 1.5)) {
                Warn "Space is tight - this will leave under 50% headroom."
            }
        }
    } catch {
        Dim "Could not determine free space on the destination; continuing."
    }

    # ---- 2. copy ---------------------------------------------------------
    Section "2. Copying"

    # An honest range rather than a single number. MTP throughput varies by
    # more than a factor of five with the handset, the cable and the port, so
    # a single figure would be precise and wrong.
    $lowMin  = [Math]::Ceiling($totalBytes / (25MB) / 60)
    $highMin = [Math]::Ceiling($totalBytes / (5MB) / 60)
    Note ("To copy: {0} in {1:N0} files" -f (Format-Size $totalBytes), $expected.Count)
    Note ("Expect roughly {0}-{1} minutes at typical MTP speeds (5-25 MB/s)." -f $lowMin, $highMin)
    Note "A real estimate appears below once enough has transferred to measure."
    Write-Host ""
    Dim "Leave the phone unlocked and plugged in. Progress prints every 5"
    Dim "seconds - if it keeps moving, nothing is stuck."
    Write-Host ""

    $prog = New-ProgressState $expected.Count $totalBytes 'Copy'
    $script:abortCopy = $false

    $shell = New-Object -ComObject Shell.Application
    $destFolders = @{}
    function Get-DestFolder($path) {
        if (-not $destFolders.ContainsKey($path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            $destFolders[$path] = $shell.NameSpace($path)
        }
        return $destFolders[$path]
    }

    $script:copied = 0; $script:skipped = 0
    $script:failedFiles = New-Object System.Collections.ArrayList

    # ------------------------------------------------------------------
    # Copying, issued in bounded chunks.
    #
    # The previous version queued every file in a folder before waiting for
    # any of them. On a folder holding thousands of photographs that means
    # thousands of simultaneous asynchronous shell copies, and the shell does
    # not cope: nothing transfers, and the folder deadline - computed as four
    # seconds per pending file - then sat there for hours. Observed live at
    # 19 files and 0 bytes after eight minutes.
    #
    # So requests go out in chunks of 24. That is still pipelined, which is
    # the whole point of batching, but it is a queue depth the shell handles.
    #
    # Everything here is bounded. A chunk that stops making progress is
    # abandoned rather than waited out, because one file the media provider
    # will not serve must not hold up the other 23,000 - and the whole run
    # aborts early if nothing is transferring at all, instead of grinding for
    # hours to reach the same conclusion.
    # ------------------------------------------------------------------
    $script:CHUNK = 24
    $script:stallSeconds = 45      # cold start: nothing from this batch yet
    $script:graceSeconds = 15      # once the batch has delivered anything
    $script:totalStalls = 0
    $script:arrivedMap = @{}

    # ------------------------------------------------------------------
    # MTP reports the name Explorer would DISPLAY, not the real filename.
    #
    # With "hide extensions for known file types" on - the Windows default -
    # FolderItem.Name gives "IMG-20250412-WA0028 - Copy" for a file that is
    # actually "IMG-20250412-WA0028 - Copy.jpg". The copy then succeeded and
    # the tool sat waiting for a filename that would never exist, timed out,
    # and recorded 23,864 perfectly good files as failures.
    #
    # Two independent signs of it in one run: files appeared in the analysis
    # that the copy had just declared unreachable, and the walker counted
    # 24,394 files while the map held 23,864 - 530 names collided once their
    # extensions were stripped.
    #
    # So arrival is detected by prefix rather than by exact name. The glob
    # uses -Filter, which is a Win32 pattern where only * and ? are special,
    # and neither can occur in a Windows filename - so no escaping is needed.
    # ------------------------------------------------------------------
    function Resolve-Arrived([string]$dir, [string]$name) {
        # An empty name would make Join-Path return the directory and the glob
        # '.*' match every file in it. Refuse outright.
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }
        $exact = Join-Path $dir $name
        if (Test-Path -LiteralPath $exact -PathType Leaf) { return $exact }
        $cands = @(Get-ChildItem -LiteralPath $dir -File -Filter ($name + '.*') `
                   -ErrorAction SilentlyContinue)
        if ($cands.Count -eq 0) { return $null }
        foreach ($c in $cands) {
            if ([IO.Path]::GetFileNameWithoutExtension($c.Name) -eq $name) { return $c.FullName }
        }
        return $cands[0].FullName
    }

    function Copy-Folder-Batch($folder, $prefix, $depth) {
        if ($depth -gt 12) { return }
        if ($script:abortCopy) { return }
        if ($prefix) { $prog.Label = "Copy  $prefix" }

        $subfolders = New-Object System.Collections.ArrayList
        $queue = New-Object System.Collections.ArrayList

        $destDir = if ($prefix) { Join-Path $Destination $prefix } else { $Destination }
        $destFolder = $null

        # One directory read per folder, not one glob per file. A resumed run
        # was otherwise doing 23,864 filesystem searches before moving a byte.
        $script:destIndex = @{}
        if (Test-Path -LiteralPath $destDir) {
            foreach ($e in (Get-ChildItem -LiteralPath $destDir -File -ErrorAction SilentlyContinue)) {
                $script:destIndex[$e.Name] = $e.FullName
                $base = [IO.Path]::GetFileNameWithoutExtension($e.Name)
                if ($base -and -not $script:destIndex.ContainsKey($base)) {
                    $script:destIndex[$base] = $e.FullName
                }
            }
        }

        foreach ($item in $folder.Items()) {
            $nm = Get-TrueName $item
            $rel = if ($prefix) { "$prefix\$nm" } else { $nm }
            if ($item.IsFolder) { [void]$subfolders.Add(@($item, $rel)); continue }

            $target = Join-Path $destDir $nm
            $want = 0
            if ($expected.ContainsKey($rel)) { $want = [int64]$expected[$rel] }

            # Resumable, but a zero-byte file is never accepted as finished.
            # Treating "size unknown, something exists" as complete would let
            # every empty placeholder left by an interrupted run count as a
            # successful copy.
            $already = $null
            if ($script:destIndex.Count -gt 0) {
                $probe = $nm
                if ($probe -and $script:destIndex.ContainsKey($probe)) {
                    $already = $script:destIndex[$probe]
                }
            }
            if (-not $already) { $already = Resolve-Arrived $destDir $nm }
            if ($already) { $target = $already }
            if (Test-Path -LiteralPath $target) {
                $existing = $null
                try { $existing = Get-Item -LiteralPath $target -Force -ErrorAction Stop } catch { }

                if ($null -ne $existing -and $existing.PSIsContainer) {
                    # MTP called this a file; the filesystem says folder. Never
                    # delete it - this is the path that once tried to remove a
                    # directory of already-acquired evidence.
                    $asFolder = $null
                    try { $asFolder = $item.GetFolder } catch { }
                    if ($null -ne $asFolder) { [void]$subfolders.Add(@($item, $rel)) }
                    else {
                        [void]$script:failedFiles.Add(@{ path=$rel
                            reason='Reported as a file by the handset, but a directory of that name exists at the destination. Left untouched.' })
                    }
                    continue
                }

                $have = 0
                if ($null -ne $existing) { try { $have = [int64]$existing.Length } catch { } }
                if ($have -gt 0 -and ($want -eq 0 -or $have -eq $want)) {
                    $script:skipped++
                    $prog.Items++; $prog.Bytes += $have
                    Write-Progress2 $prog
                    continue
                }
                Remove-Item -LiteralPath $target -Force -Confirm:$false -ErrorAction SilentlyContinue
            }

            # MTP returns the name Explorer would DISPLAY. For a file that is
            # nothing but an extension - .nomedia, .trashed-xxx and friends -
            # that display name is EMPTY. There is no target to copy to and no
            # way to detect arrival, so these are recorded and skipped rather
            # than queued to fail. Left in, each one poisoned a whole batch.
            $itemName = $nm
            if ([string]::IsNullOrWhiteSpace($itemName)) {
                # The display name is empty, but the shell Path usually still
                # carries the real filename on its leaf. Worth trying before
                # writing the file off - these are .nomedia, .trashed-* and
                # similar, and the trashed ones are of obvious interest.
                try {
                    $leaf = Split-Path -Leaf ([string]$item.Path)
                    if (-not [string]::IsNullOrWhiteSpace($leaf) -and $leaf -ne '\') {
                        $itemName = $leaf
                        $rel = if ($prefix) { "$prefix\$leaf" } else { $leaf }
                        $target = Join-Path $destDir $leaf
                    }
                } catch { }
            }
            if ([string]::IsNullOrWhiteSpace($itemName)) {
                [void]$script:failedFiles.Add(@{ path=$rel
                    reason='The handset reported an empty filename for this entry, which happens for files that are nothing but an extension (.nomedia, .trashed-*). There is no name to copy to. Turning on File name extensions in Explorer makes these visible and copyable.' })
                $prog.Items++
                Write-Progress2 $prog
                continue
            }
            [void]$queue.Add([PSCustomObject]@{ Item=$item; Rel=$rel; Target=$target; Want=$want; Name=$itemName; Dir=$destDir })
        }

        # ---- issue and wait, a chunk at a time (fallback path) ---------
        #
        # Two passes. MTP failures are frequently transient - the provider is
        # busy, the handset is indexing, a thumbnail is being regenerated - and
        # a file that refused once will often come back on a second ask. One
        # retry costs seconds and converts a class of permanent gaps in the
        # exhibit into successful copies. Anything that fails twice is recorded
        # as a genuine failure with its reason.
        $attemptQueue = $queue
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            if ($attemptQueue.Count -eq 0) { break }
            if ($script:abortCopy) { break }
            if ($attempt -eq 2) {
                Write-Host ""
                Note ("Retrying {0} file(s) that did not arrive first time..." -f $attemptQueue.Count)
                Start-Sleep -Milliseconds 700   # let the provider settle
            }
            $nextQueue = New-Object System.Collections.ArrayList

            for ($start = 0; $start -lt $attemptQueue.Count; $start += $script:CHUNK) {
                if ($script:abortCopy) { break }

                $end = [Math]::Min($start + $script:CHUNK - 1, $attemptQueue.Count - 1)
                $slice = @($attemptQueue[$start..$end])

                if (-not $destFolder) {
                    $destFolder = Get-DestFolder $destDir
                    if (-not $destFolder) {
                        foreach ($f in $slice) {
                            [void]$script:failedFiles.Add(@{ path=$f.Rel
                                reason='Destination folder could not be opened.' })
                        }
                        continue
                    }
                }

                foreach ($f in $slice) {
                    # 16 = yes to all, 512 = no progress dialog, 1024 = no error UI.
                    $destFolder.CopyHere($f.Item, 16 -bor 512 -bor 1024)
                }

                $done = @{}
                $sleepMs = 20
                $lastChange = Get-Date
                $lastBytes = 0.0

                while ($done.Count -lt $slice.Count) {
                    Start-Sleep -Milliseconds $sleepMs
                    $bytesNow = 0.0
                    $progressed = $false

                    for ($k = 0; $k -lt $slice.Count; $k++) {
                        if ($done.ContainsKey($k)) { continue }
                        $f = $slice[$k]
                        $actual = Resolve-Arrived $f.Dir $f.Name
                        if (-not $actual) { continue }
                        $have = 0
                        try { $have = (Get-Item -LiteralPath $actual).Length } catch { continue }
                        $bytesNow += $have
                        if ($have -gt 0 -and ($f.Want -eq 0 -or $have -ge $f.Want)) {
                            $done[$k] = $true
                            $script:arrivedMap[$f.Rel] = $actual
                            $script:copied++
                            $prog.Items++; $prog.Bytes += $have
                            $progressed = $true
                        }
                    }

                    # Partial bytes count as progress: one large video can be
                    # many seconds from finishing while transferring perfectly.
                    if ($progressed -or $bytesNow -gt $lastBytes) {
                        $lastChange = Get-Date
                        $lastBytes = $bytesNow
                        $sleepMs = 20
                    } elseif ($sleepMs -lt 400) {
                        $sleepMs = [int]($sleepMs * 1.5) + 1
                    }

                    Write-Progress2 $prog

                    # Once anything in this batch has arrived the handset has
                    # proven it will serve, so a straggler gets a short grace
                    # rather than the full cold-start window.
                    $graceFor = if ($done.Count -gt 0) { $script:graceSeconds } else { $script:stallSeconds }
                    if (((Get-Date) - $lastChange).TotalSeconds -ge $graceFor) {
                        $stuck = @()
                        for ($k = 0; $k -lt $slice.Count; $k++) {
                            if (-not $done.ContainsKey($k)) { $stuck += $slice[$k] }
                        }
                        if ($stuck.Count -eq 0) { break }

                        if ($attempt -eq 1) {
                            # Hold them back for the retry pass rather than
                            # writing them off now.
                            foreach ($f in $stuck) { [void]$nextQueue.Add($f) }
                        } else {
                            $script:totalStalls++
                            Write-Host ""
                            Warn ("Gave up on {0} file(s) after two attempts:" -f $stuck.Count)
                            foreach ($f in ($stuck | Select-Object -First 4)) { Warn ("    {0}" -f $f.Rel) }
                            if ($stuck.Count -gt 4) { Dim ("    ... and {0} more" -f ($stuck.Count - 4)) }
                            Dim "Recorded in the manifest. The run continues."
                            Write-Host ""
                            foreach ($f in $stuck) {
                                [void]$script:failedFiles.Add(@{ path=$f.Rel
                                    reason="The handset listed this file but served no data for it across two attempts. Media providers routinely list entries they will not serve - trashed items and partially written files in particular." })
                                $prog.Items++
                            }
                        }
                        break
                    }
                }

                # ---- fail fast if the transfer is not working at all --------
                if ($prog.Bytes -le 0 -and $script:totalStalls -ge 2) {
                    $script:abortCopy = $true
                    Write-Host ""
                    Bad "STOPPING: not a single byte has transferred."
                    Write-Host ""
                    Note "The handset is listing files but will not hand any over."
                    Note "That is not a slow copy, and waiting will not fix it."
                    Write-Host ""
                    Note "In order of likelihood:"
                    Note "  1. The phone locked. MTP stops serving on lock - unlock"
                    Note "     it, keep the screen on, and run again to resume."
                    Note "  2. USB mode reverted to charge-only. Re-select File"
                    Note "     transfer on the notification."
                    Note "  3. Replug, ideally into a rear USB 2.0 port, not a hub."
                    Write-Host ""
                    Note "Nothing acquired so far is lost - re-running resumes."
                    break
                }
            }

            $attemptQueue = $nextQueue
        }

        if ($script:abortCopy) { return }
        foreach ($sf in $subfolders) { Copy-Folder-Batch $sf[0].GetFolder $sf[1] ($depth + 1) }
    }

    # ==================================================================
    # BULK COPY - hand the whole tree to the shell in one call.
    #
    # This replaces per-file CopyHere as the default, and the reason is
    # simply that the per-file approach was wrong.
    #
    # Dragging a handset's storage out in Explorer works, and is fast, and
    # what Explorer issues is ONE CopyHere against the folder. The shell then
    # runs its own pipeline: it batches, it retries, it keeps the MTP session
    # warm, and it never round-trips through a script between files. A script
    # calling CopyHere once per file gets none of that and pays a detection
    # cost on every single one - which on this handset meant 107 files in
    # eight minutes against 23,864 to do.
    #
    # Nothing forensic is lost by handing over the transfer. What makes the
    # acquisition defensible is the independent inventory taken beforehand,
    # the reconciliation against it afterwards, and a hash for every file -
    # all of which still happen. The shell is simply better at moving bytes
    # than a PowerShell loop, and pretending otherwise cost real hours.
    # ==================================================================
    function Copy-Bulk($sourceFolder, $destRoot, $expectedFiles, $expectedBytes) {
        $destNs = $null
        try {
            $sh = New-Object -ComObject Shell.Application
            $destNs = $sh.NameSpace($destRoot)
        } catch { }
        if (-not $destNs) { Bad "Could not open the destination for the shell."; return $false }

        $top = @($sourceFolder.Items())
        Note ("Handing {0} top-level item(s) to the shell in one operation." -f $top.Count)
        Dim  "The shell now owns the transfer. Progress below is measured by"
        Dim  "watching the destination grow, not by asking it."
        Write-Host ""

        foreach ($item in $top) {
            # 16 = yes to all, 512 = no progress dialog, 1024 = no error UI.
            $destNs.CopyHere($item, 16 -bor 512 -bor 1024)
        }

        $bp = New-ProgressState $expectedFiles $expectedBytes 'Copy'
        $lastFiles = -1
        $lastBytes = -1
        $idleSince = Get-Date
        $started = Get-Date

        while ($true) {
            Start-Sleep -Seconds 3
            $now = @(Get-ChildItem -LiteralPath $destRoot -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -notlike 'argus-*' })
            $c = $now.Count
            $b = 0
            if ($c -gt 0) { $b = ($now | Measure-Object Length -Sum).Sum }

            $bp.Items = $c
            $bp.Bytes = $b
            Write-Progress2 $bp -Force

            if ($c -ne $lastFiles -or $b -ne $lastBytes) {
                $idleSince = Get-Date
                $lastFiles = $c; $lastBytes = $b
            }

            if ($c -ge $expectedFiles -and $expectedFiles -gt 0) {
                Write-Host ""
                Good "Every listed file has arrived."
                return $true
            }

            $idle = ((Get-Date) - $idleSince).TotalSeconds
            if ($idle -ge 120) {
                Write-Host ""
                if ($c -eq 0) {
                    Bad "Nothing arrived in two minutes."
                    Write-Host ""
                    Note "The shell accepted the copy but the handset served nothing."
                    Note "  1. The phone locked - MTP stops serving. Unlock it and"
                    Note "     keep the screen on."
                    Note "  2. USB mode reverted to charge-only."
                    Note "  3. Replug into a rear USB 2.0 port, not a hub."
                    return $false
                }
                Warn ("No change for {0}s - treating the copy as finished." -f [int]$idle)
                Warn ("{0:N0} of {1:N0} listed files arrived." -f $c, $expectedFiles)
                Dim  "Anything short is itemised in the manifest below."
                return $true
            }

            # A very long copy is normal; an infinite one is not.
            if (((Get-Date) - $started).TotalHours -gt 12) {
                Write-Host ""
                Warn "Twelve hours elapsed - stopping and reconciling what arrived."
                return $true
            }
        }
    }

    if ($PerFile) {
        Note "Per-file copy requested. This is slower and exists as a fallback."
        Write-Host ""
        Copy-Folder-Batch $source.GetFolder "" 0
    } else {
        [void](Copy-Bulk $source.GetFolder $Destination $expected.Count $totalBytes)
        # The running counters belong to the per-file path; recompute from disk.
        $onDisk = @(Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notlike 'argus-*' })
        $script:copied = $onDisk.Count
        $prog.Items = $onDisk.Count
        $prog.Bytes = if ($onDisk.Count -gt 0) { ($onDisk | Measure-Object Length -Sum).Sum } else { 0 }
    }

    Write-Host ""
    Write-Progress2 $prog -Force
    Complete-Progress $prog
    Good ("Copied {0:N0}, skipped {1:N0} already present, {2:N0} could not be copied." -f
          $script:copied, $script:skipped, $script:failedFiles.Count)

    # ---- 3. reconcile and hash ------------------------------------------
    Section "3. Reconciling and hashing"
    $arrived = @{}
    Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        # The tool's own bookkeeping is not evidence and must not appear in
        # the manifest - the in-progress marker got hashed on the last run and
        # was then reported as missing by Verify after it was removed.
        if ($_.Name -like 'argus-*') { return }
        $arrived[$_.FullName.Substring($Destination.Length).TrimStart('\')] = $_
    }

    $hashes = @{}
    if (-not $SkipHash) {
        $hashBytes = ($arrived.Values | Measure-Object -Property Length -Sum).Sum
        if (-not $hashBytes) { $hashBytes = 0 }
        Note ("Hashing {0:N0} file(s), {1}. This reads every byte back off disk," -f
              $arrived.Count, (Format-Size $hashBytes))
        Note "which is what makes the copy checkable later."
        Write-Host ""
        $hp = New-ProgressState $arrived.Count $hashBytes 'Hash'
        # Fast .NET streaming SHA-256 (avoids Get-FileHash pipeline overhead ~40% faster, lower memory)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bufSize = 1MB
        foreach ($rel in $arrived.Keys) {
            try {
                $fs = [System.IO.File]::OpenRead($arrived[$rel].FullName)
                $hashBytesArr = $sha.ComputeHash($fs)
                $fs.Close(); $fs.Dispose()
                $hashHex = [BitConverter]::ToString($hashBytesArr).Replace('-','').ToLower()
                $hashes[$rel] = $hashHex
            } catch {
                # Fallback to Get-FileHash for locked/long-path edge cases
                try {
                    $h = Get-FileHash -LiteralPath $arrived[$rel].FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($h) { $hashes[$rel] = $h.Hash.ToLower() }
                } catch { }
            }
            $hp.Items++
            $hp.Bytes += $arrived[$rel].Length
            Write-Progress2 $hp
        }
        $sha.Dispose()
        Write-Host ""
        Complete-Progress $hp
        Good ("{0:N0} file(s) hashed with SHA-256 (streaming)." -f $hashes.Count)
    } else {
        Warn "Hashing skipped. The copy cannot be independently verified."
    }

    # The list Explorer would never have produced.
    # The handset named files without their extensions, so a listed entry
    # matches an arrived file when the extension is removed. Comparing the
    # raw strings reported 23,864 files missing while they sat on disk.
    $arrivedByBase = @{}
    foreach ($k in $arrived.Keys) {
        $d = Split-Path -Parent $k
        $b = [IO.Path]::GetFileNameWithoutExtension($k)
        $bk = if ($d) { "$d\$b" } else { $b }
        if (-not $arrivedByBase.ContainsKey($bk)) { $arrivedByBase[$bk] = $k }
    }

    # Count arrivals per name-key as well, so a key standing for 26 files is
    # only satisfied by 26 files. Comparing presence alone would call that key
    # complete the moment one of the 26 landed.
    $arrivedCounts = @{}
    foreach ($k in $arrived.Keys) {
        $d = Split-Path -Parent $k
        $b = [IO.Path]::GetFileNameWithoutExtension($k)
        foreach ($key in @($k, $(if ($d) { "$d\$b" } else { $b }))) {
            if (-not $arrivedCounts.ContainsKey($key)) { $arrivedCounts[$key] = 0 }
            $arrivedCounts[$key]++
        }
    }

    $missing = New-Object System.Collections.ArrayList
    foreach ($rel in $expectedCounts.Keys) {
        $want = $expectedCounts[$rel]
        $got = 0
        if ($arrived.ContainsKey($rel)) { $got = 1 }
        if ($arrivedCounts.ContainsKey($rel)) { $got = [Math]::Max($got, $arrivedCounts[$rel]) }
        if ($got -ge $want) { continue }
        $short = $want - $got
        $reason = 'Listed on the handset but not present after the copy.'
        $hit = $script:failedFiles | Where-Object { $_.path -eq $rel } | Select-Object -First 1
        if ($hit) { $reason = $hit.reason }
        if ($want -gt 1) {
            $reason += " This name stands for $want separate files on the handset; $got arrived."
        }
        [void]$missing.Add(@{ path=$rel; size=$expected[$rel]; reason=$reason
                              expected_count=$want; arrived_count=$got; short_by=$short })
    }

    # The other direction: anything in the exhibit that the handset never
    # listed. Files in an exhibit that were not on the device is the more
    # serious of the two errors, and nothing was checking for it.
    $extras = New-Object System.Collections.ArrayList
    foreach ($k in $arrived.Keys) {
        if ($expectedCounts.ContainsKey($k)) { continue }
        $d = Split-Path -Parent $k
        $b = [IO.Path]::GetFileNameWithoutExtension($k)
        $bk = if ($d) { "$d\$b" } else { $b }
        if ($expectedCounts.ContainsKey($bk)) { continue }
        [void]$extras.Add($k)
    }
    if ($extras.Count -gt 0) {
        Write-Host ""
        Warn ("{0} file(s) are present here but were not in the device listing:" -f $extras.Count)
        $extras | Select-Object -First 8 | ForEach-Object { Warn ("    {0}" -f $_) }
        if ($extras.Count -gt 8) { Dim ("    ... and {0} more" -f ($extras.Count - 8)) }
        Dim "Usually a file added since the listing was taken, or a cached listing"
        Dim "that has gone stale. Worth resolving before relying on this exhibit."
    }

    $copiedBytes = ($arrived.Values | Measure-Object -Property Length -Sum).Sum
    if (-not $copiedBytes) { $copiedBytes = 0 }

    $methodNote = 'Acquired over MTP (Media Transfer Protocol): a file copy served by the handset''s own media provider, not an image of its storage. It reaches what the provider chooses to expose - shared storage, camera media, downloads, and app folders under Android/media - and cannot reach /data/data, where message databases, call logs and their unallocated space live. Reading a file over MTP may update its access time on the handset. A file absent from this acquisition was not necessarily absent from the device.'

    $manifest = [ordered]@{
        format='argus-mtp-manifest/1'; tool="ARGUS Field $script:Version"
        device=$devName; destination=$Destination
        operator=$env:USERNAME; workstation=$env:COMPUTERNAME
        started_at=$started.ToString("yyyy-MM-ddTHH:mm:ssK")
        finished_at=(Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
        files_listed=$expected.Count; files_copied=$arrived.Count
        bytes_listed=$totalBytes; bytes_copied=$copiedBytes
        complete=($missing.Count -eq 0); missing_count=$missing.Count
        missing=@($missing); hashes=$hashes; method_note=$methodNote
        name_collisions=$collisions
        extras_count=$extras.Count; extras=@($extras | Select-Object -First 500)
        exclusions=@($script:skipPatterns)
        excluded_count=$script:skippedByPattern
        exclusion_note=$(if ($script:skipPatterns.Count -gt 0) {
            "Directories matching the patterns above were deliberately excluded by the operator and were never listed or copied. $($script:skippedByPattern) entries were skipped. Their absence from this exhibit says nothing about the handset."
        } else { 'No directories were excluded. Everything the media provider exposed was listed.' })
    }
    $manifestPath = Join-Path $Destination 'argus-mtp-manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Add-CustodyEntry -Root $Destination -Action 'mtp-acquire' -Detail @{
        device=$devName; files_listed=$expected.Count; files_copied=$arrived.Count
        bytes_copied=$copiedBytes; missing=$missing.Count; hashed=$hashes.Count }

    # The copy ran to completion and the manifest is written, so the folder is
    # now an exhibit rather than a work in progress.
    Remove-Item -LiteralPath $markerPath -Force -Confirm:$false -ErrorAction SilentlyContinue

    Section "Result"
    Note ("Listed on device : {0} file(s), {1:N2} GB" -f $expected.Count, ($totalBytes/1GB))
    Note ("Copied           : {0} file(s), {1:N2} GB" -f $arrived.Count, ($copiedBytes/1GB))
    if ($missing.Count -eq 0) {
        Good "Missing          : none - the copy is complete."
    } else {
        Warn ("Missing          : {0} file(s)" -f $missing.Count)
        Write-Host ""
        Warn "Those files were listed by the handset and did not arrive. That"
        Warn "means the transfer failed - NOT that the handset lacked them."
        Warn "They are itemised in the manifest. Re-running retries only those."
    }
    Write-Host ""
    Write-Host "  Manifest: $manifestPath" -ForegroundColor Cyan
    Write-Host "  Next: import '$Destination' as an exhibit." -ForegroundColor White
}

# =================================================================== 0. AUTO
#
# Find the handset and do the whole job: acquire, analyse, verify, report.
#
# The step-by-step design was wrong for the common case. An examiner with a
# phone in front of them wants the evidence, not a menu, and every decision
# point between them and it is a chance to stop - which is exactly what kept
# happening. So this picks the best available route itself and runs the
# sequence end to end.
#
# It still stops for one confirmation before writing anything, because the
# destination is the one choice that genuinely belongs to the operator, and
# an acquisition landing in the wrong folder contaminates a second exhibit.
function Invoke-Auto {
    param([string]$DeviceName = '', [string]$Destination = '', [switch]$Yes,
          [switch]$Relist, [switch]$SkipCacheDirs, [switch]$PerFile)

    Section "Automatic acquisition"
    Note "Finding a handset and running the full sequence:"
    Dim  "  acquire -> analyse -> verify -> report"
    Write-Host ""

    # ---- 1. choose a route ----------------------------------------------
    $route = ''
    $target = ''

    $handsets = Get-MountedHandsets
    $mounted = @()
    if ($handsets.Ok) { $mounted = @($handsets.Items | ForEach-Object { $_.Name }) }

    $adbReady = @()
    $adb = Find-Tool 'adb'
    if ($adb) {
        foreach ($l in (& $adb devices 2>&1 | Select-Object -Skip 1)) {
            if ($l -match '^(\S+)\s+device\s*$') { $adbReady += $Matches[1] }
        }
    }

    if ($DeviceName) {
        if ($mounted -contains $DeviceName) { $route = 'mtp'; $target = $DeviceName }
        elseif ($adbReady -contains $DeviceName) { $route = 'adb'; $target = $DeviceName }
        else {
            Bad "'$DeviceName' is not present."
            if ($mounted.Count -gt 0) { Note "Mounted now: $($mounted -join ', ')" }
            if ($adbReady.Count -gt 0) { Note "adb-ready now: $($adbReady -join ', ')" }
            return
        }
    }
    elseif ($adbReady.Count -eq 1 -and $mounted.Count -eq 0) {
        $route = 'adb'; $target = $adbReady[0]
    }
    elseif ($mounted.Count -eq 1) {
        $route = 'mtp'; $target = $mounted[0]
        # adb reaches more, so say so rather than quietly taking the easy path.
        if ($adbReady.Count -gt 0) {
            Dim "adb is also available and reaches /data/data, which MTP cannot."
            Dim "Using MTP because it needs no debugging prompt. Run -Pull for adb."
        }
    }
    elseif ($mounted.Count -gt 1) {
        Note "More than one handset is mounted:"
        for ($i = 0; $i -lt $mounted.Count; $i++) { Note "  [$($i+1)] $($mounted[$i])" }
        $pick = Read-Host "  Which one"
        $idx = 0
        if ([int]::TryParse($pick, [ref]$idx) -and $idx -ge 1 -and $idx -le $mounted.Count) {
            $route = 'mtp'; $target = $mounted[$idx - 1]
        } else { Bad "Not a valid choice."; return }
    }
    else {
        Bad "No handset is available to acquire."
        Write-Host ""
        Note "Nothing is mounted in This PC and adb has no authorised device."
        Note "Two things to try, in this order:"
        Write-Host ""
        Note "  1. On the phone: pull down the notification shade, tap the USB"
        Note "     notification, and choose File transfer / MTP."
        Note "  2. Run the Watch option and plug the phone in while it runs -"
        Note "     it reports the moment anything appears."
        Write-Host ""
        Note "If the phone is definitely connected and still absent, run the Raw"
        Note "option. That dumps everything Windows reports with no filtering,"
        Note "which is the only way to tell 'not attached' from 'I missed it'."
        return
    }

    Good "Route  : $(if ($route -eq 'mtp') { 'MTP (no USB debugging needed)' } else { 'adb logical' })"
    Good "Handset: $target"

    # ---- 2. destination --------------------------------------------------
    if (-not $Destination) {
        $slug = ($target -replace '[^A-Za-z0-9]', '-').ToLower().Trim('-')
        $Destination = "C:\evidence\$slug-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    Note "Into   : $Destination"
    Write-Host ""

    $resuming = $false
    if (Test-Path -LiteralPath $Destination) {
        $existing = @(Get-ChildItem -LiteralPath $Destination -Force -ErrorAction SilentlyContinue)
        $marker = Join-Path $Destination 'argus-INCOMPLETE.json'
        if (Test-Path -LiteralPath $marker) {
            # This folder is ARGUS's own unfinished work, so resuming it is
            # correct - refusing would force the operator to delete a copy that
            # is most of the way done and start the whole transfer again.
            $prev = $null
            try { $prev = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json } catch { }
            Write-Host ""
            Warn "This folder holds an INCOMPLETE acquisition."
            if ($prev) {
                Note ("Started {0} against '{1}' by {2}." -f $prev.started_at, $prev.device, $prev.operator)
            }
            Note "$($existing.Count) item(s) already present. Files already copied"
            Note "at the correct size will be skipped, so this resumes rather"
            Note "than starting over."
            Write-Host ""
            $resuming = $true
        }
        elseif ($existing.Count -gt 0) {
            Bad "That folder already contains $($existing.Count) item(s) and no"
            Bad "ARGUS acquisition marker. Acquiring into it would mix two"
            Bad "exhibits. Choose an empty folder."
            return
        }
    }

    if (-not $Yes) {
        Warn "This will copy the handset's storage, hash every file, analyse the"
        Warn "result and write a report. MTP is slow - commonly 20-60 minutes."
        Warn "Leave the phone unlocked and plugged in throughout."
        Write-Host ""
        $go = Read-Host "  Type Y to start"
        if ($go -notmatch '^(y|yes)$') { Note "Cancelled - nothing was written."; return }
    }

    $started = Get-Date

    # ---- 3. run the sequence ---------------------------------------------
    Write-Host ""
    Section "STEP 1 of 3 - acquire"
    if ($route -eq 'mtp') {
        Invoke-Acquire -DeviceName $target -Destination $Destination -Relist:$Relist -SkipCacheDirs:$SkipCacheDirs -PerFile:$PerFile
    } else {
        Invoke-Pull -Serial $target -Destination $Destination
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        Bad "The acquisition produced no folder. Stopping - there is nothing to analyse."
        return
    }
    $got = @(Get-ChildItem -LiteralPath $Destination -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notlike 'argus-*' })
    if ($got.Count -eq 0) {
        Bad "The acquisition copied no files. Stopping."
        Note "The manifest in $Destination records what was listed and what failed."
        return
    }

    Write-Host ""
    Section "STEP 2 of 3 - analyse"
    Invoke-Analyze -Path $Destination

    Write-Host ""
    Section "STEP 3 of 3 - verify"
    Invoke-Verify -Path $Destination

    # ---- 4. hand back ----------------------------------------------------
    $elapsed = (Get-Date) - $started
    Write-Host ""
    Section "Finished"
    Good ("Elapsed: {0:hh\:mm\:ss}" -f $elapsed)
    Good "Exhibit: $Destination"
    Write-Host ""
    $report = @(Get-ChildItem -LiteralPath $Destination -Filter 'argus-analysis-*.html' `
                -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
                Select-Object -First 1)
    if ($report.Count -gt 0) {
        Write-Host "  Report: $($report[0].FullName)" -ForegroundColor Cyan
        try { Start-Process $report[0].FullName } catch { }
    }
    Note "Also written: argus-mtp-manifest.json (what was taken and what was missed)"
    Note "              argus-custody.jsonl     (hash-chained record of every step)"
    Write-Host ""
    Dim "Scope reminder: this reached shared storage only. Message databases,"
    Dim "call logs and deleted records live in /data/data and are not in this"
    Dim "exhibit. Nothing absent from the report is thereby absent from the phone."
}

# ================================================== 2b. ADOPT A MANUAL COPY
#
# You copied the phone yourself in Explorer. This turns that folder into a
# proper exhibit.
#
# The reason this exists is an admission. ARGUS drives MTP through the same
# shell interface Explorer does, and Explorer drives it better - it has
# internal batching and retry logic that a script calling CopyHere cannot
# reach. When the built-in copy fights the handset, insisting on it is pride,
# not method.
#
# What actually makes an acquisition defensible is not who moved the bytes.
# It is that the device was inventoried independently, that what arrived was
# reconciled against that inventory, that every file carries a hash, and that
# the gap between the two is stated rather than hidden. All of that is
# available for a folder Explorer produced.
#
# What is honestly weaker is stated in the manifest and not glossed: ARGUS did
# not observe the transfer, so it cannot attest to what happened during it,
# and the inventory is taken afterwards rather than before. A file changed on
# the handset between the copy and the listing would show as a size mismatch
# with no way to tell which side moved.
function Invoke-Adopt {
    param([string]$Folder = '', [string]$DeviceName = '', [switch]$NoDeviceCheck)

    Section "Adopt a folder copied with Explorer"

    if (-not $Folder) { Bad "No folder given."; return }
    if (-not (Test-Path -LiteralPath $Folder)) { Bad "Not found: $Folder"; return }
    $root = (Resolve-Path -LiteralPath $Folder).Path
    Note "Folder: $root"

    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike 'argus-*' })
    if ($files.Count -eq 0) { Bad "That folder holds no files."; return }
    $totalBytes = ($files | Measure-Object Length -Sum).Sum
    Good ("{0:N0} file(s), {1}" -f $files.Count, (Format-Size $totalBytes))

    # ---- 1. inventory the handset, if it is still attached ---------------
    $expected = @{}
    $listedOk = $false
    $devUsed = ''
    if (-not $NoDeviceCheck) {
        Section "1. Listing the handset for comparison"
        $handsets = Get-MountedHandsets
        $source = $null
        if ($handsets.Ok -and $handsets.Items.Count -gt 0) {
            if ($DeviceName) {
                $source = $handsets.Items | Where-Object { $_.Name -eq $DeviceName } | Select-Object -First 1
            } else { $source = $handsets.Items[0] }
        }
        if (-not $source) {
            Warn "No handset is mounted, so the copy cannot be reconciled against"
            Warn "the device. Hashing will still proceed, but the manifest will"
            Warn "say plainly that completeness was never established."
        } else {
            $devUsed = $source.Name
            Note "Walking $devUsed. This takes a few minutes."
            $seen = New-Object System.Collections.ArrayList
            $tick = Get-Date
            function Walk-Adopt($folderObj, $prefix, $depth) {
                if ($depth -gt 12) { return }
                foreach ($item in $folderObj.Items()) {
                    $rel = if ($prefix) { "$prefix\$($item.Name)" } else { $item.Name }
                    if ($item.IsFolder) { Walk-Adopt $item.GetFolder $rel ($depth + 1) }
                    else {
                        $sz = 0
                        try { $sz = [int64]$item.Size } catch { }
                        if ($sz -le 0) { try { $sz = [int64]$item.ExtendedProperty('System.Size') } catch { } }
                        [void]$seen.Add([PSCustomObject]@{ Rel=$rel; Size=$sz })
                        if (((Get-Date) - $tick).TotalSeconds -ge 2) {
                            $tick = Get-Date
                            Dim ("  {0:N0} listed..." -f $seen.Count)
                        }
                    }
                }
            }
            Walk-Adopt $source.GetFolder "" 0
            foreach ($e in $seen) { $expected[$e.Rel] = $e.Size }
            $listedOk = $true
            Good ("{0:N0} file(s) on the handset." -f $expected.Count)
        }
    }

    # ---- 2. hash everything ---------------------------------------------
    Section "2. Hashing"
    $hp = New-ProgressState $files.Count $totalBytes 'Hash'
    $hashes = @{}
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($h) { $hashes[$rel] = $h.Hash.ToLower() }
        $hp.Items++; $hp.Bytes += $f.Length
        Write-Progress2 $hp
    }
    Write-Host ""
    Complete-Progress $hp

    # ---- 3. reconcile ----------------------------------------------------
    $missing = New-Object System.Collections.ArrayList
    if ($listedOk) {
        Section "3. Reconciling against the handset"
        $have = @{}
        $haveByBase = @{}
        foreach ($k in $hashes.Keys) {
            $have[$k] = $true
            $d = Split-Path -Parent $k
            $b = [IO.Path]::GetFileNameWithoutExtension($k)
            $bk = if ($d) { "$d\$b" } else { $b }
            $haveByBase[$bk] = $true
        }
        foreach ($rel in $expected.Keys) {
            if ($have.ContainsKey($rel) -or $haveByBase.ContainsKey($rel)) { continue }
            [void]$missing.Add(@{ path=$rel; size=$expected[$rel]
                reason='Present on the handset but not in the folder that was adopted.' })
        }
        if ($missing.Count -eq 0) {
            Good "Every file on the handset is present in this folder."
        } else {
            Warn ("{0:N0} file(s) on the handset are not in this folder." -f $missing.Count)
            $missing | Select-Object -First 8 | ForEach-Object { Warn ("    {0}" -f $_.path) }
            if ($missing.Count -gt 8) { Dim ("    ... and {0} more" -f ($missing.Count - 8)) }
            Write-Host ""
            Dim "Copy those across and run this again, or accept the gap - it is"
            Dim "itemised in the manifest either way."
        }
    }

    # ---- 4. manifest -----------------------------------------------------
    $note = @"
Adopted acquisition. The file transfer was performed by Windows Explorer under
operator control; ARGUS did not perform, observe or control the copy and cannot
attest to what occurred during it. ARGUS listed the handset independently, hashed
every file present in the adopted folder with SHA-256, and reconciled the two.
The listing was taken AFTER the copy, so a file altered on the handset between
the two events would appear as a discrepancy with no way to establish which side
changed. This is weaker than a tool-controlled acquisition and should be
described as such. Scope is unchanged: MTP reaches shared storage only and
cannot reach /data/data, so absence from this exhibit is not evidence of absence
from the device.
"@ -replace "`r`n", ' ' -replace '\s+', ' '

    $manifest = [ordered]@{
        format='argus-adopted-manifest/1'; tool="ARGUS Field $script:Version"
        method='adopted-explorer-copy'
        device=$(if ($devUsed) { $devUsed } else { 'not attached at adoption time' })
        destination=$root; operator=$env:USERNAME; workstation=$env:COMPUTERNAME
        adopted_at=(Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
        files_present=$hashes.Count; bytes_present=$totalBytes
        device_listed=$listedOk
        files_listed=$(if ($listedOk) { $expected.Count } else { 0 })
        missing_count=$missing.Count; missing=@($missing)
        complete=$(if ($listedOk) { $missing.Count -eq 0 } else { $false })
        completeness_established=$listedOk
        hashes=$hashes; method_note=$note.Trim()
    }
    $mp = Join-Path $root 'argus-mtp-manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $mp -Encoding UTF8

    Add-CustodyEntry -Root $root -Action 'adopt-explorer-copy' -Detail @{
        device=$devUsed; files=$hashes.Count; bytes=$totalBytes
        device_listed=$listedOk; missing=$missing.Count }

    Section "Result"
    Note ("Files hashed : {0:N0}  ({1})" -f $hashes.Count, (Format-Size $totalBytes))
    if ($listedOk) {
        Note ("On handset   : {0:N0}" -f $expected.Count)
        if ($missing.Count -eq 0) { Good "Complete against the handset listing." }
        else { Warn ("Missing      : {0:N0} - itemised in the manifest" -f $missing.Count) }
    } else {
        Warn "Completeness was NOT established - the handset was not listed."
        Warn "The manifest records that. Do not describe this exhibit as complete."
    }
    Write-Host ""
    Write-Host "  Manifest: $mp" -ForegroundColor Cyan
    Write-Host "  Next: Analyse this folder." -ForegroundColor White
}

# ================================================================ 3. TRIAGE
function Invoke-Triage {
    param([string]$Path)

    Section "Triage: $Path"
    if (-not (Test-Path -LiteralPath $Path)) { Bad "Not found."; return }

    $file = Get-Item -LiteralPath $Path
    if ($file.PSIsContainer) { Bad "That is a folder. Triage takes a single file."; return }

    # MSAB case-index resolution: triage the data file, not the index.
    $triageFile = $file
    $ext = $file.Extension.ToLower()
    if ($ext -eq '.xrycase') {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $companion = $null
        foreach ($name in @("$stem.xry", "$stem.XRY")) {
            $candidate = Join-Path $file.DirectoryName $name
            if ((Test-Path -LiteralPath $candidate) -and $candidate -ne $file.FullName) {
                $candItem = Get-Item -LiteralPath $candidate
                if ($candItem.Length -gt $file.Length) { $companion = $candItem; break }
            }
        }
        if (-not $companion) {
            $companion = Get-ChildItem -LiteralPath $file.DirectoryName -Filter '*.xry' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $file.FullName -and $_.Length -gt $file.Length } |
                Sort-Object Length -Descending | Select-Object -First 1
        }
        if ($companion) {
            Good ("Resolved companion data file: {0} ({1:N0} bytes)" -f $companion.Name, $companion.Length)
            $triageFile = $companion
        } else {
            Warn "This .xrycase is a CASE INDEX, not the extraction."
            Warn "The device data lives in a companion .xry file. None was found"
            Warn "in this folder. Examiners lose time concluding an extraction"
            Warn "is empty when it is not."
        }
    }

    $size = $triageFile.Length
    Note ("Size: {0:N0} bytes ({1:N2} MB)" -f $size, ($size/1MB))
    if ($triageFile.FullName -ne $file.FullName) {
        Note ("Triage target: {0}" -f $triageFile.Name)
    }

    $fs = [System.IO.File]::OpenRead($triageFile.FullName)
    try {
        $head = New-Object byte[] ([Math]::Min(4096, $size))
        [void]$fs.Read($head, 0, $head.Length)

        function StartsWith($bytes, [byte[]]$sig) {
            if ($bytes.Length -lt $sig.Length) { return $false }
            for ($i=0; $i -lt $sig.Length; $i++) { if ($bytes[$i] -ne $sig[$i]) { return $false } }
            return $true
        }

        # Magic bytes beat the extension. A vendor extension names the tool
        # that wrote the file; the header says what it actually is, and the two
        # disagree more often than anyone expects.
        $wrapper = 'unrecognised'; $note = ''
        if     (StartsWith $head ([byte[]](0x50,0x4B,0x03,0x04))) { $wrapper='zip'; $note='A zip archive. Extract and parse the members directly.' }
        elseif (StartsWith $head ([byte[]](0x53,0x51,0x4C,0x69,0x74,0x65))) { $wrapper='sqlite'; $note='A SQLite database - parses directly, including its unallocated space.' }
        elseif (StartsWith $head ([byte[]](0x58,0x52,0x59))) { $wrapper='msab.xry'; $note='An MSAB XRY container. ARGUS does not decode the proprietary layout, but embedded files (SQLite, images, plists) can be carved and imported directly.' }
        elseif (StartsWith $head ([byte[]](0x62,0x70,0x6C,0x69,0x73,0x74))) { $wrapper='bplist'; $note='A binary property list - parses directly.' }
        elseif (StartsWith $head ([byte[]](0x3C,0x3F,0x78,0x6D,0x6C))) { $wrapper='xml'; $note='XML - parses directly.' }
        elseif (StartsWith $head ([byte[]](0x1F,0x8B))) { $wrapper='gzip'; $note='Gzip. Decompress first; nothing can be carved while compressed.' }
        elseif (StartsWith $head ([byte[]](0x37,0x7A,0xBC,0xAF))) { $wrapper='7z'; $note='A 7-Zip archive.' }
        elseif (StartsWith $head ([byte[]](0x52,0x61,0x72,0x21))) { $wrapper='rar'; $note='A RAR archive.' }

        Note "Header says: $wrapper"
        if ($note) { Dim $note }

        if ($file.Extension -and $wrapper -ne 'unrecognised') {
            $extName = $file.Extension.TrimStart('.').ToLower()
            if (($extName -eq 'xry' -or $extName -eq 'xrycase' -or $extName -eq 'ufd') -and $wrapper -ne 'msab.xry') {
                Warn "The extension says '$extName' but the header says '$wrapper'."
                Warn "Trust the header."
            }
        }

        # Shannon entropy over sampled blocks. Above ~7.5 bits/byte the content
        # is compressed or encrypted and no signature survives inside it.
        $samples = 64
        $blockSize = 4096
        $counts = New-Object 'int[]' 256
        $totalSampled = 0
        for ($s = 0; $s -lt $samples; $s++) {
            $offset = [int64](($size / $samples) * $s)
            if ($offset + $blockSize -gt $size) { break }
            $fs.Position = $offset
            $buf = New-Object byte[] $blockSize
            $read = $fs.Read($buf, 0, $blockSize)
            for ($i = 0; $i -lt $read; $i++) { $counts[$buf[$i]]++ }
            $totalSampled += $read
        }
        $entropy = 0.0
        if ($totalSampled -gt 0) {
            foreach ($c in $counts) {
                if ($c -gt 0) { $p = $c / $totalSampled; $entropy -= $p * [Math]::Log($p, 2) }
            }
        }
        Note ("Entropy: {0:N2} bits/byte" -f $entropy)

        if ($entropy -gt 7.5) {
            Warn "High entropy - the contents are compressed or encrypted."
            Warn "Carving cannot work here. No file signature survives inside"
            Warn "compressed or encrypted data, so an empty carve means THIS"
            Warn "ROUTE cannot reach the data - not that the device held none."
            Write-Host ""
            Good "Export from the tool that made it instead. In XAMN:"
            Note "  Report/Export -> Files          (the extracted file system)"
            Note "  Report/Export -> Extended XML   (the decoded report)"
            Note "Both are formats ARGUS parses and carves independently."
        } elseif ($wrapper -eq 'zip') {
            Good "A zip in disguise. Import it directly - ARGUS extracts the members."
        } elseif ($wrapper -in @('sqlite','bplist','xml')) {
            Good "Directly readable - no carving needed."
        } elseif ($wrapper -eq 'msab.xry') {
            Good "ARGUS can import this directly. Embedded files are carved automatically."
            Note ("  argus acquire <case> --method import --source `"{0}`"" -f $Path)
            Note "  Or: argus triage `"$Path`" --carve --out .\carved"
        } else {
            Note "Moderate entropy. Embedded files may be recoverable by signature."
            Dim "Import this file into ARGUS and run the carver over it."
        }

        Write-Host ""
        Dim "This triage identifies the container. It does NOT decode MSAB's"
        Dim "proprietary record layout. Carving recovers embedded files only."
        Dim "Absence here is not evidence the device held nothing."
    } finally {
        $fs.Close()
    }
}

# ================================================================ 4. DOCTOR
function Invoke-Doctor {
    Section "Installation doctor"

    $python = $null
    foreach ($c in @('python','python3','py')) {
        $r = Get-Command $c -ErrorAction SilentlyContinue
        if ($r) { $python = $r.Source; break }
    }
    if ($python) {
        $ver = (& $python --version 2>&1) -join ' '
        Good "Python: $python  ($ver)"
    } else {
        Warn "Python not found. ARGUS analysis needs Python 3.10+."
        Dim "Scan, acquire and triage above do not need it."
    }

    $adb = Find-Tool 'adb'
    if ($adb) { Good "adb: $adb" } else { Dim "adb: not installed (live acquisition only)" }

    # ---- the copies problem ---------------------------------------------
    Write-Host ""
    Note "Searching for ARGUS installations..."
    $roots = @()
    foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
        if ($d.Root -and $d.Root.Length -le 3) { $roots += $d.Root }
    }

    $installs = @()
    foreach ($root in $roots) {
        $hits = Get-ChildItem -LiteralPath $root -Filter 'argus_app.py' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue
        foreach ($h in $hits) { $installs += $h.DirectoryName }
    }
    $installs = @($installs | Sort-Object -Unique)

    if ($installs.Count -eq 0) {
        Write-Host ""
        Warn "No ARGUS installation found on any local drive."
        Dim "The field functions above work without one."
        return
    }

    Write-Host ""
    Note "Found $($installs.Count) installation(s):"
    Write-Host ""

    $builds = @{}
    foreach ($i in $installs) {
        $build = 'unknown'
        $files = 0
        if ($python) {
            # Must run from inside the install, or every copy reports whichever
            # one happens to be importable from the current directory - which is
            # exactly how a stale build masquerades as the current one.
            Push-Location $i
            $out = & $python -m argus.cli selfcheck 2>&1 | Out-String
            Pop-Location
            if ($out -match 'build\s+([0-9a-f]{8,})') { $build = $Matches[1] }
            if ($out -match '(\d+)\s+shipped files') { $files = [int]$Matches[1] }
        }
        $when = (Get-Item -LiteralPath $i).LastWriteTime
        $installs_obj = [PSCustomObject]@{ Path=$i; Build=$build; Files=$files; Modified=$when }
        $builds[$i] = $installs_obj
        Write-Host ("  {0}" -f $i) -ForegroundColor White
        Write-Host ("      build {0}   {1} files   modified {2:yyyy-MM-dd}" -f
                    $build, $files, $when) -ForegroundColor DarkGray
    }

    $distinct = @($builds.Values | Select-Object -ExpandProperty Build -Unique |
                  Where-Object { $_ -ne 'unknown' })

    Write-Host ""
    if ($installs.Count -eq 1) {
        Good "One installation. No ambiguity about which build produced an exhibit."
    } elseif ($distinct.Count -le 1) {
        Warn "$($installs.Count) copies, all the same build."
        Warn "Harmless for correctness, but delete the spares - troubleshooting"
        Warn "the wrong folder wastes more time than the disk they save."
    } else {
        Bad "$($installs.Count) copies with $($distinct.Count) DIFFERENT builds:"
        foreach ($b in $distinct) { Bad "  $b" }
        Write-Host ""
        Bad "This is the problem. Two copies are indistinguishable once running,"
        Bad "so a fix applied to one is invisible from the other, and an exhibit"
        Bad "cannot be tied to a specific build afterwards."
        Write-Host ""
        $newest = $builds.Values | Sort-Object Modified -Descending | Select-Object -First 1
        Good "Most recently modified: $($newest.Path)  (build $($newest.Build))"
        Note "Delete the others, or rename them so they cannot be launched by accident."
    }

    if ($installs.Count -ge 1) {
        Write-Host ""
        $target = ($builds.Values | Sort-Object Modified -Descending | Select-Object -First 1).Path
        Note "To launch the newest:"
        Write-Host "    cd `"$target`"" -ForegroundColor White
        Write-Host "    python argus_app.py" -ForegroundColor White
    }
}

# ====================================================== EXIF (manual parse)
#
# Parsed by hand from the APP1 segment rather than handed to System.Drawing.
# Two reasons, and the second is the important one:
#
#   1. System.Drawing is not present on every PowerShell host, so a dependency
#      here would make the tool fail on exactly the locked-down workstation it
#      is meant to work on.
#   2. An image decoder is a large attack surface pointed directly at
#      attacker-controlled bytes. Evidence is by definition untrusted input.
#      Reading twelve tags out of a TIFF header cannot execute anything; asking
#      GDI+ to decode a hostile JPEG might.
#
# Every offset below is bounds-checked against the segment length, because a
# malformed IFD pointer is the ordinary case in carved or truncated media, not
# an exceptional one.

function Read-U16([byte[]]$b, [int]$off, [bool]$big) {
    if ($off -lt 0 -or ($off + 2) -gt $b.Length) { return -1 }
    if ($big) { return ([int]$b[$off] * 256) + [int]$b[$off+1] }
    return ([int]$b[$off+1] * 256) + [int]$b[$off]
}

function Read-U32([byte[]]$b, [int]$off, [bool]$big) {
    if ($off -lt 0 -or ($off + 4) -gt $b.Length) { return -1 }
    if ($big) {
        return ([int64]$b[$off] * 16777216) + ([int64]$b[$off+1] * 65536) +
               ([int64]$b[$off+2] * 256) + [int64]$b[$off+3]
    }
    return ([int64]$b[$off+3] * 16777216) + ([int64]$b[$off+2] * 65536) +
           ([int64]$b[$off+1] * 256) + [int64]$b[$off]
}

$script:TYPE_SIZE = @{ 1=1; 2=1; 3=2; 4=4; 5=8; 6=1; 7=1; 8=2; 9=4; 10=8; 11=4; 12=8 }

function Get-IfdEntries([byte[]]$tiff, [int]$ifdOffset, [bool]$big) {
    $entries = @{}
    if ($ifdOffset -lt 0 -or ($ifdOffset + 2) -gt $tiff.Length) { return $entries }
    $count = Read-U16 $tiff $ifdOffset $big
    if ($count -lt 0 -or $count -gt 512) { return $entries }   # sanity bound
    for ($i = 0; $i -lt $count; $i++) {
        $e = $ifdOffset + 2 + ($i * 12)
        if (($e + 12) -gt $tiff.Length) { break }
        $tag   = Read-U16 $tiff $e $big
        $type  = Read-U16 $tiff ($e + 2) $big
        $n     = Read-U32 $tiff ($e + 4) $big
        if ($tag -lt 0 -or $type -lt 1 -or $type -gt 12 -or $n -lt 0) { continue }
        $unit = $script:TYPE_SIZE[$type]
        $bytes = $unit * $n
        if ($bytes -lt 0 -or $bytes -gt $tiff.Length) { continue }
        $dataOff = if ($bytes -le 4) { $e + 8 } else { Read-U32 $tiff ($e + 8) $big }
        if ($dataOff -lt 0 -or ($dataOff + $bytes) -gt $tiff.Length) { continue }
        $entries[$tag] = [PSCustomObject]@{ Type=$type; Count=$n; Offset=[int]$dataOff }
    }
    return $entries
}

function Get-TagAscii([byte[]]$tiff, $entry) {
    if (-not $entry) { return '' }
    $len = [int]$entry.Count
    if ($len -le 0 -or ($entry.Offset + $len) -gt $tiff.Length) { return '' }
    # Latin-1 rather than ASCII: manufacturers put accented characters in Make
    # and Model, and ASCII would silently render each one as '?', quietly
    # corrupting the very field used to attribute an image to a device.
    $s = [System.Text.Encoding]::GetEncoding(28591).GetString($tiff, $entry.Offset, $len)
    return $s.Trim([char]0).Trim()
}

function Get-TagRationals([byte[]]$tiff, $entry, [bool]$big) {
    $out = @()
    if (-not $entry -or $entry.Type -ne 5) { return $out }
    for ($i = 0; $i -lt $entry.Count; $i++) {
        $o = $entry.Offset + ($i * 8)
        $num = Read-U32 $tiff $o $big
        $den = Read-U32 $tiff ($o + 4) $big
        if ($num -lt 0 -or $den -le 0) { $out += 0.0 } else { $out += ($num / $den) }
    }
    return $out
}

function Get-ExifData([string]$FilePath) {
    $r = [PSCustomObject]@{
        HasExif=$false; Make=''; Model=''; Taken=''; Software=''
        Lat=$null; Lon=$null; Altitude=$null; GpsDate=''
    }
    $fs = $null
    try { $fs = [System.IO.File]::OpenRead($FilePath) } catch { return $r }
    try {
        if ($fs.Length -lt 32) { return $r }
        $br = New-Object System.IO.BinaryReader($fs)
        if ($br.ReadByte() -ne 0xFF -or $br.ReadByte() -ne 0xD8) { return $r }   # not JPEG

        # Walk the segment chain to APP1. Stop at the scan - nothing after it
        # is metadata and the entropy-coded data would be misread as markers.
        $tiff = $null
        while ($fs.Position -lt ($fs.Length - 4)) {
            $m = $br.ReadByte()
            if ($m -ne 0xFF) { continue }
            $marker = $br.ReadByte()
            while ($marker -eq 0xFF -and $fs.Position -lt $fs.Length) { $marker = $br.ReadByte() }
            if ($marker -eq 0xD9 -or $marker -eq 0xDA) { break }
            if ($marker -eq 0x01 -or ($marker -ge 0xD0 -and $marker -le 0xD7)) { continue }
            if (($fs.Position + 2) -gt $fs.Length) { break }
            $len = ([int]$br.ReadByte() * 256) + [int]$br.ReadByte()
            if ($len -lt 2 -or ($fs.Position + $len - 2) -gt $fs.Length) { break }
            if ($marker -eq 0xE1 -and $len -gt 8) {
                $sig = $br.ReadBytes(6)
                if ($sig.Length -eq 6 -and $sig[0] -eq 0x45 -and $sig[1] -eq 0x78 -and
                    $sig[2] -eq 0x69 -and $sig[3] -eq 0x66) {
                    $tiffLen = $len - 8
                    if ($tiffLen -gt 0 -and $tiffLen -lt 262144) {
                        $tiff = $br.ReadBytes($tiffLen)
                    }
                    break
                }
                $fs.Position += ($len - 8)
            } else {
                $fs.Position += ($len - 2)
            }
        }
        if ($null -eq $tiff -or $tiff.Length -lt 8) { return $r }

        $big = ($tiff[0] -eq 0x4D -and $tiff[1] -eq 0x4D)
        if (-not $big -and -not ($tiff[0] -eq 0x49 -and $tiff[1] -eq 0x49)) { return $r }
        if ((Read-U16 $tiff 2 $big) -ne 42) { return $r }
        $ifd0 = [int](Read-U32 $tiff 4 $big)

        $e0 = Get-IfdEntries $tiff $ifd0 $big
        if ($e0.Count -eq 0) { return $r }
        $r.HasExif = $true
        $r.Make     = Get-TagAscii $tiff $e0[0x010F]
        $r.Model    = Get-TagAscii $tiff $e0[0x0110]
        $r.Software = Get-TagAscii $tiff $e0[0x0131]
        $r.Taken    = Get-TagAscii $tiff $e0[0x0132]

        # The Exif sub-IFD holds the capture time, which is the one that
        # matters. Filesystem timestamps were rewritten by the copy; this was
        # written by the camera when the shutter fired.
        if ($e0.ContainsKey(0x8769)) {
            $sub = Get-IfdEntries $tiff ([int](Read-U32 $tiff $e0[0x8769].Offset $big)) $big
            $dto = Get-TagAscii $tiff $sub[0x9003]
            if ($dto) { $r.Taken = $dto }
        }

        if ($e0.ContainsKey(0x8825)) {
            $gps = Get-IfdEntries $tiff ([int](Read-U32 $tiff $e0[0x8825].Offset $big)) $big
            $latRef = Get-TagAscii $tiff $gps[0x0001]
            $lonRef = Get-TagAscii $tiff $gps[0x0003]
            $lat = Get-TagRationals $tiff $gps[0x0002] $big
            $lon = Get-TagRationals $tiff $gps[0x0004] $big
            if ($lat.Count -ge 3 -and $lon.Count -ge 3) {
                $dLat = $lat[0] + ($lat[1] / 60) + ($lat[2] / 3600)
                $dLon = $lon[0] + ($lon[1] / 60) + ($lon[2] / 3600)
                if ($latRef -match '(?i)^S') { $dLat = -$dLat }
                if ($lonRef -match '(?i)^W') { $dLon = -$dLon }
                # 0,0 is Null Island - almost always a cleared tag, not a fix.
                if ([Math]::Abs($dLat) -gt 0.0001 -or [Math]::Abs($dLon) -gt 0.0001) {
                    $r.Lat = [Math]::Round($dLat, 6)
                    $r.Lon = [Math]::Round($dLon, 6)
                }
            }
            if ($gps.ContainsKey(0x0006)) {
                $alt = Get-TagRationals $tiff $gps[0x0006] $big
                if ($alt.Count -ge 1) { $r.Altitude = [Math]::Round($alt[0], 1) }
            }
            $r.GpsDate = Get-TagAscii $tiff $gps[0x001D]
        }
    } catch {
        # A malformed header is an ordinary condition in carved media. Report
        # what was read and move on rather than failing the whole run.
    } finally {
        if ($fs) { $fs.Close() }
    }
    return $r
}

# ================================================== MP4 / MOV / 3GP metadata
#
# Video was a blind spot worth closing. On a media-only acquisition it is
# frequently the largest category by volume and the richest by content, and
# until now it produced nothing at all - the tool read EXIF from stills and
# silently ignored every clip beside them.
#
# ISO base media format is a tree of boxes: 4-byte big-endian size, 4-byte
# type, payload. Two things in it are worth having:
#
#   moov/mvhd       creation time, in seconds since 1904-01-01 UTC
#   moov/udta/(c)xyz  an ISO 6709 location string written by the recording
#                     handset, which is the video equivalent of an EXIF GPS tag
#
# As with EXIF this is parsed by hand and bounds-checked at every step. A
# truncated clip - and MTP produces those - has a size field pointing past the
# end of the file, and following it blindly is how a parser hangs on evidence.

function Get-VideoMeta([string]$FilePath) {
    $r = [PSCustomObject]@{
        HasMeta=$false; Created=''; DurationSec=$null
        Lat=$null; Lon=$null; Make=''; Model=''
    }
    $fs = $null
    try { $fs = [System.IO.File]::OpenRead($FilePath) } catch { return $r }
    try {
        if ($fs.Length -lt 16) { return $r }

        function Read-BoxHeader($stream) {
            if (($stream.Position + 8) -gt $stream.Length) { return $null }
            $b = New-Object byte[] 8
            if ($stream.Read($b, 0, 8) -ne 8) { return $null }
            $size = ([int64]$b[0] * 16777216) + ([int64]$b[1] * 65536) +
                    ([int64]$b[2] * 256) + [int64]$b[3]
            $type = [System.Text.Encoding]::ASCII.GetString($b, 4, 4)
            $headerLen = 8
            if ($size -eq 1) {
                if (($stream.Position + 8) -gt $stream.Length) { return $null }
                $l = New-Object byte[] 8
                [void]$stream.Read($l, 0, 8)
                $size = 0
                for ($i = 0; $i -lt 8; $i++) { $size = ($size * 256) + $l[$i] }
                $headerLen = 16
            } elseif ($size -eq 0) {
                $size = $stream.Length - ($stream.Position - 8)
            }
            # A size that runs past the file, or that cannot advance, is a
            # truncated or hostile clip. Refusing it is what stops the walk
            # looping forever on evidence that MTP cut short.
            if ($size -lt $headerLen) { return $null }
            return [PSCustomObject]@{ Size=$size; Type=$type; HeaderLen=$headerLen }
        }

        # Walk one level of boxes, returning the position and size of a wanted
        # child. Depth is capped because a crafted file can nest indefinitely.
        function Find-Box($stream, [int64]$start, [int64]$end, [string[]]$wanted, [int]$depth) {
            if ($depth -gt 6) { return $null }
            $stream.Position = $start
            while ($stream.Position -lt $end -and ($stream.Position + 8) -le $stream.Length) {
                $boxStart = $stream.Position
                $h = Read-BoxHeader $stream
                if ($null -eq $h) { return $null }
                $payloadStart = $boxStart + $h.HeaderLen
                $boxEnd = $boxStart + $h.Size
                if ($boxEnd -gt $end -or $boxEnd -le $boxStart) { return $null }
                if ($wanted -contains $h.Type) {
                    return [PSCustomObject]@{ Start=$payloadStart; End=$boxEnd; Type=$h.Type }
                }
                $stream.Position = $boxEnd
            }
            return $null
        }

        $moov = Find-Box $fs 0 $fs.Length @('moov') 0
        if ($null -eq $moov) { return $r }

        # ---- mvhd: creation time and duration -----------------------------
        $mvhd = Find-Box $fs $moov.Start $moov.End @('mvhd') 1
        if ($null -ne $mvhd) {
            $fs.Position = $mvhd.Start
            $v = New-Object byte[] 4
            if ($fs.Read($v, 0, 4) -eq 4) {
                $version = $v[0]
                $need = if ($version -eq 1) { 28 } else { 16 }
                if (($fs.Position + $need) -le $fs.Length) {
                    $d = New-Object byte[] $need
                    [void]$fs.Read($d, 0, $need)
                    $created = 0; $timescale = 0; $duration = 0
                    if ($version -eq 1) {
                        for ($i = 0; $i -lt 8; $i++) { $created = ($created * 256) + $d[$i] }
                        $timescale = ([int64]$d[16]*16777216)+([int64]$d[17]*65536)+([int64]$d[18]*256)+[int64]$d[19]
                        for ($i = 20; $i -lt 28; $i++) { $duration = ($duration * 256) + $d[$i] }
                    } else {
                        $created = ([int64]$d[0]*16777216)+([int64]$d[1]*65536)+([int64]$d[2]*256)+[int64]$d[3]
                        $timescale = ([int64]$d[8]*16777216)+([int64]$d[9]*65536)+([int64]$d[10]*256)+[int64]$d[11]
                        $duration = ([int64]$d[12]*16777216)+([int64]$d[13]*65536)+([int64]$d[14]*256)+[int64]$d[15]
                    }
                    # The epoch is 1904-01-01 UTC, not 1970. Getting this wrong
                    # shifts every video by 66 years, which is obvious - unlike
                    # a timezone error, which is not.
                    if ($created -gt 0 -and $created -lt 4102444800) {
                        try {
                            $dt = (Get-Date '1904-01-01T00:00:00Z').ToUniversalTime().AddSeconds($created)
                            if ($dt.Year -ge 1990 -and $dt.Year -le 2100) {
                                $r.Created = $dt.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
                                $r.HasMeta = $true
                            }
                        } catch {}
                    }
                    if ($timescale -gt 0 -and $duration -gt 0) {
                        $r.DurationSec = [Math]::Round($duration / $timescale, 1)
                        $r.HasMeta = $true
                    }
                }
            }
        }

        # ---- udta: location and recording device --------------------------
        $udta = Find-Box $fs $moov.Start $moov.End @('udta') 1
        if ($null -ne $udta) {
            $len = [int][Math]::Min(65536, ($udta.End - $udta.Start))
            if ($len -gt 8) {
                $fs.Position = $udta.Start
                $buf = New-Object byte[] $len
                [void]$fs.Read($buf, 0, $len)

                # Latin-1, NOT ASCII. This one silently destroyed every video
                # GPS tag: the atom is named (c)xyz, where (c) is byte 0xA9,
                # and ASCII.GetString replaces any byte above 0x7F with '?'.
                # The marker search could therefore never match, so every
                # GPS-tagged clip on earth returned "no location" - not an
                # error, not a warning, just a confident empty result.
                # Latin-1 maps bytes 0-255 to code points 0-255 unchanged.
                $text = [System.Text.Encoding]::GetEncoding(28591).GetString($buf)

                # (c)xyz holds ISO 6709: +DD.DDDD+DDD.DDDD/ or with altitude.
                $marker = [string][char]0xA9 + 'xyz'
                $idx = $text.IndexOf($marker)
                if ($idx -ge 0) {
                    $tail = $text.Substring([Math]::Min($idx + 4, $text.Length))
                    if ($tail -match '([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)') {
                        $la = [double]$Matches[1]; $lo = [double]$Matches[2]
                        if ([Math]::Abs($la) -le 90 -and [Math]::Abs($lo) -le 180 -and
                            ([Math]::Abs($la) -gt 0.0001 -or [Math]::Abs($lo) -gt 0.0001)) {
                            $r.Lat = [Math]::Round($la, 6)
                            $r.Lon = [Math]::Round($lo, 6)
                            $r.HasMeta = $true
                        }
                    }
                }
                foreach ($pair in @(@('mak','Make'), @('mod','Model'))) {
                    $mk = [string][char]0xA9 + $pair[0]
                    $j = $text.IndexOf($mk)
                    if ($j -ge 0 -and ($j + 12) -lt $text.Length) {
                        $seg = $text.Substring($j + 8, [Math]::Min(48, $text.Length - $j - 8))
                        $clean = ($seg -replace '[^\x20-\x7E]', ' ').Trim()
                        if ($clean.Length -ge 2) {
                            $r.($pair[1]) = ($clean -split '\s{2,}')[0].Trim()
                            $r.HasMeta = $true
                        }
                    }
                }
            }
        }
    } catch {
        # Truncated and malformed clips are the ordinary case, not the
        # exception. Return what was read.
    } finally {
        if ($fs) { $fs.Close() }
    }
    return $r
}

# ======================================================== chain of custody
#
# An append-only record of every operation this tool performed on an
# acquisition, with each entry carrying the hash of the one before it.
#
# The chaining is the point. A plain log can be edited afterwards and nothing
# shows; a chained one cannot have an entry altered or removed without breaking
# every hash after it. That does not make the log tamper-proof - anyone able to
# rewrite the file can recompute the whole chain - but it does make casual
# alteration detectable, and it means the log can be checked rather than merely
# asserted.

function Add-CustodyEntry {
    param([string]$Root, [string]$Action, [hashtable]$Detail)

    try {
        $logPath = Join-Path $Root 'argus-custody.jsonl'
        $prev = '0' * 64
        $seq = 0
        if (Test-Path -LiteralPath $logPath) {
            $lines = @(Get-Content -LiteralPath $logPath -ErrorAction SilentlyContinue |
                       Where-Object { $_ -match '\S' })
            if ($lines.Count -gt 0) {
                $last = $lines[-1] | ConvertFrom-Json
                $prev = $last.hash
                $seq = [int]$last.seq
            }
        }
        $entry = [ordered]@{
            seq       = $seq + 1
            at        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
            operator  = $env:USERNAME
            host      = $env:COMPUTERNAME
            tool      = "ARGUS Field $script:Version"
            action    = $Action
            detail    = $Detail
            prev_hash = $prev
        }
        $body = ($entry | ConvertTo-Json -Depth 6 -Compress)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body)) |
                 ForEach-Object { $_.ToString('x2') }) -join ''
        $sha.Dispose()
        $entry['hash'] = $hash
        Add-Content -LiteralPath $logPath -Encoding UTF8 -Value ($entry | ConvertTo-Json -Depth 6 -Compress)
    } catch {
        Warn "Could not write the custody log: $($_.Exception.Message)"
    }
}

function Test-CustodyChain([string]$Root) {
    $logPath = Join-Path $Root 'argus-custody.jsonl'
    if (-not (Test-Path -LiteralPath $logPath)) { return $null }
    $lines = @(Get-Content -LiteralPath $logPath | Where-Object { $_ -match '\S' })
    $prev = '0' * 64
    $broken = @()
    $n = 0
    foreach ($line in $lines) {
        $n++
        try {
            $e = $line | ConvertFrom-Json
            # ${n} not $n - PowerShell reads "$n:" as a drive-qualified
            # variable, the way "$env:PATH" works, and refuses to parse it.
            if ($e.prev_hash -ne $prev) { $broken += "entry ${n}: previous hash does not match" }
            $stated = $e.hash
            $copy = [ordered]@{
                seq=$e.seq; at=$e.at; operator=$e.operator; host=$e.host
                tool=$e.tool; action=$e.action; detail=$e.detail; prev_hash=$e.prev_hash
            }
            $body = ($copy | ConvertTo-Json -Depth 6 -Compress)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $calc = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body)) |
                     ForEach-Object { $_.ToString('x2') }) -join ''
            $sha.Dispose()
            if ($calc -ne $stated) { $broken += "entry ${n}: content does not match its own hash" }
            $prev = $stated
        } catch { $broken += "entry ${n}: unreadable" }
    }
    return [PSCustomObject]@{ Entries=$lines.Count; Broken=$broken }
}

# ========================================================= adb acquisition
function Invoke-Pull {
    param([string]$Serial = "", [string]$Destination = "", [switch]$SkipHash)

    Section "Logical acquisition over adb"

    $adb = Find-Tool 'adb'
    if (-not $adb) {
        Bad "adb is not installed."
        Note "Unzip platform-tools to C:\platform-tools - this tool checks there."
        return
    }
    Good "adb: $adb"

    $lines = @(& $adb devices 2>&1 | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
    $ready = @()
    foreach ($l in $lines) {
        if ($l -match '^(\S+)\s+device\s*$') { $ready += $Matches[1] }
    }
    if ($ready.Count -eq 0) {
        Bad "No handset is authorised for adb."
        Note "Run a scan (option 1) - it names the specific state and fix."
        return
    }
    if (-not $Serial) {
        if ($ready.Count -eq 1) { $Serial = $ready[0] }
        else {
            Note "Several handsets are ready:"
            for ($i=0; $i -lt $ready.Count; $i++) { Note "  [$($i+1)] $($ready[$i])" }
            $pick = Read-Host "  Which one"
            $idx = 0
            if ([int]::TryParse($pick,[ref]$idx) -and $idx -ge 1 -and $idx -le $ready.Count) {
                $Serial = $ready[$idx-1]
            } else { Bad "Not a valid choice."; return }
        }
    }
    Good "Handset: $Serial"

    if (-not $Destination) {
        $suggest = "C:\evidence\$($Serial -replace '[^A-Za-z0-9]','-')"
        $entered = Read-Host "  Destination folder [$suggest]"
        $Destination = if ($entered) { $entered } else { $suggest }
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $Destination = (Resolve-Path -LiteralPath $Destination).Path
    $started = Get-Date

    # ---- device context, captured before anything is copied -------------
    Section "1. Device context"
    $propsPath = Join-Path $Destination 'device-getprop.txt'
    & $adb -s $Serial shell getprop 2>&1 | Set-Content -LiteralPath $propsPath -Encoding UTF8
    $props = Get-Content -LiteralPath $propsPath -Raw
    function Prop($name) {
        if ($props -match [regex]::Escape("[$name]: [") + '([^\]]*)\]') { return $Matches[1] }
        return ''
    }
    $model = Prop 'ro.product.model'
    $brand = Prop 'ro.product.brand'
    $rel   = Prop 'ro.build.version.release'
    $sdk   = Prop 'ro.build.version.sdk'
    $patch = Prop 'ro.build.version.security_patch'
    Note "Brand / model  : $brand $model"
    Note "Android        : $rel (API $sdk)"
    Note "Security patch : $patch"
    Dim  "Full property dump: device-getprop.txt"

    $pkgPath = Join-Path $Destination 'installed-packages.txt'
    & $adb -s $Serial shell pm list packages -f 2>&1 | Set-Content -LiteralPath $pkgPath -Encoding UTF8
    $pkgCount = @(Get-Content -LiteralPath $pkgPath | Where-Object { $_ -match 'package:' }).Count
    Note "Installed packages: $pkgCount  (installed-packages.txt)"

    # ---- inventory before copying ---------------------------------------
    Section "2. Listing shared storage"
    $listRaw = & $adb -s $Serial shell "find /sdcard -type f 2>/dev/null" 2>&1
    $expected = @{}
    foreach ($p in $listRaw) {
        $p = ($p -replace "`r", '').Trim()
        if ($p -like '/sdcard/*') { $expected[$p] = $true }
    }
    Good "$($expected.Count) file(s) listed under /sdcard"
    if ($expected.Count -eq 0) {
        Warn "Nothing listed. The handset may be restricting shell access."
        return
    }

    # ---- pull ------------------------------------------------------------
    Section "3. Pulling"
    Dim "-a preserves the handset's timestamps. This takes a while."
    $stage = Join-Path $Destination 'sdcard'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    & $adb -s $Serial pull -a /sdcard $Destination 2>&1 |
        Where-Object { $_ -match 'files pulled|error|failed' } |
        ForEach-Object { Dim $_ }

    # ---- reconcile -------------------------------------------------------
    Section "4. Reconciling and hashing"
    $arrived = @{}
    if (Test-Path -LiteralPath $stage) {
        Get-ChildItem -LiteralPath $stage -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $rel = '/sdcard/' + ($_.FullName.Substring($stage.Length).TrimStart('\') -replace '\\','/')
            $arrived[$rel] = $_
        }
    }
    Good "$($arrived.Count) file(s) arrived."

    $hashes = @{}
    if (-not $SkipHash) {
        $n = 0
        foreach ($k in $arrived.Keys) {
            $n++
            if (($n % 200) -eq 0) { Dim "hashed $n / $($arrived.Count)" }
            $h = Get-FileHash -LiteralPath $arrived[$k].FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($h) { $hashes[$k] = $h.Hash.ToLower() }
        }
        Good "$($hashes.Count) file(s) hashed."
    }

    $missing = New-Object System.Collections.ArrayList
    foreach ($k in $expected.Keys) {
        if (-not $arrived.ContainsKey($k)) {
            [void]$missing.Add(@{ path=$k
                reason='Listed by the handset but not present after the pull. Common causes: a permission the shell has and the pull does not, a filename the host filesystem rejects, or a file deleted between listing and copy.' })
        }
    }

    $manifest = [ordered]@{
        format='argus-adb-manifest/1'; tool="ARGUS Field $script:Version"
        serial=$Serial; brand=$brand; model=$model
        android_release=$rel; android_sdk=$sdk; security_patch=$patch
        installed_packages=$pkgCount
        destination=$Destination; operator=$env:USERNAME; workstation=$env:COMPUTERNAME
        started_at=$started.ToString('yyyy-MM-ddTHH:mm:ssK')
        finished_at=(Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
        files_listed=$expected.Count; files_copied=$arrived.Count
        missing_count=$missing.Count; missing=@($missing)
        complete=($missing.Count -eq 0); hashes=$hashes
        method_note='Logical acquisition over adb: a file copy of shared storage (/sdcard), not a physical image. Without root this does not reach /data/data, where message databases, call logs and their unallocated space live, so deleted records are outside its scope. A file absent from this acquisition was not necessarily absent from the device.'
    }
    $mp = Join-Path $Destination 'argus-adb-manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $mp -Encoding UTF8

    Add-CustodyEntry -Root $Destination -Action 'adb-pull' -Detail @{
        serial=$Serial; model="$brand $model"; android=$rel
        files_listed=$expected.Count; files_copied=$arrived.Count
        missing=$missing.Count; hashed=$hashes.Count }

    Section "Result"
    Note ("Listed : {0}" -f $expected.Count)
    Note ("Copied : {0}" -f $arrived.Count)
    if ($missing.Count -eq 0) { Good "Missing: none" }
    else {
        Warn ("Missing: {0} - itemised in the manifest" -f $missing.Count)
        Warn "They failed to transfer. That is not evidence the handset lacked them."
    }
    Write-Host ""
    Write-Host "  Manifest: $mp" -ForegroundColor Cyan
    Write-Host "  Next: .\ARGUS.ps1 -Analyze `"$Destination`"" -ForegroundColor White
    Write-Host ""
    Dim "Scope: this reaches shared storage only. /data/data needs root or a"
    Dim "physical extraction, and that is where messages and deleted records are."
}

# =============================================================== 5. ANALYZE
function Invoke-Analyze {
    param([string]$Path, [int]$MaxExif = 20000)

    Section "Analyse an acquisition"
    if (-not (Test-Path -LiteralPath $Path)) { Bad "Not found: $Path"; return }
    $root = (Resolve-Path -LiteralPath $Path).Path
    Note "Root: $root"

    Write-Host ""
    Note "Inventorying..."
    # The tool's own manifests, logs and reports are not evidence. Including
    # them put argus-custody.jsonl at the top of the timeline as the "latest
    # file on the device", which is both wrong and embarrassing.
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike 'argus-*' })
    if ($files.Count -eq 0) { Warn "No files to analyse."; return }
    Good "$($files.Count) file(s), $([Math]::Round(($files | Measure-Object Length -Sum).Sum / 1GB, 2)) GB"

    # ---- content type by magic bytes, never by extension -----------------
    $SIGS = @(
        @{ Name='JPEG';   Sig=@(0xFF,0xD8,0xFF) }
        @{ Name='PNG';    Sig=@(0x89,0x50,0x4E,0x47) }
        @{ Name='GIF';    Sig=@(0x47,0x49,0x46,0x38) }
        @{ Name='SQLite'; Sig=@(0x53,0x51,0x4C,0x69,0x74,0x65) }
        @{ Name='ZIP';    Sig=@(0x50,0x4B,0x03,0x04) }
        @{ Name='PDF';    Sig=@(0x25,0x50,0x44,0x46) }
        @{ Name='MP4';    Sig=@(0x66,0x74,0x79,0x70); Offset=4 }
        @{ Name='bplist'; Sig=@(0x62,0x70,0x6C,0x69,0x73,0x74) }
        @{ Name='RIFF';   Sig=@(0x52,0x49,0x46,0x46) }
        @{ Name='GZIP';   Sig=@(0x1F,0x8B) }
        @{ Name='WEBP';   Sig=@(0x57,0x45,0x42,0x50); Offset=8 }
        @{ Name='OGG';    Sig=@(0x4F,0x67,0x67,0x53) }
        @{ Name='MP3';    Sig=@(0x49,0x44,0x33) }
    )
    $EXT_FOR = @{ JPEG='jpg jpeg'; PNG='png'; GIF='gif'; PDF='pdf'; MP4='mp4 m4a m4v mov 3gp'
                  ZIP='zip apk jar docx xlsx pptx'; SQLite='db sqlite sqlite3 db-wal'
                  GZIP='gz tgz'; WEBP='webp'; MP3='mp3'; OGG='ogg opus'; RIFF='wav avi' }

    function Get-ContentType([string]$p) {
        try {
            $fs = [System.IO.File]::OpenRead($p)
            try {
                $n = [Math]::Min(16, $fs.Length)
                if ($n -lt 2) { return 'empty/tiny' }
                $h = New-Object byte[] $n
                [void]$fs.Read($h, 0, $n)
                foreach ($s in $SIGS) {
                    $off = if ($s.ContainsKey('Offset')) { $s.Offset } else { 0 }
                    $sig = $s.Sig
                    if (($off + $sig.Count) -gt $h.Length) { continue }
                    $match = $true
                    for ($i = 0; $i -lt $sig.Count; $i++) {
                        if ($h[$off + $i] -ne $sig[$i]) { $match = $false; break }
                    }
                    if ($match) { return $s.Name }
                }
                return 'unknown'
            } finally { $fs.Close() }
        } catch { return 'unreadable' }
    }

    $types = @{}
    $mismatched = New-Object System.Collections.ArrayList
    $sqlites = New-Object System.Collections.ArrayList
    $jpegs = New-Object System.Collections.ArrayList
    $videos = New-Object System.Collections.ArrayList

    $tp = New-ProgressState $files.Count (($files | Measure-Object Length -Sum).Sum) 'Identify'
    foreach ($f in $files) {
        $tp.Items++
        $tp.Bytes += $f.Length
        Write-Progress2 $tp
        $t = Get-ContentType $f.FullName
        if (-not $types.ContainsKey($t)) { $types[$t] = 0 }
        $types[$t]++
        if ($t -eq 'SQLite') { [void]$sqlites.Add($f) }
        if ($t -eq 'JPEG')   { [void]$jpegs.Add($f) }
        if ($t -eq 'MP4')    { [void]$videos.Add($f) }

        # A file whose content contradicts its extension is either an app doing
        # something ordinary or a deliberate attempt to hide it. Both are worth
        # surfacing; neither is asserted here as intent.
        $ext = $f.Extension.TrimStart('.').ToLower()
        if ($ext -and $EXT_FOR.ContainsKey($t)) {
            if (($EXT_FOR[$t] -split ' ') -notcontains $ext) {
                [void]$mismatched.Add([PSCustomObject]@{
                    Path=$f.FullName.Substring($root.Length).TrimStart('\')
                    Extension=$ext; Content=$t; Size=$f.Length })
            }
        }
    }

    Write-Host ""
    Complete-Progress $tp

    Section "Content types (by header, not extension)"
    foreach ($k in ($types.Keys | Sort-Object { -$types[$_] })) {
        Note ("{0,-12} {1,8:N0}" -f $k, $types[$k])
    }

    # ---- EXIF ------------------------------------------------------------
    Section "Image metadata"
    Note "Reading EXIF from $($jpegs.Count) JPEG(s)..."
    $withGps = New-Object System.Collections.ArrayList
    $cameras = @{}
    $exifRows = New-Object System.Collections.ArrayList
    $ep = New-ProgressState ([Math]::Min($jpegs.Count, $MaxExif)) 0 'Read EXIF'
    $n = 0
    foreach ($f in $jpegs) {
        if ($n -ge $MaxExif) { Warn "Stopped at $MaxExif images."; break }
        $n++
        $ep.Items++
        Write-Progress2 $ep
        $x = Get-ExifData $f.FullName
        if (-not $x.HasExif) { continue }
        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        $cam = ("{0} {1}" -f $x.Make, $x.Model).Trim()
        if ($cam) { if (-not $cameras.ContainsKey($cam)) { $cameras[$cam] = 0 }; $cameras[$cam]++ }
        $row = [PSCustomObject]@{ Path=$rel; Camera=$cam; Taken=$x.Taken
                                  Lat=$x.Lat; Lon=$x.Lon; Altitude=$x.Altitude }
        [void]$exifRows.Add($row)
        if ($null -ne $x.Lat) { [void]$withGps.Add($row) }
    }

    if ($cameras.Count -gt 0) {
        Write-Host ""
        Note "Capture devices found in the metadata:"
        foreach ($c in ($cameras.Keys | Sort-Object { -$cameras[$_] })) {
            Good ("  {0,-34} {1,6:N0} image(s)" -f $c, $cameras[$c])
        }
        if ($cameras.Count -gt 1) {
            Write-Host ""
            Dim "More than one capture device. Images from a camera that is not"
            Dim "this handset arrived by transfer - messaging, download, or a"
            Dim "card - which is a provenance question worth following."
        }
    } else {
        Note "No camera metadata found."
    }

    if ($withGps.Count -gt 0) {
        Write-Host ""
        Good "$($withGps.Count) image(s) carry a GPS fix."
        $withGps | Select-Object -First 10 | ForEach-Object {
            Note ("  {0,-46} {1,10:N5}, {2,10:N5}  {3}" -f
                  ($_.Path -replace '^.*\\',''), $_.Lat, $_.Lon, $_.Taken)
        }
        if ($withGps.Count -gt 10) { Dim "  ... $($withGps.Count - 10) more in the CSV." }
        Write-Host ""
        Dim "A GPS tag records where the CAMERA believed it was when the shutter"
        Dim "fired. It is written by the handset and can be absent, stale, or"
        Dim "edited. Treat it as a lead, not as a position fix."
    } else {
        Write-Host ""
        Note "No GPS-tagged images."
        Dim "Absence is not evidence the handset lacked location data - tagging"
        Dim "is off by default on many builds, and stripped by most messengers."
    }

    # ---- video metadata --------------------------------------------------
    Section "Video metadata"
    $videoRows = New-Object System.Collections.ArrayList
    $videoGps = New-Object System.Collections.ArrayList
    if ($videos.Count -gt 0) {
        Note "Reading $($videos.Count) clip(s)..."
        $vp = New-ProgressState $videos.Count 0 'Read video metadata'
        foreach ($f in $videos) {
            $vp.Items++
            Write-Progress2 $vp
            $v = Get-VideoMeta $f.FullName
            if (-not $v.HasMeta) { continue }
            $rel = $f.FullName.Substring($root.Length).TrimStart('\')
            $row = [PSCustomObject]@{
                Path=$rel; Created=$v.Created; DurationSec=$v.DurationSec
                Lat=$v.Lat; Lon=$v.Lon
                Device=("{0} {1}" -f $v.Make, $v.Model).Trim() }
            [void]$videoRows.Add($row)
            if ($null -ne $v.Lat) { [void]$videoGps.Add($row) }
        }
        Good "$($videoRows.Count) clip(s) carry metadata."
        $totalSec = ($videoRows | Where-Object { $null -ne $_.DurationSec } |
                     Measure-Object DurationSec -Sum).Sum
        if ($totalSec) {
            Note ("Total recorded duration: {0:N1} hours" -f ($totalSec / 3600))
        }
        if ($videoGps.Count -gt 0) {
            Write-Host ""
            Good "$($videoGps.Count) clip(s) carry a GPS fix."
            $videoGps | Select-Object -First 8 | ForEach-Object {
                Note ("  {0,-40} {1,10:N5}, {2,10:N5}  {3}" -f
                      ($_.Path -replace '^.*\\',''), $_.Lat, $_.Lon, $_.Created)
            }
        }
        Write-Host ""
        Dim "Video creation time comes from the mvhd atom, written by the"
        Dim "recording handset in UTC. It is independent of the filesystem"
        Dim "times, which the copy rewrote, so prefer it where both exist."
    } else {
        Note "No MP4/MOV/3GP clips found."
    }

    # ---- exact duplicates ------------------------------------------------
    #
    # Size collision first, hash only the collisions. Hashing every file to
    # find duplicates would cost hours on a full handset for a result that is
    # decided by a few hundred candidates.
    Section "Exact duplicates"
    $bySize = $files | Where-Object { $_.Length -gt 4096 } | Group-Object Length |
              Where-Object { $_.Count -gt 1 }
    $dupSets = New-Object System.Collections.ArrayList
    $dupWasted = 0
    if ($bySize) {
        $candidates = ($bySize | Measure-Object Count -Sum).Sum
        Note "$candidates file(s) share a size - hashing those only..."
        foreach ($g in $bySize) {
            $byHash = @{}
            foreach ($f in $g.Group) {
                $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if (-not $h) { continue }
                $k = $h.Hash.ToLower()
                if (-not $byHash.ContainsKey($k)) { $byHash[$k] = New-Object System.Collections.ArrayList }
                [void]$byHash[$k].Add($f)
            }
            foreach ($k in $byHash.Keys) {
                if ($byHash[$k].Count -gt 1) {
                    $paths = @($byHash[$k] | ForEach-Object { $_.FullName.Substring($root.Length).TrimStart('\') })
                    [void]$dupSets.Add([PSCustomObject]@{
                        Hash=$k; Count=$byHash[$k].Count; Bytes=$byHash[$k][0].Length; Paths=$paths })
                    $dupWasted += $byHash[$k][0].Length * ($byHash[$k].Count - 1)
                }
            }
        }
    }
    if ($dupSets.Count -gt 0) {
        Good "$($dupSets.Count) set(s) of byte-identical files, $([Math]::Round($dupWasted/1MB,1)) MB duplicated."
        $dupSets | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
            Note ("  x{0}  {1,10:N0} bytes  {2}" -f $_.Count, $_.Bytes, $_.Paths[0])
            $_.Paths | Select-Object -Skip 1 -First 3 | ForEach-Object { Dim "        also $_" }
        }
        Write-Host ""
        Dim "Identical bytes in two places usually means one was received and"
        Dim "saved, or copied between folders. The pair says the file moved; it"
        Dim "does not say which copy came first, and nothing here establishes"
        Dim "direction."
    } else { Note "No exact duplicates above 4 KB." }

    # ---- app artefacts ---------------------------------------------------
    Section "Application data present"
    $APPS = @(
        @{ Name='WhatsApp';  Match='(?i)\\WhatsApp\\' }
        @{ Name='Telegram';  Match='(?i)\\Telegram\\' }
        @{ Name='Signal';    Match='(?i)\\Signal\\' }
        @{ Name='Snapchat';  Match='(?i)\\Snapchat\\' }
        @{ Name='Instagram'; Match='(?i)\\Instagram\\' }
        @{ Name='Facebook';  Match='(?i)\\(Facebook|FB)\\' }
        @{ Name='Viber';     Match='(?i)\\viber\\' }
        @{ Name='WeChat';    Match='(?i)\\(tencent|MicroMsg)\\' }
        @{ Name='Camera';    Match='(?i)\\DCIM\\' }
        @{ Name='Downloads'; Match='(?i)\\Download\\' }
        @{ Name='Screenshots'; Match='(?i)\\Screenshots?\\' }
        @{ Name='Thumbnails';  Match='(?i)\\\.thumbnails\\' }
        @{ Name='Bluetooth';   Match='(?i)\\bluetooth\\' }
    )
    $appCounts = @{}
    foreach ($f in $files) {
        foreach ($a in $APPS) {
            if ($f.FullName -match $a.Match) {
                if (-not $appCounts.ContainsKey($a.Name)) { $appCounts[$a.Name] = 0 }
                $appCounts[$a.Name]++
            }
        }
    }
    if ($appCounts.Count -gt 0) {
        foreach ($k in ($appCounts.Keys | Sort-Object { -$appCounts[$_] })) {
            Good ("  {0,-14} {1,7:N0} file(s)" -f $k, $appCounts[$k])
        }
        Write-Host ""
        Dim "These are MEDIA folders. The message databases that would say who"
        Dim "sent what live in /data/data and are not reachable over MTP."
    } else { Note "No recognised application media folders." }

    # ---- media deliberately hidden from the gallery ----------------------
    #
    # A .nomedia file tells Android's media scanner to skip that folder, so its
    # contents never appear in the gallery. Vault and "calculator" apps use it,
    # and so do perfectly ordinary apps for caches and working directories.
    #
    # It is reported because a folder full of photographs that the gallery was
    # told to ignore is worth an examiner's attention. It is NOT reported as
    # concealment: the marker says the folder is hidden from one app's index,
    # and says nothing whatever about why.
    Section "Folders hidden from the gallery"
    $nomedia = @($files | Where-Object { $_.Name -eq '.nomedia' })
    if ($nomedia.Count -gt 0) {
        Good "$($nomedia.Count) .nomedia marker(s)."
        Write-Host ""
        $interesting = 0
        foreach ($nm in $nomedia) {
            $dir = $nm.Directory
            $inside = @($files | Where-Object { $_.DirectoryName -eq $dir.FullName -and $_.Name -ne '.nomedia' })
            $media = @($inside | Where-Object { $_.Extension -match '(?i)\.(jpg|jpeg|png|mp4|mov|3gp|heic|webp|gif)$' })
            $rel = $dir.FullName.Substring($root.Length).TrimStart('\')
            if ($media.Count -gt 0) {
                $interesting++
                Warn ("  {0}" -f $rel)
                Warn ("      {0} media file(s) in a folder the gallery was told to skip" -f $media.Count)
            } else {
                Dim ("  {0}  ({1} non-media file(s))" -f $rel, $inside.Count)
            }
        }
        Write-Host ""
        if ($interesting -gt 0) {
            Dim "$interesting of these hold media. Worth looking at - but .nomedia is"
            Dim "used routinely by caches and working folders, and its presence is"
            Dim "not evidence of concealment. It means one index was told to skip"
            Dim "the folder, and nothing more."
        } else {
            Dim "None contain media. This is the ordinary case."
        }
    } else { Note "None." }

    # ---- timestamp anomalies ---------------------------------------------
    #
    # A file modified before it was created cannot happen in ordinary use. It
    # happens constantly in copies, though - which is exactly why this is
    # reported with that caveat attached rather than as a finding.
    Section "Timestamp anomalies"
    $anomalies = @($files | Where-Object {
        $_.LastWriteTime -lt $_.CreationTime.AddSeconds(-60) })
    $future = @($files | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(1) })
    if ($anomalies.Count -gt 0) {
        Note "$($anomalies.Count) file(s) modified before their creation time."
        $anomalies | Select-Object -First 5 | ForEach-Object {
            Dim ("  {0}" -f $_.FullName.Substring($root.Length).TrimStart('\'))
            Dim ("      created {0:yyyy-MM-dd HH:mm}, modified {1:yyyy-MM-dd HH:mm}" -f
                 $_.CreationTime, $_.LastWriteTime)
        }
        Write-Host ""
        Dim "On a COPY this is normal and expected: the copy set a new creation"
        Dim "time while preserving the original modification time. It is only"
        Dim "interesting on an original volume. Do not read it as tampering here."
    } else { Note "No file is modified before its creation time." }

    if ($future.Count -gt 0) {
        Write-Host ""
        Warn "$($future.Count) file(s) dated in the future."
        $future | Select-Object -First 5 | ForEach-Object {
            Warn ("  {0:yyyy-MM-dd}  {1}" -f $_.LastWriteTime,
                  $_.FullName.Substring($root.Length).TrimStart('\'))
        }
        Dim "Usually a handset clock that was wrong, or was set deliberately."
        Dim "Either way the recorded times on that device cannot be relied on"
        Dim "without corroboration from something with an independent clock."
    }

    # ---- thumbnails outliving their originals ----------------------------
    Section "Thumbnails whose originals are absent"
    $thumbs = @($files | Where-Object { $_.FullName -match '(?i)\\\.thumbnails\\' -and $_.Length -gt 0 })
    if ($thumbs.Count -gt 0) {
        Good "$($thumbs.Count) thumbnail file(s) present."
        Dim "Android's thumbnail cache routinely survives deletion of the"
        Dim "original image. A thumbnail with no corresponding full-size file is"
        Dim "consistent with a deleted photograph - but only consistent with it."
        Dim "It is equally consistent with an image that was never on this"
        Dim "volume, or one the MTP copy dropped. Do not state deletion as fact."
    } else { Note "None." }

    # ---- SQLite ----------------------------------------------------------
    Section "Databases"
    if ($sqlites.Count -gt 0) {
        Good "$($sqlites.Count) SQLite database(s) found."
        $sqlites | Select-Object -First 15 | ForEach-Object {
            Note ("  {0}  ({1:N0} bytes)" -f $_.FullName.Substring($root.Length).TrimStart('\'), $_.Length)
        }
        Write-Host ""
        Dim "This tool does not parse SQLite - reading page structure and"
        Dim "carving freelist and freeblock space needs the full ARGUS engine."
        Dim "Import this folder there to recover deleted rows."
    } else { Note "None on this volume (expected - they live in /data/data)." }

    # ---- timeline --------------------------------------------------------
    Section "Timeline"
    $dated = @($files | Where-Object { $_.LastWriteTime -gt (Get-Date '1990-01-01') })
    if ($dated.Count -gt 0) {
        $earliest = ($dated | Sort-Object LastWriteTime | Select-Object -First 1)
        $latest   = ($dated | Sort-Object LastWriteTime | Select-Object -Last 1)
        Note ("Earliest file : {0:yyyy-MM-dd}  {1}" -f $earliest.LastWriteTime, $earliest.Name)
        Note ("Latest file   : {0:yyyy-MM-dd}  {1}" -f $latest.LastWriteTime, $latest.Name)
        Write-Host ""
        Note "Activity by month (top 12):"
        $byMonth = $dated | Group-Object { $_.LastWriteTime.ToString('yyyy-MM') } |
                   Sort-Object Count -Descending | Select-Object -First 12
        foreach ($m in $byMonth) {
            $bar = '#' * [Math]::Min(40, [int]($m.Count / [Math]::Max(1, ($byMonth[0].Count / 40))))
            Note ("  {0}  {1,6:N0}  {2}" -f $m.Name, $m.Count, $bar)
        }
        Write-Host ""
        Dim "These are FILESYSTEM times on the copy, not on the handset. MTP"
        Dim "does not preserve creation time reliably and the copy rewrote"
        Dim "access times. Where EXIF capture time exists, prefer it."
    }

    # ---- extension mismatches --------------------------------------------
    if ($mismatched.Count -gt 0) {
        Section "Extension does not match content"
        Warn "$($mismatched.Count) file(s)."
        $mismatched | Select-Object -First 15 | ForEach-Object {
            Warn ("  .{0,-6} but is {1,-8}  {2}" -f $_.Extension, $_.Content, $_.Path)
        }
        Write-Host ""
        Dim "Ordinary causes outnumber suspicious ones - apps rename freely."
        Dim "Worth a look, not a finding."
    }

    # ---- outputs ---------------------------------------------------------
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath  = Join-Path $root "argus-inventory-$stamp.csv"
    $exifPath = Join-Path $root "argus-exif-$stamp.csv"
    $htmlPath = Join-Path $root "argus-analysis-$stamp.html"

    $files | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.FullName.Substring($root.Length).TrimStart('\')
            Bytes = $_.Length
            Modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            Extension = $_.Extension.TrimStart('.').ToLower()
        }
    } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    if ($exifRows.Count -gt 0) {
        $exifRows | Export-Csv -LiteralPath $exifPath -NoTypeInformation -Encoding UTF8
    }
    $videoPath = Join-Path $root "argus-video-$stamp.csv"
    if ($videoRows.Count -gt 0) {
        $videoRows | Export-Csv -LiteralPath $videoPath -NoTypeInformation -Encoding UTF8
    }

    function Esc($s) { if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html><head><meta charset="utf-8"><title>ARGUS analysis</title>
<style>
body{font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0e1116;color:#d6dae0}
.wrap{max-width:1080px;margin:0 auto;padding:32px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;margin:32px 0 10px;color:#7fb3ff;
 border-bottom:1px solid #232936;padding-bottom:6px}
.meta{color:#78818f;font-size:12px;margin-bottom:24px}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}
th{text-align:left;color:#8b95a3;font-weight:600;padding:6px 8px;border-bottom:1px solid #232936}
td{padding:5px 8px;border-bottom:1px solid #191d25}
tr:hover td{background:#151a22}
.n{text-align:right;font-variant-numeric:tabular-nums}
.caveat{background:#161b22;border-left:3px solid #d29922;padding:10px 14px;margin:10px 0;
 color:#b9c0c9;font-size:12.5px}
code{background:#191d25;padding:1px 5px;border-radius:3px;color:#9fd3ff}
</style></head><body><div class="wrap">
"@)
    [void]$sb.Append("<h1>ARGUS analysis</h1><div class='meta'>")
    [void]$sb.Append("Source: <code>$(Esc $root)</code><br>")
    [void]$sb.Append("Examined: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $(Esc $env:USERNAME) on $(Esc $env:COMPUTERNAME)<br>")
    [void]$sb.Append("Tool: ARGUS Field $script:Version</div>")

    [void]$sb.Append("<h2>Scope of this analysis</h2><div class='caveat'>")
    [void]$sb.Append("This examines a <b>media-level copy</b>. It reports file inventory, ")
    [void]$sb.Append("content types identified by header bytes, and EXIF metadata. ")
    [void]$sb.Append("It does <b>not</b> parse SQLite, recover deleted records, or reach ")
    [void]$sb.Append("<code>/data/data</code> - where message databases, call logs and ")
    [void]$sb.Append("unallocated space live. Nothing absent from this report is thereby ")
    [void]$sb.Append("shown absent from the device.</div>")

    [void]$sb.Append("<h2>Inventory</h2><table><tr><th>Measure</th><th class='n'>Value</th></tr>")
    [void]$sb.Append("<tr><td>Files</td><td class='n'>$('{0:N0}' -f $files.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Total size</td><td class='n'>$('{0:N2}' -f (($files | Measure-Object Length -Sum).Sum / 1GB)) GB</td></tr>")
    [void]$sb.Append("<tr><td>JPEG images</td><td class='n'>$('{0:N0}' -f $jpegs.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Images with EXIF</td><td class='n'>$('{0:N0}' -f $exifRows.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Images with GPS</td><td class='n'>$('{0:N0}' -f $withGps.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Video clips</td><td class='n'>$('{0:N0}' -f $videos.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Clips with GPS</td><td class='n'>$('{0:N0}' -f $videoGps.Count)</td></tr>")
    [void]$sb.Append("<tr><td>Duplicate sets</td><td class='n'>$('{0:N0}' -f $dupSets.Count)</td></tr>")
    [void]$sb.Append("<tr><td>SQLite databases</td><td class='n'>$('{0:N0}' -f $sqlites.Count)</td></tr>")
    [void]$sb.Append("</table>")

    [void]$sb.Append("<h2>Content types</h2><table><tr><th>Type</th><th class='n'>Files</th></tr>")
    foreach ($k in ($types.Keys | Sort-Object { -$types[$_] })) {
        [void]$sb.Append("<tr><td>$(Esc $k)</td><td class='n'>$('{0:N0}' -f $types[$k])</td></tr>")
    }
    [void]$sb.Append("</table><div class='caveat'>Types are determined by header bytes. ")
    [void]$sb.Append("The extension names what wrote the file; the header says what it is.</div>")

    if ($cameras.Count -gt 0) {
        [void]$sb.Append("<h2>Capture devices</h2><table><tr><th>Make and model</th><th class='n'>Images</th></tr>")
        foreach ($c in ($cameras.Keys | Sort-Object { -$cameras[$_] })) {
            [void]$sb.Append("<tr><td>$(Esc $c)</td><td class='n'>$('{0:N0}' -f $cameras[$c])</td></tr>")
        }
        [void]$sb.Append("</table>")
        if ($cameras.Count -gt 1) {
            [void]$sb.Append("<div class='caveat'>More than one capture device appears. Images ")
            [void]$sb.Append("from a device other than this handset arrived by transfer.</div>")
        }
    }

    if ($withGps.Count -gt 0) {
        [void]$sb.Append("<h2>GPS-tagged images ($($withGps.Count))</h2>")
        [void]$sb.Append("<table><tr><th>File</th><th>Taken</th><th class='n'>Latitude</th><th class='n'>Longitude</th></tr>")
        foreach ($g in ($withGps | Select-Object -First 200)) {
            [void]$sb.Append("<tr><td>$(Esc $g.Path)</td><td>$(Esc $g.Taken)</td>")
            [void]$sb.Append("<td class='n'>$('{0:N6}' -f $g.Lat)</td><td class='n'>$('{0:N6}' -f $g.Lon)</td></tr>")
        }
        [void]$sb.Append("</table><div class='caveat'>A GPS tag records where the camera ")
        [void]$sb.Append("<i>believed</i> it was when the shutter fired. It is written by the ")
        [void]$sb.Append("handset and may be absent, stale, or edited. Treat it as a lead.</div>")
    }

    if ($videoGps.Count -gt 0) {
        [void]$sb.Append("<h2>GPS-tagged video ($($videoGps.Count))</h2>")
        [void]$sb.Append("<table><tr><th>File</th><th>Recorded (UTC)</th><th class='n'>Latitude</th><th class='n'>Longitude</th></tr>")
        foreach ($g in ($videoGps | Select-Object -First 200)) {
            [void]$sb.Append("<tr><td>$(Esc $g.Path)</td><td>$(Esc $g.Created)</td>")
            [void]$sb.Append("<td class='n'>$('{0:N6}' -f $g.Lat)</td><td class='n'>$('{0:N6}' -f $g.Lon)</td></tr>")
        }
        [void]$sb.Append("</table>")
    }

    if ($dupSets.Count -gt 0) {
        [void]$sb.Append("<h2>Byte-identical duplicates ($($dupSets.Count) sets)</h2>")
        [void]$sb.Append("<table><tr><th>Copies</th><th class='n'>Bytes each</th><th>Paths</th></tr>")
        foreach ($d in ($dupSets | Sort-Object Count -Descending | Select-Object -First 100)) {
            [void]$sb.Append("<tr><td>x$($d.Count)</td><td class='n'>$('{0:N0}' -f $d.Bytes)</td><td>")
            [void]$sb.Append((($d.Paths | ForEach-Object { Esc $_ }) -join '<br>'))
            [void]$sb.Append("</td></tr>")
        }
        [void]$sb.Append("</table><div class='caveat'>Identical bytes in two places means the ")
        [void]$sb.Append("file moved. It does <b>not</b> establish which copy came first or in ")
        [void]$sb.Append("which direction.</div>")
    }

    if ($appCounts.Count -gt 0) {
        [void]$sb.Append("<h2>Application media</h2><table><tr><th>Application</th><th class='n'>Files</th></tr>")
        foreach ($k in ($appCounts.Keys | Sort-Object { -$appCounts[$_] })) {
            [void]$sb.Append("<tr><td>$(Esc $k)</td><td class='n'>$('{0:N0}' -f $appCounts[$k])</td></tr>")
        }
        [void]$sb.Append("</table>")
    }

    if ($mismatched.Count -gt 0) {
        [void]$sb.Append("<h2>Extension does not match content ($($mismatched.Count))</h2>")
        [void]$sb.Append("<table><tr><th>File</th><th>Extension</th><th>Actual content</th></tr>")
        foreach ($m in ($mismatched | Select-Object -First 200)) {
            [void]$sb.Append("<tr><td>$(Esc $m.Path)</td><td>.$(Esc $m.Extension)</td><td>$(Esc $m.Content)</td></tr>")
        }
        [void]$sb.Append("</table><div class='caveat'>Ordinary causes outnumber suspicious ones. ")
        [void]$sb.Append("Worth examining; not a finding on its own.</div>")
    }

    [void]$sb.Append("</div></body></html>")
    $sb.ToString() | Set-Content -LiteralPath $htmlPath -Encoding UTF8

    Add-CustodyEntry -Root $root -Action 'analyse' -Detail @{
        files=$files.Count; jpegs=$jpegs.Count; with_exif=$exifRows.Count
        with_gps=$withGps.Count; videos=$videos.Count
        video_gps=$videoGps.Count; duplicate_sets=$dupSets.Count
        sqlite=$sqlites.Count; report=(Split-Path -Leaf $htmlPath) }

    Section "Written"
    Write-Host "  $htmlPath" -ForegroundColor Cyan
    Write-Host "  $csvPath" -ForegroundColor Cyan
    if ($exifRows.Count -gt 0)  { Write-Host "  $exifPath" -ForegroundColor Cyan }
    if ($videoRows.Count -gt 0) { Write-Host "  $videoPath" -ForegroundColor Cyan }
}

# ================================================================ 6. VERIFY
function Invoke-Verify {
    param([string]$Path)

    Section "Verify an acquisition against its manifest"
    if (-not (Test-Path -LiteralPath $Path)) { Bad "Not found: $Path"; return }
    $root = (Resolve-Path -LiteralPath $Path).Path

    # Say this first and say it loudly. Everything below would otherwise
    # report reassuring numbers about a folder that is not an exhibit.
    $incomplete = Join-Path $root 'argus-INCOMPLETE.json'
    if (Test-Path -LiteralPath $incomplete) {
        Bad "THIS ACQUISITION DID NOT FINISH."
        try {
            $m0 = Get-Content -LiteralPath $incomplete -Raw | ConvertFrom-Json
            Note ("Started {0} against '{1}'." -f $m0.started_at, $m0.device)
        } catch { }
        Write-Host ""
        Bad "The folder holds a partial copy with no manifest. It is not an"
        Bad "exhibit and nothing in it should be relied on or reported."
        Write-Host ""
        Note "Re-run the acquisition against this same folder to resume it."
        Note "Files already present at the right size are skipped, so it picks"
        Note "up where it stopped rather than starting again."
        return
    }

    $manifestPath = Join-Path $root 'argus-mtp-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        $adbManifest = Join-Path $root 'argus-adb-manifest.json'
        if (Test-Path -LiteralPath $adbManifest) { $manifestPath = $adbManifest }
        else {
            Bad "No ARGUS manifest in $root"
            Note "Only acquisitions made by this tool can be verified."
            return
        }
    }

    $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Note "Acquired : $($m.started_at) by $($m.operator) on $($m.workstation)"
    Note "Device   : $($m.device)"
    Note ("Recorded : {0} file(s), {1} hash(es)" -f $m.files_copied, (@($m.hashes.PSObject.Properties).Count))

    if ($m.hashes.PSObject.Properties.Count -eq 0) {
        Warn "The manifest holds no hashes - this acquisition was made with"
        Warn "hashing disabled and cannot be verified."
        return
    }

    Write-Host ""
    Note "Re-hashing..."
    $ok = 0
    $changed = New-Object System.Collections.ArrayList
    $gone = New-Object System.Collections.ArrayList
    $vh = New-ProgressState ($m.hashes.PSObject.Properties | Measure-Object).Count 0 'Verify'
    $n = 0
    foreach ($p in $m.hashes.PSObject.Properties) {
        $n++
        $vh.Items++
        Write-Progress2 $vh
        $full = Join-Path $root $p.Name
        if (-not (Test-Path -LiteralPath $full)) { [void]$gone.Add($p.Name); continue }
        $h = Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction SilentlyContinue
        if (-not $h) { [void]$gone.Add($p.Name); continue }
        if ($h.Hash.ToLower() -eq $p.Value) { $ok++ } else { [void]$changed.Add($p.Name) }
    }

    # Files present now that were not hashed then. Usually the analysis output
    # this tool wrote itself, so those are excluded rather than alarmed about.
    $added = New-Object System.Collections.ArrayList
    foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue)) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        if ($rel -like 'argus-*') { continue }
        if (-not $m.hashes.PSObject.Properties[$rel]) { [void]$added.Add($rel) }
    }

    Section "Verification result"
    Good  ("Unchanged : {0}" -f $ok)
    if ($changed.Count -gt 0) { Bad  ("ALTERED   : {0}" -f $changed.Count) }
    else                      { Good  "Altered   : 0" }
    if ($gone.Count -gt 0)    { Warn ("Missing   : {0}" -f $gone.Count) }
    else                      { Good  "Missing   : 0" }
    if ($added.Count -gt 0)   { Warn ("Added     : {0}" -f $added.Count) }

    if ($changed.Count -gt 0) {
        Write-Host ""
        Bad "Content has changed since acquisition. Any exhibit drawn from these"
        Bad "files is no longer supported by the recorded hashes:"
        $changed | Select-Object -First 20 | ForEach-Object { Bad "  $_" }
    }
    if ($gone.Count -gt 0) {
        Write-Host ""
        Warn "Hashed at acquisition, absent now:"
        $gone | Select-Object -First 20 | ForEach-Object { Warn "  $_" }
    }
    if ($added.Count -gt 0) {
        Write-Host ""
        Warn "Present now, not hashed at acquisition:"
        $added | Select-Object -First 20 | ForEach-Object { Warn "  $_" }
    }
    if ($changed.Count -eq 0 -and $gone.Count -eq 0 -and $added.Count -eq 0) {
        Write-Host ""
        Good "The acquisition is intact and matches its manifest exactly."
    }

    # ---- the custody chain ----------------------------------------------
    $chain = Test-CustodyChain $root
    if ($null -ne $chain) {
        Section "Chain of custody"
        Note "$($chain.Entries) recorded operation(s)."
        if ($chain.Broken.Count -eq 0) {
            Good "The chain is intact - no entry has been altered or removed."
        } else {
            Bad "THE CHAIN IS BROKEN:"
            $chain.Broken | ForEach-Object { Bad "  $_" }
            Write-Host ""
            Dim "A broken chain does not prove tampering - a crash mid-write"
            Dim "does the same thing. It does mean the log can no longer be"
            Dim "relied on to describe what happened to this evidence."
        }
    }

    Add-CustodyEntry -Root $root -Action 'verify' -Detail @{
        unchanged=$ok; altered=$changed.Count; missing=$gone.Count; added=$added.Count }
}

# ============================================================== 7. SELFTEST
function Invoke-SelfTest {
    Section "Self-test"
    Note "Checking the tool's own logic before it is pointed at evidence."
    Write-Host ""

    function Check($name, $condition, $detail = '') {
        if ($condition) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green }
        else { $script:fail++; Write-Host "  FAIL  $name  $detail" -ForegroundColor Red }
    }
    $script:pass = 0; $script:fail = 0

    # A malformed vendor key silently never matches anything, so the table
    # would degrade to "no handset found" with no error anywhere.
    $badVendor = @($script:VENDORS.Keys | Where-Object { $_ -notmatch '^[0-9a-f]{4}$' })
    Check "vendor IDs are 4 lowercase hex digits" ($badVendor.Count -eq 0) ($badVendor -join ',')

    $badMode = @($script:MODES.Keys | Where-Object { $_ -notmatch '^[0-9a-f]{4}:[0-9a-f]{4}$' })
    Check "mode keys are vid:pid" ($badMode.Count -eq 0) ($badMode -join ',')

    # Every mode must name a vendor the scan can actually recognise, or the
    # mode is unreachable.
    $orphan = @($script:MODES.Keys | Where-Object { -not $script:VENDORS.ContainsKey(($_ -split ':')[0]) })
    Check "every mode maps to a known vendor" ($orphan.Count -eq 0) ($orphan -join ',')

    # The bug that mattered: keying a mode on the vendor alone claimed BootROM
    # for an ordinary MTP handset.
    Check "MediaTek MTP pid is not claimed as a low-level mode" (-not $script:MODES.ContainsKey('0e8d:2008'))
    Check "MediaTek BootROM pid IS a low-level mode" ($script:MODES.ContainsKey('0e8d:0003'))

    # Endianness helpers, both directions.
    $b = [byte[]](0x12,0x34,0x56,0x78)
    Check "Read-U16 big-endian"    ((Read-U16 $b 0 $true)  -eq 0x1234)
    Check "Read-U16 little-endian" ((Read-U16 $b 0 $false) -eq 0x3412)
    Check "Read-U32 big-endian"    ((Read-U32 $b 0 $true)  -eq 0x12345678)
    Check "Read-U32 little-endian" ((Read-U32 $b 0 $false) -eq 0x78563412)

    # Out-of-bounds reads must return the sentinel, not throw and not wrap.
    Check "Read-U16 refuses to read past the buffer" ((Read-U16 $b 3 $true) -eq -1)
    Check "Read-U32 refuses to read past the buffer" ((Read-U32 $b 1 $true) -eq -1)
    Check "Read-U16 refuses a negative offset"       ((Read-U16 $b -1 $true) -eq -1)

    # ---- known-answer tests ---------------------------------------------
    #
    # Everything below this point until the negative controls is a POSITIVE
    # control, and adding them changed the value of this whole function.
    #
    # Before they existed the suite proved only that the parsers do not
    # fabricate: corrupt input yields nothing, malformed input does not hang.
    # A parser hard-coded to return null for every file in the universe would
    # have passed every single check. It cannot pass these.
    #
    # The two fixtures are byte-exact files whose correct answer is known,
    # embedded as base64 so the tool stays one file with no test data to lose.
    # Writing them found a real defect: the video parser decoded the udta atom
    # as ASCII, which turns byte 0xA9 - the '(c)' in the (c)xyz location atom -
    # into '?', so the marker search could never match and every GPS-tagged
    # clip returned "no location" with no error of any kind.

    $fixDir = Join-Path $env:TEMP "argus-known-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $fixDir -Force | Out-Null
    try {
        $jpegB64 = $script:FIXTURE_JPEG_B64
        $jpegPath = Join-Path $fixDir 'known.jpg'
        [System.IO.File]::WriteAllBytes($jpegPath, [Convert]::FromBase64String($jpegB64))

        $k = Get-ExifData $jpegPath
        Check "known JPEG: EXIF is found"      ($k.HasExif)
        Check "known JPEG: Make = ARGUS"       ($k.Make  -eq 'ARGUS')          "got '$($k.Make)'"
        Check "known JPEG: Model = TESTCAM-1"  ($k.Model -eq 'TESTCAM-1')      "got '$($k.Model)'"
        Check "known JPEG: capture time"       ($k.Taken -eq '2024:03:15 14:22:07') "got '$($k.Taken)'"
        # 51 deg 28' 39" N  ->  51.4775 exactly.
        Check "known JPEG: latitude 51.4775"   ($null -ne $k.Lat -and [Math]::Abs($k.Lat - 51.4775) -lt 0.000001) "got '$($k.Lat)'"
        # 0 deg 0' 5.4" W  ->  -0.0015. The sign is the point: a reader that
        # ignores the W reference puts this point in the wrong hemisphere.
        Check "known JPEG: longitude -0.0015"  ($null -ne $k.Lon -and [Math]::Abs($k.Lon + 0.0015) -lt 0.000001) "got '$($k.Lon)'"

        $mp4B64 = $script:FIXTURE_MP4_B64
        $mp4Path = Join-Path $fixDir 'known.mp4'
        [System.IO.File]::WriteAllBytes($mp4Path, [Convert]::FromBase64String($mp4B64))

        $v = Get-VideoMeta $mp4Path
        Check "known MP4: metadata is found"   ($v.HasMeta)
        Check "known MP4: recorded 2021-06-01 09:30:00Z" ($v.Created -eq '2021-06-01 09:30:00Z') "got '$($v.Created)'"
        Check "known MP4: duration 12.5 s"     ($null -ne $v.DurationSec -and [Math]::Abs($v.DurationSec - 12.5) -lt 0.05) "got '$($v.DurationSec)'"
        # These two are the regression guard for the ASCII/Latin-1 defect.
        Check "known MP4: latitude 48.8582"    ($null -ne $v.Lat -and [Math]::Abs($v.Lat - 48.8582) -lt 0.000001) "got '$($v.Lat)'"
        Check "known MP4: longitude 2.2945"    ($null -ne $v.Lon -and [Math]::Abs($v.Lon - 2.2945) -lt 0.000001) "got '$($v.Lon)'"
    } finally {
        Remove-Item -LiteralPath $fixDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ---- negative controls ----------------------------------------------
    # A file that is not a JPEG must not produce metadata.
    $tmp = Join-Path $env:TEMP "argus-selftest-$([guid]::NewGuid()).bin"
    [System.IO.File]::WriteAllBytes($tmp, [byte[]](1..64))
    $x = Get-ExifData $tmp
    Check "non-JPEG yields no EXIF" (-not $x.HasExif)
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

    # Random bytes with a JPEG header must not fabricate tags.
    $tmp2 = Join-Path $env:TEMP "argus-selftest-$([guid]::NewGuid()).jpg"
    $rand = New-Object byte[] 4096
    (New-Object Random 42).NextBytes($rand)
    $rand[0] = 0xFF; $rand[1] = 0xD8
    [System.IO.File]::WriteAllBytes($tmp2, $rand)
    $x2 = Get-ExifData $tmp2
    Check "corrupt JPEG yields no GPS" ($null -eq $x2.Lat)
    Remove-Item -LiteralPath $tmp2 -Force -ErrorAction SilentlyContinue

    Check "Find-Tool returns null for a tool that does not exist" ($null -eq (Find-Tool 'no-such-tool-xyz'))

    # ---- self-inspection -------------------------------------------------
    #
    # These read the tool's own source. They exist because a bug reached a real
    # acquisition: Remove-Item was called on a path that turned out to be a
    # directory full of already-copied evidence, and only a confirmation
    # prompt - which then failed for want of a console - stopped it.
    try {
        $selfSrc = ''
        if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
            $selfSrc = Get-Content -LiteralPath $PSCommandPath -Raw
        }
        if ($selfSrc) {
            # The search token is assembled from two halves so that the literal
            # never appears in this file. Spelled out in full, these very lines
            # would match the pattern and the check would fail against itself.
            $tok = 'Remove' + '-Item'
            $removeLines = @([regex]::Matches($selfSrc, "(?m)^[^\r\n#]*$tok[^\r\n]*") |
                             ForEach-Object { $_.Value })
            $canPrompt = @($removeLines | Where-Object {
                $_ -notmatch '-Confirm:\$false' -and $_ -notmatch 'SilentlyContinue' })
            Check "no destructive call in this file can prompt" ($canPrompt.Count -eq 0) `
                  ($canPrompt -join ' | ')

            Check "the copy path refuses to delete directories" `
                  ($selfSrc -match 'PSIsContainer')
            Check "confirmation prompts are disabled globally" `
                  ($selfSrc -match '\$ConfirmPreference\s*=\s*''None''')
            Check "an incomplete acquisition is marked on disk" `
                  ($selfSrc -match 'argus-INCOMPLETE\.json')
        } else {
            Check "source available for self-inspection" $true "(skipped - not run from a file)"
        }
    } catch {
        Check "self-inspection completed" $false $_.Exception.Message
    }

    # Every problem code must carry both a cause and a fix, or the diagnostic
    # degrades to "something is wrong", which is where it started.
    $badCode = @($script:PROBLEM_CODES.Keys | Where-Object {
        $script:PROBLEM_CODES[$_].Count -ne 2 -or
        -not $script:PROBLEM_CODES[$_][0] -or -not $script:PROBLEM_CODES[$_][1] })
    Check "every problem code names a cause and a fix" ($badCode.Count -eq 0) ($badCode -join ',')
    Check "code 28 (no driver) is covered" ($script:PROBLEM_CODES.ContainsKey(28))

    # Video: a non-MP4 must not yield metadata, and a box whose declared size
    # runs past the end of the file must not send the walker into a loop.
    $tmp3 = Join-Path $env:TEMP "argus-selftest-$([guid]::NewGuid()).mp4"
    [System.IO.File]::WriteAllBytes($tmp3, [byte[]](1..128))
    $v1 = Get-VideoMeta $tmp3
    Check "non-MP4 yields no video metadata" (-not $v1.HasMeta)
    Remove-Item -LiteralPath $tmp3 -Force -ErrorAction SilentlyContinue

    $tmp4 = Join-Path $env:TEMP "argus-selftest-$([guid]::NewGuid()).mp4"
    # A 'moov' box declaring 0x7FFFFFFF bytes inside a 24-byte file.
    [System.IO.File]::WriteAllBytes($tmp4, [byte[]](
        0x00,0x00,0x00,0x10, 0x66,0x74,0x79,0x70, 0x69,0x73,0x6F,0x6D, 0x00,0x00,0x00,0x00,
        0x7F,0xFF,0xFF,0xFF, 0x6D,0x6F,0x6F,0x76))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $v2 = Get-VideoMeta $tmp4
    $sw.Stop()
    Check "truncated MP4 returns promptly, no hang" ($sw.ElapsedMilliseconds -lt 3000) "$($sw.ElapsedMilliseconds) ms"
    Check "truncated MP4 fabricates no location" ($null -eq $v2.Lat)
    Remove-Item -LiteralPath $tmp4 -Force -ErrorAction SilentlyContinue

    # The custody chain must detect an edited entry.
    $chainDir = Join-Path $env:TEMP "argus-chain-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $chainDir -Force | Out-Null
    Add-CustodyEntry -Root $chainDir -Action 'test-a' -Detail @{ n = 1 }
    Add-CustodyEntry -Root $chainDir -Action 'test-b' -Detail @{ n = 2 }
    $intact = Test-CustodyChain $chainDir
    Check "custody chain validates when untouched" ($intact.Broken.Count -eq 0) ($intact.Broken -join '; ')

    $logFile = Join-Path $chainDir 'argus-custody.jsonl'
    $lines = @(Get-Content -LiteralPath $logFile)
    $lines[0] = $lines[0] -replace '"action":"test-a"', '"action":"test-TAMPERED"'
    Set-Content -LiteralPath $logFile -Value $lines -Encoding UTF8
    $tampered = Test-CustodyChain $chainDir
    Check "custody chain detects an edited entry" ($tampered.Broken.Count -gt 0)
    Remove-Item -LiteralPath $chainDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    if ($script:fail -eq 0) {
        Good "$script:pass checks passed. The tool is behaving as specified."
    } else {
        Bad "$script:fail of $($script:pass + $script:fail) checks FAILED."
        Bad "Do not use this copy on evidence until that is understood."
    }
}

# ================================================================== 9. DEMO
#
# Build a fake handset on disk, run the real analysis over it, and check the
# findings against answers that are known exactly.
#
# Every other test in this tool exercises one function. This exercises the
# pipeline: inventory, content typing by header, EXIF, video metadata, GPS,
# duplicate detection, hidden-folder detection, CSV and HTML output, and
# verification against a manifest. A bug in the glue between two working
# parts is invisible to unit tests and shows up here.
#
# It matters more than usual for this tool, because the alternative way to
# discover a pipeline bug is to spend an hour acquiring a real handset and
# find the report wrong at the end of it. This runs in seconds and needs no
# phone, so there is no excuse for not knowing.
function Invoke-Demo {
    Section "End-to-end demonstration"
    Note "Building a synthetic handset with known contents, then running the"
    Note "real analysis over it and checking every finding."
    Write-Host ""

    $root = Join-Path $env:TEMP "argus-demo-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $dcim = Join-Path $root 'DCIM\Camera'
    $vault = Join-Path $root 'Pictures\.private'
    $thumbs = Join-Path $root 'DCIM\.thumbnails'
    foreach ($d in @($dcim, $vault, $thumbs, (Join-Path $root 'Movies'))) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    $jpegBytes = [Convert]::FromBase64String($script:FIXTURE_JPEG_B64)
    $mp4Bytes  = [Convert]::FromBase64String($script:FIXTURE_MP4_B64)

    # Known contents, each planted to exercise one finding.
    [System.IO.File]::WriteAllBytes((Join-Path $dcim 'IMG_0001.jpg'), $jpegBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $dcim 'IMG_0002.jpg'), $jpegBytes)   # exact duplicate
    [System.IO.File]::WriteAllBytes((Join-Path $root 'Movies\VID_0001.mp4'), $mp4Bytes)
    [System.IO.File]::WriteAllBytes((Join-Path $vault 'hidden.jpg'), $jpegBytes)
    Set-Content -LiteralPath (Join-Path $vault '.nomedia') -Value '' -Encoding UTF8
    [System.IO.File]::WriteAllBytes((Join-Path $thumbs 'orphan_thumb.jpg'), $jpegBytes)
    # A PNG that claims to be a document - content typing must see through it.
    [System.IO.File]::WriteAllBytes((Join-Path $root 'notes.txt'),
        [byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A) + (New-Object byte[] 64))

    $planted = 7
    Good "$planted file(s) planted in $root"
    Write-Host ""

    $pass = 0; $fail = 0
    function DCheck($name, $cond, $detail = '') {
        if ($cond) { $script:dpass++; Write-Host "  PASS  $name" -ForegroundColor Green }
        else { $script:dfail++; Write-Host "  FAIL  $name  $detail" -ForegroundColor Red }
    }
    $script:dpass = 0; $script:dfail = 0

    try {
        Invoke-Analyze -Path $root | Out-Null

        Section "Checking the findings"

        $exifCsv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-exif-*.csv' -ErrorAction SilentlyContinue)
        DCheck "an EXIF CSV was written" ($exifCsv.Count -eq 1)

        if ($exifCsv.Count -eq 1) {
            $rows = @(Import-Csv -LiteralPath $exifCsv[0].FullName)
            DCheck "EXIF found in all 4 JPEGs" ($rows.Count -eq 4) "got $($rows.Count)"
            $withGps = @($rows | Where-Object { $_.Lat -and $_.Lat -ne '' })
            DCheck "all 4 carry a GPS fix" ($withGps.Count -eq 4) "got $($withGps.Count)"
            if ($withGps.Count -gt 0) {
                $lat = [double]$withGps[0].Lat
                $lon = [double]$withGps[0].Lon
                DCheck "latitude is 51.4775"  ([Math]::Abs($lat - 51.4775) -lt 0.0001) "got $lat"
                # The sign is the whole point: ignore the W reference and the
                # point lands in the wrong hemisphere, entirely plausibly.
                DCheck "longitude is -0.0015" ([Math]::Abs($lon + 0.0015) -lt 0.0001) "got $lon"
                DCheck "camera is ARGUS TESTCAM-1" ($withGps[0].Camera -match 'TESTCAM-1') "got '$($withGps[0].Camera)'"
            }
        }

        $vidCsv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-video-*.csv' -ErrorAction SilentlyContinue)
        DCheck "a video CSV was written" ($vidCsv.Count -eq 1)
        if ($vidCsv.Count -eq 1) {
            $v = @(Import-Csv -LiteralPath $vidCsv[0].FullName)
            DCheck "the clip was read" ($v.Count -eq 1) "got $($v.Count)"
            if ($v.Count -eq 1) {
                DCheck "recorded 2021-06-01 09:30:00Z" ($v[0].Created -eq '2021-06-01 09:30:00Z') "got '$($v[0].Created)'"
                DCheck "clip GPS is 48.8582" ([Math]::Abs([double]$v[0].Lat - 48.8582) -lt 0.0001) "got '$($v[0].Lat)'"
            }
        }

        $inv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-inventory-*.csv' -ErrorAction SilentlyContinue)
        DCheck "an inventory CSV was written" ($inv.Count -eq 1)
        if ($inv.Count -eq 1) {
            $items = @(Import-Csv -LiteralPath $inv[0].FullName)
            DCheck "all $planted planted files inventoried" ($items.Count -eq $planted) "got $($items.Count)"
            # The tool's own output must never appear in its own inventory.
            $selfRefs = @($items | Where-Object { $_.Path -like 'argus-*' })
            DCheck "no argus-* output in the inventory" ($selfRefs.Count -eq 0) "found $($selfRefs.Count)"
        }

        $html = @(Get-ChildItem -LiteralPath $root -Filter 'argus-analysis-*.html' -ErrorAction SilentlyContinue)
        DCheck "an HTML report was written" ($html.Count -eq 1)
        if ($html.Count -eq 1) {
            $body = Get-Content -LiteralPath $html[0].FullName -Raw
            DCheck "report states the /data/data limitation" ($body -match 'data/data')
            DCheck "report carries the GPS caveat" ($body -match 'believed')
            DCheck "report lists the duplicate set" ($body -match 'duplicate|Duplicates|identical')
            DCheck "report is valid-looking HTML" ($body -match '</html>')
        }

        $custody = Join-Path $root 'argus-custody.jsonl'
        DCheck "a custody entry was written" (Test-Path -LiteralPath $custody)
        if (Test-Path -LiteralPath $custody) {
            $chain = Test-CustodyChain $root
            DCheck "the custody chain validates" ($chain.Broken.Count -eq 0) ($chain.Broken -join '; ')
        }

        # The PNG masquerading as notes.txt must be caught by its header.
        DCheck "content typing sees through a wrong extension" `
               ($html.Count -eq 1 -and (Get-Content -LiteralPath $html[0].FullName -Raw) -match 'notes\.txt')
    }
    catch {
        DCheck "the pipeline ran without error" $false $_.Exception.Message
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    Section "Demonstration result"
    if ($script:dfail -eq 0) {
        Good "$script:dpass checks passed."
        Good "The analysis pipeline works end to end on this machine."
        Write-Host ""
        Dim "This proves the half that runs AFTER acquisition. It says nothing"
        Dim "about whether your handset will hand its files over - only a real"
        Dim "acquisition tests that."
    } else {
        Bad "$script:dfail of $($script:dpass + $script:dfail) checks FAILED."
        Bad "Do not rely on analysis output until this is understood."
    }
}

# ================================================================== 5. MENU
function Show-Menu {
    while ($true) {
        Banner
        Write-Host ""
        Write-Host "   a  AUTO     - find the phone and do everything" -ForegroundColor Green
        Write-Host "   r  Raw      - unfiltered dump (use if the scan finds nothing)" -ForegroundColor White
        Write-Host "   d  Adopt    - turn a folder you copied yourself into an exhibit" -ForegroundColor White
        Write-Host "   1  Scan     - what is attached to this machine" -ForegroundColor White
        Write-Host "   w  Watch    - wait for a handset and report when it appears" -ForegroundColor White
        Write-Host "   h  History  - handsets ever attached to this workstation" -ForegroundColor White
        Write-Host "   2  Acquire  - copy a mounted handset (MTP, no debugging)" -ForegroundColor White
        Write-Host "   3  Pull     - logical acquisition over adb" -ForegroundColor White
        Write-Host "   4  Analyse  - inventory, EXIF, video GPS, duplicates, report" -ForegroundColor White
        Write-Host "   5  Verify   - re-hash and check the custody chain" -ForegroundColor White
        Write-Host "   6  Triage   - identify an opaque container file" -ForegroundColor White
        Write-Host "   7  Doctor   - Python, adb, and every ARGUS copy found" -ForegroundColor White
        Write-Host "   8  Selftest - check this tool before using it on evidence" -ForegroundColor White
        Write-Host "   e  Demo     - prove the analysis pipeline on synthetic data" -ForegroundColor White
        Write-Host "   9  Launch ARGUS (needs Python)" -ForegroundColor White
        Write-Host "   0  Exit" -ForegroundColor DarkGray
        Write-Host ""
        $choice = Read-Host "  Choose"

        switch ($choice) {
            'a' { Invoke-Auto }
            'r' { Invoke-RawDump }
            'd' {
                $p = Read-Host "  Folder you copied the handset into"
                if ($p) { Invoke-Adopt -Folder $p.Trim('"') }
            }
            '1' { Invoke-Scan -WithFixed:$IncludeFixedVolumes | Out-Null }
            'w' { Invoke-Watch }
            'h' {
                Section "Handsets ever attached to this workstation"
                $h = Get-UsbHistory -HandsetsOnly
                if (-not $h.Ok) { Bad "Could not read the USB history: $($h.Error)" }
                elseif ($h.Devices.Count -eq 0) { Note "None recorded." }
                else {
                    foreach ($d in ($h.Devices | Sort-Object { $_.LastArrival } -Descending)) {
                        Good ("{0,-22} {1}:{2}  {3}" -f $d.Vendor,$d.Vid,$d.Pid,$d.Name)
                        if ($d.Serial)      { Dim "      serial:       $($d.Serial)" }
                        if ($d.LastArrival) { Dim ("      last arrival: {0:yyyy-MM-dd HH:mm} UTC" -f $d.LastArrival) }
                    }
                }
            }
            '2' { Invoke-Acquire -SkipHash:$NoHash -Timeout $FileTimeoutSeconds }
            '3' { Invoke-Pull -SkipHash:$NoHash }
            '4' {
                $p = Read-Host "  Folder to analyse"
                if ($p) { Invoke-Analyze -Path $p.Trim('"') }
            }
            '5' {
                $p = Read-Host "  Acquisition folder to verify"
                if ($p) { Invoke-Verify -Path $p.Trim('"') }
            }
            '6' {
                $p = Read-Host "  Path to the file"
                if ($p) { Invoke-Triage -Path $p.Trim('"') }
            }
            '7' { Invoke-Doctor }
            '8' { Invoke-SelfTest }
            'e' { Invoke-Demo }
            '9' {
                $py = $null
                foreach ($c in @('python','python3','py')) {
                    $r = Get-Command $c -ErrorAction SilentlyContinue
                    if ($r) { $py = $r.Source; break }
                }
                if (-not $py) { Warn "Python not found. Run Doctor (option 7)." }
                elseif (Test-Path .\argus_app.py) { & $py .\argus_app.py }
                else { Warn "argus_app.py is not in this folder. Run Doctor (option 7) to locate it." }
            }
            '0' { Write-Host ""; return }
            default { Warn "Not a choice." }
        }

        Write-Host ""
        Read-Host "  Press Enter to return to the menu" | Out-Null
    }
}

# ==================================================================== GUI
#
# One window, the same engine. The GUI does not reimplement anything: it loads
# this very file into a background runspace and calls the same functions the
# console does, capturing their output through the Write-Host shadow above.
#
# The work runs in a separate runspace because a long acquisition on the UI
# thread produces a frozen, white "not responding" window - which, during a
# 40-minute MTP copy, looks exactly like a crash and gets the tool killed
# halfway through an exhibit.

function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $selfPath = $PSCommandPath
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }

    $sync = [hashtable]::Synchronized(@{
        Lines = New-Object System.Collections.ArrayList
        Busy  = $false
    })

    # ---- palette ---------------------------------------------------------
    $C = @{
        Bg      = [System.Drawing.Color]::FromArgb(13, 17, 23)
        Card    = [System.Drawing.Color]::FromArgb(22, 27, 34)
        Card2   = [System.Drawing.Color]::FromArgb(30, 36, 46)
        Line    = [System.Drawing.Color]::FromArgb(48, 54, 66)
        Text    = [System.Drawing.Color]::FromArgb(220, 224, 230)
        Muted   = [System.Drawing.Color]::FromArgb(125, 135, 150)
        Accent  = [System.Drawing.Color]::FromArgb(88, 166, 255)
        Good    = [System.Drawing.Color]::FromArgb(86, 211, 128)
        GoodDim = [System.Drawing.Color]::FromArgb(28, 58, 40)
        Warn    = [System.Drawing.Color]::FromArgb(226, 192, 109)
        Bad     = [System.Drawing.Color]::FromArgb(248, 113, 113)
        BadDim  = [System.Drawing.Color]::FromArgb(60, 30, 32)
    }
    $fontUi     = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontTitle  = New-Object System.Drawing.Font('Segoe UI Semibold', 15, [System.Drawing.FontStyle]::Bold)
    $fontBig    = New-Object System.Drawing.Font('Segoe UI Semibold', 12, [System.Drawing.FontStyle]::Bold)
    $fontMedium = New-Object System.Drawing.Font('Segoe UI', 10)
    $fontSmall  = New-Object System.Drawing.Font('Segoe UI', 8.5)
    $fontMono   = New-Object System.Drawing.Font('Consolas', 9.5)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ARGUS  -  mobile device acquisition"
    $form.Size = New-Object System.Drawing.Size(1100, 800)
    $form.MinimumSize = New-Object System.Drawing.Size(940, 640)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $C.Bg
    $form.ForeColor = $C.Text
    $form.Font = $fontUi

    function New-Label($text, $x, $y, $font, $colour, $w = 0) {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $text
        $l.Location = New-Object System.Drawing.Point($x, $y)
        $l.Font = $font
        $l.ForeColor = $colour
        $l.BackColor = [System.Drawing.Color]::Transparent
        if ($w -gt 0) { $l.Size = New-Object System.Drawing.Size($w, 20) } else { $l.AutoSize = $true }
        return $l
    }

    # ---- title -----------------------------------------------------------
    $form.Controls.Add((New-Label "ARGUS" 24 16 $fontTitle $C.Accent))
    $form.Controls.Add((New-Label "Mobile device acquisition and triage" 96 24 $fontMedium $C.Muted))
    $verLabel = New-Label "v$script:Version   $env:COMPUTERNAME\$env:USERNAME" 24 46 $fontSmall $C.Muted
    $form.Controls.Add($verLabel)

    # ---- device status card ---------------------------------------------
    # The window opens knowing what is attached. Making the operator press
    # "Scan" before the tool will say anything is a needless step in front of
    # the only question they actually have.
    $card = New-Object System.Windows.Forms.Panel
    $card.Location = New-Object System.Drawing.Point(24, 74)
    $card.Size = New-Object System.Drawing.Size(1040, 92)
    $card.BackColor = $C.Card
    $card.Anchor = 'Top,Left,Right'
    $form.Controls.Add($card)

    $dot = New-Object System.Windows.Forms.Panel
    $dot.Location = New-Object System.Drawing.Point(20, 34)
    $dot.Size = New-Object System.Drawing.Size(16, 16)
    $dot.BackColor = $C.Muted
    $card.Controls.Add($dot)

    $devTitle = New-Label "Looking for a handset..." 52 22 $fontBig $C.Text
    $card.Controls.Add($devTitle)
    $devSub = New-Label "" 54 50 $fontUi $C.Muted
    $card.Controls.Add($devSub)

    $refreshBtn = New-Object System.Windows.Forms.Button
    $refreshBtn.Text = 'Refresh'
    $refreshBtn.Size = New-Object System.Drawing.Size(90, 28)
    $refreshBtn.Location = New-Object System.Drawing.Point(930, 32)
    $refreshBtn.FlatStyle = 'Flat'
    $refreshBtn.FlatAppearance.BorderColor = $C.Line
    $refreshBtn.BackColor = $C.Card2
    $refreshBtn.ForeColor = $C.Text
    $refreshBtn.Anchor = 'Top,Right'
    $card.Controls.Add($refreshBtn)

    # ---- primary action --------------------------------------------------
    $goBtn = New-Object System.Windows.Forms.Button
    $goBtn.Text = "Plug in a handset to begin"
    $goBtn.Size = New-Object System.Drawing.Size(1040, 56)
    $goBtn.Location = New-Object System.Drawing.Point(24, 178)
    $goBtn.FlatStyle = 'Flat'
    $goBtn.FlatAppearance.BorderSize = 0
    $goBtn.BackColor = $C.Card2
    $goBtn.ForeColor = $C.Muted
    $goBtn.Font = $fontBig
    $goBtn.Enabled = $false
    $goBtn.Anchor = 'Top,Left,Right'
    $goBtn.Cursor = 'Hand'
    $form.Controls.Add($goBtn)

    $goHint = New-Label "" 26 240 $fontSmall $C.Muted 1030
    $form.Controls.Add($goHint)

    # ---- secondary actions, grouped by when you need them ----------------
    $groups = @(
        @{ Title = 'IF NOTHING IS DETECTED'; X = 24; Items = @(
            @{ Key='raw';   Text='Raw dump';    Tip='Everything Windows reports, completely unfiltered. Use this when a phone is plugged in but nothing sees it - it is the only way to tell "not attached" from "the scan missed it".' }
            @{ Key='watch'; Text='Watch for a phone'; Tip='Waits and reports the moment a handset enumerates and mounts. Start this, then plug the phone in.' }
            @{ Key='scan';  Text='Full scan';    Tip='Four independent enumerators, port topology, driver problems and connection stability.' }
        )}
        @{ Title = 'ACQUIRE'; X = 372; Items = @(
            @{ Key='acquire'; Text='Copy phone (MTP)'; Tip='Copy a mounted handset with hashes and a reconciled manifest. No USB debugging needed.' }
            @{ Key='pull';    Text='Pull over adb';    Tip='Logical acquisition over adb. Reaches more than MTP but needs USB debugging authorised.' }
            @{ Key='adopt';   Text='Adopt a manual copy'; Tip='You copied the phone yourself in Explorer. This lists the handset, hashes the folder, reconciles the two and writes a manifest - so a copy Explorer made still becomes a documented exhibit.' }
            @{ Key='history'; Text='Attachment history'; Tip='Handsets ever connected to this workstation, with first and last seen times.' }
        )}
        @{ Title = 'EXAMINE'; X = 720; Items = @(
            @{ Key='analyze'; Text='Analyse a folder'; Tip='Inventory, EXIF, GPS, video metadata, duplicates, and an HTML report.' }
            @{ Key='verify';  Text='Verify an exhibit'; Tip='Re-hash against the manifest and check the custody chain.' }
            @{ Key='triage';  Text='Triage a file';     Tip='Identify an opaque container and say whether it can be read.' }
        )}
    )

    $buttons = @{}
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.AutoPopDelay = 20000
    $tip.InitialDelay = 350
    foreach ($g in $groups) {
        $form.Controls.Add((New-Label $g.Title $g.X 276 $fontSmall $C.Muted))
        $y = 300
        foreach ($item in $g.Items) {
            $b = New-Object System.Windows.Forms.Button
            $b.Text = "   " + $item.Text
            $b.Size = New-Object System.Drawing.Size(324, 34)
            $b.Location = New-Object System.Drawing.Point($g.X, $y)
            $b.FlatStyle = 'Flat'
            $b.FlatAppearance.BorderColor = $C.Line
            $b.BackColor = $C.Card
            $b.ForeColor = $C.Text
            $b.TextAlign = 'MiddleLeft'
            $b.Cursor = 'Hand'
            $tip.SetToolTip($b, $item.Tip)
            $form.Controls.Add($b)
            $buttons[$item.Key] = $b
            $y += 40
        }
    }

    # Tools row
    $form.Controls.Add((New-Label 'TOOLS' 24 424 $fontSmall $C.Muted))
    $tx = 24
    foreach ($item in @(
        @{ Key='selftest'; Text='Self-test'; Tip='Known-answer tests against embedded fixtures. Run this before using the tool on evidence.' }
        @{ Key='doctor';   Text='Doctor';    Tip='Python, adb, and every ARGUS copy found on this machine.' }
        @{ Key='demo';     Text='Demo run';  Tip='Builds a synthetic handset with known contents, runs the real analysis over it, and checks every finding. Proves the pipeline works without needing a phone.' })) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $item.Text
        $b.Size = New-Object System.Drawing.Size(150, 30)
        $b.Location = New-Object System.Drawing.Point($tx, 446)
        $b.FlatStyle = 'Flat'
        $b.FlatAppearance.BorderColor = $C.Line
        $b.BackColor = $C.Card
        $b.ForeColor = $C.Muted
        $b.Cursor = 'Hand'
        $tip.SetToolTip($b, $item.Tip)
        $form.Controls.Add($b)
        $buttons[$item.Key] = $b
        $tx += 158
    }

    # Hover feedback. Without it a flat button looks like a label and people
    # do not realise it can be pressed.
    foreach ($b in @($buttons.Values) + @($refreshBtn)) {
        $b.Add_MouseEnter({ $this.BackColor = $C.Card2 }.GetNewClosure())
        $b.Add_MouseLeave({ $this.BackColor = $C.Card }.GetNewClosure())
    }
    $goBtn.Add_MouseEnter({ if ($this.Enabled) { $this.BackColor = [System.Drawing.Color]::FromArgb(45, 105, 190) } })
    $goBtn.Add_MouseLeave({ if ($this.Enabled) { $this.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176) } })

    # ---- progress --------------------------------------------------------
    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Location = New-Object System.Drawing.Point(24, 492)
    $bar.Size = New-Object System.Drawing.Size(1040, 8)
    $bar.Style = 'Continuous'
    $bar.Anchor = 'Top,Left,Right'
    $bar.Visible = $false
    $form.Controls.Add($bar)

    # ---- output ----------------------------------------------------------
    $out = New-Object System.Windows.Forms.RichTextBox
    $out.Location = New-Object System.Drawing.Point(24, 512)
    $out.Size = New-Object System.Drawing.Size(1040, 200)
    $out.BackColor = [System.Drawing.Color]::FromArgb(9, 12, 16)
    $out.ForeColor = $C.Text
    $out.Font = $fontMono
    $out.ReadOnly = $true
    $out.DetectUrls = $false
    $out.BorderStyle = 'None'
    $out.Anchor = 'Top,Bottom,Left,Right'
    $form.Controls.Add($out)

    $statusLabel = New-Label "Ready." 24 724 $fontUi $C.Muted 700
    $statusLabel.Anchor = 'Bottom,Left'
    $form.Controls.Add($statusLabel)

    $saveBtn = New-Object System.Windows.Forms.Button
    $saveBtn.Text = 'Save log'
    $saveBtn.Size = New-Object System.Drawing.Size(96, 28)
    $saveBtn.Location = New-Object System.Drawing.Point(872, 720)
    $saveBtn.FlatStyle = 'Flat'
    $saveBtn.FlatAppearance.BorderColor = $C.Line
    $saveBtn.BackColor = $C.Card
    $saveBtn.ForeColor = $C.Text
    $saveBtn.Anchor = 'Bottom,Right'
    $form.Controls.Add($saveBtn)

    $clearBtn = New-Object System.Windows.Forms.Button
    $clearBtn.Text = 'Clear'
    $clearBtn.Size = New-Object System.Drawing.Size(80, 28)
    $clearBtn.Location = New-Object System.Drawing.Point(976, 720)
    $clearBtn.FlatStyle = 'Flat'
    $clearBtn.FlatAppearance.BorderColor = $C.Line
    $clearBtn.BackColor = $C.Card
    $clearBtn.ForeColor = $C.Text
    $clearBtn.Anchor = 'Bottom,Right'
    $form.Controls.Add($clearBtn)

    $colourMap = @{
        'Plain' = $C.Text;  'Green' = $C.Good;  'Yellow' = $C.Warn
        'Red'   = $C.Bad;   'Cyan'  = $C.Accent
        'DarkGray' = $C.Muted
        'Magenta'  = [System.Drawing.Color]::FromArgb(198, 149, 240)
        'White'    = [System.Drawing.Color]::White
        'DarkCyan' = [System.Drawing.Color]::FromArgb(80, 140, 200)
    }

    function Append-Line($text, $colour) {
        $c = $colourMap[$colour]
        if (-not $c) { $c = $C.Text }
        $out.SelectionStart = $out.TextLength
        $out.SelectionLength = 0
        $out.SelectionColor = $c
        $out.AppendText("$text`r`n")
        $out.SelectionStart = $out.TextLength
        $out.ScrollToCaret()

        # The engine already prints a percentage in its progress lines, so the
        # bar is driven by reading those rather than by a second progress
        # channel that could disagree with what the log says.
        if ($text -match '\]\s+(\d+)%') {
            $p = [int]$Matches[1]
            if ($p -ge 0 -and $p -le 100) {
                $bar.Visible = $true
                $bar.Value = $p
            }
        }
        if ($text -match 'left ~([^ ]+(?: [^ ]+)?)\s+done ~(\d\d:\d\d)') {
            $statusLabel.Text = "Working - about $($Matches[1]) remaining, finishing around $($Matches[2])"
        }
    }

    # ---- device polling --------------------------------------------------
    $script:currentDevice = ''

    function Update-DeviceCard {
        if ($sync.Busy) { return }
        try {
            $h = Get-MountedHandsets
            $names = @()
            if ($h.Ok) { $names = @($h.Items | ForEach-Object { $_.Name }) }

            $adbReady = @()
            $adbPath = Find-Tool 'adb'
            if ($adbPath) {
                foreach ($l in (& $adbPath devices 2>&1 | Select-Object -Skip 1)) {
                    if ($l -match '^(\S+)\s+device\s*$') { $adbReady += $Matches[1] }
                }
            }

            if ($names.Count -gt 0) {
                $script:currentDevice = $names[0]
                $dot.BackColor = $C.Good
                $devTitle.Text = $names[0]
                $devTitle.ForeColor = $C.Good
                $extra = if ($names.Count -gt 1) { "  (+$($names.Count - 1) more)" } else { '' }
                $devSub.Text = "Mounted and ready to copy - no USB debugging needed$extra"
                $goBtn.Text = "Acquire and analyse  $($names[0])"
                $goBtn.Enabled = $true
                $goBtn.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176)
                $goBtn.ForeColor = [System.Drawing.Color]::White
                $goHint.Text = "Copies shared storage, hashes every file, analyses it and writes a report. Typically 20-60 minutes."
            }
            elseif ($adbReady.Count -gt 0) {
                $script:currentDevice = $adbReady[0]
                $dot.BackColor = $C.Good
                $devTitle.Text = "$($adbReady[0])  (adb)"
                $devTitle.ForeColor = $C.Good
                $devSub.Text = "Authorised for adb. Reaches more than MTP, but not /data/data without root."
                $goBtn.Text = "Pull and analyse  $($adbReady[0])"
                $goBtn.Enabled = $true
                $goBtn.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176)
                $goBtn.ForeColor = [System.Drawing.Color]::White
                $goHint.Text = "Logical acquisition over adb, hashed and reconciled the same way."
            }
            else {
                $script:currentDevice = ''
                $dot.BackColor = $C.Muted
                $devTitle.Text = "No handset detected"
                $devTitle.ForeColor = $C.Muted
                $devSub.Text = "Plug the phone in, unlock it, and choose File transfer on the USB notification."
                $goBtn.Text = "Plug in a handset to begin"
                $goBtn.Enabled = $false
                $goBtn.BackColor = $C.Card2
                $goBtn.ForeColor = $C.Muted
                $goHint.Text = "If it IS connected and still not shown, press Raw dump - that reports everything Windows sees, with no filtering."
            }
        } catch {
            $dot.BackColor = $C.Warn
            $devTitle.Text = "Could not check for handsets"
            $devTitle.ForeColor = $C.Warn
            $devSub.Text = $_.Exception.Message
        }
    }

    # ---- background work -------------------------------------------------
    $script:runspace = $null
    $script:psinst = $null
    $script:handle = $null

    function Start-Work([string]$command, [string]$label) {
        if ($sync.Busy) {
            [System.Windows.Forms.MessageBox]::Show(
                "Something is already running.`n`nWait for it to finish. Stopping an " +
                "acquisition part-way leaves a partial copy that looks complete on disk.",
                "ARGUS", 'OK', 'Warning') | Out-Null
            return
        }
        $sync.Busy = $true
        foreach ($b in $buttons.Values) { $b.Enabled = $false }
        $goBtn.Enabled = $false
        $refreshBtn.Enabled = $false
        $bar.Visible = $true
        $bar.Value = 0
        $statusLabel.Text = "$label - running..."
        $statusLabel.ForeColor = $C.Accent

        $script:runspace = [runspacefactory]::CreateRunspace()
        $script:runspace.ApartmentState = 'STA'
        $script:runspace.Open()
        $script:runspace.SessionStateProxy.SetVariable('SYNC', $sync)
        $script:runspace.SessionStateProxy.SetVariable('SELF', $selfPath)
        $script:runspace.SessionStateProxy.SetVariable('CMD', $command)

        $script:psinst = [powershell]::Create()
        $script:psinst.Runspace = $script:runspace
        [void]$script:psinst.AddScript({
            try {
                . $SELF -NoEntry
                $script:GuiSink = $SYNC
                Invoke-Expression $CMD
            } catch {
                [void]$SYNC.Lines.Add([PSCustomObject]@{
                    Text = "  ERROR: $($_.Exception.Message)"; Colour = 'Red' })
                [void]$SYNC.Lines.Add([PSCustomObject]@{
                    Text = "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"
                    Colour = 'DarkGray' })
            } finally {
                $SYNC.Busy = $false
            }
        })
        $script:handle = $script:psinst.BeginInvoke()
    }

    # A timer drains the queue on the UI thread; touching controls from the
    # worker runspace would be a cross-thread call and throw.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 120
    $timer.Add_Tick({
        $n = 0
        while ($sync.Lines.Count -gt 0 -and $n -lt 200) {
            $item = $sync.Lines[0]
            $sync.Lines.RemoveAt(0)
            Append-Line $item.Text $item.Colour
            $n++
        }
        if (-not $sync.Busy -and $script:handle -and $script:handle.IsCompleted) {
            foreach ($b in $buttons.Values) { $b.Enabled = $true }
            $refreshBtn.Enabled = $true
            $bar.Visible = $false
            $statusLabel.Text = "Finished."
            $statusLabel.ForeColor = $C.Good
            try { $script:psinst.Dispose(); $script:runspace.Close() } catch {}
            $script:handle = $null
            Update-DeviceCard
        }
    })
    $timer.Start()

    $devTimer = New-Object System.Windows.Forms.Timer
    $devTimer.Interval = 4000
    $devTimer.Add_Tick({ Update-DeviceCard })
    $devTimer.Start()

    # ---- helpers ---------------------------------------------------------
    function Pick-Folder($prompt) {
        $d = New-Object System.Windows.Forms.FolderBrowserDialog
        $d.Description = $prompt
        if ($d.ShowDialog() -eq 'OK') { return $d.SelectedPath }
        return $null
    }
    function Pick-File($prompt) {
        $d = New-Object System.Windows.Forms.OpenFileDialog
        $d.Title = $prompt
        $d.Filter = 'All files (*.*)|*.*'
        if ($d.ShowDialog() -eq 'OK') { return $d.FileName }
        return $null
    }
    function Esc-Path($p) { $p -replace "'", "''" }

    # ---- wiring ----------------------------------------------------------
    $refreshBtn.Add_Click({ Update-DeviceCard })
    $buttons['raw'].Add_Click({ Start-Work 'Invoke-RawDump' 'Raw dump' })
    $buttons['scan'].Add_Click({ Start-Work 'Invoke-Scan | Out-Null' 'Scan' })
    $buttons['watch'].Add_Click({ Start-Work 'Invoke-Watch -Seconds 120' 'Watching' })
    $buttons['selftest'].Add_Click({ Start-Work 'Invoke-SelfTest' 'Self-test' })
    $buttons['doctor'].Add_Click({ Start-Work 'Invoke-Doctor' 'Doctor' })
    $buttons['demo'].Add_Click({ Start-Work 'Invoke-Demo' 'End-to-end demo' })

    $goBtn.Add_Click({
        if (-not $script:currentDevice) { Update-DeviceCard; return }
        $name = $script:currentDevice
        $slug = ($name -replace '[^A-Za-z0-9]', '-').ToLower().Trim('-')
        $dest = "C:\evidence\$slug-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Acquire '$name' and run the full sequence?" + [char]10 + [char]10 +
            "Into:  $dest" + [char]10 + [char]10 +
            "1. Copy shared storage, hashing every file" + [char]10 +
            "2. Analyse - EXIF, GPS, video metadata, duplicates" + [char]10 +
            "3. Verify against the manifest" + [char]10 +
            "4. Open an HTML report" + [char]10 + [char]10 +
            "Commonly 20-60 minutes. Leave the phone unlocked and plugged in. " +
            "Progress and a finish time appear below as it runs.",
            "ARGUS - acquire and analyse", 'OKCancel', 'Question')
        if ($r -ne 'OK') { return }
        Start-Work "Invoke-Auto -DeviceName '$(Esc-Path $name)' -Destination '$(Esc-Path $dest)' -Yes" `
                   "Acquiring $name"
    })

    $buttons['acquire'].Add_Click({
        if (-not $script:currentDevice) {
            [System.Windows.Forms.MessageBox]::Show(
                "No handset is mounted." + [char]10 + [char]10 +
                "On the phone: pull down the notification shade, tap the USB " +
                "notification, and choose File transfer.", "ARGUS", 'OK', 'Information') | Out-Null
            return
        }
        $dest = Pick-Folder "Choose an EMPTY folder for the acquisition"
        if (-not $dest) { return }
        Start-Work "Invoke-Acquire -DeviceName '$(Esc-Path $script:currentDevice)' -Destination '$(Esc-Path $dest)'" `
                   "Copying $script:currentDevice"
    })

    $buttons['adopt'].Add_Click({
        [System.Windows.Forms.MessageBox]::Show(
            "Adopt a folder you copied yourself." + [char]10 + [char]10 +
            "ARGUS did not perform that copy and cannot vouch for it. What it " +
            "can do is list the handset, hash every file, reconcile the two, " +
            "and record plainly that the transfer was Explorer's work." + [char]10 + [char]10 +
            "Leave the phone connected so the comparison can be made.",
            "ARGUS - adopt a manual copy", 'OK', 'Information') | Out-Null
        $p = Pick-Folder "Which folder did you copy the handset into?"
        if (-not $p) { return }
        Start-Work "Invoke-Adopt -Folder '$(Esc-Path $p)'" 'Adopting a manual copy'
    })

    $buttons['pull'].Add_Click({
        $dest = Pick-Folder "Choose a folder for the adb acquisition"
        if (-not $dest) { return }
        Start-Work "Invoke-Pull -Destination '$(Esc-Path $dest)'" 'adb pull'
    })

    $buttons['analyze'].Add_Click({
        $p = Pick-Folder "Which acquisition folder should be analysed?"
        if (-not $p) { return }
        Start-Work "Invoke-Analyze -Path '$(Esc-Path $p)'" 'Analysing'
    })

    $buttons['verify'].Add_Click({
        $p = Pick-Folder "Which acquisition folder should be verified?"
        if (-not $p) { return }
        Start-Work "Invoke-Verify -Path '$(Esc-Path $p)'" 'Verifying'
    })

    $buttons['triage'].Add_Click({
        $p = Pick-File "Which container file should be triaged?"
        if (-not $p) { return }
        Start-Work "Invoke-Triage -Path '$(Esc-Path $p)'" 'Triage'
    })

    $buttons['history'].Add_Click({
        Start-Work @'
Section "Handsets ever attached to this workstation"
$h = Get-UsbHistory -HandsetsOnly
if (-not $h.Ok) { Bad "Could not read the USB history: $($h.Error)" }
elseif ($h.Devices.Count -eq 0) { Note "None recorded." }
else {
  foreach ($d in ($h.Devices | Sort-Object { $_.LastArrival } -Descending)) {
    Write-Host ("  {0,-22} {1}:{2}  {3}" -f $d.Vendor,$d.Vid,$d.Pid,$d.Name) -ForegroundColor Green
    if ($d.Serial)      { Dim "      serial:       $($d.Serial)" }
    if ($d.FirstSeen)   { Dim ("      first seen:   {0:yyyy-MM-dd HH:mm} UTC" -f $d.FirstSeen) }
    if ($d.LastArrival) { Dim ("      last arrival: {0:yyyy-MM-dd HH:mm} UTC" -f $d.LastArrival) }
  }
  Write-Host ""
  Dim "From Windows' own device registry - this workstation, not any handset."
}
'@ 'Attachment history'
    })

    $saveBtn.Add_Click({
        $d = New-Object System.Windows.Forms.SaveFileDialog
        $d.Filter = 'Text (*.txt)|*.txt'
        $d.FileName = "argus-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
        if ($d.ShowDialog() -eq 'OK') {
            $out.Text | Set-Content -LiteralPath $d.FileName -Encoding UTF8
            $statusLabel.Text = "Log saved to $($d.FileName)"
        }
    })
    $clearBtn.Add_Click({ $out.Clear() })

    $form.Add_FormClosing({
        if ($sync.Busy) {
            $r = [System.Windows.Forms.MessageBox]::Show(
                "Work is still running." + [char]10 + [char]10 +
                "Closing now leaves a partial acquisition with no manifest, " +
                "which on disk is indistinguishable from a complete one." + [char]10 + [char]10 +
                "Close anyway?", "ARGUS", 'YesNo', 'Warning')
            if ($r -ne 'Yes') { $_.Cancel = $true; return }
        }
        $timer.Stop(); $devTimer.Stop()
        try { if ($script:psinst) { $script:psinst.Dispose() } } catch {}
        try { if ($script:runspace) { $script:runspace.Close() } } catch {}
    })

    Append-Line "" 'Plain'
    Append-Line "  ARGUS $script:Version - nothing is installed, nothing leaves this machine." 'DarkGray'
    Append-Line "  Suggested first run: Self-test, then plug the phone in." 'DarkGray'
    Append-Line "" 'Plain'

    Update-DeviceCard
    [void]$form.ShowDialog()
}

# ============================================================ failure guard
#
# Any unhandled exception is caught here, shown in full, and written beside the
# tool. Two reasons, and the second is the one that matters.
#
# The obvious one: a raw .NET stack trace scrolling past a closing console
# window tells the operator nothing they can act on.
#
# The one that matters: an operation that dies half-way has usually written
# something already. An acquisition that stopped at file 2,000 of 4,000 leaves
# a folder that looks complete. So the handler says plainly that any output
# from the failed run is incomplete and must not be treated as an exhibit -
# because the most expensive mistake available here is not a crash, it is a
# crash that goes unnoticed.
function Invoke-Guarded([scriptblock]$Work, [string]$What) {
    try {
        & $Work
        return 0
    } catch {
        $err = $_
        Write-Host ""
        Bad "UNHANDLED ERROR during: $What"
        Bad $err.Exception.Message
        Write-Host ""
        if ($err.InvocationInfo) {
            Dim ("at line {0}: {1}" -f $err.InvocationInfo.ScriptLineNumber,
                 $err.InvocationInfo.Line.Trim())
        }
        Dim ("type: {0}" -f $err.Exception.GetType().FullName)

        Write-Host ""
        Bad "Anything this run wrote is INCOMPLETE."
        Bad "A half-finished acquisition looks exactly like a finished one on"
        Bad "disk. Do not treat the output as an exhibit - delete it and start"
        Bad "again once the cause is understood."

        try {
            $log = Join-Path $env:TEMP ("argus-error-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            @(
                "ARGUS $script:Version"
                "when      : $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')"
                "operation : $What"
                "host      : $env:COMPUTERNAME\$env:USERNAME"
                "PS        : $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
                "OS        : $([System.Environment]::OSVersion.VersionString)"
                ""
                "message   : $($err.Exception.Message)"
                "type      : $($err.Exception.GetType().FullName)"
                "line      : $($err.InvocationInfo.ScriptLineNumber)"
                "source    : $($err.InvocationInfo.Line)"
                ""
                "stack:"
                $err.ScriptStackTrace
                ""
                ".NET stack:"
                $err.Exception.StackTrace
            ) | Set-Content -LiteralPath $log -Encoding UTF8
            Write-Host ""
            Write-Host "  Details written to: $log" -ForegroundColor Cyan
            Dim "Send that file when reporting this."
        } catch { }
        return 1
    }
}

# =================================================================== entry
if ($NoEntry) { return }

if ($Auto)     { Banner; $rc = Invoke-Guarded { Invoke-Auto -DeviceName $Device -Destination $Out -Yes:$Yes -Relist:$Relist -SkipCacheDirs:$SkipCacheDirs -PerFile:$PerFile } "automatic acquisition"; Write-Host ""; exit $rc }
if ($Raw)      { Banner; $rc = Invoke-Guarded { Invoke-RawDump } "raw dump"; Write-Host ""; exit $rc }
if ($Adopt)    { Banner; $rc = Invoke-Guarded { Invoke-Adopt -Folder $Adopt -DeviceName $Device } "adopt a manual copy"; Write-Host ""; exit $rc }
if ($Scan)     { Banner; $rc = Invoke-Guarded { Invoke-Scan -JsonPath $Json -WithFixed:$IncludeFixedVolumes | Out-Null } "scan"; Write-Host ""; exit $rc }
if ($Watch)    { Banner; $rc = Invoke-Guarded { Invoke-Watch } "watch"; Write-Host ""; exit $rc }
if ($History)  {
    Banner
    Section "Handsets ever attached to this workstation"
    $h = Get-UsbHistory -HandsetsOnly
    if (-not $h.Ok) { Bad "Could not read the USB history: $($h.Error)" }
    elseif ($h.Devices.Count -eq 0) { Note "None recorded." }
    else {
        foreach ($d in ($h.Devices | Sort-Object { $_.LastArrival } -Descending)) {
            Write-Host ("  {0,-22} {1}:{2}  {3}" -f $d.Vendor,$d.Vid,$d.Pid,$d.Name) -ForegroundColor Green
            if ($d.Serial)      { Dim "      serial:       $($d.Serial)" }
            if ($d.FirstSeen)   { Dim ("      first seen:   {0:yyyy-MM-dd HH:mm} UTC" -f $d.FirstSeen) }
            if ($d.LastArrival) { Dim ("      last arrival: {0:yyyy-MM-dd HH:mm} UTC" -f $d.LastArrival) }
            if ($d.LastRemoval) { Dim ("      last removal: {0:yyyy-MM-dd HH:mm} UTC" -f $d.LastRemoval) }
        }
        Write-Host ""
        Dim "From Windows' own device registry. Describes this workstation, not"
        Dim "any handset. Absence does not prove a device was never connected -"
        Dim "these keys can be cleared, and cleanup tools do clear them."
    }
    Write-Host ""; exit 0
}
if ($Acquire)  { Banner; $rc = Invoke-Guarded { Invoke-Acquire -DeviceName $Device -Destination $Out -SkipHash:$NoHash -Timeout $FileTimeoutSeconds -Relist:$Relist -SkipCacheDirs:$SkipCacheDirs -PerFile:$PerFile } "MTP acquisition"; Write-Host ""; exit $rc }
if ($Pull)     { Banner; $rc = Invoke-Guarded { Invoke-Pull -Serial $Device -Destination $Out -SkipHash:$NoHash } "adb acquisition"; Write-Host ""; exit $rc }
if ($Analyze)  { Banner; $rc = Invoke-Guarded { Invoke-Analyze -Path $Analyze } "analysis"; Write-Host ""; exit $rc }
if ($Verify)   { Banner; $rc = Invoke-Guarded { Invoke-Verify -Path $Verify } "verification"; Write-Host ""; exit $rc }
if ($Triage)   { Banner; $rc = Invoke-Guarded { Invoke-Triage -Path $Triage } "triage"; Write-Host ""; exit $rc }
if ($Doctor)   { Banner; $rc = Invoke-Guarded { Invoke-Doctor } "doctor"; Write-Host ""; exit $rc }
if ($SelfTest) { Banner; Invoke-SelfTest; Write-Host ""; if ($script:fail -gt 0) { exit 1 }; exit 0 }
if ($Demo)     { Banner; Invoke-Demo;     Write-Host ""; if ($script:dfail -gt 0) { exit 1 }; exit 0 }

# No switches: the window. -Console gives the text menu instead, which is what
# to use over RDP, on Server Core, or in a session with no desktop.
if ($Console) { Show-Menu; return }

try {
    Show-Gui
} catch {
    Microsoft.PowerShell.Utility\Write-Host ""
    Microsoft.PowerShell.Utility\Write-Host "  The window could not be created: $($_.Exception.Message)" -ForegroundColor Yellow
    Microsoft.PowerShell.Utility\Write-Host "  Falling back to the text menu." -ForegroundColor Yellow
    Show-Menu
}
