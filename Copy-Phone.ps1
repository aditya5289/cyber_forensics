# Copy-Phone.ps1 - forensic copy of an MTP-mounted handset.
#
# Standalone. No ARGUS install, no Python, no modules. Windows only.
#
#   powershell -ExecutionPolicy Bypass -File .\Copy-Phone.ps1 -Out C:\evidence\oppo-f11
#
# Dragging the folder out in Explorer performs the same copy and tells you
# nothing about it: no hashes, no record of what was taken, and - the dangerous
# one - no record of what was MISSED. MTP transfers fail individually and
# quietly. A file locked by the handset, a name Windows rejects, an entry the
# media provider lists but will not serve. Copy 4,000 files, receive 3,960, and
# Explorer reports success.
#
# So this lists the device first, copies, then reconciles the two. Every file
# that arrived is hashed. Every file that did not is named in the manifest.
#
# What this reaches: shared storage - camera media, downloads, documents, and
# app folders under Android/media including WhatsApp media.
# What it cannot reach: /data/data, where message databases, call logs and the
# unallocated space holding deleted records live. That needs adb or a physical
# extraction. A file absent from this copy was NOT necessarily absent from the
# handset.

param(
    [string]$Device = "",
    [Parameter(Mandatory = $true)][string]$Out,
    [switch]$NoHash,
    [int]$FileTimeoutSeconds = 180
)

$ErrorActionPreference = 'SilentlyContinue'

function Section($text) {
    Write-Host ""
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("-" * $text.Length) -ForegroundColor DarkGray
}

$shell = New-Object -ComObject Shell.Application
$known = @('Desktop','Documents','Downloads','Music','Pictures','Videos','3D Objects')

# ------------------------------------------------------------- find the device
Section "Handset"

$candidates = @()
foreach ($item in $shell.NameSpace(17).Items()) {
    if ($item.IsFolder -and -not ($item.Path -match '^[A-Z]:\\$') -and
        $known -notcontains $item.Name) {
        $candidates += $item
    }
}

if ($candidates.Count -eq 0) {
    Write-Host "  No handset mounted in This PC." -ForegroundColor Red
    Write-Host "  On the phone: pull down the notification shade, tap the USB"
    Write-Host "  notification, choose File transfer / MTP, then run this again."
    exit 1
}

$source = $null
if ($Device) {
    $source = $candidates | Where-Object { $_.Name -eq $Device } | Select-Object -First 1
    if (-not $source) {
        Write-Host "  '$Device' is not mounted. Present:" -ForegroundColor Red
        $candidates | ForEach-Object { Write-Host "    $($_.Name)" }
        exit 1
    }
} elseif ($candidates.Count -eq 1) {
    $source = $candidates[0]
} else {
    Write-Host "  More than one handset is mounted. Name the one you want with -Device:" -ForegroundColor Yellow
    $candidates | ForEach-Object { Write-Host "    $($_.Name)" }
    exit 1
}

$deviceName = $source.Name
Write-Host "  $deviceName" -ForegroundColor Green

# The examination copy must not land on the device being examined, and must not
# overwrite an existing acquisition.
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path
Write-Host "  -> $Out" -ForegroundColor DarkGray

$started = Get-Date

# --------------------------------------------------------------- list first
Section "1. Listing the device"
Write-Host "  This walks the whole handset over MTP and is slow. Please wait." -ForegroundColor DarkGray

$listed = New-Object System.Collections.ArrayList

function Walk-Device($folder, $prefix, $depth) {
    if ($depth -gt 12) { return }
    foreach ($item in $folder.Items()) {
        $rel = if ($prefix) { "$prefix\$($item.Name)" } else { $item.Name }
        if ($item.IsFolder) {
            [void]$listed.Add([PSCustomObject]@{ Kind='D'; Rel=$rel; Size=0 })
            Walk-Device $item.GetFolder $rel ($depth + 1)
        } else {
            $size = 0
            try { $size = [int64]$item.ExtendedProperty('System.Size') } catch {}
            [void]$listed.Add([PSCustomObject]@{ Kind='F'; Rel=$rel; Size=$size })
        }
    }
}

Walk-Device $source.GetFolder "" 0

$expected = @{}
foreach ($entry in $listed) {
    if ($entry.Kind -eq 'F') { $expected[$entry.Rel] = $entry.Size }
}
$totalBytes = ($listed | Where-Object { $_.Kind -eq 'F' } |
                Measure-Object -Property Size -Sum).Sum
if (-not $totalBytes) { $totalBytes = 0 }

Write-Host ("  {0} file(s), {1:N2} GB" -f $expected.Count,
            ($totalBytes / 1GB)) -ForegroundColor Green
Write-Host "  This inventory is what makes a shortfall detectable afterwards." -ForegroundColor DarkGray

if ($expected.Count -eq 0) {
    Write-Host "  Nothing to copy." -ForegroundColor Yellow
    exit 0
}

# -------------------------------------------------------------------- copy
Section "2. Copying"
Write-Host "  MTP is slow - a full handset commonly takes 20-60 minutes." -ForegroundColor DarkGray
Write-Host "  Leave the phone unlocked and do not unplug it." -ForegroundColor DarkGray
Write-Host ""

$destFolders = @{}
function Get-DestFolder($path) {
    if (-not $destFolders.ContainsKey($path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $destFolders[$path] = $shell.NameSpace($path)
    }
    return $destFolders[$path]
}

$copied = 0
$skipped = 0
$failed = New-Object System.Collections.ArrayList
$index = 0

function Copy-Tree($folder, $prefix, $depth) {
    if ($depth -gt 12) { return }
    foreach ($item in $folder.Items()) {
        $rel = if ($prefix) { "$prefix\$($item.Name)" } else { $item.Name }

        if ($item.IsFolder) {
            Copy-Tree $item.GetFolder $rel ($depth + 1)
            continue
        }

        $script:index++
        $target = Join-Path $Out $rel

        # Resumable: an existing file of the listed size is left alone, so an
        # interrupted acquisition can be restarted without recopying hours.
        if (Test-Path -LiteralPath $target) {
            $have = (Get-Item -LiteralPath $target).Length
            if ($expected[$rel] -eq 0 -or $have -eq $expected[$rel]) {
                $script:skipped++
                continue
            }
            Remove-Item -LiteralPath $target -Force
        }

        $destDir = Split-Path -Parent $target
        $destFolder = Get-DestFolder $destDir
        if (-not $destFolder) {
            [void]$script:failed.Add(@{ path = $rel;
                reason = "Destination folder could not be opened." })
            continue
        }

        # 16 = yes to all, 512 = no progress dialog, 1024 = no error UI.
        $destFolder.CopyHere($item, 16 -bor 512 -bor 1024)

        # CopyHere is asynchronous and reports nothing. Wait for the file to
        # appear, then for its size to stop changing.
        $deadline = (Get-Date).AddSeconds($FileTimeoutSeconds)
        $last = -1
        $stable = 0
        $ok = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 200
            if (Test-Path -LiteralPath $target) {
                $now = (Get-Item -LiteralPath $target).Length
                if ($now -eq $last) {
                    $stable++
                    if ($stable -ge 3) { $ok = $true; break }
                } else {
                    $stable = 0
                    $last = $now
                }
            }
        }

        if ($ok) {
            $script:copied++
            if (($script:copied % 25) -eq 0) {
                Write-Host ("  {0} / {1}  {2}" -f $script:copied,
                            $expected.Count, $rel) -ForegroundColor DarkGray
            }
        } else {
            [void]$script:failed.Add(@{ path = $rel;
                reason = "Copy did not complete within $FileTimeoutSeconds s." })
            Write-Host "  FAILED: $rel" -ForegroundColor Yellow
        }
    }
}

Copy-Tree $source.GetFolder "" 0

Write-Host ""
Write-Host ("  Copied {0}, skipped {1} already present, {2} failed outright." -f
            $copied, $skipped, $failed.Count) -ForegroundColor Green

# ------------------------------------------------------- reconcile and hash
Section "3. Reconciling and hashing"

$arrived = @{}
Get-ChildItem -LiteralPath $Out -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($Out.Length).TrimStart('\')
    $arrived[$rel] = $_
}

$hashes = @{}
if (-not $NoHash) {
    $n = 0
    foreach ($rel in $arrived.Keys) {
        $n++
        if (($n % 200) -eq 0) {
            Write-Host "  hashed $n / $($arrived.Count)" -ForegroundColor DarkGray
        }
        $h = Get-FileHash -LiteralPath $arrived[$rel].FullName -Algorithm SHA256
        if ($h) { $hashes[$rel] = $h.Hash.ToLower() }
    }
    Write-Host "  $($hashes.Count) file(s) hashed (SHA-256)." -ForegroundColor Green
} else {
    Write-Host "  Hashing skipped (-NoHash). The copy is not verifiable." -ForegroundColor Yellow
}

# The list Explorer would never have produced.
$missing = New-Object System.Collections.ArrayList
foreach ($rel in $expected.Keys) {
    if (-not $arrived.ContainsKey($rel)) {
        $reason = "Listed on the handset but not present after the copy."
        $hit = $failed | Where-Object { $_.path -eq $rel } | Select-Object -First 1
        if ($hit) { $reason = $hit.reason }
        [void]$missing.Add(@{ path = $rel; size = $expected[$rel]; reason = $reason })
    }
}

$copiedBytes = ($arrived.Values | Measure-Object -Property Length -Sum).Sum
if (-not $copiedBytes) { $copiedBytes = 0 }

# --------------------------------------------------------------- manifest
$methodNote = @"
Acquired over MTP (Media Transfer Protocol): a file copy served by the handset's
own media provider, not an image of its storage. It reaches what the provider
chooses to expose - shared storage, camera media, downloads, and app folders
under Android/media - and cannot reach /data/data, where message databases, call
logs and their unallocated space live. Reading a file over MTP may update its
access time on the handset. A file absent from this acquisition was not
necessarily absent from the device.
"@

$manifest = [ordered]@{
    format        = "argus-mtp-manifest/1"
    tool          = "Copy-Phone.ps1 (standalone)"
    device        = $deviceName
    destination   = $Out
    operator      = $env:USERNAME
    workstation   = $env:COMPUTERNAME
    started_at    = $started.ToString("yyyy-MM-ddTHH:mm:ssK")
    finished_at   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    files_listed  = $expected.Count
    files_copied  = $arrived.Count
    bytes_listed  = $totalBytes
    bytes_copied  = $copiedBytes
    complete      = ($missing.Count -eq 0)
    missing_count = $missing.Count
    missing       = @($missing)
    hashes        = $hashes
    method_note   = ($methodNote -replace "`r`n", " " -replace "\s+", " ").Trim()
}

$manifestPath = Join-Path $Out "argus-mtp-manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

# --------------------------------------------------------------- verdict
Section "Result"

Write-Host ("  Listed on device : {0} file(s), {1:N2} GB" -f
            $expected.Count, ($totalBytes / 1GB))
Write-Host ("  Copied           : {0} file(s), {1:N2} GB" -f
            $arrived.Count, ($copiedBytes / 1GB))

if ($missing.Count -eq 0) {
    Write-Host "  Missing          : none - the copy is complete." -ForegroundColor Green
} else {
    Write-Host ("  Missing          : {0} file(s)" -f $missing.Count) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Those files were listed by the handset and did not arrive." -ForegroundColor Yellow
    Write-Host "  That means the transfer failed - NOT that the handset lacked" -ForegroundColor Yellow
    Write-Host "  them. They are itemised in the manifest. Re-running this" -ForegroundColor Yellow
    Write-Host "  script retries only what is missing." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Manifest: $manifestPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next: import '$Out' as an exhibit." -ForegroundColor White
Write-Host ""
