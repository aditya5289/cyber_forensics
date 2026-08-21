"""Acquiring from a handset that is browsable but not debuggable.

A phone in file-transfer mode is mounted, visible, and full of evidence, while
adb sees nothing because USB debugging was never enabled. The standard advice is
to drag the folder out in Explorer, and it works — but it produces no hashes, no
record of what was taken, and no record of what was *missed*. Explorer silently
skips files it cannot read and reports a count nobody writes down.

That last point is the reason this module exists. MTP transfers fail
individually and quietly: a file locked by the phone, a name the host filesystem
rejects, a media provider that lists an entry it will not serve. An examiner who
copies 4,000 files and receives 3,960 has no way to know unless something counts
them. Concluding a photograph was absent when the copy dropped it is exactly the
kind of error that survives all the way into a report.

So every file is hashed as it lands, every failure is recorded with its reason,
and the manifest states plainly what this is: a copy through the handset's own
media provider, not an image of its storage. MTP shows what the provider
chooses to expose. It cannot reach ``/data/data``, and absence here is never
evidence that the device did not hold something.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .progress import ProgressMeter, human_bytes

# Shell FOF_* flags for CopyHere — must never pop Replace/Skip dialogs.
# FOF_SILENT | FOF_NOCONFIRMATION | FOF_SIMPLEPROGRESS | FOF_NOCONFIRMMKDIR
# | FOF_NOERRORUI | FOF_NOCOPYSECURITYATTRIBS
_SHELL_COPY_FLAGS = 0x0004 | 0x0010 | 0x0100 | 0x0200 | 0x0400 | 0x0800

CHECKPOINT_NAME = ".argus-mtp-checkpoint.json"
_SKIP_ARTIFACTS = {
    ".argus-mtp-listing.json", "argus-mtp-manifest.json", CHECKPOINT_NAME,
}

# Windows exposes MTP through the shell namespace rather than a drive letter, so
# ordinary file APIs cannot reach it. The Shell.Application COM object is the
# route every file manager uses, and it is available on any Windows install
# without extra software — which matters on a locked-down workstation.
_ENUMERATE_DEVICES = r"""
$shell = New-Object -ComObject Shell.Application
$pc = $shell.NameSpace(17)
if ($pc -ne $null) {
  foreach ($item in $pc.Items()) {
    if ($item.IsFolder -and -not $item.Path.EndsWith(':\')) {
      Write-Output ("{0}|{1}" -f $item.Name, $item.Path)
    }
  }
}
"""

_LIST_TREE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$shell = New-Object -ComObject Shell.Application

function Walk($folder, $prefix, $depth) {
  if ($depth -gt __MAXDEPTH__) { return }
  foreach ($item in $folder.Items()) {
    $rel = if ($prefix) { "$prefix/$($item.Name)" } else { $item.Name }
    if ($item.IsFolder) {
      Write-Output ("D|$rel|0")
      Walk $item.GetFolder $rel ($depth + 1)
    } else {
      Write-Output ("F|$rel|$($item.ExtendedProperty('System.Size'))")
    }
  }
}

$device = $null
foreach ($item in $shell.NameSpace(17).Items()) {
  if ($item.Name -eq '__DEVICE__') { $device = $item.GetFolder }
}
if ($device -ne $null) { Walk $device '' 0 }
"""

_LIST_VOLUMES = r"""
$ErrorActionPreference = 'SilentlyContinue'
$shell = New-Object -ComObject Shell.Application
$device = $null
foreach ($item in $shell.NameSpace(17).Items()) {
  if ($item.Name -eq '__DEVICE__') { $device = $item.GetFolder }
}
if ($device -eq $null) { return }
foreach ($item in $device.Items()) {
  if ($item.IsFolder) {
    $count = 0
    try { $count = @($item.GetFolder().Items()).Count } catch {}
    Write-Output ("{0}|{1}" -f $item.Name, $count)
  }
}
"""

_LIST_CHILDREN = r"""
$ErrorActionPreference = 'SilentlyContinue'
$shell = New-Object -ComObject Shell.Application
$device = $null
foreach ($item in $shell.NameSpace(17).Items()) {
  if ($item.Name -eq '__DEVICE__') { $device = $item.GetFolder }
}
if ($device -eq $null) { return }
foreach ($vol in $device.Items()) {
  if (-not $vol.IsFolder) { continue }
  $vname = $vol.Name
  try {
    foreach ($child in $vol.GetFolder().Items()) {
      $kind = if ($child.IsFolder) { 'D' } else { 'F' }
      Write-Output ("{0}/{1}|{2}" -f $vname, $child.Name, $kind)
    }
  } catch {}
}
"""

_COPY_TREE = r"""
$ErrorActionPreference = 'Continue'
$destPath = '__DEST__'
$deviceName = '__DEVICE__'
$expectedFiles = __EXPECTED_FILES__
$timeoutSec = __TIMEOUT_SEC__
$copyFlags = __COPY_FLAGS__
$skipExisting = __SKIP_EXISTING__

Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class ArgusDlg {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
}
"@

$script:ShellApp = $null
function Get-ShellApp {
  if ($null -eq $script:ShellApp) { $script:ShellApp = New-Object -ComObject Shell.Application }
  return $script:ShellApp
}

function Dismiss-CopyDialogs {
  [ArgusDlg]::EnumWindows({
    param($h, $l)
    if (-not [ArgusDlg]::IsWindowVisible($h)) { return $true }
    $sb = New-Object System.Text.StringBuilder 512
    [void][ArgusDlg]::GetWindowText($h, $sb, 512)
    $t = $sb.ToString()
    if ($t -match 'Replace|Confirm File|File Conflict|already exists') {
      [ArgusDlg]::SendMessage($h, 0x0111, [IntPtr]9, [IntPtr]0) | Out-Null
    }
    return $true
  }, [IntPtr]::Zero) | Out-Null
}

function Pump-Messages {
  Dismiss-CopyDialogs
  for ($i = 0; $i -lt 4; $i++) { [System.Windows.Forms.Application]::DoEvents() }
}

function Get-CopyPriority([string]$name) {
  $n = ($name + '').ToLower()
  if ($n -eq 'dcim') { return 0 }
  if ($n -match 'picture|photo|camera') { return 1 }
  if ($n -in @('download','downloads')) { return 2 }
  if ($n -in @('document','documents')) { return 3 }
  if ($n -match 'record|voice|call') { return 4 }
  if ($n -match 'whatsapp|telegram|signal|viber') { return 5 }
  if ($n -match 'contact|backup|vivobackup|iqoo') { return 6 }
  if ($n -in @('music','movies','ringtones','notifications')) { return 7 }
  if ($n -eq 'android') { return 90 }
  return 50
}

function Get-DestFileCount {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return 0 }
  return @(
    Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue
  ).Count
}

function Copy-MtpItem {
  param($item, [string]$localDest, [int]$flags, [bool]$skip)
  $target = Join-Path $localDest $item.Name
  $shell = Get-ShellApp
  try {
    if ($item.IsFolder) {
      if ($skip -and (Test-Path -LiteralPath $target)) {
        Write-Output ('SKIP|folder already on disk: ' + $item.Name)
        return
      }
      $ns = $shell.NameSpace($localDest)
      if ($null -eq $ns) {
        Write-Output ('WARN|Cannot open destination for folder: ' + $item.Name)
        return
      }
      $ns.CopyHere($item, $flags)
      Pump-Messages
      Start-Sleep -Milliseconds 150
      Write-Output ('FOLDER|ok|' + $item.Name)
      return
    }
    if ($skip -and (Test-Path -LiteralPath $target)) { return }
    $ns = $shell.NameSpace($localDest)
    if ($null -eq $ns) { return }
    $ns.CopyHere($item, $flags)
    Pump-Messages
  } catch {
    Write-Output ('WARN|Copy failed for ' + $item.Name + ': ' + $_.Exception.Message)
  }
}

function Copy-MtpFolderChildren {
  param($sourceFolder, [string]$localDest, [int]$flags)
  # Last resort: copy direct children one-by-one when bulk CopyHere on a folder fails.
  $shell = Get-ShellApp
  if (-not (Test-Path -LiteralPath $localDest)) {
    New-Item -ItemType Directory -Force -Path $localDest | Out-Null
  }
  foreach ($child in @($sourceFolder.Items())) {
    try {
      $target = Join-Path $localDest $child.Name
      if (Test-Path -LiteralPath $target) { continue }
      if ($child.IsFolder) {
        $ns = $shell.NameSpace($localDest)
        if ($null -ne $ns) { $ns.CopyHere($child, $flags) }
      } else {
        $ns = $shell.NameSpace($localDest)
        if ($null -ne $ns) { $ns.CopyHere($child, $flags) }
      }
      Pump-Messages
      Start-Sleep -Milliseconds 80
    } catch {
      Write-Output ('WARN|Child copy failed: ' + $child.Name)
    }
  }
}

function Wait-ForCopySettle {
  param([int]$MinFiles, [int]$TimeoutSec, [int]$StartCount)
  $stable = 0
  $last = $StartCount
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    Pump-Messages
    Start-Sleep -Milliseconds __POLL_MS__
    $count = Get-DestFileCount $destPath
    Write-Output "PROGRESS|$count"
    if ($count -eq $last -and $count -gt $StartCount) { $stable++ } else { $stable = 0 }
    if ($stable -ge __STABLE__) {
      if ($MinFiles -gt 0 -and $count -ge $MinFiles) { return $count }
      if ($MinFiles -le 0 -and $stable -ge (__STABLE__ * 5)) { return $count }
    }
    $last = $count
  }
  return (Get-DestFileCount $destPath)
}

$shell = Get-ShellApp
$destRoot = $destPath
if (-not (Test-Path -LiteralPath $destRoot)) {
  New-Item -ItemType Directory -Force -Path $destRoot | Out-Null
}
$dest = $shell.NameSpace($destRoot)
if ($null -eq $dest) {
  Write-Output ('ERR|Destination folder not accessible via Shell: ' + $destPath)
  exit 1
}

$device = $null
foreach ($item in $shell.NameSpace(17).Items()) {
  if ($item.Name -eq $deviceName) { $device = $item.GetFolder; break }
}
if ($null -eq $device) {
  Write-Output ('ERR|Device not found in This PC: ' + $deviceName)
  exit 1
}

$copyRoot = $device
$subtree = '__SUBTREE__'
if ($subtree -and $subtree.Length -gt 0) {
  foreach ($part in $subtree.Split('/')) {
    if (-not $part) { continue }
    $found = $null
    foreach ($item in $copyRoot.Items()) {
      if ($item.Name -eq $part) { $found = $item.GetFolder(); break }
    }
    if ($null -eq $found) {
      Write-Output ('ERR|Subtree not found on device: ' + $subtree)
      exit 1
    }
    $copyRoot = $found
  }
}

$before = Get-DestFileCount $destPath
$queued = 0
$reportEvery = __REPORT_EVERY__
$ProgressPreference = 'SilentlyContinue'

$items = @($copyRoot.Items()) | Sort-Object { Get-CopyPriority $_.Name }, Name
Write-Output ('COPY|bulk:' + $subtree + ':' + $items.Count)
foreach ($item in $items) {
  Copy-MtpItem $item $destPath $copyFlags $skipExisting
  $script:queued++
  if ($item.IsFolder) {
    try { $script:queued += @($item.GetFolder().Items()).Count } catch {}
    Pump-Messages
    Write-Output ('FOLDER|queued|' + $item.Name)
  }
  if ($script:queued % $reportEvery -eq 0) { Write-Output "PROGRESS|$script:queued" }
}
# Let every queued CopyHere finish — do not check per-folder counts here (async).
Pump-Messages
Write-Output ('QUEUED|' + $queued)

$final = Wait-ForCopySettle -MinFiles $expectedFiles -TimeoutSec $timeoutSec -StartCount $before
Write-Output ('DONE|' + $final)
"""

_RETRY_FILES = r"""
$ErrorActionPreference = 'Continue'
$deviceName = '__DEVICE__'
$destPath = '__DEST__'
$files = @(__FILES__)
$copyFlags = __COPY_FLAGS__
Add-Type -AssemblyName System.Windows.Forms
$shell = New-Object -ComObject Shell.Application

$device = $null
foreach ($item in $shell.NameSpace(17).Items()) {
  if ($item.Name -eq $deviceName) { $device = $item.GetFolder; break }
}
if ($null -eq $device) {
  Write-Output ('ERR|Device not found: ' + $deviceName)
  exit 1
}

$ok = 0
$skip = 0
$fail = 0
foreach ($rel in $files) {
  $parts = $rel.Split('/')
  $folder = $device
  $found = $true
  for ($i = 0; $i -lt $parts.Length - 1; $i++) {
    $next = $null
    foreach ($item in $folder.Items()) {
      if ($item.Name -eq $parts[$i]) { $next = $item.GetFolder(); break }
    }
    if ($null -eq $next) { $found = $false; break }
    $folder = $next
  }
  if (-not $found) { $fail++; continue }
  $leaf = $parts[-1]
  $localDir = $destPath
  if ($parts.Length -gt 1) {
    $localDir = Join-Path $destPath (($parts[0..($parts.Length-2)] -join '\'))
  }
  if (-not (Test-Path -LiteralPath $localDir)) {
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
  }
  $targetPath = Join-Path $localDir $leaf
  if (Test-Path -LiteralPath $targetPath) { $skip++; continue }
  $target = $null
  foreach ($item in $folder.Items()) {
    if ($item.Name -eq $leaf -and -not $item.IsFolder) { $target = $item; break }
  }
  if ($null -eq $target) { $fail++; continue }
  $ns = $shell.NameSpace($localDir)
  $ns.CopyHere($target, $copyFlags)
  [System.Windows.Forms.Application]::DoEvents()
  Start-Sleep -Milliseconds 25
  $ok++
}
Write-Output ('RETRY|' + $ok + '|' + $fail + '|' + $skip)
"""


def _retry_missing_files(device_name: str, destination: Path,
                         missing: List[Dict[str, Any]],
                         say: Callable[..., None],
                         turbo: bool = False) -> int:
    """Second pass — copy listed files that did not arrive on the first pass."""
    if not missing:
        return 0
    paths = [m["path"] for m in missing if m.get("path")]
    if not paths:
        return 0
    batch_size = 120 if turbo else 80
    recovered = 0
    dest = str(destination.resolve())
    for start in range(0, len(paths), batch_size):
        chunk = paths[start:start + batch_size]
        quoted = ", ".join(f"'{_ps_quote(p)}'" for p in chunk)
        script = (_RETRY_FILES
                  .replace("__DEVICE__", _ps_quote(device_name))
                  .replace("__DEST__", _ps_quote(dest))
                  .replace("__FILES__", quoted)
                  .replace("__COPY_FLAGS__", str(_SHELL_COPY_FLAGS)))
        say(f"Retry pass — files {start + 1}–{start + len(chunk)} of "
            f"{len(paths):,}…", phase="transfer")
        out, err = _powershell(script, timeout=3600)
        if "RETRY|" in out:
            parts = out.split("RETRY|", 1)[1].strip().split("|")
            try:
                recovered += int(parts[0])
            except (IndexError, ValueError):
                pass
        if "ERR|" in out:
            say(out.split("ERR|", 1)[1].strip(), phase="transfer")
        if err.strip():
            say(err.strip()[:200], phase="transfer")
    return recovered


@dataclass
class MTPDevice:
    """A handset visible in the shell namespace."""

    name: str
    path: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {"name": self.name, "path": self.path}


@dataclass
class AcquisitionResult:
    """What was taken, and — just as importantly — what was not."""

    device: str = ""
    destination: str = ""
    files_copied: int = 0
    bytes_copied: int = 0
    files_listed: int = 0
    missing: List[Dict[str, Any]] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    warnings: List[str] = field(default_factory=list)
    method_note: str = ""
    volumes: List[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing

    def as_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device, "destination": self.destination,
            "files_copied": self.files_copied,
            "bytes_copied": self.bytes_copied,
            "files_listed": self.files_listed,
            "missing_count": len(self.missing),
            "missing": self.missing[:500],
            "complete": self.complete,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "warnings": self.warnings,
            "method_note": self.method_note,
            "volumes": self.volumes,
        }


METHOD_NOTE = (
    "Acquired over MTP (Media Transfer Protocol): a file copy served by the "
    "handset's own media provider, not an image of its storage. It reaches "
    "what the provider chooses to expose — shared storage, camera media, "
    "downloads, and app folders under Android/media — and cannot reach "
    "/data/data, where message databases, call logs and their unallocated "
    "space live. Reading a file over MTP may update its access time on the "
    "handset. A file absent from this acquisition was not necessarily absent "
    "from the device."
)

LISTING_CACHE_NAME = ".argus-mtp-listing.json"


def _load_listing_cache(destination: Path, device_name: str) -> Optional[List[Dict[str, Any]]]:
    path = destination / LISTING_CACHE_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("device") == device_name and data.get("entries"):
            return list(data["entries"])
    except (OSError, json.JSONDecodeError, TypeError, KeyError):
        pass
    return None


def _save_listing_cache(destination: Path, device_name: str,
                        listing: List[Dict[str, Any]]) -> None:
    path = destination / LISTING_CACHE_NAME
    payload = {
        "device": device_name,
        "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "entries": listing,
    }
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False),
                    encoding="utf-8")


def _index_arrived(destination: Path) -> Dict[str, Path]:
    """Single-pass walk — builds the arrived-file map without rglob."""
    arrived: Dict[str, Path] = {}
    try:
        for dirpath, _dirnames, filenames in os.walk(destination):
            for name in filenames:
                if name in _SKIP_ARTIFACTS:
                    continue
                full = Path(dirpath) / name
                try:
                    rel = full.relative_to(destination).as_posix()
                except ValueError:
                    continue
                arrived[rel] = full
    except OSError:
        pass
    return arrived


class _DiskStats:
    """Cached file/byte counters — avoids full-tree walks every poll."""

    def __init__(self, root: Path, *, refresh_sec: float = 2.0) -> None:
        self.root = root
        self.refresh_sec = refresh_sec
        self._lock = threading.Lock()
        self._files = 0
        self._bytes = 0
        self._scanned_at = 0.0

    def snapshot(self, *, force: bool = False) -> Tuple[int, int]:
        now = time.time()
        with self._lock:
            if force or now - self._scanned_at >= self.refresh_sec:
                self._files, self._bytes = self._scan()
                self._scanned_at = now
            return self._files, self._bytes

    def _scan(self) -> Tuple[int, int]:
        """Count files and bytes under the destination.

        ``os.scandir`` rather than ``os.walk`` + ``os.path.getsize``: the size
        already arrives in the directory entry, so this costs one syscall per
        directory instead of one per *file*. That matters because the copy
        polls this every couple of seconds while the tree is still growing —
        measured at 8,000 files it went from ~1.6s a scan to ~0.05s, which is
        the difference between a progress meter and a second process fighting
        the transfer for the same disk.

        Recursion is by real directories only, so a symlink cannot send the
        scan round a loop.
        """
        files = 0
        nbytes = 0
        stack = [str(self.root)]
        while stack:
            try:
                with os.scandir(stack.pop()) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                                continue
                            if entry.name in _SKIP_ARTIFACTS:
                                continue
                            files += 1
                            nbytes += entry.stat(follow_symlinks=False).st_size
                        except OSError:
                            pass
            except OSError:
                continue
        return files, nbytes


def _save_checkpoint(destination: Path, device_name: str, *,
                     files: int = 0, nbytes: int = 0,
                     phase: str = "transfer") -> None:
    path = destination / CHECKPOINT_NAME
    payload = {
        "device": device_name,
        "phase": phase,
        "files_on_disk": files,
        "bytes_on_disk": nbytes,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    try:
        path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    except OSError:
        pass


def _load_checkpoint(destination: Path, device_name: str) -> Optional[Dict[str, Any]]:
    path = destination / CHECKPOINT_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("device") == device_name:
            return data
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return None


def _build_arrival_lookup(
        arrived: Dict[str, Path]) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Case-insensitive and basename indexes for MTP path reconciliation."""
    by_lower: Dict[str, str] = {}
    by_tail: Dict[str, List[str]] = {}
    for rel in arrived:
        low = rel.lower()
        by_lower[low] = rel
        tail = rel.rsplit("/", 1)[-1].lower()
        by_tail.setdefault(tail, []).append(rel)
    return by_lower, by_tail


def _resolve_listed_path(expected: str, arrived: Dict[str, Path],
                         by_lower: Dict[str, str],
                         by_tail: Dict[str, List[str]]) -> Optional[str]:
    """Match a handset listing path to a file that landed on disk."""
    if expected in arrived:
        return expected
    low = expected.lower()
    if low in by_lower:
        return by_lower[low]
    parts = expected.split("/")
    for depth in range(min(len(parts), 6), 1, -1):
        suffix = "/".join(parts[-depth:]).lower()
        for rel in arrived:
            if rel.lower().endswith(suffix):
                return rel
    tail = parts[-1].lower()
    candidates = by_tail.get(tail, [])
    if len(candidates) == 1:
        return candidates[0]
    return None


def _should_retry_missing(expected: Dict[str, int], arrived: Dict[str, Path],
                          missing: List[Dict[str, Any]]) -> bool:
    """Retry listed files that did not arrive, unless the inventory is stale.

    Skip per-file retry only when bulk copy clearly *beat* the listing
    (more files on disk than MTP enumerated). A large shortfall is the
    opposite — stalls and partial-file deletions — and must be retried.
    """
    if not missing:
        return False
    if len(arrived) > max(len(expected), 1) * 1.05:
        return False
    return True


# Forensic filenames worth surfacing after an MTP-only copy.
_COMM_PATTERNS = (
    "mmssms.db", "contacts2.db", "calllog.db", "msgstore.db",
    "wa.db", "bugle_db", "telephony.db", "gmm_storage.db",
    "gmm_myplaces.db", "fused_location", "location.cache",
)
_COMM_GLOBS = (
    "*.vcf", "*.vcard", "sms-*.xml", "calls-*.xml", "*smsbackup*.xml",
    "*call-log*.xml", "content/*.txt", "dumpsys/*.txt",
)


def scan_communication_artifacts(destination: Path) -> Dict[str, Any]:
    """Summarise calls/contacts/messages material reachable via MTP."""
    found: Dict[str, List[str]] = {
        "databases": [], "backups": [], "vcards": [], "whatsapp": [],
    }
    try:
        for dirpath, _dirnames, filenames in os.walk(destination):
            for name in filenames:
                low = name.lower()
                rel = (Path(dirpath) / name).relative_to(destination).as_posix()
                if low in _COMM_PATTERNS or any(
                        low.endswith(p) for p in _COMM_PATTERNS):
                    found["databases"].append(rel)
                elif low.endswith((".vcf", ".vcard")):
                    found["vcards"].append(rel)
                elif low.endswith(".xml") and any(
                        k in low for k in ("sms", "call", "backup")):
                    found["backups"].append(rel)
                elif "whatsapp" in rel.lower() and low.endswith(".db"):
                    found["whatsapp"].append(rel)
    except OSError:
        pass
    return {
        "databases": found["databases"][:40],
        "backups": found["backups"][:40],
        "vcards": found["vcards"][:40],
        "whatsapp": found["whatsapp"][:40],
        "counts": {k: len(v) for k, v in found.items()},
    }


def _mtp_workers(job_count: int, turbo: bool) -> int:
    """How many simultaneous Shell.Application copies the USB bus can take.

    MTP is a single media-provider session. More than two or three concurrent
    PowerShell COM workers on the same handset (especially Vivo/Oppo/BBK) causes
    hung copies, duplicated progress, and premature 'done' signals. One volume
    = one worker; two volumes (internal + SD) = two workers max.
    """
    if job_count <= 1:
        return 1
    cap = 3 if turbo else 2
    return min(job_count, cap)


def _coalesce_copy_jobs(jobs: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Merge per-folder jobs into volume-level jobs (one CopyHere stream per volume).

    Listing immediate children is useful for a quick start estimate, but copying
    24 folders in parallel on one MTP device is slower and less reliable than
    copying each storage volume as a whole — the way Explorer drag-and-drop works.
    """
    if not jobs:
        return []
    volumes: Dict[str, int] = {}
    for path, count in jobs:
        vol = (path or "").split("/", 1)[0] or path
        if not vol:
            continue
        volumes[vol] = volumes.get(vol, 0) + int(count or 0)
    merged = sorted(volumes.items(), key=lambda kv: -kv[1])
    return merged if merged else jobs


def _parallel_copy_jobs(listing: List[Dict[str, Any]],
                        min_files: int = 15) -> List[Tuple[str, int]]:
    """Partition a listing into independent subtree copy jobs.

    When a handset exposes one top-level volume (e.g. ``Internal storage``),
    jobs are split at the next level (``DCIM``, ``Download``, …) so multiple
    PowerShell workers can copy in parallel. Every listed subtree is included
    — small folders must not be dropped just because they have few files.
    """
    files = [e for e in listing if e.get("kind") == "F"]
    if not files:
        return []

    top: Dict[str, int] = {}
    for entry in files:
        parts = entry["path"].split("/", 1)
        key = parts[0] if len(parts) > 1 else "__root__"
        top[key] = top.get(key, 0) + 1

    def _split_under(prefix: str, entries: List[Dict[str, Any]]) -> Dict[str, int]:
        inner: Dict[str, int] = {}
        lead = prefix + "/"
        for entry in entries:
            rel = entry["path"]
            if not rel.startswith(lead):
                continue
            rest = rel[len(lead):]
            child = rest.split("/", 1)[0] if "/" in rest else "__root__"
            path = prefix if child == "__root__" else f"{prefix}/{child}"
            inner[path] = inner.get(path, 0) + 1
        return inner

    jobs: List[Tuple[str, int]] = []
    if len(top) == 1:
        sole = next(iter(top))
        if sole == "__root__":
            return []
        # One storage volume — copy it whole (Explorer drag-and-drop). Splitting
        # into 24 parallel folder jobs overloads the MTP media provider.
        jobs = [(sole, top[sole])]
    else:
        jobs = [(key, count) for key, count in top.items()
                if key != "__root__"]
        root_count = top.get("__root__", 0)
        if root_count:
            jobs.append(("__root__", root_count))

    jobs.sort(key=lambda item: -item[1])
    return jobs


def _volume_child_jobs(volume: str, listing: List[Dict[str, Any]]
                       ) -> List[Tuple[str, int]]:
    """Split one storage volume into its top-level folders for stall recovery."""
    if not volume or volume == "__root__" or not listing:
        return []
    prefix = volume.rstrip("/") + "/"
    children: Dict[str, int] = {}
    for entry in listing:
        if entry.get("kind") != "F":
            continue
        path = str(entry.get("path") or "")
        if not path.startswith(prefix):
            continue
        child = path[len(prefix):].split("/", 1)[0]
        if not child:
            continue
        key = f"{volume.rstrip('/')}/{child}"
        children[key] = children.get(key, 0) + 1
    return sorted(children.items(), key=lambda kv: -kv[1])


def _build_copy_script(device_name: str, dest_path: str, expected: int,
                       *, subtree: str = "", turbo: bool = False,
                       skip_existing: bool = True) -> str:
    # Large folders (Android, DCIM) can sit quiet for minutes — need long settle.
    stable_ps = "10" if turbo else "12"
    poll_ms = "400" if turbo else "500"
    report_every = "6" if turbo else "4"
    skip_ps = "$true" if skip_existing else "$false"
    return (_COPY_TREE
            .replace("__DEVICE__", _ps_quote(device_name))
            .replace("__DEST__", _ps_quote(dest_path))
            .replace("__SUBTREE__", _ps_quote(subtree))
            .replace("__EXPECTED_FILES__", str(expected))
            .replace("__TIMEOUT_SEC__", "14400")
            .replace("__STABLE__", stable_ps)
            .replace("__POLL_MS__", poll_ms)
            .replace("__REPORT_EVERY__", report_every)
            .replace("__COPY_FLAGS__", str(_SHELL_COPY_FLAGS))
            .replace("__SKIP_EXISTING__", skip_ps))


def _parse_copy_warnings(out: str) -> List[str]:
    """Collect non-fatal folder copy issues from PowerShell stdout."""
    warns: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("WARN|"):
            warns.append(line.split("|", 1)[1].strip())
        elif line.startswith("RETRY|folder|"):
            warns.append(f"Retrying folder: {line.split('|', 2)[-1]}")
    return warns


def _run_copy_script(script: str, destination: Path, wait_expected: int,
                     progress_total: int,
                     say: Callable[..., None], meter: ProgressMeter,
                     bytes_total: int, turbo: bool,
                     *,
                     quiet: bool = False,
                     wait_root: Optional[Path] = None,
                     jobs_done: int = 0,
                     jobs_total: int = 0,
                     disk_stats: Optional[_DiskStats] = None
                     ) -> Tuple[str, str, int, List[str]]:
    """Execute one copy script and wait for files to land."""
    proc, start_err = _powershell_start(script, timeout=14400)
    ps_out: List[str] = []
    if not proc:
        return "", start_err or "PowerShell could not start the copy.", 0, []

    reader = threading.Thread(
        target=_drain_progress_lines,
        args=(proc, say, meter, progress_total, bytes_total, ps_out),
        kwargs={"quiet": True},
        daemon=True,
        name="argus-mtp-progress",
    )
    reader.start()
    watch = wait_root or destination
    stats = disk_stats or _DiskStats(watch, refresh_sec=2.0)
    landed_count = _wait_for_copy(
        watch, wait_expected, say, meter, bytes_total, proc=proc,
        stable_polls=4 if turbo else 6,
        scan_interval=2.2,
        quiet=quiet,
        jobs_done=jobs_done,
        jobs_total=jobs_total,
        disk_stats=stats,
        stall_exit_seconds=60 if turbo else 75)
    reader.join(timeout=10)
    try:
        proc.wait(timeout=14400)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)
    out = "".join(ps_out)
    err = (proc.stderr.read() if proc.stderr else "") or ""
    folder_warns = _parse_copy_warnings(out)
    if folder_warns and not quiet:
        for note in folder_warns[:5]:
            say(f"Copy note — {note}", phase="transfer")
    return out, err, landed_count, folder_warns


def _shrink_note(last_files: int, last_bytes: int,
                 files: int, nbytes: int) -> str:
    """Describe content leaving the destination mid-copy, or return ''.

    Content disappearing is not a progress update, it is an event. Explorer
    deletes a partially written file when its transfer fails, so the bytes on
    disk drop while the file count keeps climbing — a large video can arrive,
    fail, and vanish between two polls with nothing to show it was ever
    attempted. Whether the examiner hears about it otherwise depends on the
    MTP inventory having listed it, and a stale inventory is precisely the
    case where it would not.

    A first observation (``last_files < 0``) has nothing to compare against
    and is never a shrink.
    """
    if last_files < 0 or (files >= last_files and nbytes >= last_bytes):
        return ""
    return (f"Content left the destination during the copy: "
            f"{last_files:,} → {files:,} file(s), "
            f"{human_bytes(last_bytes)} → {human_bytes(nbytes)}. "
            f"The usual cause is a transfer failing part-way and the partial "
            f"file being removed. Any file the handset listed but did not "
            f"deliver is named in the reconciliation below.")


def _copy_parallel_subtrees(device_name: str, destination: Path,
                            jobs: List[Tuple[str, int]],
                            expected_total: int, expected_bytes: int,
                            say: Callable[..., None],
                            meter: ProgressMeter,
                            turbo: bool,
                            *,
                            inventory: Optional[Dict[str, Any]] = None,
                            listing: Optional[List[Dict[str, Any]]] = None
                            ) -> Tuple[List[str], List[str], int]:
    """Copy MTP storage volumes — one reliable Shell worker per volume."""
    jobs = _coalesce_copy_jobs(jobs)
    workers = _mtp_workers(len(jobs), turbo)
    jobs_total = len(jobs)
    disk_stats = _DiskStats(destination, refresh_sec=2.0 if turbo else 2.5)
    vol_word = "volume" if jobs_total == 1 else "volumes"
    say(f"God-level MTP — {jobs_total} storage {vol_word}, {workers} worker(s) "
        f"(priority forensic folders first, silent copy, dialog-safe)",
        phase="transfer", progress_current=0,
        progress_total=_copy_progress_total(expected_total, 0, 0, jobs_total),
        bytes_total=expected_bytes,
        jobs_current=0, jobs_total=jobs_total)

    warnings: List[str] = []
    errors: List[str] = []
    jobs_done = 0
    landed_total = 0
    lock = threading.Lock()
    last_emit = 0.0
    last_files = -1
    last_bytes = -1
    last_growth = time.time()
    shrink_events = 0
    shrink_bytes = 0
    stop = threading.Event()

    def _live_expected() -> Tuple[int, int]:
        if inventory is None:
            return expected_total, expected_bytes
        with inventory.get("lock", threading.Lock()):
            return int(inventory.get("files", expected_total)), int(
                inventory.get("bytes", expected_bytes))

    def _emit_global(force: bool = False) -> None:
        nonlocal last_emit, last_files, last_bytes, last_growth
        nonlocal shrink_events, shrink_bytes
        now = time.time()
        if not force and now - last_emit < 1.4:
            return
        files, nbytes = disk_stats.snapshot(force=force)
        note = _shrink_note(last_files, last_bytes, files, nbytes)
        if note:
            shrink_events += 1
            shrink_bytes += max(0, last_bytes - nbytes)
            if shrink_events <= 3:
                warnings.append(note)
                say(note, phase="transfer", level="warning")
        # Bytes count as movement too: one large file streaming in holds the
        # file count flat for minutes while the transfer is perfectly healthy.
        if files != last_files or nbytes != last_bytes:
            last_growth = now
        if not force and files == last_files and now - last_emit < 8:
            return
        last_emit = now
        last_files = files
        last_bytes = nbytes
        exp_files, exp_bytes = _live_expected()
        tot = _copy_progress_total(exp_files, files, jobs_done, jobs_total)
        # Per-volume workers run quiet, so this board is the only line the
        # examiner sees. Repeating it verbatim every 8s looks identical
        # whether the copy is progressing or wedged — name the stall so the
        # difference is visible without watching the clock.
        stall = now - last_growth
        elapsed = f"no new data for {int(stall)}s" if stall >= 30 else ""
        _emit_copy_progress(
            say, meter, files, tot, nbytes, max(exp_bytes, nbytes),
            _copy_progress_message(
                files, exp_files, jobs_done=jobs_done,
                jobs_total=jobs_total, meter=meter, elapsed=elapsed,
                bytes_cur=nbytes, bytes_total=max(exp_bytes, nbytes)),
            jobs_current=jobs_done, jobs_total=jobs_total)
        _save_checkpoint(destination, device_name, files=files,
                         nbytes=nbytes, phase="transfer")

    def _progress_loop() -> None:
        while not stop.wait(2.0):
            with lock:
                _emit_global()

    watcher = threading.Thread(target=_progress_loop, daemon=True,
                               name="argus-mtp-board")
    watcher.start()

    def _job(subtree: str, count: int) -> Tuple[str, str, int]:
        nonlocal jobs_done
        if subtree == "__root__":
            sub_dest = destination
            subtree_path = ""
        else:
            sub_dest = destination / subtree.replace("/", os.sep)
            sub_dest.mkdir(parents=True, exist_ok=True)
            subtree_path = subtree
        baseline = _count_files(sub_dest)
        exp_files, exp_bytes = _live_expected()
        for _ in range(45):
            if exp_files > 0:
                break
            time.sleep(2)
            exp_files, exp_bytes = _live_expected()
        with lock:
            done_now = jobs_done
        script = _build_copy_script(
            device_name, str(sub_dest.resolve()),
            max(count or exp_files, 1),
            subtree=subtree_path, turbo=turbo, skip_existing=True)
        out, err, _landed, folder_warns = _run_copy_script(
            script, destination, count or exp_files, exp_files, say, meter,
            exp_bytes, turbo,
            quiet=True, wait_root=sub_dest,
            jobs_done=done_now, jobs_total=jobs_total,
            disk_stats=disk_stats)
        local = max(0, disk_stats.snapshot(force=True)[0] - baseline)
        if listing and count and local < int(max(count, 1) * 0.85):
            kids = _volume_child_jobs(subtree, listing)
            if kids:
                say(f"Volume {subtree} short — recovering {len(kids)} folder(s) "
                    "one at a time…", phase="transfer")
                for kid, kid_count in kids[:32]:
                    kid_dest = destination / kid.replace("/", os.sep)
                    kid_dest.mkdir(parents=True, exist_ok=True)
                    kid_script = _build_copy_script(
                        device_name, str(kid_dest.resolve()),
                        max(kid_count, 1), subtree=kid, turbo=turbo,
                        skip_existing=True)
                    _run_copy_script(
                        kid_script, destination, kid_count, exp_files, say,
                        meter, exp_bytes, turbo, quiet=True,
                        wait_root=kid_dest, jobs_done=done_now,
                        jobs_total=jobs_total, disk_stats=disk_stats)
                local = max(0, disk_stats.snapshot(force=True)[0] - baseline)
        label = subtree or "(device root)"
        with lock:
            jobs_done += 1
            global_files, nbytes = disk_stats.snapshot(force=True)
            exp_files, exp_bytes = _live_expected()
            say(f"Volume done — {label}: +{local:,} file(s) this volume "
                f"({jobs_done}/{jobs_total} volumes, {global_files:,} total)",
                phase="transfer",
                progress_current=global_files,
                progress_total=_copy_progress_total(
                    exp_files, global_files, jobs_done, jobs_total),
                bytes_current=nbytes,
                bytes_total=max(exp_bytes, nbytes),
                jobs_current=jobs_done, jobs_total=jobs_total)
            _emit_global(force=True)
        return out, err, local, folder_warns

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_job, subtree, count) for subtree, count in jobs]
        for fut in as_completed(futures):
            try:
                out, err, landed, folder_warns = fut.result()
            except Exception as exc:
                warnings.append(f"parallel MTP worker failed: {exc}")
                continue
            warnings.extend(folder_warns[:10])
            landed_total = max(landed_total, _count_files(destination))
            if "ERR|" in out:
                warnings.append(out.split("ERR|", 1)[1].strip())
            if err.strip():
                errors.append(err.strip()[:400])

    stop.set()
    watcher.join(timeout=5)
    if shrink_events > 3:
        warnings.append(
            f"Content left the destination {shrink_events:,} time(s) during "
            f"this copy, {human_bytes(shrink_bytes)} in total across all "
            f"occurrences (the first three are itemised above). Repeated "
            f"removals point at the transfer failing rather than at one "
            f"awkward file.")
    landed_total = _count_files(destination)
    return warnings, errors, landed_total


def _ps_creation_flags() -> int:
    """High-priority new process on Windows so copy workers are not starved."""
    if not sys.platform.startswith("win"):
        return 0
    # HIGH_PRIORITY_CLASS | CREATE_NO_WINDOW
    return 0x00000080 | 0x08000000


_PS_UTF8_PREFIX = (
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); "
    "$OutputEncoding = [Console]::OutputEncoding; "
)


def _powershell(script: str, timeout: int = 900) -> Tuple[str, str]:
    script = _PS_UTF8_PREFIX + script
    for shell in ("powershell", "pwsh"):
        if not shutil.which(shell):
            continue
        try:
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-STA",
                 "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, check=False,
                creationflags=_ps_creation_flags())
            return completed.stdout or "", completed.stderr or ""
        except (OSError, subprocess.SubprocessError) as exc:
            return "", str(exc)
    return "", "PowerShell is not available"


def _powershell_start(script: str,
                      timeout: int = 14400) -> Tuple[Optional[subprocess.Popen], str]:
    """Start a PowerShell script without blocking on its output."""
    script = _PS_UTF8_PREFIX + script
    for shell in ("powershell", "pwsh"):
        if not shutil.which(shell):
            continue
        try:
            proc = subprocess.Popen(
                [shell, "-NoProfile", "-NonInteractive", "-STA",
                 "-ExecutionPolicy", "Bypass", "-Command", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=_ps_creation_flags(),
            )
            return proc, ""
        except (OSError, subprocess.SubprocessError) as exc:
            return None, str(exc)
    return None, "PowerShell is not available"


def backend() -> str:
    """Which MTP transport this host can use: windows-shell, gvfs, libmtp, or ''."""
    if sys.platform.startswith("win"):
        return "windows-shell"
    if _unix_mtp_mounts():
        return "gvfs"
    if shutil.which("gio") or shutil.which("mtp-detect") or shutil.which("simple-mtpfs"):
        return "libmtp"
    return ""


def available() -> bool:
    """Is MTP acquisition possible on this platform?"""
    return bool(backend())


_UNIX_VOLUME_MARKERS = (
    "dcim", "android", "whatsapp", "download", "pictures", "movies",
    "music", "documents", "internal storage", "sd card",
)
_UNIX_VOLUME_SKIP = {
    "macintosh hd", "untitled", "data", "system", "preboot", "recovery",
    "vm", "windows", "efi", "boot", "home",
}


def _unix_looks_like_phone_storage(root: Path) -> bool:
    """True when a directory looks like Android shared storage, not a local disk."""
    try:
        names = {p.name.lower() for p in root.iterdir()}
    except OSError:
        return False
    return any(marker in names or any(marker in n for n in names)
               for marker in _UNIX_VOLUME_MARKERS)


def _unix_mtp_mounts() -> List[MTPDevice]:
    """GVFS / libmtp / Android File Transfer mounts on Linux and macOS."""
    mounts: List[MTPDevice] = []
    seen: set[str] = set()
    bases: List[Path] = []
    if hasattr(os, "getuid"):
        bases.append(Path(f"/run/user/{os.getuid()}/gvfs"))
    bases.append(Path.home() / ".gvfs")
    bases.append(Path("/Volumes"))
    for base in bases:
        if not base.is_dir():
            continue
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            low = child.name.lower()
            gvfs_mtp = low.startswith("mtp:") or "mtp:host=" in low or low.startswith("mtp;")
            volume = base.name == "Volumes"
            if volume:
                if low in _UNIX_VOLUME_SKIP or low.startswith("com."):
                    continue
                if not _unix_looks_like_phone_storage(child):
                    continue
            elif not gvfs_mtp and not _unix_looks_like_phone_storage(child):
                continue
            try:
                key = str(child.resolve())
            except OSError:
                key = str(child)
            if key in seen:
                continue
            seen.add(key)
            display = child.name
            if "mtp:host=" in display.lower():
                display = display.split("mtp:host=", 1)[-1]
            mounts.append(MTPDevice(name=display, path=key))
    return mounts


def _unix_match_device(device_name: str) -> Optional[MTPDevice]:
    want = (device_name or "").strip().lower()
    found = _unix_mtp_mounts()
    if not want:
        return found[0] if found else None
    for dev in found:
        name = dev.name.lower()
        path = (dev.path or "").lower()
        if name == want or want in name or name in want or want in path:
            return dev
    return found[0] if len(found) == 1 else None


def devices() -> List[MTPDevice]:
    """Handsets mounted in the shell namespace (This PC) or GVFS/libmtp."""
    if not available():
        return []
    if not sys.platform.startswith("win"):
        return _unix_mtp_mounts()
    out, _err = _powershell(_ENUMERATE_DEVICES, timeout=60)
    found: List[MTPDevice] = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        name, path = line.split("|", 1)
        name = name.strip()
        if not name or name.lower() in ("desktop", "documents", "downloads",
                                        "music", "pictures", "videos",
                                        "3d objects"):
            continue
        found.append(MTPDevice(name=name, path=path.strip()))
    return found


def pick_device(found: List[MTPDevice], *,
                name: str = "", serial: str = "",
                hints: Optional[List[str]] = None) -> Optional[MTPDevice]:
    """Choose the MTP handset that matches the exhibit, not the first on the bus."""
    if not found:
        return None
    tokens: List[str] = []
    for raw in [name, serial, *(hints or [])]:
        token = (raw or "").strip().lower()
        if not token:
            continue
        if token not in tokens:
            tokens.append(token)
        for part in token.replace("_", " ").replace("-", " ").split():
            if part not in tokens:
                tokens.append(part)
        if len(token) >= 8:
            prefix = token[:8]
            if prefix not in tokens:
                tokens.append(prefix)
    if not tokens:
        return found[0]
    ranked: List[tuple] = []
    for device in found:
        blob = f"{device.name} {device.path}".lower()
        score = 0
        for token in tokens:
            if len(token) < 3:
                continue
            if token == device.name.lower():
                score += 50
            elif token in blob:
                score += 20
            elif blob in token:
                score += 10
        ranked.append((score, device))
    ranked.sort(key=lambda item: -item[0])
    return ranked[0][1] if ranked[0][0] else found[0]


def list_volumes(device_name: str) -> List[str]:
    """Top-level storage roots the phone exposes (Internal storage, SD card)."""
    if not available() or not device_name:
        return []
    if not sys.platform.startswith("win"):
        mount = _unix_match_device(device_name)
        if not mount:
            return []
        names: List[str] = []
        try:
            for child in Path(mount.path).iterdir():
                if child.is_dir():
                    names.append(child.name)
        except OSError:
            return [mount.name]
        return names or [mount.name]
    script = _LIST_VOLUMES.replace("__DEVICE__", _ps_quote(device_name))
    out, _err = _powershell(script, timeout=60)
    names: List[str] = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        name = line.split("|", 1)[0].strip()
        if name:
            names.append(name)
    return names


def list_copy_jobs(device_name: str) -> List[Tuple[str, int]]:
    """Storage volumes on the handset — enough to start copying immediately.

    A full tree walk can take minutes. Volume names (``Internal storage``,
    ``SD card``) are available in seconds and are the right unit for MTP copy:
  one Shell worker per volume, not one per top-level folder.
    """
    volumes = list_volumes(device_name)
    return [(name, 0) for name in volumes]


def list_tree(device_name: str, max_depth: int = 6) -> List[Dict[str, Any]]:
    """Enumerate the device before copying.

    The listing is what makes missing files detectable afterwards. Without it
    there is nothing to compare the copy against, and a partial transfer is
    indistinguishable from a phone that simply held less.
    """
    if not available():
        return []
    script = (_LIST_TREE.replace("__DEVICE__", device_name)
                        .replace("__MAXDEPTH__", str(max_depth)))
    out, _err = _powershell(script, timeout=600)
    entries: List[Dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        kind, rel, size = parts
        if kind not in ("F", "D"):
            continue
        try:
            size_value = int(size) if size.strip().isdigit() else 0
        except ValueError:
            size_value = 0
        entries.append({"kind": kind, "path": rel, "size": size_value})
    return entries


def _ps_quote(value: str) -> str:
    """Escape a path for embedding in a PowerShell single-quoted string."""
    return (value or "").replace("'", "''")


def _copy_progress_message(count: int, expected: int, *,
                           jobs_done: int = 0, jobs_total: int = 0,
                           elapsed: str = "",
                           meter: Optional[ProgressMeter] = None,
                           bytes_cur: int = 0,
                           bytes_total: int = 0,
                           stalled: bool = False) -> str:
    """Human progress line — throughput, data volume, never 'N of 0'."""
    if expected > 0:
        body = f"{count:,} of {expected:,} file(s)"
    else:
        body = f"{count:,} file(s) on disk"
        if jobs_total > 0:
            body += f" · {jobs_done}/{jobs_total} volumes"
        else:
            body += " · inventory still running"
    if bytes_cur > 0:
        if bytes_total > 0 and bytes_cur > int(bytes_total * 1.25):
            # In-flight/partial files inflate the on-disk total; don't show
            # "12 GB / 1.23 GB" as if the listing was wrong.
            body += f" · {human_bytes(bytes_total)} listed"
        else:
            body += f" · {human_bytes(bytes_cur)}"
            if bytes_total > bytes_cur:
                body += f" / {human_bytes(bytes_total)}"
    if meter and count > 0 and not stalled:
        rate = meter.rate(count)
        if rate >= 0.5:
            body += f" · {rate:.1f} files/s"
        eta = int(meter.eta_seconds(count, expected or count))
        if eta > 0 and expected > count:
            mins, secs = divmod(eta, 60)
            body += f" · ~{mins}m {secs:02d}s left"
    if stalled:
        suffix = f" ({elapsed})" if elapsed else ""
        return f"Stalled — {body}{suffix} · recovery next"
    if elapsed:
        return f"Copy in progress… {body} ({elapsed})"
    return f"Copying… {body}"


def _copy_progress_total(expected_files: int, arrived: int,
                         jobs_done: int, jobs_total: int) -> int:
    """Denominator for the progress bar while the listing is still running."""
    if expected_files > 0:
        return max(expected_files, arrived)
    if jobs_total > 0:
        return max(jobs_total, arrived + max(0, jobs_total - jobs_done))
    return max(arrived, 1)


def _bytes_on_disk(root: Path) -> int:
    return _DiskStats(root, refresh_sec=0).snapshot(force=True)[1]


def _count_files(root: Path) -> int:
    return _DiskStats(root, refresh_sec=0).snapshot(force=True)[0]


def _drain_progress_lines(proc: subprocess.Popen,
                          say: Callable[..., None],
                          meter: ProgressMeter,
                          expected: int,
                          bytes_total: int,
                          sink: List[str],
                          *,
                          quiet: bool = False) -> None:
    """Read PowerShell stdout, keep full output. Disk counts come from Python."""
    if not proc.stdout:
        return
    for raw in proc.stdout:
        sink.append(raw)
        if quiet:
            continue
        line = (raw or "").strip()
        if not line.startswith("PROGRESS|"):
            continue
        # PowerShell reports queued CopyHere items, not files on disk.
        # Ignore those as arrivals so the UI does not jump backwards.


def _emit_copy_progress(say: Callable[..., None], meter: ProgressMeter,
                        count: int, expected: int,
                        bytes_current: int, bytes_total: int,
                        message: str, **extra: Any) -> None:
    snap = meter.snapshot(
        current=count, total=expected,
        bytes_current=bytes_current, bytes_total=bytes_total,
        message=message)
    snap.pop("message", None)
    snap.update(extra)
    say(message, **snap)


def _stable_polls_needed(expected: int, count: int, base: int) -> int:
    """Require longer settling when we are far below the listed file total."""
    if expected <= 0:
        return base
    ratio = count / max(expected, 1)
    if ratio < 0.70:
        return max(base, 10)
    if ratio < 0.90:
        return max(base, 8)
    if ratio < 0.97:
        return max(base, 6)
    return base


def _extended_settle(destination: Path, expected: int, expected_bytes: int,
                       say: Callable[..., None], meter: ProgressMeter,
                       landed: int, *, turbo: bool) -> int:
    """Keep watching disk until listed file count is reached or timeout."""
    if expected <= 0 or landed >= expected:
        return landed
    if landed >= int(expected * 0.995):
        return landed
    say(f"Only {landed:,} of {expected:,} listed file(s) on disk — "
        f"waiting briefly for MTP to flush, then retrying gaps…",
        phase="transfer",
        progress_current=landed, progress_total=expected,
        bytes_total=expected_bytes)
    stats = _DiskStats(destination, refresh_sec=2.0)
    return _wait_for_copy(
        destination, expected, say, meter, expected_bytes,
        proc=None, timeout=180,
        stable_polls=8 if turbo else 10,
        scan_interval=2.0, disk_stats=stats,
        stall_exit_seconds=45)


def _top_folders_from_listing(listing: List[Dict[str, Any]],
                              volume: str) -> Dict[str, int]:
    """Count listed files per top-level folder under a volume."""
    prefix = volume + "/"
    counts: Dict[str, int] = {}
    for entry in listing:
        if entry.get("kind") != "F":
            continue
        path = entry.get("path") or ""
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):]
        folder = rest.split("/", 1)[0] if "/" in rest else "__root__"
        key = volume if folder == "__root__" else f"{volume}/{folder}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _missing_top_folders(destination: Path, listing: List[Dict[str, Any]],
                         volume: str, *, min_files: int = 3
                         ) -> List[Tuple[str, int]]:
    """Top-level folders listed on device but absent or nearly empty on disk."""
    arrived = _index_arrived(destination)
    by_folder = _top_folders_from_listing(listing, volume)
    missing: List[Tuple[str, int]] = []
    for folder_path, listed in sorted(by_folder.items(), key=lambda kv: -kv[1]):
        if listed < min_files:
            continue
        prefix = folder_path.replace("/", os.sep) + os.sep
        on_disk = sum(
            1 for rel in arrived
            if rel.replace("/", os.sep).startswith(prefix) or rel == folder_path)
        if on_disk < max(1, int(listed * 0.05)):
            missing.append((folder_path, listed))
    return missing


def _retry_missing_folders(device_name: str, destination: Path,
                             folders: List[Tuple[str, int]],
                             say: Callable[..., None],
                             meter: ProgressMeter,
                             expected_bytes: int,
                             turbo: bool) -> int:
    """Second pass — copy top-level folders that did not land on the first pass."""
    if not folders:
        return _count_files(destination)
    before = _count_files(destination)
    for subtree, listed in folders[:12]:
        say(f"Retrying folder — {subtree} ({listed:,} file(s) listed on device)…",
            phase="transfer")
        sub_dest = (destination / subtree.replace("/", os.sep)
                    if "/" in subtree else destination)
        sub_dest.mkdir(parents=True, exist_ok=True)
        script = _build_copy_script(
            device_name, str(sub_dest.resolve()), listed,
            subtree=subtree, turbo=turbo, skip_existing=True)
        _run_copy_script(
            script, destination, listed, listed, say, meter,
            expected_bytes, turbo, quiet=True, wait_root=sub_dest)
    after = _count_files(destination)
    if after > before:
        say(f"Folder retry pass added {after - before:,} file(s) "
            f"({after:,} total on disk).", phase="transfer")
    return after


def _wait_for_copy(destination: Path, expected: int,
                   say: Callable[..., None],
                   meter: ProgressMeter,
                   bytes_total: int,
                   timeout: int = 14400,
                   proc: Optional[subprocess.Popen] = None,
                   *,
                   stable_polls: int = 8,
                   scan_interval: float = 1.5,
                   quiet: bool = False,
                   jobs_done: int = 0,
                   jobs_total: int = 0,
                   disk_stats: Optional[_DiskStats] = None,
                   on_progress: Optional[Callable[[int, int], None]] = None,
                   stall_exit_seconds: Optional[float] = None
                   ) -> int:
    """Wait until the MTP shell copy has landed files on disk.

    CopyHere is asynchronous; without this wait reconciliation runs against an
    empty folder. Exits when PowerShell has finished *and* the file count is
    stable. Never gives up while the copy process is still alive — a large
    folder can sit quiet for minutes before Explorer flushes files.
    """
    meter.set_phase("transfer")
    stats = disk_stats or _DiskStats(destination, refresh_sec=scan_interval)
    deadline = time.time() + timeout
    started = time.time()
    last = -1
    last_bytes = -1
    last_report = 0.0
    last_scan = 0.0
    last_growth = time.time()
    count = 0
    bytes_cur = 0
    scanned_stable = 0
    while time.time() < deadline:
        now = time.time()
        alive = proc is not None and proc.poll() is None
        if alive and last_scan > 0 and now - last_scan < scan_interval:
            time.sleep(min(0.2, scan_interval))
            continue
        count, bytes_cur = stats.snapshot(force=not alive)
        last_scan = now
        if count != last or bytes_cur != last_bytes:
            scanned_stable = 0
            last_growth = now
            if on_progress:
                on_progress(count, bytes_cur)
            if not quiet:
                tot = _copy_progress_total(expected, count, jobs_done, jobs_total)
                _emit_copy_progress(
                    say, meter, count, tot,
                    bytes_cur, max(bytes_total, bytes_cur),
                    _copy_progress_message(
                        count, expected, jobs_done=jobs_done,
                        jobs_total=jobs_total, meter=meter,
                        bytes_cur=bytes_cur,
                        bytes_total=max(bytes_total, bytes_cur)))
            last_report = now
        else:
            scanned_stable += 1
            stall = now - last_growth
            stalled = not alive and stall >= 60
            hung_worker = alive and stall_exit_seconds and stall >= stall_exit_seconds
            finished_short = (stall_exit_seconds and not alive
                              and stall >= stall_exit_seconds
                              and expected > 0
                              and count < int(expected * 0.97))
            if hung_worker or finished_short:
                if hung_worker and proc is not None:
                    say(f"Copy worker silent {int(stall)}s — killing hung "
                        "stream and recovering remaining folders…",
                        phase="transfer",
                        progress_current=count,
                        progress_total=max(expected, count),
                        bytes_current=bytes_cur,
                        bytes_total=max(bytes_total, bytes_cur))
                    try:
                        proc.kill()
                    except OSError:
                        pass
                elif not quiet:
                    say(f"MTP copy stalled at {count:,}/{expected:,} for "
                        f"{int(stall)}s — moving to folder/file recovery…",
                        phase="transfer",
                        progress_current=count, progress_total=expected,
                        bytes_current=bytes_cur,
                        bytes_total=max(bytes_total, bytes_cur))
                return count
            if not quiet and now - last_report >= 12:
                elapsed = int(now - started)
                mins, secs = divmod(elapsed, 60)
                note = ""
                if alive and stall >= 90:
                    note = " · large folder flushing on device"
                elif stalled:
                    note = f" · no new files for {int(stall)}s"
                tot = _copy_progress_total(expected, count, jobs_done, jobs_total)
                _emit_copy_progress(
                    say, meter, count, tot,
                    bytes_cur, max(bytes_total, bytes_cur),
                    _copy_progress_message(
                        count, expected, jobs_done=jobs_done,
                        jobs_total=jobs_total,
                        elapsed=f"{mins}m {secs:02d}s elapsed{note}",
                        meter=meter, bytes_cur=bytes_cur,
                        bytes_total=max(bytes_total, bytes_cur),
                        stalled=stalled))
                last_report = now
            if not alive and scanned_stable >= _stable_polls_needed(
                    expected, count, stable_polls):
                if expected <= 0 or count >= int(expected * 0.97):
                    return count
                shortfall = stable_polls + (10 if expected > 0
                                            and count < int(expected * 0.90)
                                            else 20)
                if scanned_stable >= shortfall:
                    return count
        last = count
        last_bytes = bytes_cur
    return stats.snapshot(force=True)[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def check_free_space(destination: Path, needed_bytes: int,
                     headroom: float = 0.05) -> dict:
    """Pre-flight free-space check with configurable headroom.

    Returns dict with ok, free, needed, shortfall. headroom is 5% default
    (10% for >10GB acquisitions is applied by caller). Never raises — a
    failure to stat is reported as ok=True with a warning so acquisition
    can still proceed on exotic filesystems.
    """
    try:
        free = shutil.disk_usage(destination).free if destination.exists() else shutil.disk_usage(destination.parent).free
    except OSError:
        return {"ok": True, "free": -1, "needed": needed_bytes, "warning": "free-space check unavailable"}
    needed = int(needed_bytes * (1.0 + headroom))
    if free < needed:
        return {"ok": False, "free": free, "needed": needed, "shortfall": needed - free}
    return {"ok": True, "free": free, "needed": needed, "shortfall": 0}


def verify_manifest(manifest_path: Path | str, root: Path | str | None = None) -> dict:
    """Re-hash acquisition against its manifest — mirrors PowerShell Verify.

    Reports unchanged / altered / missing / added. Returns dict with counts
    and detail lists. Hash mismatches are integrity failures, not silent.
    """
    manifest_path = Path(manifest_path)
    if root is None:
        root = manifest_path.parent
    else:
        root = Path(root)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc), "unchanged": [], "altered": [], "missing": [], "added": []}
    hashes: dict = data.get("hashes") or {}
    # support both flat hashes and nested manifest shapes
    if not hashes and "hashes" in data:
        hashes = data["hashes"]
    unchanged: list = []
    altered: list = []
    missing: list = []
    for rel, expected in hashes.items():
        local = root / rel.replace("/", os.sep)
        if not local.is_file():
            # also try as stored rel with backslash on Windows manifests
            alt = root / rel.replace("\\", os.sep).replace("/", os.sep)
            if alt.is_file():
                local = alt
            else:
                missing.append(rel)
                continue
        actual = _sha256(local)
        if not actual:
            missing.append(rel)
        elif actual.lower() == str(expected).lower():
            unchanged.append(rel)
        else:
            altered.append({"path": rel, "expected": expected, "actual": actual})
    # detect added files not in manifest
    arrived = _index_arrived(root)
    added = [rel for rel in arrived if rel not in hashes and rel.replace(os.sep, "/") not in hashes and rel.replace("/", "\\") not in hashes]
    # also handle case-insensitive manifest keys
    manifest_lower = {k.lower(): k for k in hashes}
    added = [rel for rel in added if rel.lower() not in manifest_lower]
    return {
        "ok": len(altered) == 0 and len(missing) == 0,
        "unchanged": unchanged,
        "altered": altered,
        "missing": missing,
        "added": added,
        "counts": {"unchanged": len(unchanged), "altered": len(altered), "missing": len(missing), "added": len(added)},
    }


def _acquire_unix(device_name: str, destination: Path,
                  result: AcquisitionResult,
                  progress: Optional[Callable[[str], None]],
                  *, hash_files: bool, resume: bool,
                  turbo: bool) -> AcquisitionResult:
    """Copy from a GVFS / Android File Transfer mount — hashed, with shortfall."""
    mount = _unix_match_device(device_name)
    if not mount:
        result.warnings.append(
            "No MTP mount visible. On Linux install gvfs-mtp or libmtp and "
            "unlock the phone on File transfer. On macOS open Android File "
            "Transfer, then retry.")
        result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        return result
    src = Path(mount.path)
    result.method_note = (
        METHOD_NOTE + " Copied from a desktop MTP mount (GVFS/libmtp/"
        "Android File Transfer), not the Windows Shell namespace.")
    result.volumes = [p.name for p in src.iterdir() if p.is_dir()] or [mount.name]
    meter = ProgressMeter()

    def say(message: str, **extra: Any) -> None:
        if not progress:
            return
        if extra.get("phase"):
            meter.set_phase(str(extra.pop("phase")))
        snap = meter.snapshot(
            current=int(extra.get("progress_current", 0)),
            total=int(extra.get("progress_total", 0)),
            bytes_current=int(extra.get("bytes_current", 0)),
            bytes_total=int(extra.get("bytes_total", 0)),
            message=message)
        snap.pop("message", None)
        snap.update(extra)
        try:
            progress(message, **snap)
        except TypeError:
            progress(message)

    say(f"Copying from MTP mount {mount.name}…", phase="transfer")
    listed = 0
    copied = 0
    nbytes = 0
    expected: Dict[str, int] = {}
    for dirpath, _dirnames, filenames in os.walk(src):
        for name in filenames:
            if name in _SKIP_ARTIFACTS:
                continue
            remote = Path(dirpath) / name
            try:
                rel = remote.relative_to(src).as_posix()
                size = remote.stat().st_size
            except OSError:
                continue
            listed += 1
            expected[rel] = size
            local = destination / rel.replace("/", os.sep)
            if resume and local.is_file():
                try:
                    if local.stat().st_size == size:
                        copied += 1
                        nbytes += size
                        continue
                except OSError:
                    pass
            local.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(remote, local)
                copied += 1
                nbytes += size
                if hash_files and not turbo:
                    digest = _sha256(local)
                    if digest:
                        result.hashes[rel] = digest
            except OSError as exc:
                result.missing.append({"path": rel, "size": size,
                                       "reason": str(exc)[:200]})
            if listed == 1 or listed % 250 == 0:
                say(f"Copying… {copied:,} of {listed:,} file(s)",
                    phase="transfer",
                    progress_current=copied, progress_total=max(listed, 1),
                    bytes_current=nbytes)
    arrived = _index_arrived(destination)
    for rel, size in expected.items():
        if rel not in arrived and not any(
                m.get("path") == rel for m in result.missing):
            result.missing.append({"path": rel, "size": size,
                                   "reason": "not on disk after copy"})
    result.files_listed = listed
    result.files_copied = len(arrived)
    result.bytes_copied = nbytes
    result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    say(f"Done: {result.files_copied} file(s) from {mount.name}.",
        phase="verify")
    return result


def acquire(device_name: str, destination: Path | str,
            progress: Optional[Callable[[str], None]] = None,
            hash_files: bool = True,
            resume: bool = False,
            turbo: bool = False) -> AcquisitionResult:
    """Copy a handset's shared storage, recording hashes and every failure."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    result = AcquisitionResult(
        device=device_name, destination=str(destination),
        started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        method_note=METHOD_NOTE)

    if not available():
        result.warnings.append(
            "MTP acquisition is implemented for Windows Shell, Linux GVFS/"
            "libmtp, and macOS Android File Transfer mounts. mount the handset "
            "and retry, or enable USB debugging for ADB.")
        result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        return result

    if not sys.platform.startswith("win"):
        return _acquire_unix(
            device_name, destination, result, progress,
            hash_files=hash_files, resume=resume, turbo=turbo)

    meter = ProgressMeter()

    def say(message: str, **extra: Any) -> None:
        if not progress:
            return
        if extra.get("phase"):
            meter.set_phase(str(extra.pop("phase")))
        cur = int(extra.get("progress_current", 0))
        tot = int(extra.get("progress_total", 0))
        bcur = int(extra.get("bytes_current", 0))
        btot = int(extra.get("bytes_total", 0))
        snap = meter.snapshot(
            current=cur, total=tot,
            bytes_current=bcur, bytes_total=btot, message=message)
        snap.pop("message", None)
        snap.update(extra)
        try:
            progress(message, **snap)
        except TypeError:
            progress(message)

    # 1. Inventory. A full tree walk can take minutes — start the copy as soon
    #    as we know the top-level folders, and finish the listing in parallel.
    meter.set_phase("inventory")
    say(f"Listing {device_name}…", phase="inventory",
        progress_current=0, progress_total=0)
    listing: List[Dict[str, Any]] = []
    listing_thread: Optional[threading.Thread] = None
    listing_box: List[Dict[str, Any]] = []
    fast_jobs: List[Tuple[str, int]] = []
    inventory_live: Dict[str, Any] = {
        "files": 0, "bytes": 0, "lock": threading.Lock(),
    }
    if resume:
        cached = _load_listing_cache(destination, device_name)
        if cached:
            listing = cached
            say(f"Using cached device listing ({len(cached):,} entries) — "
                f"skipping re-enumeration.",
                phase="inventory")
        ckpt = _load_checkpoint(destination, device_name)
        if ckpt:
            say(f"Resume checkpoint — {ckpt.get('files_on_disk', 0):,} "
                f"file(s) already on disk "
                f"({human_bytes(int(ckpt.get('bytes_on_disk', 0)))}).",
                phase="inventory")
    if not listing:
        volumes_now = list_volumes(device_name)
        fast_jobs = _coalesce_copy_jobs(list_copy_jobs(device_name))
        if not fast_jobs and volumes_now:
            fast_jobs = [(name, 0) for name in volumes_now]
        if fast_jobs:
            say("Starting copy immediately — full inventory runs in parallel "
                f"({len(fast_jobs)} storage volume(s) queued).",
                phase="inventory")

            def _bg_list() -> None:
                listing_box.extend(
                    list_tree(device_name, max_depth=16 if turbo else 20))
                files = sum(1 for e in listing_box if e.get("kind") == "F")
                nbytes = sum(
                    int(e.get("size") or 0)
                    for e in listing_box if e.get("kind") == "F")
                with inventory_live["lock"]:
                    inventory_live["files"] = files
                    inventory_live["bytes"] = nbytes
                if files:
                    say(f"Inventory complete — {files:,} file(s) listed "
                        f"({nbytes / (1024 ** 3):.2f} GB).",
                        phase="inventory",
                        progress_total=files, bytes_total=nbytes)

            listing_thread = threading.Thread(
                target=_bg_list, daemon=True, name="argus-mtp-inventory")
            listing_thread.start()
        else:
            listing = list_tree(device_name, max_depth=16 if turbo else 20)
            if listing:
                _save_listing_cache(destination, device_name, listing)
    expected = {e["path"]: e["size"] for e in listing if e["kind"] == "F"}
    expected_bytes = sum(expected.values())
    result.files_listed = len(expected)
    volumes: List[str] = []
    for entry in listing:
        if entry.get("kind") != "D":
            continue
        top = (entry.get("path") or "").split("/", 1)[0]
        if top and top not in volumes:
            volumes.append(top)
    if not volumes:
        volumes = [j[0].split("/", 1)[0] for j in fast_jobs]
        volumes = list(dict.fromkeys(volumes))
    if not volumes:
        volumes = list_volumes(device_name)
    result.volumes = volumes
    if volumes:
        say("Storage volumes: " + ", ".join(volumes), phase="inventory")
    if expected:
        say(f"{len(expected):,} file(s) listed on the device.",
            phase="inventory", progress_current=0,
            progress_total=len(expected), bytes_total=expected_bytes)

    # ---- pre-flight free-space check (mirrors PowerShell 5% + 10% for >10GB) ----
    if expected_bytes > 0:
        headroom = 0.10 if expected_bytes > 10 * (1024 ** 3) else 0.05
        space = check_free_space(destination, expected_bytes, headroom=headroom)
        if space.get("free", -1) >= 0:
            say(f"Free on destination: {human_bytes(space['free'])} — "
                f"needed {human_bytes(space['needed'])} "
                f"({len(expected):,} files, {human_bytes(expected_bytes)} + {int(headroom*100)}% headroom)",
                phase="inventory")
            if not space["ok"]:
                short = space.get("shortfall", 0)
                msg = (f"NOT ENOUGH FREE SPACE — need {human_bytes(space['needed'])}, "
                       f"have {human_bytes(space['free'])} (short by {human_bytes(short)}). "
                       f"Free space or choose another destination. Nothing has been copied yet.")
                result.warnings.append(msg)
                say(msg, phase="inventory", level="error")
                result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                return result
            if space["free"] < space["needed"] * 1.5:
                warn = "Space is tight — will leave under 50% headroom after copy."
                result.warnings.append(warn)
                say(warn, phase="inventory", level="warning")

    pre_arrived: Dict[str, int] = {}
    matched = 0
    if resume:
        for rel, path in _index_arrived(destination).items():
            try:
                pre_arrived[rel] = path.stat().st_size
            except OSError:
                pass
        matched = sum(1 for rel, size in expected.items()
                      if pre_arrived.get(rel) == size)
        if matched:
            say(f"Resume: {matched:,} of {len(expected):,} file(s) already "
                f"at correct size — copy will skip existing.",
                phase="transfer",
                progress_current=matched,
                progress_total=len(expected) or 1)

    # 2. Copy. One CopyHere per folder (Explorer speed) on parallel USB streams.
    copy_hint = ("God-level MTP — silent dialog-safe copy, forensic folders "
                 "first (DCIM → messages → Android), parallel inventory."
                 if turbo else
                 "God-level MTP — silent copy, forensic priority ordering.")
    say(copy_hint,
        phase="transfer", progress_current=matched,
        progress_total=_copy_progress_total(
            len(expected), matched, 0, len(fast_jobs or [])),
        bytes_total=expected_bytes,
        jobs_current=0, jobs_total=len(fast_jobs or []))

    parallel_jobs = _coalesce_copy_jobs(
        fast_jobs or _parallel_copy_jobs(listing))
    landed_count = matched
    if parallel_jobs:
        job_warnings, job_errors, landed_count = _copy_parallel_subtrees(
            device_name, destination, parallel_jobs,
            len(expected), expected_bytes, say, meter, turbo,
            inventory=inventory_live if listing_thread else None,
            listing=listing or listing_box)
        result.warnings.extend(job_warnings)
        if job_errors:
            result.warnings.append("; ".join(job_errors[:3]))
    else:
        dest_path = str(destination.resolve())
        script = _build_copy_script(
            device_name, dest_path, len(expected), turbo=turbo,
            skip_existing=True)
        proc, start_err = _powershell_start(script, timeout=14400)
        ps_out: List[str] = []
        out = err = ""
        if not proc:
            result.warnings.append(start_err or "PowerShell could not start the copy.")
        else:
            say(f"Copy started — watching {dest_path}")
            reader = threading.Thread(
                target=_drain_progress_lines,
                args=(proc, say, meter, len(expected), expected_bytes, ps_out),
                kwargs={"quiet": True},
                daemon=True,
                name="argus-mtp-progress",
            )
            reader.start()
            landed_count = _wait_for_copy(
                destination, len(expected), say, meter, expected_bytes, proc=proc,
                stable_polls=4 if turbo else 6,
                scan_interval=2.2)
            reader.join(timeout=10)
            try:
                proc.wait(timeout=14400)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
                result.warnings.append(
                    "PowerShell copy process did not exit cleanly after files "
                    "stopped arriving.")
            out = "".join(ps_out)
            err = (proc.stderr.read() if proc.stderr else "") or ""
        if "ERR|" in out:
            result.warnings.append(out.split("ERR|", 1)[1].strip())
        if err.strip():
            result.warnings.append(err.strip()[:400])

    if listing_thread is not None:
        say("Finishing device inventory for missing-file check…",
            phase="inventory")
        listing_thread.join(timeout=600)
        listing = listing_box
        if listing:
            _save_listing_cache(destination, device_name, listing)
        expected = {e["path"]: e["size"] for e in listing if e["kind"] == "F"}
        expected_bytes = sum(expected.values())
        result.files_listed = len(expected)
        if not listing:
            result.warnings.append(
                "Full MTP listing did not finish — copied files are kept, "
                "but a missing-file check could not run.")
        else:
            vols: List[str] = []
            for entry in listing:
                if entry.get("kind") != "D":
                    continue
                top = (entry.get("path") or "").split("/", 1)[0]
                if top and top not in vols:
                    vols.append(top)
            if vols:
                result.volumes = vols

    landed_count = _extended_settle(
        destination, len(expected), expected_bytes, say, meter,
        landed_count, turbo=turbo)

    if listing and result.volumes:
        for vol in result.volumes:
            gaps = _missing_top_folders(destination, listing, vol)
            if gaps:
                names = ", ".join(p.split("/")[-1] for p, _ in gaps[:6])
                say(f"Missing folder(s) on disk — retrying: {names}",
                    phase="transfer")
                landed_count = _retry_missing_folders(
                    device_name, destination, gaps, say, meter,
                    expected_bytes, turbo)
                landed_count = _extended_settle(
                    destination, len(expected), expected_bytes, say, meter,
                    landed_count, turbo=turbo)

    if landed_count < len(expected) and len(expected) > 0:
        say(f"Copy pass finished with {landed_count} of {len(expected)} "
            f"file(s) on disk — reconciling shortfall.")

    # 3. Reconcile what arrived against what was listed.
    meter.set_phase("verify")
    bytes_now = _bytes_on_disk(destination)
    say("Reconciling…" if turbo else "Hashing and reconciling…",
        phase="verify",
        progress_current=landed_count,
        progress_total=len(expected), bytes_total=expected_bytes,
        bytes_current=bytes_now)
    arrived = _index_arrived(destination)
    by_lower, by_tail = _build_arrival_lookup(arrived)

    result.files_copied = len(arrived)
    for relative, path in arrived.items():
        try:
            result.bytes_copied += path.stat().st_size
        except OSError:
            pass

    if hash_files and arrived:
        hash_workers = min(16, max(4, (os.cpu_count() or 4) * 2))
        items = list(arrived.items())

        def _hash_pair(item: Tuple[str, Path]) -> Tuple[str, str]:
            rel, p = item
            return rel, _sha256(p)

        hashed = 0
        total_hash = len(items)
        with ThreadPoolExecutor(max_workers=hash_workers) as pool:
            for rel, digest in pool.map(_hash_pair, items):
                if digest:
                    result.hashes[rel] = digest
                hashed += 1
                if hashed == 1 or hashed == total_hash or hashed % 250 == 0:
                    say(f"Hashing {hashed:,}/{total_hash:,} file(s)…",
                        phase="verify",
                        progress_current=hashed,
                        progress_total=total_hash,
                        bytes_current=bytes_now,
                        bytes_total=expected_bytes)

    # A listed file that never arrived is the thing Explorer would not have
    # told anyone about. Fuzzy matching handles Windows case drift and MTP
    # path quirks; skip retry when bulk copy clearly exceeded the inventory.
    matched = 0
    for relative, size in expected.items():
        if _resolve_listed_path(relative, arrived, by_lower, by_tail):
            matched += 1
            continue
        result.missing.append({
            "path": relative, "size": size,
            "reason": ("Listed on the handset but not present after the copy. "
                       "MTP transfers fail individually — a file locked by the "
                       "device, a name the host filesystem rejects, or an entry "
                       "the media provider lists but will not serve."),
        })

    if result.missing and len(arrived) > len(expected):
        result.warnings.append(
            f"Bulk copy brought {len(arrived):,} file(s) but the MTP inventory "
            f"listed only {len(expected):,} — {matched:,} listed paths matched "
            f"on disk. {len(result.missing):,} listing entries could not be "
            f"matched (often stale MTP cache entries, not copy failures).")

    if result.missing and _should_retry_missing(expected, arrived, result.missing):
        say(f"Retrying {len(result.missing):,} missing file(s)…",
            phase="transfer")
        _retry_missing_files(device_name, destination, result.missing,
                             say, turbo=turbo)
        arrived = _index_arrived(destination)
        by_lower, by_tail = _build_arrival_lookup(arrived)
        result.files_copied = len(arrived)
        result.bytes_copied = 0
        for relative, path in arrived.items():
            try:
                result.bytes_copied += path.stat().st_size
            except OSError:
                pass
        if hash_files and arrived:
            hash_workers = min(16, max(4, (os.cpu_count() or 4) * 2))
            items = list(arrived.items())

            def _hash_pair(item: Tuple[str, Path]) -> Tuple[str, str]:
                rel, p = item
                return rel, _sha256(p)

            with ThreadPoolExecutor(max_workers=hash_workers) as pool:
                for rel, digest in pool.map(_hash_pair, items):
                    if digest:
                        result.hashes[rel] = digest
        still_missing: List[Dict[str, Any]] = []
        for relative, size in expected.items():
            if _resolve_listed_path(relative, arrived, by_lower, by_tail):
                continue
            still_missing.append({
                "path": relative, "size": size,
                "reason": ("Listed on the handset but not present after retry. "
                           "MTP may refuse locked or unsupported files."),
            })
        result.missing = still_missing
    elif result.missing:
        if len(arrived) > len(expected):
            say(f"Skipping per-file retry — {len(arrived):,} file(s) on disk "
                f"vs {len(expected):,} listed (bulk copy exceeded inventory).",
                phase="transfer")
            result.missing = result.missing[:100]
        else:
            say(f"{len(result.missing):,} listed file(s) did not arrive "
                f"({len(arrived):,} on disk vs {len(expected):,} listed).",
                phase="transfer")

    result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if result.missing:
        result.warnings.append(
            f"{len(result.missing)} listed file(s) did not arrive. They are "
            f"itemised in the manifest. Do not treat their absence as evidence "
            f"the handset lacked them.")
    say(f"Done: {result.files_copied} file(s), "
        f"{result.bytes_copied / (1024 ** 3):.2f} GB, "
        f"{len(result.missing)} missing.")
    return result


def write_manifest(result: AcquisitionResult, path: Path | str) -> Path:
    """Record the acquisition beside the evidence.

    Per-file hashes make the copy checkable later, and the missing list is what
    stops an absence being read as a finding.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.as_dict()
    payload["hashes"] = result.hashes
    payload["format"] = "argus-mtp-manifest/1"
    listed = int(result.files_listed or 0)
    copied = int(result.files_copied or 0)
    if listed > 0:
        payload["completeness_pct"] = round(100.0 * copied / listed, 2)
    if result.missing:
        folders: Dict[str, int] = {}
        for entry in result.missing[:500]:
            rel = entry.get("path") or ""
            top = rel.split("/", 2)[:2]
            key = "/".join(top) if len(top) > 1 else rel.split("/", 1)[0]
            if key:
                folders[key] = folders.get(key, 0) + 1
        payload["top_missing_folders"] = sorted(
            folders.items(), key=lambda kv: -kv[1])[:12]
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False),
                    encoding="utf-8")
    return path
