"""Physical Android acquisition — bit-for-bit partition images over ADB.

This is the live equivalent of a chip-off or E01: when the handset already
grants a root shell (Magisk, engineering build, custom recovery), ARGUS
images the evidential block devices through ``adb exec-out dd``. It does not
exploit bootloaders, talk EDL/Sahara, or unlock anything. No root, no image.

Why this still matters on FBE devices: the raw ``userdata`` image preserves
unallocated space the logical/file-system methods never see. Decryption is a
later, separate problem (keys, if present, are recorded from ``metadata`` /
``keymaster``). The image is evidence either way.

Priority partitions are dumped by default. OS partitions (system, vendor,
boot) add tens of gigabytes and almost no case facts; they are skipped unless
the examiner asks for a full image.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.hashing import hash_file
from ..devices.detect import find_tool
from .android_adb import AdbSession, PullResult
from .progress import human_bytes

# Names that typically hold user evidence, radio NV, or encryption metadata.
PRIORITY_NAMES = (
    "userdata", "metadata", "persist", "frp", "footer",
    "keymaster", "keymaster_a", "keymaster_b",
    "modemst1", "modemst2", "fsg", "fsc",
    "misc", "param", "persistent",
    "efs", "efs_backup", "nvram", "nvdata",
    "protect1", "protect2", "sec_efs", "carrier", "omr",
    "secdata", "devinfo", "devcfg", "devcfg_a", "devcfg_b",
)

# Firmware / OS — skip unless full=True.
SKIP_NAMES = {
    "boot", "boot_a", "boot_b", "init_boot", "init_boot_a", "init_boot_b",
    "recovery", "recovery_a", "recovery_b",
    "vbmeta", "vbmeta_a", "vbmeta_b", "vbmeta_system", "vbmeta_system_a",
    "dtbo", "dtbo_a", "dtbo_b",
    "system", "system_a", "system_b", "system_ext", "system_ext_a",
    "vendor", "vendor_a", "vendor_b", "product", "product_a", "product_b",
    "odm", "odm_a", "odm_b", "vendor_dlkm", "system_dlkm",
    "super", "cache", "userdata_virtual", "scratch",
    "ramdump", "logdump", "minidump", "rawdump",
}

_BY_NAME_LS = (
    "ls -l /dev/block/by-name 2>/dev/null; "
    "ls -l /dev/block/bootdevice/by-name 2>/dev/null; "
    "ls -l /dev/block/platform/*/by-name 2>/dev/null"
)


@dataclass
class Partition:
    name: str
    device: str
    size: int = 0
    priority: bool = False


@dataclass
class PhysicalResult:
    partitions: List[Partition] = field(default_factory=list)
    dumped: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    bytes_total: int = 0
    hashes: Dict[str, str] = field(default_factory=dict)
    rooted: bool = False
    crypto: str = ""
    notes: List[str] = field(default_factory=list)
    carved_files: int = 0

    def as_pull(self) -> PullResult:
        return PullResult(
            pulled=list(self.dumped),
            skipped=list(self.skipped),
            failed=list(self.failed),
            bytes_total=self.bytes_total,
            passes=["physical"],
        )


def parse_proc_partitions(text: str) -> Dict[str, int]:
    """Map device basename → size in bytes from ``/proc/partitions``."""
    sizes: Dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[2].isdigit():
            continue
        name = parts[3]
        if name in ("major", "name"):
            continue
        sizes[name] = int(parts[2]) * 1024
    return sizes


def parse_by_name_listing(text: str) -> List[Tuple[str, str]]:
    """Parse ``ls -l …/by-name`` into ``(name, resolved device path)``."""
    found: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if "->" not in line and "→" not in line:
            continue
        sep = "->" if "->" in line else "→"
        left, right = line.rsplit(sep, 1)
        target = right.strip()
        name = left.rstrip().split()[-1]
        if not name or name in (".", ".."):
            continue
        if not target.startswith("/"):
            # Relative symlink — keep the by-name path as the dump source.
            target = name
        found.append((name, target))
    return found


def select_partitions(named: List[Tuple[str, str]],
                      sizes: Dict[str, int],
                      *, full: bool = False) -> List[Partition]:
    """Choose which block devices to image."""
    selected: List[Partition] = []
    seen: set[str] = set()
    for name, device in named:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        basename = Path(device).name if device.startswith("/") else name
        size = sizes.get(basename, 0) or sizes.get(name, 0)
        if not full and key in SKIP_NAMES:
            continue
        if not full and key not in PRIORITY_NAMES and not key.startswith("userdata"):
            continue
        selected.append(Partition(
            name=name, device=device if device.startswith("/") else
            f"/dev/block/by-name/{name}",
            size=size, priority=key in PRIORITY_NAMES))
    selected.sort(key=lambda p: (0 if p.priority else 1, p.name))
    return selected


def _root_wrap(session: AdbSession, command: str) -> str:
    ident = session.shell("id")
    if "uid=0" in ident:
        return command
    return f"su -c {shlex.quote(command)}"


def _creation_flags() -> int:
    if sys.platform.startswith("win"):
        return 0x08000000  # CREATE_NO_WINDOW
    return 0


def probe_root(session: AdbSession) -> bool:
    """True when a root shell can actually run privileged commands."""
    ident = session.shell("id")
    if "uid=0" in ident:
        return True
    wrapped = session.shell("su -c id")
    return "uid=0" in wrapped


def _dump_block(session: AdbSession, remote: str, local: Path,
                expected: int,
                log: Optional[Callable[..., None]] = None,
                timeout: int = 86400) -> Tuple[bool, str]:
    """Stream ``dd`` of a block device over ``adb exec-out`` (binary-safe)."""
    local.parent.mkdir(parents=True, exist_ok=True)
    if expected and local.is_file() and local.stat().st_size >= expected:
        return True, "resumed"
    adb = find_tool("adb") or "adb"
    dd = f"dd if={shlex.quote(remote)} bs=1048576"
    cmd = _root_wrap(session, dd)
    stop = threading.Event()

    def watch() -> None:
        last = -1
        while not stop.wait(4):
            try:
                size = local.stat().st_size if local.exists() else 0
            except OSError:
                size = 0
            if size == last:
                continue
            last = size
            if log:
                extra = f" of {human_bytes(expected)}" if expected else ""
                log("adb.physical", "progress",
                    f"Imaging {remote} — {human_bytes(size)}{extra}")

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    err = ""
    try:
        with local.open("wb") as out:
            proc = subprocess.Popen(
                [adb, "-s", session.serial, "exec-out", cmd],
                stdout=out, stderr=subprocess.PIPE,
                creationflags=_creation_flags())
            try:
                _out, err_b = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return False, "dd timed out"
            err = (err_b or b"").decode("utf-8", "replace")[:300]
            if proc.returncode not in (0, None) and not (
                    local.exists() and local.stat().st_size > 0):
                return False, err or f"dd exit {proc.returncode}"
    except OSError as exc:
        return False, str(exc)[:200]
    finally:
        stop.set()
        watcher.join(timeout=2)
    try:
        size = local.stat().st_size
    except OSError:
        size = 0
    if size <= 0:
        try:
            local.unlink()
        except OSError:
            pass
        return False, err or "empty image"
    return True, "ok"


def _carve_userdata(image: Path, dest: Path,
                    log: Optional[Callable[..., None]] = None) -> int:
    """Signature-carve a userdata image so decode finds SQLite without a FS driver."""
    from .adapters import StagedSource, _carve_image_file
    try:
        size = image.stat().st_size
    except OSError:
        return 0
    if size > 128 * 1024 * 1024 * 1024:
        if log:
            log("adb.physical", "note",
                f"Skipping carve of {image.name} ({human_bytes(size)}) — "
                "over 128 GiB; import the image later if needed.")
        return 0
    staged = StagedSource(root=dest, adapter="physical.carve",
                          source_format="physical userdata image")
    try:
        _carve_image_file(image, dest, staged)
    except Exception as exc:
        if log:
            log("adb.physical", "warning",
                f"Carve of {image.name} failed: {type(exc).__name__}: {exc}",
                level="warning")
        return 0
    if log and staged.files:
        log("adb.physical", "ok",
            f"Carved {staged.files:,} file(s) from {image.name}")
    return staged.files


def write_manifest(dest: Path, result: PhysicalResult) -> Path:
    payload = {
        "format": "argus-physical-manifest/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rooted": result.rooted,
        "crypto": result.crypto,
        "bytes": result.bytes_total,
        "carved_files": result.carved_files,
        "partitions": [
            {"name": p.name, "device": p.device, "size": p.size,
             "priority": p.priority} for p in result.partitions
        ],
        "dumped": result.dumped,
        "skipped": result.skipped,
        "failed": result.failed,
        "hashes": result.hashes,
        "notes": result.notes,
        "method_note": (
            "Bit-for-bit copy of selected block devices through a root ADB "
            "shell. This is not a chip-off or EDL image. File-based encryption "
            "means userdata may be ciphertext until keys are applied."
        ),
    }
    target = dest / "argus-physical-manifest.json"
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def acquire(session: AdbSession, dest: Path,
            log: Optional[Callable[..., None]] = None,
            *,
            full: bool = False,
            hash_files: bool = True,
            resume: bool = True,
            carve: bool = True) -> PhysicalResult:
    """Image priority (or all) partitions into ``dest``."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    result = PhysicalResult()
    result.rooted = probe_root(session)
    crypto = session.shell("getprop ro.crypto.type").strip() or \
        session.shell("getprop ro.crypto.state").strip()
    result.crypto = crypto
    if log:
        log("adb.physical", "start",
            "Physical acquisition — mapping block devices"
            + (f" (crypto={crypto})" if crypto else ""))

    if not result.rooted:
        result.notes.append(
            "No root shell. Physical imaging needs Magisk, an engineering "
            "build, or custom recovery. Use Comprehensive until root is available.")
        if log:
            log("adb.physical", "error", result.notes[-1], level="error")
        write_manifest(dest, result)
        return result

    listing = session.shell(_root_wrap(session, _BY_NAME_LS))
    proc_parts = session.shell(_root_wrap(session, "cat /proc/partitions"))
    mounts = session.shell(_root_wrap(session, "cat /proc/mounts"))
    (dest / "by-name.txt").write_text(listing, encoding="utf-8")
    (dest / "proc-partitions.txt").write_text(proc_parts, encoding="utf-8")
    (dest / "proc-mounts.txt").write_text(mounts, encoding="utf-8")

    named = parse_by_name_listing(listing)
    sizes = parse_proc_partitions(proc_parts)
    if not named:
        # Fall back to raw mmc/sd names that look like userdata.
        for name, size in sizes.items():
            if "userdata" in name or name.endswith("p43"):
                named.append((name, f"/dev/block/{name}"))
    selected = select_partitions(named, sizes, full=full)
    result.partitions = selected
    if not selected:
        result.notes.append(
            "No evidential partitions found under /dev/block/by-name.")
        if log:
            log("adb.physical", "warning", result.notes[-1], level="warning")
        write_manifest(dest, result)
        return result

    if log:
        log("adb.physical", "ok",
            f"{len(selected)} partition(s) queued"
            + (" (full image)" if full else " (priority set)"))

    images = dest / "images"
    images.mkdir(parents=True, exist_ok=True)
    for part in selected:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", part.name)
        local = images / f"{safe}.dd"
        if log:
            log("adb.physical", "progress",
                f"Imaging {part.name} ({human_bytes(part.size) if part.size else 'size unknown'})")
        ok, msg = _dump_block(session, part.device, local, part.size, log=log)
        if not ok:
            result.failed.append(f"{part.name}: {msg}")
            if log:
                log("adb.physical", "warning",
                    f"{part.name} failed — {msg}", level="warning")
            continue
        size = local.stat().st_size
        result.dumped.append(part.name)
        result.bytes_total += size
        if hash_files:
            digest = hash_file(local).sha256
            result.hashes[part.name] = digest
        if log:
            extra = " (resumed)" if msg == "resumed" else ""
            log("adb.physical", "ok",
                f"{part.name}: {human_bytes(size)}{extra}")
        if carve and part.name.lower().startswith("userdata"):
            result.carved_files += _carve_userdata(local, dest / "carved", log)

    if crypto in ("file", "FBE") or "encrypted" in crypto.lower():
        result.notes.append(
            "Storage is file-based encrypted. The userdata image is a valid "
            "physical exhibit but file contents stay ciphertext until keys "
            "from metadata/keymaster (or the lock-screen derived key) are applied.")
    write_manifest(dest, result)
    if log:
        log("adb.physical", "ok",
            f"Physical complete — {len(result.dumped)} image(s), "
            f"{human_bytes(result.bytes_total)}"
            + (f", {result.carved_files:,} carved file(s)" if result.carved_files else ""))
    return result
