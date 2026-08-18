"""Live iOS acquisition — backup first, then media copy, then iTunes reuse.

A trusted USB iPhone can be acquired without jailbreak:

1. ``idevicebackup2`` full logical backup (messages, calls, app containers
   that allow backup).
2. Windows Explorer / WPD copy of the handset (Camera Roll, DCIM) when the
   phone is visible under This PC — the same route as MTP.
3. Reuse an iTunes / Apple Devices backup already on this workstation for
   the same UDID.

Any of these is a lawful logical acquisition. Chip-off and checkm8 are out of
scope and are not attempted.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from ..core.errors import AcquisitionError
from ..devices.detect import find_tool


def looks_like_apple(name: str = "", os_family: str = "",
                     transport: str = "") -> bool:
    if (os_family or "").lower().startswith("android"):
        return False
    blob = f"{name} {os_family} {transport}".lower()
    return any(token in blob for token in (
        "iphone", "ipad", "ipod", "ios", "ipados", "usbmux", "apple"))


def itunes_backup_roots() -> List[Path]:
    home = Path.home()
    candidates = [
        home / "AppData" / "Roaming" / "Apple Computer" / "MobileSync" / "Backup",
        home / "Apple" / "MobileSync" / "Backup",
        home / "Library" / "Application Support" / "MobileSync" / "Backup",
    ]
    return [p for p in candidates if p.is_dir()]


def find_existing_itunes_backup(udid: str) -> Optional[Path]:
    """Return a local iTunes/Finder backup folder for this UDID, if any."""
    if not udid:
        return None
    key = udid.replace("-", "").lower()
    for root in itunes_backup_roots():
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            name = entry.name.replace("-", "").lower()
            if name == key or name.startswith(key) or key.startswith(name):
                if ((entry / "Manifest.db").exists()
                        or (entry / "Info.plist").exists()):
                    return entry
    return None


def windows_apple_names() -> List[str]:
    """Display names of Apple handsets currently in This PC."""
    try:
        from . import mtp
        if not mtp.available():
            return []
        return [dev.name for dev in mtp.devices()
                if looks_like_apple(dev.name)]
    except Exception:
        return []


def copy_windows_media(device_name: str, dest: Path,
                       log: Optional[Callable[..., None]] = None,
                       turbo: bool = True):
    """Copy Camera Roll / DCIM as exposed by Windows over WPD."""
    from . import mtp
    dest.mkdir(parents=True, exist_ok=True)
    if log:
        log("ios.media", "start",
            f"Copying media from Windows portable device '{device_name}' "
            "(Camera Roll / DCIM). Keep the iPhone unlocked.")
    result = mtp.acquire(
        device_name, dest,
        progress=(lambda msg, **extra: log("ios.media", "progress", msg, **extra)
                  if log else None),
        hash_files=not turbo,
        turbo=turbo)
    if log:
        log("ios.media", "ok",
            f"Copied {result.files_copied} of {result.files_listed} listed "
            f"file(s) from {device_name}")
    return result


def create_backup(udid: str, dest: Path,
                  password: Optional[str] = None,
                  log: Optional[Callable[..., None]] = None) -> Path:
    """Run a full iOS backup into ``dest`` using libimobiledevice."""
    tool = find_tool("idevicebackup2")
    if not tool:
        raise AcquisitionError(
            "idevicebackup2 is not installed. Install libimobiledevice, "
            "trust the handset on this workstation, then retry — or create "
            "the backup with iTunes/Finder and import the folder.")

    dest.mkdir(parents=True, exist_ok=True)
    cmd = [tool, "backup", "--full", str(dest)]
    if udid:
        cmd.extend(["--udid", udid])
    if password:
        cmd.extend(["--password", password])

    if log:
        log("ios.backup", "start",
            "Starting full iOS backup — keep the handset unlocked, trusted, "
            "and on charge. Confirm any backup prompt on the phone. "
            "This may take 30–90 minutes.",
            level="warning")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(
            "iOS backup timed out after 2 hours — check USB connection and "
            "retry") from exc
    except FileNotFoundError as exc:
        raise AcquisitionError(f"idevicebackup2 not runnable: {tool}") from exc

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        hint = combined.strip()[-400:] or f"exit {proc.returncode}"
        if "password" in combined.lower() or "encrypted" in combined.lower():
            raise AcquisitionError(
                "The iOS backup is encrypted. Supply the backup password, or "
                "disable backup encryption on the device.")
        raise AcquisitionError(f"iOS backup failed: {hint}")

    return _locate_backup(dest, log)


def _locate_backup(dest: Path, log: Optional[Callable[..., None]] = None) -> Path:
    manifest = dest / "Manifest.db"
    if not manifest.exists():
        for candidate in dest.rglob("Manifest.db"):
            dest = candidate.parent
            break
    if not (dest / "Manifest.db").exists():
        raise AcquisitionError(
            "idevicebackup2 finished but Manifest.db was not found — "
            "the backup may be incomplete.")
    if log:
        size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        log("ios.backup", "ok",
            f"Backup complete: {dest.name} ({size:,} bytes)",
            bytes=size)
    return dest


def acquire_ios(udid: str, dest: Path, *,
                display_name: str = "",
                password: Optional[str] = None,
                turbo: bool = False,
                log: Optional[Callable[..., None]] = None) -> Tuple[Path, str]:
    """Acquire an iPhone/iPad by the first route that works.

    Returns ``(evidence_root, route)`` where route is
    ``idevicebackup2`` | ``itunes`` | ``windows-media``.
    """
    dest.mkdir(parents=True, exist_ok=True)
    errors: List[str] = []

    if find_tool("idevicebackup2"):
        try:
            backup = create_backup(udid, dest / "ios_backup", password, log)
            return backup, "idevicebackup2"
        except AcquisitionError as exc:
            errors.append(str(exc))
            if log:
                log("ios.backup", "warning",
                    f"Live backup unavailable — {exc}. Trying other routes.",
                    level="warning")

    existing = find_existing_itunes_backup(udid)
    if existing:
        target = dest / "ios_backup" / existing.name
        if log:
            log("ios.backup", "start",
                f"Reusing iTunes/Apple Devices backup at {existing}")
        shutil.copytree(existing, target, dirs_exist_ok=True)
        try:
            return _locate_backup(target, log), "itunes"
        except AcquisitionError as exc:
            errors.append(str(exc))

    names = []
    if display_name:
        names.append(display_name)
    names.extend(windows_apple_names())
    seen = set()
    for name in names:
        key = name.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        try:
            media = dest / "ios_media"
            result = copy_windows_media(name, media, log=log, turbo=turbo)
            if result.files_copied:
                return media, "windows-media"
            errors.append(f"Windows media copy of '{name}' produced no files")
        except Exception as exc:
            errors.append(f"Windows media copy of '{name}': {exc}")

    detail = " ".join(errors) if errors else (
        "No iOS acquisition route succeeded.")
    raise AcquisitionError(
        "Could not extract this Apple device. Unlock the iPhone, tap Trust, "
        "keep it on a data cable, then either install libimobiledevice "
        "(idevicebackup2), create an iTunes/Finder backup and import it, "
        "or confirm the phone is visible under This PC so Camera Roll can "
        f"be copied. {detail}")
