"""Everything attached, not merely everything that answers adb.

adb and libimobiledevice only see handsets that cooperate. A phone in MTP mode,
one whose driver never bound, one sitting in fastboot, one where USB debugging
was never enabled — all of these are physically present, enumerated by the
operating system, and completely invisible to the tools ARGUS was asking.

The result was the worst possible message: "no device detected", to an examiner
who is looking directly at a phone plugged into the machine. That is not a
detection failure the examiner can act on, it is the tool contradicting the
evidence of their own eyes.

So this asks the operating system what is on the bus, independently of whether
any forensic tool can talk to it. A USB device with Oppo's vendor ID is a fact
worth reporting even when adb shrugs: it tells the examiner the cable and port
are fine and the problem is further up, which is a completely different
afternoon's work from hunting for a broken lead.

Mounted volumes matter for the same reason. An SD card or a phone in mass
storage mode is evidence that can be imaged right now, with no adb involved at
all.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .identity import USB_VENDORS as MOBILE_VENDORS

# Modes that tell an examiner something specific about what is possible.
#
# Keyed on vendor *and product* ID, because the vendor alone does not identify a
# mode. MediaTek's 0e8d covers the preloader, the BootROM download agent, and
# perfectly ordinary MTP and ADB interfaces. Announcing "BootROM — physical
# acquisition is a candidate" for a phone that is merely sitting in file
# transfer mode is a confident wrong answer, and it points the examiner at an
# afternoon of low-level tooling when the device is browsable in Explorer.
LOW_LEVEL_MODES: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("05c6", "9008"): (
        "Qualcomm EDL / 9008",
        "The handset is in Emergency Download mode. A physical image is "
        "possible with a signed programmer for this OEM. adb does not operate "
        "here."),
    ("0e8d", "0003"): (
        "MediaTek BootROM (download agent)",
        "The handset is in the MediaTek BootROM, below the operating system. "
        "Physical acquisition is a candidate; whether the image is readable "
        "still depends on the encryption scheme."),
    ("0e8d", "2000"): (
        "MediaTek preloader",
        "The handset is in the MediaTek preloader. This window is brief and "
        "usually closes as the device continues to boot."),
    ("0e8d", "2001"): (
        "MediaTek preloader (alternate)",
        "The handset is in a MediaTek preloader mode below the operating "
        "system."),
    ("1782", "4d00"): (
        "Unisoc/Spreadtrum diagnostic",
        "The handset is in a Spreadtrum diagnostic mode, which frequently "
        "permits a full read."),
}

# Product IDs that mean the handset is mounted and browsable right now. Worth
# saying, because it is a route to evidence that needs no adb, no debugging
# toggle and no vendor tooling — just a file copy.
BROWSABLE_HINT = (
    "The handset appears to be in file-transfer (MTP) mode. If it is visible "
    "in the file manager, its shared storage — photos, video, downloads, and "
    "app folders under Android/media — can be copied off and imported "
    "directly. That reaches everything the phone exposes over MTP without any "
    "of the adb prerequisites.")


@dataclass
class BusDevice:
    """Something the operating system can see on USB."""

    vendor_id: str = ""
    product_id: str = ""
    vendor: str = ""
    description: str = ""
    source: str = ""
    mode_name: str = ""
    mode_note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"vendor_id": self.vendor_id, "product_id": self.product_id,
                "vendor": self.vendor, "description": self.description,
                "source": self.source, "mode_name": self.mode_name,
                "mode_note": self.mode_note}


@dataclass
class Volume:
    """A mounted filesystem that could hold evidence."""

    path: str
    label: str = ""
    filesystem: str = ""
    total_bytes: int = 0
    free_bytes: int = 0
    removable: bool = False
    looks_like_evidence: bool = False
    markers: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "label": self.label,
                "filesystem": self.filesystem,
                "total_bytes": self.total_bytes, "free_bytes": self.free_bytes,
                "removable": self.removable,
                "looks_like_evidence": self.looks_like_evidence,
                "markers": self.markers}


def _run(command: List[str], timeout: int = 20) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, check=False)
        return (completed.stdout or "") + (completed.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def _powershell(script: str) -> str:
    for shell in ("powershell", "pwsh"):
        out = _run([shell, "-NoProfile", "-NonInteractive", "-Command", script],
                   timeout=30)
        if out.strip():
            return out
    return ""


# ─────────────────────────────────────────────────────────────── USB devices
def usb_devices() -> List[BusDevice]:
    """Every USB device the OS knows about, whatever any forensic tool thinks."""
    if sys.platform.startswith("win"):
        return _usb_windows()
    if sys.platform == "darwin":
        return _usb_macos()
    return _usb_linux()


def _identify(vendor_id: str, product_id: str, description: str,
              source: str) -> BusDevice:
    vendor_id = (vendor_id or "").lower().strip()
    product_id = (product_id or "").lower().strip()
    vendor = MOBILE_VENDORS.get(vendor_id, "")
    mode = LOW_LEVEL_MODES.get((vendor_id, product_id))

    note = mode[1] if mode else ""
    if not note and re.search(r"(?i)\bMTP\b|portable device|file.?transfer",
                              description or ""):
        note = BROWSABLE_HINT

    return BusDevice(vendor_id=vendor_id, product_id=product_id,
                     vendor=vendor, description=description.strip(),
                     source=source, mode_name=mode[0] if mode else "",
                     mode_note=note)


def _usb_windows() -> List[BusDevice]:
    out = _powershell(
        "Get-PnpDevice -PresentOnly | "
        "Where-Object { $_.InstanceId -like 'USB*' } | "
        "Select-Object -Property InstanceId,FriendlyName | "
        "ForEach-Object { \"$($_.InstanceId)|$($_.FriendlyName)\" }")
    found: List[BusDevice] = []
    seen = set()
    for line in out.splitlines():
        if "|" not in line:
            continue
        instance, name = line.split("|", 1)
        match = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})",
                          instance)
        if not match:
            continue
        key = (match.group(1).lower(), match.group(2).lower(), name.strip())
        if key in seen:
            continue
        seen.add(key)
        found.append(_identify(match.group(1), match.group(2), name, "pnp"))
    return found


def _usb_linux() -> List[BusDevice]:
    found: List[BusDevice] = []
    out = _run(["lsusb"])
    for line in out.splitlines():
        match = re.search(r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)",
                          line)
        if match:
            found.append(_identify(match.group(1), match.group(2),
                                   match.group(3), "lsusb"))
    if found:
        return found

    # lsusb is not always installed; sysfs always is on Linux.
    root = Path("/sys/bus/usb/devices")
    if not root.is_dir():
        return found
    for entry in sorted(root.glob("*")):
        vid = entry / "idVendor"
        pid = entry / "idProduct"
        if not (vid.exists() and pid.exists()):
            continue
        try:
            product = (entry / "product")
            label = product.read_text().strip() if product.exists() else ""
            found.append(_identify(vid.read_text(), pid.read_text(), label,
                                   "sysfs"))
        except OSError:
            continue
    return found


def _usb_macos() -> List[BusDevice]:
    out = _run(["system_profiler", "SPUSBDataType"], timeout=40)
    found: List[BusDevice] = []
    name = ""
    vid = ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("Product ID"):
            name = stripped.rstrip(":")
        match = re.match(r"Product ID:\s*0x([0-9a-fA-F]+)", stripped)
        if match:
            pid = match.group(1)
            if vid:
                found.append(_identify(vid, pid, name, "system_profiler"))
                vid = ""
            continue
        match = re.match(r"Vendor ID:\s*0x([0-9a-fA-F]+)", stripped)
        if match:
            vid = match.group(1)
    return found


def mobile_devices_on_bus() -> List[BusDevice]:
    """USB devices whose vendor ID belongs to a handset manufacturer."""
    return [d for d in usb_devices() if d.vendor]


# ──────────────────────────────────────────────────────────────── volumes
# Directories that mark a volume as worth examining rather than as somebody's
# music collection.
EVIDENCE_MARKERS = ("DCIM", "Android", "LOST.DIR", "WhatsApp", "Pictures",
                    "Movies", "Download", "MIUI", "backup", "Telegram")


def volumes(include_fixed: bool = False) -> List[Volume]:
    """Mounted filesystems that could hold evidence.

    An SD card or a handset in mass-storage mode can be imaged immediately, with
    no adb and no vendor tooling. Listing them turns "no device detected" into a
    usable next step.
    """
    found: List[Volume] = []
    for path, removable in _candidate_mounts(include_fixed):
        try:
            usage = os.statvfs(path) if hasattr(os, "statvfs") else None
        except OSError:
            usage = None
        total = free = 0
        if usage is not None:
            total = usage.f_blocks * usage.f_frsize
            free = usage.f_bavail * usage.f_frsize
        elif sys.platform.startswith("win"):
            try:
                import shutil as _shutil
                stats = _shutil.disk_usage(path)
                total, free = stats.total, stats.free
            except OSError:
                pass

        markers: List[str] = []
        try:
            entries = {e.name for e in os.scandir(path)}
            markers = sorted(m for m in EVIDENCE_MARKERS if m in entries)
        except OSError:
            pass

        found.append(Volume(path=str(path), removable=removable,
                            total_bytes=total, free_bytes=free,
                            looks_like_evidence=bool(markers),
                            markers=markers))
    return found


def _candidate_mounts(include_fixed: bool) -> List[Tuple[str, bool]]:
    out: List[Tuple[str, bool]] = []
    if sys.platform.startswith("win"):
        listing = _powershell(
            "Get-Volume | Where-Object { $_.DriveLetter } | "
            "ForEach-Object { \"$($_.DriveLetter)|$($_.DriveType)\" }")
        for line in listing.splitlines():
            if "|" not in line:
                continue
            letter, kind = line.split("|", 1)
            letter, kind = letter.strip(), kind.strip().lower()
            if not letter:
                continue
            removable = kind in ("removable", "cd-rom")
            if removable or include_fixed:
                out.append((f"{letter}:\\", removable))
        return out

    roots = ["/media", "/run/media", "/mnt", "/Volumes"]
    for root in roots:
        base = Path(root)
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            try:
                if entry.is_dir() and os.path.ismount(entry):
                    out.append((str(entry), True))
                elif entry.is_dir():
                    for sub in sorted(entry.iterdir()):
                        if sub.is_dir() and os.path.ismount(sub):
                            out.append((str(sub), True))
            except OSError:
                continue
    return out


# ─────────────────────────────────────────────────────────────── fastboot
def fastboot_devices() -> List[Dict[str, str]]:
    """Handsets sitting in bootloader mode.

    adb cannot see these at all, so without this a phone in fastboot reports as
    absent — when in fact it is in a mode that may permit a physical image.
    """
    from .detect import find_tool

    binary = find_tool("fastboot")
    if not binary:
        return []
    out = _run([binary, "devices"])
    found: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].strip() == "fastboot":
            found.append({"serial": parts[0], "mode": "fastboot",
                          "note": ("In bootloader mode. adb does not operate "
                                   "here; reboot to the system for a logical "
                                   "acquisition, or use fastboot tooling if a "
                                   "bootloader-level route is intended and "
                                   "authorised.")})
    return found


# ───────────────────────────────────────────────────────────────── summary
def scan_all() -> Dict[str, Any]:
    """Every attached source, from every angle available."""
    usb = usb_devices()
    mobiles = [d for d in usb if d.vendor]
    vols = volumes()
    fastboot = fastboot_devices()

    notes: List[str] = []
    if mobiles:
        names = ", ".join(sorted({d.vendor for d in mobiles}))
        notes.append(
            f"USB reports hardware from: {names}. The cable and port are "
            f"therefore working. If adb still shows nothing, the problem is "
            f"USB debugging, the connection mode, or the driver — not the "
            f"physical connection.")
    for device in mobiles:
        if device.mode_note:
            label = device.mode_name or device.vendor
            notes.append(f"{label}: {device.mode_note}")
    if fastboot:
        notes.append(f"{len(fastboot)} handset(s) in bootloader mode.")
    evidence_volumes = [v for v in vols if v.looks_like_evidence]
    if evidence_volumes:
        notes.append(
            f"{len(evidence_volumes)} mounted volume(s) contain directories "
            f"typical of a handset or memory card. These can be imported "
            f"directly — no adb required.")

    return {
        "usb_total": len(usb),
        "mobile_hardware": [d.as_dict() for d in mobiles],
        "volumes": [v.as_dict() for v in vols],
        "fastboot": fastboot,
        "notes": notes,
    }
