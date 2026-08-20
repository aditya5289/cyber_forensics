"""Live device detection (lab manual §5.4, Steps 6–7).

Detects connected handsets exactly the way a real acquisition workstation does:

* **Android** via ``adb`` — enumerates devices, reads ``ro.product.*`` build
  properties, IMEI, battery, encryption state and root availability.
* **iOS** via ``libimobiledevice`` (``idevice_id`` / ``ideviceinfo``) — reads
  ProductType, ProductVersion, serial, IMEI and the pairing/trust state.

Both toolchains are optional.  If neither is installed the module degrades
cleanly and reports *why* nothing was found rather than pretending no device
is attached — silently reporting "no device" when the cause is a missing
binary is how examiners lose an hour.
"""

from __future__ import annotations

import re
import os
import shutil
from pathlib import Path
import sys
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..core.errors import AcquisitionError
from .identity import (
    android_identity_from_props,
    ios_marketing_name,
    usb_identity_from_path,
)

ADB_TIMEOUT = 20


@dataclass
class DetectedDevice:
    """A handset currently attached to the workstation."""

    transport: str                    # "adb" | "usbmux" | "manual"
    serial: str = ""
    make: str = ""
    model: str = ""
    marketing_name: str = ""
    os_family: str = ""
    os_version: str = ""
    build_id: str = ""
    chipset: str = ""
    imei: str = ""
    iccid: str = ""
    phone_number: str = ""
    lock_state: str = "unlocked"
    trusted: bool = True
    rooted: bool = False
    encrypted: bool = True
    battery: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return " ".join(filter(None, [self.make, self.marketing_name or self.model]))

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["name"] = self.name
        return d


def _run(cmd: List[str], timeout: int = ADB_TIMEOUT) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return (proc.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# Install instructions have to match the machine in front of the examiner.
# Telling a Windows user to run `apt install` is not a hint, it is a dead end —
# and on a locked-down workstation they cannot verify it is wrong by trying it.
INSTALL_HINTS: Dict[str, Dict[str, str]] = {
    "adb": {
        # winget frequently installs this package without putting adb on PATH
        # (microsoft/winget-pkgs#103349), so the manual route is listed first —
        # an instruction that appears to succeed and then leaves the tool
        # uncallable wastes more time than one that is plainly manual.
        # The winget route fails in two distinct ways often enough that it is
        # no longer recommended: it installs without putting adb on PATH
        # (microsoft/winget-pkgs#103349), and its manifest hash goes stale
        # because Google republishes the archive in place, producing
        # "Installer hash does not match". That second failure must not be
        # waved away with --ignore-security-hash on a machine that will touch
        # evidence: the error cannot distinguish a stale manifest from a
        # tampered download, and that distinction is the entire point.
        "win32": ("Download Android SDK Platform-Tools directly from "
                  "https://dl.google.com/android/repository/"
                  "platform-tools-latest-windows.zip, unzip it, and add that "
                  "folder to PATH. Avoid the winget package: it frequently "
                  "installs without adding adb to PATH, and its manifest hash "
                  "goes stale (\"Installer hash does not match\"). Do not "
                  "bypass that hash check on a forensic workstation."),
        "darwin": "brew install --cask android-platform-tools",
        "linux": "apt install android-tools-adb  (or: dnf install android-tools)",
    },
    "libimobiledevice": {
        "win32": ("Install iTunes (which provides the Apple Mobile Device "
                  "Service), or build libimobiledevice for Windows. Live iOS "
                  "acquisition on Windows is awkward — importing an existing "
                  "iTunes backup is the reliable route."),
        "darwin": "brew install libimobiledevice",
        "linux": "apt install libimobiledevice-utils  (or: dnf install libimobiledevice-utils)",
    },
}


def _hint(tool: str) -> str:
    """The install instruction for *this* operating system."""
    if sys.platform.startswith("win"):
        key = "win32"
    elif sys.platform == "darwin":
        key = "darwin"
    else:
        key = "linux"
    return INSTALL_HINTS.get(tool, {}).get(key, "")


# Where these tools actually get installed, per platform. `shutil.which` only
# searches PATH, and PATH is read once when the process starts — so an examiner
# who installs adb while ARGUS is open, then presses "Scan again", is told the
# tool is still missing. That reads as the install having failed. Worse, the
# most common Windows install is an unzip to a folder that was never added to
# PATH at all, which no amount of rescanning will ever find.
WELL_KNOWN: Dict[str, Dict[str, List[str]]] = {
    "adb": {
        "win32": [
            r"C:\platform-tools\adb.exe",
            r"C:\Android\platform-tools\adb.exe",
            r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe",
            r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe",
            r"%ProgramFiles%\Android\platform-tools\adb.exe",
            r"%ProgramFiles(x86)%\Android\android-sdk\platform-tools\adb.exe",
            r"%LOCALAPPDATA%\Microsoft\WinGet\Links\adb.exe",
        ],
        "darwin": [
            "/opt/homebrew/bin/adb", "/usr/local/bin/adb",
            "~/Library/Android/sdk/platform-tools/adb",
        ],
        "linux": [
            "/usr/bin/adb", "/usr/local/bin/adb", "/snap/bin/adb",
            "~/Android/Sdk/platform-tools/adb",
        ],
    },
    "idevice_id": {
        "win32": [
            r"%ProgramFiles%\libimobiledevice\idevice_id.exe",
            r"C:\libimobiledevice\idevice_id.exe",
        ],
        "darwin": ["/opt/homebrew/bin/idevice_id", "/usr/local/bin/idevice_id"],
        "linux": ["/usr/bin/idevice_id", "/usr/local/bin/idevice_id"],
    },
    "ideviceinfo": {
        "win32": [
            r"%ProgramFiles%\libimobiledevice\ideviceinfo.exe",
            r"C:\libimobiledevice\ideviceinfo.exe",
        ],
        "darwin": ["/opt/homebrew/bin/ideviceinfo", "/usr/local/bin/ideviceinfo"],
        "linux": ["/usr/bin/ideviceinfo", "/usr/local/bin/ideviceinfo"],
    },
    "idevicebackup2": {
        "win32": [
            r"%ProgramFiles%\libimobiledevice\idevicebackup2.exe",
            r"C:\libimobiledevice\idevicebackup2.exe",
        ],
        "darwin": ["/opt/homebrew/bin/idevicebackup2",
                   "/usr/local/bin/idevicebackup2"],
        "linux": ["/usr/bin/idevicebackup2", "/usr/local/bin/idevicebackup2"],
    },
}


def _platform_key() -> str:
    if sys.platform.startswith("win"):
        return "win32"
    return "darwin" if sys.platform == "darwin" else "linux"


def find_tool(name: str) -> str:
    r"""Locate an executable: PATH first, then the usual install locations.

    Returns the path, or "" if it genuinely is not present. Falling back to
    well-known locations means the common case — unzip platform-tools to
    C:\platform-tools and never touch PATH — simply works, and "Scan again"
    behaves the way its label promises.

    Note the r-prefix: a Windows path in a plain docstring makes ``\p`` an
    invalid escape sequence, which Python 3.12+ warns about on every import and
    will eventually reject outright. It also prints a warning to the examiner's
    console during an otherwise clean run, which does not inspire confidence.
    """
    found = shutil.which(name)
    if found:
        return found
    for candidate in WELL_KNOWN.get(name, {}).get(_platform_key(), []):
        expanded = Path(os.path.expandvars(candidate)).expanduser()
        if "%" in str(expanded):
            continue                      # an unset variable; skip it
        try:
            if expanded.is_file() and os.access(expanded, os.X_OK):
                return str(expanded)
        except OSError:
            continue
    return ""


def _first_line(text: str) -> str:
    """First line of command output, tolerating no output at all."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def toolchain_status() -> Dict[str, Any]:
    """Report which acquisition toolchains are usable on this workstation."""
    adb = find_tool("adb")
    idev = find_tool("idevice_id")
    ideviceinfo = find_tool("ideviceinfo")
    return {
        "adb": {
            "available": bool(adb), "path": adb,
            # A binary on PATH is not the same as a binary that runs. A broken
            # install, the wrong architecture, or a policy block all produce an
            # executable that returns nothing — and indexing [0] into that empty
            # output crashed device detection outright, on a workstation where
            # the examiner has no way to see why.
            "version": _first_line(_run([adb, "version"])) if adb else "",
            "install_hint": _hint("adb"),
            "needed_for": "Live acquisition from a connected Android handset.",
            "not_needed_for": ("Importing an extraction that already exists on "
                               "disk, which is the usual case."),
        },
        "libimobiledevice": {
            "available": bool(idev and ideviceinfo),
            "path": idev,
            "backup": find_tool("idevicebackup2"),
            "install_hint": _hint("libimobiledevice"),
            "needed_for": "Live acquisition from a connected iPhone or iPad.",
            "not_needed_for": "Importing an existing iTunes backup folder.",
        },
    }


# --------------------------------------------------------------------- Android
def _adb_props(serial: str, adb: str = "adb") -> Dict[str, str]:
    out = _run([adb, "-s", serial, "shell", "getprop"])
    props: Dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]", line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return props


# Neither reliably answers across vendors and Android versions, so both are
# tried in order and the first that yields a plausible IMEI wins.
_IMEI_COMMANDS = (
    "service call iphonesubinfo 1",
    "dumpsys iphonesubinfo",
)


def _parse_imei(out: str) -> str:
    """Pull an IMEI out of either reply shape, or return ''."""
    # `service call` returns UTF-16 chunks inside parcel dumps
    chunks = re.findall(r"'([^']*)'", out)
    digits = "".join(re.sub(r"[^0-9]", "", c) for c in chunks)
    if len(digits) >= 14:
        return digits[:15]
    m = re.search(r"Device ID\s*=\s*(\d{14,16})", out)
    return m.group(1) if m else ""


def _adb_imei(serial: str, adb: str = "adb", *,
              probed: Optional[List[str]] = None) -> str:
    """IMEI, from pre-batched replies when available.

    On a handset where neither command answers — common enough — querying
    separately costs two full timeouts before giving up. *probed* lets the
    batched read supply both replies for the price of one round trip.
    """
    if probed is None:
        probed = [_run([adb, "-s", serial, "shell", cmd])
                  for cmd in _IMEI_COMMANDS]
    for out in probed:
        if not out:
            continue
        found = _parse_imei(out)
        if found:
            return found
    return ""


# One `adb shell` per field meant six USB round trips and six process spawns to
# describe a single handset on top of getprop, each able to sit near
# ADB_TIMEOUT on a sluggish device — and a deep scan pays that per device.
# These are all independent one-shot reads, so they go down the wire together:
# eight invocations per device becomes two.
#
# `;` rather than `&&`: an older toybox with no `which` must fail that section
# alone, not silently truncate every field after it.
_PROBE_MARK = "__ARGUS_FIELD__"

_PROBE_COMMANDS = (
    ("battery", "dumpsys battery"),
    ("su", "which su"),
    ("android_id", "settings get secure android_id"),
    ("storage", "df -h /data"),
    ("imei_0", _IMEI_COMMANDS[0]),
    ("imei_1", _IMEI_COMMANDS[1]),
)


def _adb_probe_batch(serial: str, adb: str) -> Dict[str, str]:
    """Read the one-shot device fields in a single shell invocation.

    Returns ``{}`` if the output does not have the expected shape, so the
    caller can fall back to querying each field separately rather than
    reporting a device as featureless because one marker went missing.
    """
    script = f"; echo {_PROBE_MARK}; ".join(cmd for _, cmd in _PROBE_COMMANDS)
    # The batch shares one timeout where the individual calls each had their
    # own, so it is given more room than a single read would get.
    out = _run([adb, "-s", serial, "shell", script], timeout=ADB_TIMEOUT + 15)
    parts = out.split(_PROBE_MARK)
    if not out or len(parts) != len(_PROBE_COMMANDS):
        return {}
    return {name: parts[i].strip()
            for i, (name, _) in enumerate(_PROBE_COMMANDS)}


def _build_android_device(serial: str, state: str, entry, adb: str,
                          *, deep: bool) -> DetectedDevice:
    """Build one Android DetectedDevice from an adb listing entry."""
    from .diagnose import STATE_MEANING

    meaning, fix = STATE_MEANING.get(
        state, ("Unrecognised adb state.",
                "Consult the adb documentation for this state."))

    if state != "device":
        return DetectedDevice(
            transport="adb", serial=serial,
            make=entry.product.split("_")[0] if entry.product else "",
            model=entry.model or "",
            marketing_name=entry.model or serial,
            os_family="Android",
            lock_state="locked" if state == "unauthorized" else "unknown",
            trusted=False,
            raw={"adb_state": state, "ready": False,
                 "meaning": meaning, "hint": fix},
        )

    if not deep:
        return DetectedDevice(
            transport="adb", serial=serial,
            make=entry.product.split("_")[0] if entry.product else "",
            model=entry.model or "",
            marketing_name=entry.model or serial,
            os_family="Android",
            lock_state="unlocked",
            trusted=True,
            raw={"adb_state": state, "ready": True, "deep_scan": False},
        )

    props = _adb_props(serial, adb)
    ident = android_identity_from_props(props)
    probe = _adb_probe_batch(serial, adb)
    if probe:
        battery_raw = probe["battery"]
        rooted = bool(probe["su"])
        android_id = _first_line(probe["android_id"])
        storage = _first_line(probe["storage"])
    else:
        battery_raw = _run([adb, "-s", serial, "shell", "dumpsys", "battery"])
        rooted = bool(_run([adb, "-s", serial, "shell", "which", "su"]))
        android_id = _first_line(_run(
            [adb, "-s", serial, "shell", "settings", "get", "secure",
             "android_id"]))
        storage = _first_line(_run(
            [adb, "-s", serial, "shell", "df", "-h", "/data"]))
    imei = _adb_imei(
        serial, adb,
        probed=[probe["imei_0"], probe["imei_1"]] if probe else None)
    m = re.search(r"level:\s*(\d+)", battery_raw)
    ident["android_id"] = android_id
    ident["storage_data"] = storage
    return DetectedDevice(
        transport="adb", serial=serial,
        make=ident["make"],
        model=ident["model"],
        marketing_name=ident["marketing_name"] or ident["model"],
        os_family="Android",
        os_version=ident["os_version"],
        build_id=ident["build_id"],
        chipset=ident["chipset"],
        imei=imei,
        lock_state="unlocked",
        rooted=rooted,
        encrypted=(ident.get("crypto_state") or "encrypted") == "encrypted",
        battery=int(m.group(1)) if m else None,
        raw={"adb_state": state, "ready": True, "deep_scan": True,
             "identity": ident,
             "props": {k: v for k, v in props.items()
                       if k.startswith(("ro.product", "ro.build",
                                        "ro.crypto", "gsm."))}},
    )


def detect_android(deep: bool = True) -> List[DetectedDevice]:
    """Every Android handset on the bus, whatever state it is in.

    Three faults lived here, and together they made a connected phone report as
    "no device detected":

    * ``shutil.which`` only searches PATH, so a perfectly good adb sitting in
      ``C:\\platform-tools`` was invisible — while `selfcheck` reported it as
      available, because that used the wider lookup. Two answers to the same
      question, and the scan had the wrong one.
    * Splitting the listing on whitespace turned the state ``no permissions``
      into ``no``, matching nothing.
    * Anything not in state ``device`` was dropped entirely. A handset that is
      plugged in and enumerating, but offline or awaiting authorisation, is not
      "no device" — it is a device with a specific, fixable problem, and hiding
      it sends the examiner to check the cable.

    Devices in every state are now returned, each carrying its adb state and
    what to do about it. Several handsets can be attached at once; each is
    queried by serial, so their properties never cross.
    """
    adb = find_tool("adb")
    if not adb:
        return []

    from .diagnose import parse_devices
    from concurrent.futures import ThreadPoolExecutor, as_completed

    listing = _run([adb, "devices", "-l"])
    entries = parse_devices(listing)
    if not entries:
        return []

    if deep and sum(1 for e in entries if e.state == "device") > 1:
        devices: List[DetectedDevice] = []
        with ThreadPoolExecutor(
                max_workers=min(4, len(entries))) as pool:
            futures = {
                pool.submit(_build_android_device, e.serial, e.state, e, adb,
                            deep=deep): e
                for e in entries
            }
            for fut in as_completed(futures):
                devices.append(fut.result())
        devices.sort(key=lambda d: d.serial)
        return devices

    return [_build_android_device(e.serial, e.state, e, adb, deep=deep)
            for e in entries]


# ------------------------------------------------------------------------ iOS


def detect_ios() -> List[DetectedDevice]:
    idevice_id = find_tool("idevice_id")
    ideviceinfo = find_tool("ideviceinfo")
    if not (idevice_id and ideviceinfo):
        return []
    udids = [u.strip() for u in _run([idevice_id, "-l"]).splitlines() if u.strip()]
    devices: List[DetectedDevice] = []
    for udid in udids:
        raw = _run([ideviceinfo, "-u", udid])
        info: Dict[str, str] = {}
        for line in raw.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                info[k.strip()] = v.strip()
        if not info:
            devices.append(DetectedDevice(
                transport="usbmux", serial=udid, make="Apple",
                os_family="iOS", trusted=False, lock_state="locked",
                raw={"hint": "Device is not paired — tap 'Trust' on the handset."}))
            continue
        product_type = info.get("ProductType", "")
        devices.append(DetectedDevice(
            transport="usbmux", serial=udid, make="Apple",
            model=product_type,
            marketing_name=ios_marketing_name(
                product_type, info.get("DeviceName", product_type)),
            os_family="iOS", os_version=info.get("ProductVersion", ""),
            build_id=info.get("BuildVersion", ""),
            chipset=info.get("HardwarePlatform", ""),
            imei=info.get("InternationalMobileEquipmentIdentity", ""),
            iccid=info.get("IntegratedCircuitCardIdentity", ""),
            phone_number=info.get("PhoneNumber", ""),
            lock_state="unlocked" if info.get("PasswordProtected") != "true"
                       else "afu",
            trusted=True,
            encrypted=True,
            raw={"ideviceinfo": info},
        ))
    return devices


# ------------------------------------------------------------------ public API
def detect_all(*, deep: bool = True, refresh_adb: bool = False) -> Dict[str, Any]:
    """Step 7: auto-detect connected devices (parallel god-level scan)."""
    from .scan import scan_devices
    return scan_devices(deep=deep, refresh_adb=refresh_adb)


def _normalize_serial_key(serial: str) -> str:
    """Normalise a device serial or MTP shell path for comparison.

    Windows MTP paths arrive with inconsistent escaping depending on whether
    they came from PowerShell, the browser JSON layer, or a saved batch plan.
    """
    if not serial:
        return ""
    key = serial.strip().lower()
    key = key.replace("/", "\\")
    while "\\\\" in key:
        key = key.replace("\\\\", "\\")
    return key


def _serial_usb_fragment(serial: str) -> str:
    """Extract the stable USB instance id from an MTP device path."""
    key = _normalize_serial_key(serial)
    marker = "usb#"
    if marker in key:
        frag = key.split(marker, 1)[1]
        if "#{" in frag:
            frag = frag.split("#{", 1)[0]
        return marker + frag.rstrip("\\")
    return key


def _serial_matches(wanted: str, device: DetectedDevice) -> bool:
    """True if ``wanted`` refers to ``device`` (ADB serial, MTP path, or name)."""
    if not wanted:
        return False
    if device.serial == wanted:
        return True
    w_norm = _normalize_serial_key(wanted)
    d_norm = _normalize_serial_key(device.serial)
    if w_norm and d_norm and w_norm == d_norm:
        return True
    w_usb = _serial_usb_fragment(wanted)
    d_usb = _serial_usb_fragment(device.serial)
    if w_usb and d_usb and w_usb == d_usb:
        return True
    mtp_path = (device.raw or {}).get("mtp_path", "")
    if mtp_path and _normalize_serial_key(mtp_path) == w_norm:
        return True
    if mtp_path and _serial_usb_fragment(mtp_path) == w_usb:
        return True
    name = (device.marketing_name or device.model or device.name or "").strip()
    if name and wanted.strip().lower() == name.lower():
        return True
    return False


def _find_by_serial(serial: str,
                    devices: List[DetectedDevice]) -> Optional[DetectedDevice]:
    for d in devices:
        if _serial_matches(serial, d):
            return d
    return None


def _detect_mtp_devices(existing: List[DetectedDevice]) -> List[DetectedDevice]:
    """Handsets visible in the Windows shell namespace (file-transfer mode)."""
    found: List[DetectedDevice] = []
    try:
        from ..acquire import mtp
        if not mtp.available():
            return found
        for mtp_dev in mtp.devices():
            found.append(_device_from_mtp(mtp_dev))
    except Exception:                                         # pragma: no cover
        pass
    return found


def _looks_like_mtp_serial(serial: str) -> bool:
    key = _normalize_serial_key(serial)
    return key.startswith("::") or "usb#vid_" in key


def _device_from_mtp(mtp_dev, serial: str = "") -> DetectedDevice:
    path = serial or mtp_dev.path or mtp_dev.name
    usb = usb_identity_from_path(path)
    confidence = "usb+name" if usb.get("usb_vid") else "name_only"
    make = usb.get("usb_vendor", "")
    apple = "iphone" in (mtp_dev.name or "").lower() or "ipad" in (
        mtp_dev.name or "").lower() or "ipod" in (mtp_dev.name or "").lower()
    if apple or (usb.get("usb_vid") or "") == "05ac":
        make = "Apple"
        os_family = "iOS"
    else:
        os_family = "Android"
        make = make.split("/")[0].strip() if make else ""
    return DetectedDevice(
        transport="mtp",
        serial=path,
        make=make,
        model=mtp_dev.name,
        marketing_name=mtp_dev.name,
        os_family=os_family,
        os_version="",
        lock_state="unlocked",
        trusted=True,
        raw={"mtp_path": mtp_dev.path or path, "mtp_name": mtp_dev.name,
             "ready": True, "confidence": confidence, **usb},
    )


def resolve_device(serial: Optional[str] = None, *,
                   transport: str = "",
                   mtp_name: str = "",
                   device_name: str = "") -> DetectedDevice:
    """Find a connected handset, with MTP fallbacks for path drift.

    The UI may cache a Windows MTP shell path from an earlier scan. By the
    time extraction starts the path string can differ slightly, or PowerShell
    may return a fresh path — so we match on USB instance id and display name
    before giving up.
    """
    if not serial and not mtp_name and not device_name:
        return require_device(None)

    pools: List[List[DetectedDevice]] = [list_connected()]
    android, ios = detect_android(), detect_ios()
    pools.append(android + ios + _detect_mtp_devices(android + ios))

    if serial:
        for pool in pools:
            hit = _find_by_serial(serial, pool)
            if hit:
                return hit

    label = (mtp_name or device_name or "").strip()
    if label:
        for pool in pools:
            for d in pool:
                if d.transport != "mtp":
                    continue
                names = {label.lower(), (d.raw or {}).get("mtp_name", "").lower(),
                         d.name.lower(), d.model.lower()}
                if label.lower() in names:
                    return d
        try:
            from ..acquire import mtp
            if mtp.available():
                for mdev in mtp.devices():
                    if mdev.name.strip().lower() == label.lower():
                        return _device_from_mtp(mdev, serial or "")
        except Exception:                                     # pragma: no cover
            pass

    if serial and _looks_like_mtp_serial(serial):
        try:
            from ..acquire import mtp
            if mtp.available():
                want_usb = _serial_usb_fragment(serial)
                for mdev in mtp.devices():
                    if want_usb and _serial_usb_fragment(mdev.path) == want_usb:
                        return _device_from_mtp(mdev, serial)
                if label:
                    for mdev in mtp.devices():
                        if mdev.name.strip().lower() == label.lower():
                            return _device_from_mtp(mdev, serial)
                # Last resort: trust the cached MTP path from the UI scan.
                return DetectedDevice(
                    transport="mtp",
                    serial=serial,
                    model=label or "MTP device",
                    marketing_name=label or "MTP device",
                    os_family="Android",
                    lock_state="unlocked",
                    trusted=True,
                    raw={"mtp_path": serial, "mtp_name": label,
                         "ready": True, "synthetic": True},
                )
        except Exception:                                     # pragma: no cover
            pass

    if serial:
        raise AcquisitionError(
            f"device with serial {serial!r} is not connected. "
            f"If this is an MTP handset, choose extraction method 'mtp', "
            f"confirm file-transfer mode on the phone, and click Scan again.")
    return require_device(None)


def require_device(serial: Optional[str] = None) -> DetectedDevice:
    """Resolve exactly one connected device or explain what is wrong."""
    if serial:
        return resolve_device(serial)
    found = list_connected()
    if not found:
        raise AcquisitionError(
            "no device detected. " + " ".join(detect_all()["diagnostics"]))
    if len(found) > 1:
        names = ", ".join(
            f"{(d.raw or {}).get('mtp_name') or d.serial[:24]} ({d.name})"
            for d in found)
        raise AcquisitionError(
            f"{len(found)} devices connected; specify one with --serial: {names}")
    return found[0]


def list_connected() -> List[DetectedDevice]:
    """All handsets currently reachable — adb, usbmux, or MTP."""
    android = detect_android()
    ios = detect_ios()
    return android + ios + _detect_mtp_devices(android + ios)


def get_device(serial: str) -> DetectedDevice:
    """Return one connected device by serial or raise."""
    return resolve_device(serial)


def get_devices(serials: Optional[List[str]] = None) -> List[DetectedDevice]:
    """Return connected devices, optionally filtered by serial list."""
    found = list_connected()
    if not serials:
        return found
    matched: List[DetectedDevice] = []
    for wanted in serials:
        hit = _find_by_serial(wanted, found)
        if hit and hit not in matched:
            matched.append(hit)
    missing = [s for s in serials
               if not any(_serial_matches(s, d) for d in matched)]
    if missing:
        raise AcquisitionError(
            f"device(s) not connected: {', '.join(sorted(missing))}")
    return matched
