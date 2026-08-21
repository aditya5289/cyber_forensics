"""Why the handset in front of you is not being detected.

"No device detected — check the cable, confirm USB debugging" is not a
diagnosis. It is a list of everything that could be wrong, handed to someone who
has already checked most of it. Meanwhile adb knows exactly what state the
device is in, and nobody asked it.

So this runs the checks, reads the actual state, and names the specific cause.
`unauthorized` is not the same problem as `offline`, which is not the same as an
empty list, and each has a different fix.

Vendor skins matter more than they should. ColorOS hides a second switch behind
USB debugging that must also be on; MIUI requires a signed-in account and a
separate "USB debugging (Security settings)" toggle; both fail in ways that look
like a broken cable. Guidance that ignores the skin sends an examiner to check
hardware when the problem is a settings screen.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# adb's own vocabulary for what it found on the bus. Each means something
# different and needs a different response.
STATE_MEANING: Dict[str, Tuple[str, str]] = {
    "device": (
        "Connected and authorised.",
        "Nothing to fix — ARGUS can talk to this handset."),
    "unauthorized": (
        "The handset is connected but has not trusted this computer.",
        "Unlock the screen. A dialog asking to allow USB debugging should "
        "appear — tick 'Always allow from this computer' and accept. If no "
        "dialog appears, revoke existing authorisations in Developer options "
        "and replug. On ColorOS and MIUI the prompt sometimes only appears "
        "after the USB mode is switched to File transfer."),
    "offline": (
        "The handset enumerated but is not responding to adb.",
        "Usually the USB mode or the daemon rather than the cable. Set USB "
        "mode to File transfer (MTP) from the notification shade, then run "
        "`adb kill-server` followed by `adb devices`. If it persists, a "
        "different USB port — ideally USB 2.0 rather than 3.x — often "
        "resolves it."),
    "no permissions": (
        "The operating system is blocking access to the USB device.",
        "On Linux this is a udev rule. Add a rule for the vendor ID or run adb "
        "with sufficient privilege. On Windows this normally means the wrong "
        "driver is bound."),
    "recovery": (
        "The handset is in recovery mode, not booted normally.",
        "Reboot to the system before acquiring. Recovery exposes almost no "
        "user data."),
    "sideload": (
        "The handset is in sideload mode.",
        "Reboot to the system."),
    "bootloader": (
        "The handset is in bootloader/fastboot mode.",
        "adb does not operate here. Reboot to the system, or use fastboot "
        "tooling if a bootloader-level acquisition is intended and authorised."),
    "authorizing": (
        "Authorisation is in progress.",
        "Accept the prompt on the handset. If it does not settle within a few "
        "seconds, replug and try again."),
}

# Vendor skins that hide extra switches. These cost far more examiner time than
# they should, because the symptom looks like a hardware fault.
VENDOR_NOTES: Dict[str, List[str]] = {
    "oppo": [
        "ColorOS: Developer options also has **Disable permission monitoring**, "
        "which must be ON. Without it adb connects but is refused on most "
        "operations, and the handset often shows as 'unauthorized' no matter "
        "how many times the prompt is accepted.",
        "ColorOS defaults the USB connection to charge-only. Pull down the "
        "notification shade after plugging in and choose File transfer (MTP).",
        "Developer options are unlocked at Settings → About device → Version → "
        "tap Build number seven times.",
    ],
    "realme": [
        "realme UI is ColorOS-derived: Developer options also has **Disable "
        "permission monitoring**, which must be ON.",
        "Set the USB mode to File transfer from the notification shade.",
    ],
    "oneplus": [
        "OxygenOS on recent releases behaves like ColorOS — check for a "
        "**Disable permission monitoring** toggle in Developer options.",
    ],
    "xiaomi": [
        "MIUI requires **USB debugging (Security settings)** in addition to the "
        "ordinary USB debugging toggle, and it will not enable without a "
        "signed-in Mi account and a SIM in the device.",
        "MIUI reverts USB debugging after a period of inactivity; re-check it "
        "if a previously working device stops responding.",
    ],
    "redmi": [
        "MIUI requires **USB debugging (Security settings)** as well as the "
        "ordinary toggle, and a signed-in Mi account to enable it.",
    ],
    "huawei": [
        "EMUI hides developer options behind Settings → About phone → tap "
        "Build number seven times, and USB debugging resets on reboot in some "
        "builds.",
    ],
    "samsung": [
        "One UI: if the handset shows as unauthorized repeatedly, revoke USB "
        "debugging authorisations in Developer options and replug.",
    ],
    "vivo": [
        "**Developer options is hidden** until unlocked: Settings → System "
        "management → About phone → Version info → tap **Software version** "
        "(or **Build number**) **7–10 times** until “You are now a developer”. "
        "Then: System management → Developer options.",
        "Funtouch OS requires **USB debugging (Security settings)** in addition "
        "to the ordinary toggle on many builds (including Y02).",
        "Y-series handsets often enumerate as VID 2D95 in MTP-only mode. Switch "
        "USB to **File transfer**, keep the screen unlocked, and tap **Allow** "
        "when the RSA prompt appears after enabling debugging.",
        "If Developer options cannot be enabled (work profile, parental lock): "
        "export SMS with **SMS Backup & Restore** to Download/, contacts as "
        "**vCard** from the Contacts app, then re-run **MTP** extraction.",
    ],
    "iqoo": [
        "iQOO is Vivo/Funtouch: enable **USB debugging (Security settings)** "
        "as well as the ordinary USB debugging toggle.",
    ],
    "tecno": [
        "HiOS (Tecno): Developer options is unlocked by tapping Build number "
        "seven times. USB often defaults to charging — switch to File transfer "
        "from the shade before enabling debugging.",
        "Many Tecno handsets enumerate as MediaTek VID 0E8D. If adb never "
        "appears, keep MTP extraction running and import a PhoneClone / HiOS "
        "backup from shared storage.",
    ],
    "infinix": [
        "XOS (Infinix): same family as Tecno HiOS. Enable USB debugging and "
        "File transfer. Clone-phone backups land under /sdcard/PhoneClone or "
        "XOS/Backup — ARGUS pulls those on Comprehensive.",
    ],
    "itel": [
        "itel (Transsion): low-cost Android, often MTP-only until File transfer "
        "is selected. USB debugging may be labelled USB debugging (Security).",
    ],
    "motorola": [
        "Motorola: USB defaults to charging on many G-series builds. Switch to "
        "File transfer, then accept the RSA prompt. Moto Backup folders on "
        "shared storage are pulled when Comprehensive runs.",
    ],
}


@dataclass
class DeviceState:
    """One entry from `adb devices -l`."""

    serial: str
    state: str
    model: str = ""
    device: str = ""
    product: str = ""
    transport: str = ""

    @property
    def vendor_hint(self) -> str:
        blob = f"{self.model} {self.device} {self.product}".lower()
        for vendor in VENDOR_NOTES:
            if vendor in blob:
                return vendor
        return ""

    def as_dict(self) -> Dict[str, Any]:
        meaning, fix = STATE_MEANING.get(
            self.state, ("Unrecognised adb state.",
                         "Consult adb documentation for this state."))
        return {"serial": self.serial, "state": self.state,
                "model": self.model, "device": self.device,
                "product": self.product, "meaning": meaning, "fix": fix,
                "vendor": self.vendor_hint}


@dataclass
class Diagnosis:
    """What is actually wrong, and what to do about it."""

    adb_path: str = ""
    adb_version: str = ""
    adb_available: bool = False
    devices: List[DeviceState] = field(default_factory=list)
    ready: List[str] = field(default_factory=list)
    problems: List[Dict[str, str]] = field(default_factory=list)
    vendor_guidance: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    raw: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "adb": {"available": self.adb_available, "path": self.adb_path,
                    "version": self.adb_version},
            "devices": [d.as_dict() for d in self.devices],
            "ready": self.ready,
            "problems": self.problems,
            "vendor_guidance": self.vendor_guidance,
            "next_steps": self.next_steps,
            "raw_output": self.raw,
        }


def _run(command: List[str], timeout: int = 20) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, check=False)
        return (completed.stdout or "") + (completed.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_devices(output: str) -> List[DeviceState]:
    """Parse `adb devices -l`.

    The state can contain a space — "no permissions" — so splitting on
    whitespace and taking field two silently mislabels it as "no", which then
    matches nothing and produces "unrecognised state" for a problem that has a
    perfectly good explanation.
    """
    found: List[DeviceState] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        match = re.match(r"^(\S+)\s+(no permissions|[a-z]+)\s*(.*)$", line)
        if not match:
            continue
        serial, state, rest = match.groups()
        attributes = dict(re.findall(r"(\w+):(\S+)", rest or ""))
        found.append(DeviceState(
            serial=serial, state=state,
            model=attributes.get("model", ""),
            device=attributes.get("device", ""),
            product=attributes.get("product", ""),
            transport=attributes.get("transport_id", "")))
    return found


def diagnose(adb: Optional[str] = None) -> Diagnosis:
    """Find out why a handset is not being detected, and say what to do."""
    from .detect import find_tool

    result = Diagnosis()
    result.adb_path = adb or find_tool("adb")
    result.adb_available = bool(result.adb_path)

    if not result.adb_available:
        result.problems.append({
            "issue": "adb is not installed or could not be found.",
            "fix": ("Unzip Android SDK Platform-Tools to C:\\platform-tools "
                    "(ARGUS checks that location and the other standard install "
                    "paths without needing PATH changes), then restart ARGUS."),
        })
        result.next_steps.append(
            "Live acquisition needs adb. Importing an extraction that already "
            "exists on disk does not — choose Import instead.")
        return result

    version = _run([result.adb_path, "version"])
    result.adb_version = next((line.strip() for line in version.splitlines()
                               if line.strip()), "")

    listing = _run([result.adb_path, "devices", "-l"])
    result.raw = listing.strip()
    result.devices = parse_devices(listing)

    if not result.devices:
        result.problems.append({
            "issue": "adb is running but no handset is on the bus at all.",
            "fix": ("In order of how often each is the cause: (1) the cable is "
                    "charge-only — these are visually identical to data cables "
                    "and are the most common cause; (2) USB debugging is off in "
                    "Developer options; (3) the USB mode is set to charging "
                    "rather than File transfer; (4) the vendor USB driver is "
                    "not installed — check Device Manager for a device with a "
                    "warning triangle."),
        })
        result.next_steps.append(
            "Try a different cable first. It costs nothing and it is usually "
            "the answer.")
        result.next_steps.append(
            "Then: adb kill-server, replug, adb devices.")
        result.next_steps.append(
            "If the handset is BFU, destroyed, or will not authorise: dump "
            "the SIM/USIM with a reader and import it (argus acquire "
            "--method sim --source <dump>). ARGUS does not drive the reader.")
        return result

    seen_vendors = set()
    for state in result.devices:
        meaning, fix = STATE_MEANING.get(
            state.state, ("Unrecognised adb state.",
                          "Consult the adb documentation for this state."))
        label = f"{state.model or state.serial} ({state.state})"
        if state.state == "device":
            result.ready.append(label)
        else:
            result.problems.append({"issue": f"{label}: {meaning}", "fix": fix})
            if state.state in ("unauthorized", "offline"):
                result.next_steps.append(
                    "If the phone stays locked (BFU): import a SIM dump for "
                    "SMS and contacts that never lived on the handset.")
        if state.vendor_hint:
            seen_vendors.add(state.vendor_hint)

    for vendor in sorted(seen_vendors):
        result.vendor_guidance.extend(VENDOR_NOTES[vendor])

    if result.ready and not result.problems:
        result.next_steps.append(
            "The handset is reachable. Press Scan again in ARGUS and it will "
            "appear with its capability matrix.")
    elif result.ready:
        result.next_steps.append(
            "At least one handset is usable; the others need attention above.")
    return result


def vendor_guidance_for(name: str) -> List[str]:
    """Skin-specific notes for a make, when the device is not enumerating.

    Used when adb sees nothing at all and there is no model string to key on —
    the examiner still knows what they plugged in.
    """
    key = (name or "").strip().lower()
    for vendor, notes in VENDOR_NOTES.items():
        if vendor in key:
            return list(notes)
    return []
