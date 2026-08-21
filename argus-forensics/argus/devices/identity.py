"""Structured device identity — USB, ADB, MTP and iOS in one record.

Detection used to stop at a display name. Acquisition then recorded whatever
the first transport happened to know. An MTP-only Y-series handset therefore
landed in the case as "Y02" with a blank make, no VID/PID, and no storage
map — facts the USB bus already had.

This module is the single place that turns a VID/PID, an MTP shell path, or a
``getprop`` dump into a stable identity dict that both the scanner and the
acquisition engine write into the container.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# USB-IF vendor IDs. Several BBK brands share silicon and sometimes VID.
USB_VENDORS: Dict[str, str] = {
    "18d1": "Google",
    "22b8": "Motorola",
    "04e8": "Samsung",
    "22d9": "Oppo",
    "2a70": "OnePlus",
    "2717": "Xiaomi",
    "2916": "Android (generic / ADB interface)",
    "0bb4": "HTC",
    "12d1": "Huawei",
    "19d2": "ZTE",
    "0fce": "Sony",
    "1004": "LG",
    "05c6": "Qualcomm (bootloader / EDL mode)",
    "0e8d": "MediaTek (BootROM / preloader)",
    "1782": "Spreadtrum / Unisoc",
    "05ac": "Apple",
    "2d95": "Vivo / iQOO / Y-series (BBK)",
    "1f3a": "Allwinner",
    "2207": "Rockchip",
    "0b05": "ASUS",
    "0489": "Foxconn",
    "1bbb": "T-Mobile / Alcatel",
    "2b4c": "Nothing",
    "0531": "Wacom",
    "0e79": "Archos",
    "201e": "Haier",
    "2a47": "Nothing (alternate)",
    "04c5": "Fujitsu",
    "1d4d": "Pegatron",
    "1e0e": "Transsion (Tecno / Infinix / itel)",
    "2ec1": "Transsion alternate",
}

# Common Android USB product IDs (Google composite / OEM MTP).
USB_PRODUCT_MODES: Dict[str, str] = {
    "4ee0": "ADB (charging)",
    "4ee1": "ADB",
    "4ee2": "ADB + accessory",
    "4ee3": "ADB + accessory",
    "4ee4": "RNDIS",
    "4ee5": "RNDIS + ADB",
    "4ee6": "PTP",
    "4ee7": "PTP + ADB",
    "4ee8": "MTP",
    "4ee9": "MTP + ADB",
    "4eea": "MIDI",
    "4eeb": "MIDI + ADB",
    "4eec": "accessory",
    "4eed": "accessory + ADB",
    "2012": "MTP",
    "201d": "MTP + ADB",
    "2008": "MTP",
    "200a": "MTP + ADB",
    "200b": "PTP",
    "200c": "PTP + ADB",
    "200e": "MIDI",
    "6002": "MTP / file transfer",
    "6003": "MTP + ADB",
    "9008": "Qualcomm EDL 9008",
    "0003": "MediaTek BootROM",
    "2000": "MediaTek preloader",
}

IOS_MODEL_MAP: Dict[str, str] = {
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd generation)",
    "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
    "iPhone17,5": "iPhone 16e",
    "iPad13,16": "iPad (10th generation)",
    "iPad14,1": "iPad mini (6th generation)",
    "iPad16,3": "iPad mini (A17 Pro)",
}


_VID_PID_RE = re.compile(
    r"vid[_:]([0-9a-f]{4}).*?pid[_:]([0-9a-f]{4})", re.I)
_USB_SERIAL_RE = re.compile(
    r"vid_[0-9a-f]{4}&pid_[0-9a-f]{4}#([^#\\{]+)", re.I)


def parse_usb_ids(text: str) -> Tuple[str, str]:
    """Extract ``(vid, pid)`` from an MTP path, PnP instance id, or USB string."""
    if not text:
        return "", ""
    match = _VID_PID_RE.search(text.replace("\\", "/"))
    if not match:
        return "", ""
    return match.group(1).lower(), match.group(2).lower()


def parse_usb_instance_serial(text: str) -> str:
    """Hardware serial fragment from a Windows MTP/PnP instance id."""
    if not text:
        return ""
    match = _USB_SERIAL_RE.search(text.replace("/", "\\"))
    return (match.group(1) or "").strip() if match else ""


def vendor_for_vid(vid: str) -> str:
    return USB_VENDORS.get((vid or "").lower(), "")


def mode_for_pid(pid: str) -> str:
    return USB_PRODUCT_MODES.get((pid or "").lower(), "")


def ios_marketing_name(product_type: str, fallback: str = "") -> str:
    return IOS_MODEL_MAP.get(product_type, fallback or product_type)


def usb_identity_from_path(path: str) -> Dict[str, str]:
    vid, pid = parse_usb_ids(path)
    serial = parse_usb_instance_serial(path)
    return {
        "usb_vid": vid,
        "usb_pid": pid,
        "usb_vendor": vendor_for_vid(vid),
        "usb_mode": mode_for_pid(pid),
        "usb_instance_serial": serial,
    }


def android_identity_from_props(props: Dict[str, str]) -> Dict[str, Any]:
    """Normalise a ``getprop`` map into examiner-facing identity fields."""
    def g(*keys: str) -> str:
        for key in keys:
            val = (props.get(key) or "").strip()
            if val:
                return val
        return ""

    sdk = g("ro.build.version.sdk")
    try:
        sdk_n = int(sdk) if sdk else None
    except ValueError:
        sdk_n = None
    return {
        "make": g("ro.product.manufacturer", "ro.product.brand"),
        "brand": g("ro.product.brand"),
        "model": g("ro.product.model"),
        "marketing_name": g("ro.product.marketname", "ro.product.model"),
        "device": g("ro.product.device"),
        "board": g("ro.product.board", "ro.board.platform"),
        "hardware": g("ro.hardware"),
        "chipset": g("ro.board.platform", "ro.hardware"),
        "os_version": g("ro.build.version.release"),
        "sdk": sdk_n,
        "security_patch": g("ro.build.version.security_patch"),
        "build_id": g("ro.build.display.id", "ro.build.id"),
        "fingerprint": g("ro.build.fingerprint"),
        "serialno": g("ro.serialno", "ro.boot.serialno"),
        "crypto_state": g("ro.crypto.state"),
        "crypto_type": g("ro.crypto.type"),
        "ab_update": g("ro.build.ab_update"),
        "incremental": g("ro.build.version.incremental"),
        "sim_operator": g("gsm.sim.operator.alpha", "gsm.operator.alpha"),
        "sim_state": g("gsm.sim.state"),
    }


def write_identity(path: Path | str, payload: Dict[str, Any]) -> Path:
    """Write ``device_identity.json`` beside the raw evidence."""
    target = Path(path)
    if target.is_dir() or target.suffix.lower() != ".json":
        target = target / "device_identity.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    body = dict(payload)
    body.setdefault("format", "argus-device-identity/1")
    target.write_text(json.dumps(body, indent=2, ensure_ascii=False, default=str),
                      encoding="utf-8")
    return target


def snapshot_from_detected(device: Any) -> Dict[str, Any]:
    """Flatten a :class:`DetectedDevice` into a portable identity record."""
    raw = dict(getattr(device, "raw", None) or {})
    usb = usb_identity_from_path(
        getattr(device, "serial", "") or raw.get("mtp_path", ""))
    if not usb.get("usb_vid"):
        usb = {
            "usb_vid": raw.get("usb_vid", ""),
            "usb_pid": raw.get("usb_pid", ""),
            "usb_vendor": raw.get("usb_vendor", ""),
            "usb_mode": raw.get("usb_mode", ""),
            "usb_instance_serial": raw.get("usb_instance_serial", ""),
        }
    return {
        "transport": getattr(device, "transport", ""),
        "name": getattr(device, "name", ""),
        "make": getattr(device, "make", "") or usb.get("usb_vendor", ""),
        "model": getattr(device, "model", ""),
        "marketing_name": getattr(device, "marketing_name", ""),
        "os_family": getattr(device, "os_family", ""),
        "os_version": getattr(device, "os_version", ""),
        "build_id": getattr(device, "build_id", ""),
        "chipset": getattr(device, "chipset", ""),
        "serial": getattr(device, "serial", ""),
        "imei": getattr(device, "imei", ""),
        "iccid": getattr(device, "iccid", ""),
        "phone_number": getattr(device, "phone_number", ""),
        "lock_state": getattr(device, "lock_state", ""),
        "trusted": bool(getattr(device, "trusted", True)),
        "rooted": bool(getattr(device, "rooted", False)),
        "encrypted": bool(getattr(device, "encrypted", True)),
        "battery": getattr(device, "battery", None),
        "mtp_name": raw.get("mtp_name", ""),
        "mtp_path": raw.get("mtp_path", ""),
        "adb_state": raw.get("adb_state", ""),
        "volumes": raw.get("volumes") or [],
        "recommended_method": raw.get("recommended_method", ""),
        "identity": raw.get("identity") or {},
        **usb,
    }
