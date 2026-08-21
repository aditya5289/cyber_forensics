"""Vendor-specific acquisition paths for Android handsets.

Static ``FS_TARGETS`` / ``COMM_EXPORT_PATHS`` cover AOSP well; OEM skins store
backups and exports in brand-specific folders.  This module expands paths based
on ``ro.product.manufacturer`` captured during device_report().
"""

from __future__ import annotations

from typing import Dict, List, Tuple

PathEntry = Tuple[str, str]

_VENDOR_FS: Dict[str, List[PathEntry]] = {
    "vivo": [
        ("/sdcard/Android/data/com.vivo.easyshare/files", "Other"),
        ("/sdcard/Android/data/com.vivo.browser", "Web"),
        ("/data/data/com.vivo.im/databases", "Messages"),
        ("/data/data/com.android.bbksms/databases", "Messages"),
    ],
    "bbk": [
        ("/sdcard/Android/data/com.vivo.easyshare/files", "Other"),
        ("/data/data/com.android.bbksms/databases", "Messages"),
    ],
    "iqoo": [
        ("/sdcard/Android/data/com.vivo.easyshare/files", "Other"),
    ],
    "samsung": [
        ("/sdcard/SmartSwitch", "Other"),
        ("/sdcard/Samsung", "Other"),
        ("/sdcard/LOST.DIR", "Files & Media"),
        ("/data/data/com.samsung.android.messaging/databases", "Messages"),
        ("/data/data/com.samsung.android.dialer/databases", "Calls"),
    ],
    "xiaomi": [
        ("/sdcard/MIUI", "Other"),
        ("/sdcard/Xiaomi", "Other"),
        ("/sdcard/MIUI/backup", "Other"),
        ("/data/data/com.miui.smsextra/databases", "Messages"),
    ],
    "redmi": [
        ("/sdcard/MIUI", "Other"),
        ("/sdcard/MIUI/backup", "Other"),
    ],
    "oppo": [
        ("/sdcard/OPPO", "Other"),
        ("/sdcard/ColorOS", "Other"),
        ("/sdcard/Backup", "Other"),
        ("/sdcard/Android/data/com.coloros.backuprestore", "Other"),
    ],
    "realme": [
        ("/sdcard/Realme", "Other"),
        ("/sdcard/ColorOS", "Other"),
        ("/sdcard/Backup", "Other"),
    ],
    "oneplus": [
        ("/sdcard/OnePlus", "Other"),
        ("/sdcard/Backup", "Other"),
    ],
    "huawei": [
        ("/sdcard/Huawei", "Other"),
        ("/sdcard/HwBackup", "Other"),
    ],
    "honor": [
        ("/sdcard/Honor", "Other"),
        ("/sdcard/Backup", "Other"),
    ],
    "motorola": [
        ("/sdcard/Motorola", "Other"),
        ("/sdcard/MotoBackup", "Other"),
        ("/data/data/com.motorola.ccc.ota/databases", "Other"),
    ],
    "google": [
        ("/data/data/com.google.android.apps.messaging/databases", "Messages"),
        ("/sdcard/Google Messages", "Messages"),
    ],
    "transsion": [
        ("/sdcard/HiOS", "Other"),
        ("/sdcard/XOS", "Other"),
        ("/sdcard/Transsion", "Other"),
        ("/sdcard/Backup", "Other"),
        ("/sdcard/PhoneClone", "Other"),
        ("/sdcard/Android/data/com.transsion.phonemaster", "Other"),
        ("/sdcard/Android/data/com.transsion.letswitch", "Other"),
        ("/data/data/com.transsion.smartmessage/databases", "Messages"),
        ("/data/data/com.transsion.deskclock/databases", "Other"),
        ("/data/data/com.transsion.notebook/databases", "Other"),
    ],
}

_VENDOR_COMM: Dict[str, List[PathEntry]] = {
    "vivo": [
        ("/sdcard/EasyShare/Backup", "Messages"),
        ("/sdcard/vivo/backup", "Other"),
        ("/sdcard/BBK/backup", "Other"),
    ],
    "bbk": [
        ("/sdcard/EasyShare/Backup", "Messages"),
    ],
    "samsung": [
        ("/sdcard/SmartSwitch", "Other"),
        ("/sdcard/Samsung/backup", "Other"),
    ],
    "xiaomi": [
        ("/sdcard/MIUI/backup", "Other"),
        ("/sdcard/Xiaomi/backup", "Other"),
    ],
    "redmi": [
        ("/sdcard/MIUI/backup", "Other"),
    ],
    "oppo": [
        ("/sdcard/OPPO/Backup", "Other"),
        ("/sdcard/ColorOS/Backup", "Other"),
    ],
    "realme": [
        ("/sdcard/Realme/Backup", "Other"),
        ("/sdcard/ColorOS/Backup", "Other"),
    ],
    "oneplus": [
        ("/sdcard/OnePlus/Backup", "Other"),
        ("/sdcard/OxygenOS/Backup", "Other"),
    ],
    "motorola": [
        ("/sdcard/MotoBackup", "Other"),
        ("/sdcard/Motorola/Backup", "Other"),
    ],
    "transsion": [
        ("/sdcard/HiOS/Backup", "Other"),
        ("/sdcard/XOS/Backup", "Other"),
        ("/sdcard/PhoneClone", "Other"),
        ("/sdcard/Transsion/Backup", "Other"),
        ("/sdcard/LetsSwitch", "Other"),
    ],
}

_PROVIDER_EXTRAS: Dict[str, List[Tuple[str, str, str]]] = {
    "vivo": [
        ("mms_part", "content://mms/part", "Messages"),
        ("vivo_sms", "content://com.vivo.mms/sms", "Messages"),
    ],
    "bbk": [
        ("mms_part", "content://mms/part", "Messages"),
        ("bbk_sms", "content://com.android.bbksms/sms", "Messages"),
    ],
    "samsung": [
        ("mms_part", "content://mms/part", "Messages"),
        ("sec_calls", "content://logs/calls", "Calls"),
    ],
    "xiaomi": [
        ("mms_part", "content://mms/part", "Messages"),
    ],
    "oppo": [
        ("mms_part", "content://mms/part", "Messages"),
        ("coloros_sms", "content://com.coloros.mms/sms", "Messages"),
        ("oppo_sms", "content://com.oppo.mms/sms", "Messages"),
        ("coloros_calls", "content://com.coloros.phonemanager/calllog", "Calls"),
    ],
    "realme": [
        ("mms_part", "content://mms/part", "Messages"),
        ("coloros_sms", "content://com.coloros.mms/sms", "Messages"),
    ],
    "oneplus": [
        ("mms_part", "content://mms/part", "Messages"),
        ("coloros_sms", "content://com.coloros.mms/sms", "Messages"),
    ],
    "motorola": [
        ("mms_part", "content://mms/part", "Messages"),
    ],
    "transsion": [
        ("mms_part", "content://mms/part", "Messages"),
        ("transsion_sms", "content://com.transsion.smartmessage/sms", "Messages"),
        ("hios_sms", "content://sms", "Messages"),
    ],
}

_MAKE_ALIASES: Dict[str, str] = {
    "iqoo": "vivo",
    "bbk": "vivo",
    "funtouch": "vivo",
    "poco": "xiaomi",
    "redmi": "xiaomi",
    "miui": "xiaomi",
    "coloros": "oppo",
    "oxygenos": "oneplus",
    "moto": "motorola",
    "pixel": "google",
    "tecno": "transsion",
    "infinix": "transsion",
    "itel": "transsion",
    "hios": "transsion",
    "xos": "transsion",
}


def _normalize_make(make: str) -> str:
    m = (make or "").strip().lower()
    if not m:
        return ""
    for alias, canonical in _MAKE_ALIASES.items():
        if alias in m:
            return canonical
    for key in _VENDOR_FS:
        if key in m:
            return key
    return m.split()[0]


def expand_fs_paths(make: str, model: str = "") -> List[PathEntry]:
    """Extra filesystem targets for the detected manufacturer."""
    key = _normalize_make(make)
    out: List[PathEntry] = list(_VENDOR_FS.get(key, []))
    if "y02" in (model or "").lower() or "v2217" in (model or "").lower():
        out.extend(_VENDOR_FS.get("vivo", []))
    seen: set[str] = set()
    deduped: List[PathEntry] = []
    for path, cat in out:
        if path not in seen:
            seen.add(path)
            deduped.append((path, cat))
    return deduped


def expand_comm_paths(make: str, model: str = "") -> List[PathEntry]:
    """Extra shared-storage export paths for the manufacturer."""
    key = _normalize_make(make)
    out: List[PathEntry] = list(_VENDOR_COMM.get(key, []))
    if "y02" in (model or "").lower():
        out.extend(_VENDOR_COMM.get("vivo", []))
    seen: set[str] = set()
    deduped: List[PathEntry] = []
    for path, cat in out:
        if path not in seen:
            seen.add(path)
            deduped.append((path, cat))
    return deduped


def extra_providers(make: str) -> List[Tuple[str, str, str]]:
    """OEM content-provider URIs to add to logical query work list."""
    key = _normalize_make(make)
    return list(_PROVIDER_EXTRAS.get(key, []))
