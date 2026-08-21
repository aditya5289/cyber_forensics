"""Dedicated communications acquisition — SMS, MMS, contacts, calls, SIM.

Supplements the general logical query with provider URIs and shell fallbacks
tuned for OEM skins (Vivo/Funtouch, Samsung, MIUI) where standard AOSP URIs
return empty rows.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .android_adb import (
    AdbSession,
    PullResult,
    _merge_pull,
    export_dumpsys,
    logical_query,
)

# Providers always attempted when any comm category is requested.
COMMS_PROVIDERS: List[Tuple[str, str, str]] = [
    ("sms", "content://sms", "Messages"),
    ("sms_inbox", "content://sms/inbox", "Messages"),
    ("sms_sent", "content://sms/sent", "Messages"),
    ("sms_draft", "content://sms/draft", "Messages"),
    ("sms_outbox", "content://sms/outbox", "Messages"),
    ("sms_failed", "content://sms/failed", "Messages"),
    ("mms", "content://mms", "Messages"),
    ("mms_part", "content://mms/part", "Messages"),
    ("mms_addr", "content://mms/addr", "Messages"),
    ("threads", "content://mms-sms/conversations", "Messages"),
    ("threads_simple", "content://mms-sms/conversations?simple=true", "Messages"),
    ("calls", "content://call_log/calls", "Calls"),
    ("sec_calls", "content://logs/calls", "Calls"),
    ("sec_call", "content://logs/call", "Calls"),
    ("samsung_sms", "content://com.samsung.android.messaging/sms", "Messages"),
    ("samsung_msg", "content://com.samsung.android.messaging/message", "Messages"),
    ("samsung_dialer", "content://com.samsung.android.dialer/calls", "Calls"),
    ("google_sms", "content://com.google.android.apps.messaging.datamodel.MmsSmsProvider", "Messages"),
    ("contacts", "content://com.android.contacts/data/phones", "Contacts"),
    ("contacts_all", "content://com.android.contacts/contacts", "Contacts"),
    ("contacts_data", "content://com.android.contacts/data", "Contacts"),
    ("contacts_email", "content://com.android.contacts/data/emails", "Contacts"),
    ("contacts_lookup", "content://com.android.contacts/phone_lookup", "Contacts"),
    ("contacts_structured", "content://com.android.contacts/data/postals", "Contacts"),
    ("contacts_raw", "content://com.android.contacts/raw_contacts", "Contacts"),
    ("icc_adn", "content://icc/adn", "Contacts"),
    ("icc_adn0", "content://icc/adn/subId/0", "Contacts"),
    ("icc_adn1", "content://icc/adn/subId/1", "Contacts"),
    ("icc_fdn", "content://icc/fdn", "Contacts"),
    ("icc_sdn", "content://icc/sdn", "Contacts"),
    ("icc_sms", "content://icc/sms", "Messages"),
    ("voicemail", "content://com.android.voicemail/voicemail", "Calls"),
    ("blocked", "content://com.android.blockednumber/blocked", "Calls"),
    ("vivo_sms", "content://com.vivo.mms/sms", "Messages"),
    ("bbk_sms", "content://com.android.bbksms/sms", "Messages"),
    ("coloros_sms", "content://com.coloros.mms/sms", "Messages"),
    ("oppo_sms", "content://com.oppo.mms/sms", "Messages"),
    ("transsion_sms", "content://com.transsion.smartmessage/sms", "Messages"),
]

_COMMS_DUMPSYS = (
    ("call_log", "dumpsys call_log", "Calls"),
    ("telephony", "dumpsys telephony.registry", "Calls"),
    ("telecom", "dumpsys telecom", "Calls"),
    ("phone", "dumpsys phone", "Calls"),
    ("contacts", "dumpsys contact", "Contacts"),
    ("notification", "dumpsys notification --noredact", "Messages"),
    ("isub", "dumpsys isub", "Calls"),
    ("sms", "dumpsys sms", "Messages"),
    ("mms", "dumpsys mms", "Messages"),
    ("iccphonebook", "dumpsys iccphonebook", "Contacts"),
    ("iphonesubinfo", "dumpsys iphonesubinfo", "Calls"),
    ("simphonebook", "dumpsys simphonebook", "Contacts"),
)

# Telephony / contacts databases — pulled when root or readable on shared storage.
COMM_DATABASE_TARGETS: List[Tuple[str, str]] = [
    ("/data/data/com.android.providers.telephony/databases/mmssms.db", "Messages"),
    ("/data/data/com.android.providers.telephony/databases/telephony.db", "Calls"),
    ("/data/data/com.android.providers.contacts/databases/contacts2.db", "Contacts"),
    ("/data/data/com.android.providers.contacts/databases/calllog.db", "Calls"),
    ("/data/data/com.android.bbksms/databases/mmssms.db", "Messages"),
    ("/data/data/com.android.bbksms/databases/sms.db", "Messages"),
    ("/data/data/com.vivo.im/databases/im.db", "Messages"),
    ("/data/data/com.vivo.contacts/databases/contacts.db", "Contacts"),
    ("/data/data/com.google.android.apps.messaging/databases/bugle_db", "Messages"),
    ("/data/data/com.samsung.android.messaging/databases/messages.db", "Messages"),
    ("/data/data/com.samsung.android.messaging/databases/message.db", "Messages"),
    ("/data/data/com.samsung.android.dialer/databases/phone.db", "Calls"),
    ("/data/data/com.samsung.android.dialer/databases/dialer.db", "Calls"),
    ("/data/data/com.sec.android.provider.logsprovider/databases/logs.db", "Calls"),
    ("/data/data/com.miui.smsextra/databases/sms.db", "Messages"),
    ("/data/data/com.coloros.mms/databases", "Messages"),
    ("/data/data/com.transsion.smartmessage/databases", "Messages"),
    ("/data/data/com.tencent.mm/MicroMsg", "Messages"),
]

_SDCARD_DB_HINTS = re.compile(
    r"(mmssms|sms|message|contact|calllog|call_log|telephony|bugle|logs\.db)",
    re.IGNORECASE)

_GRANTED_SERIALS: set = set()

_RUNTIME_PERMS = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_CALENDAR",
)

_APPOPS = (
    "READ_SMS",
    "READ_CALL_LOG",
    "READ_CONTACTS",
    "READ_PHONE_STATE",
)


def grant_comms_runtime(session: AdbSession,
                        log: Optional[Callable[..., None]] = None) -> None:
    """Ask the unlocked handset to let the ADB shell read SMS, calls, contacts.

    Modern Android often refuses. The grant is still worth attempting: when it
    succeeds, content-provider dumps are complete allocated records instead of
    dumpsys fragments.
    """
    serial = getattr(session, "serial", "") or ""
    if serial in _GRANTED_SERIALS:
        return
    perms = " ; ".join(
        f"pm grant com.android.shell {perm} >/dev/null 2>&1"
        for perm in _RUNTIME_PERMS)
    ops = " ; ".join(
        f"cmd appops set com.android.shell {op} allow >/dev/null 2>&1"
        for op in _APPOPS)
    try:
        session.shell(f"{perms} ; {ops}", timeout=20)
    except Exception:
        pass
    _GRANTED_SERIALS.add(serial)
    if log:
        log("adb.comms", "ok",
            "Requested SMS, call-log and contacts read access for the ADB shell")


def _wants_comms(categories: Optional[List[str]]) -> bool:
    if not categories:
        return True
    return bool({c for c in categories
                 if c in ("Messages", "Contacts", "Calls", "Chats")})


def _wants_messages(categories: Optional[List[str]]) -> bool:
    if not categories:
        return True
    return "Messages" in categories or "Chats" in categories


def _wants_contacts(categories: Optional[List[str]]) -> bool:
    if not categories:
        return True
    return "Contacts" in categories


def _wants_calls(categories: Optional[List[str]]) -> bool:
    if not categories:
        return True
    return "Calls" in categories


def discover_sdcard_comm_databases(session: AdbSession,
                                   log: Optional[Callable[..., None]] = None,
                                   limit: int = 24) -> List[Tuple[str, str]]:
    """Find SMS/contact SQLite files on shared storage (backup apps)."""
    found: List[Tuple[str, str]] = []
    roots = ("/sdcard", "/storage/emulated/0")
    for root in roots:
        if not session.exists(root):
            continue
        listing = session.shell(
            f"find {root} -maxdepth 6 -type f "
            f"\\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \\) "
            f"2>/dev/null | head -{limit * 3}")
        for line in listing.splitlines():
            path = line.strip()
            if not path or not _SDCARD_DB_HINTS.search(path):
                continue
            cat = "Messages"
            if "contact" in path.lower():
                cat = "Contacts"
            elif "call" in path.lower():
                cat = "Calls"
            found.append((path, cat))
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    if found and log:
        log("adb.comms", "note",
            f"Discovered {len(found)} communication database(s) on shared storage")
    return found


def discover_sdcard_comm_xml(session: AdbSession,
                             log: Optional[Callable[..., None]] = None,
                             limit: int = 20) -> List[Tuple[str, str]]:
    """Find SMS Backup / call XML exports on shared storage."""
    found: List[Tuple[str, str]] = []
    roots = ("/sdcard", "/storage/emulated/0")
    for root in roots:
        if not session.exists(root):
            continue
        listing = session.shell(
            f"find {root} -maxdepth 5 -type f "
            f"\\( -iname 'sms*.xml' -o -iname 'calls*.xml' "
            f"-o -iname '*smsbackup*.xml' -o -iname '*call-log*.xml' \\) "
            f"2>/dev/null | head -{limit * 2}")
        for line in listing.splitlines():
            path = line.strip()
            if not path:
                continue
            cat = "Calls" if "call" in path.lower() else "Messages"
            found.append((path, cat))
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    if found and log:
        log("adb.comms", "note",
            f"Discovered {len(found)} SMS/call XML backup(s) on shared storage")
    return found


def default_sms_package(session: AdbSession) -> str:
    """Package holding the SMS role, e.g. Samsung Messages or Google Messages."""
    out = ""
    try:
        out = session.shell(
            "cmd role get android.app.role.SMS 2>/dev/null", timeout=8)
    except Exception:
        out = ""
    for line in reversed((out or "").splitlines()):
        line = line.strip()
        if not line:
            continue
        tokens = re.findall(r"[a-zA-Z0-9_.]+", line)
        for token in reversed(tokens):
            if "." in token and not token.startswith("android.app.role"):
                return token
    return ""


def capture_telephony_identity(session: AdbSession, dest: Path,
                               log: Optional[Callable[..., None]] = None
                               ) -> PullResult:
    """MSISDN / ICCID / IMEI fragments from dumpsys and getprop."""
    result = PullResult()
    out_dir = dest / "comms"
    out_dir.mkdir(parents=True, exist_ok=True)
    blobs: List[str] = []
    commands = (
        "getprop | grep -iE 'ril\\.|gsm\\.|cdma\\.|sim\\.|imei|msisdn|operator|serialno'",
        "dumpsys isub",
        "dumpsys iphonesubinfo",
    )
    for cmd in commands:
        try:
            text = session.shell(cmd, timeout=20) or ""
        except Exception:
            text = ""
        if text.strip():
            blobs.append(f"# {cmd}\n{text.strip()}\n")
    if not blobs:
        return result
    target = out_dir / "telephony_identity.txt"
    target.write_text("\n".join(blobs), encoding="utf-8")
    result.pulled.append("telephony_identity")
    result.bytes_total += target.stat().st_size
    if log:
        log("adb.comms", "ok", "Captured SIM / telephony identity dump",
            category="Calls")
    return result


def _write_comms_yield(dest: Path, logical: PullResult,
                       log: Optional[Callable[..., None]] = None) -> None:
    stats = getattr(logical, "provider_stats", None) or []
    summary = {
        "providers": stats,
        "row_total": sum(int(s.get("rows") or 0) for s in stats if isinstance(s, dict)),
        "providers_with_rows": [
            s.get("key") for s in stats
            if isinstance(s, dict) and int(s.get("rows") or 0) > 0],
    }
    out = dest / "comms" / "yield.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if log:
        names = ", ".join(summary["providers_with_rows"][:12]) or "none"
        log("adb.comms", "ok",
            f"Logical comms yield: {summary['row_total']:,} row(s) "
            f"from {len(summary['providers_with_rows'])} provider(s) ({names})")


def pull_comm_databases(session: AdbSession, dest: Path,
                        categories: Optional[List[str]] = None,
                        log: Optional[Callable[..., None]] = None,
                        extra_paths: Optional[List[Tuple[str, str]]] = None
                        ) -> PullResult:
    """Pull telephony/contacts DBs and any sdcard-discovered databases."""
    from .android_adb import SIDECARS, _tree_size

    result = PullResult()
    targets = list(COMM_DATABASE_TARGETS)
    seen = {p for p, _ in targets}
    for path, cat in (extra_paths or []):
        if path not in seen:
            targets.append((path, cat))
            seen.add(path)
    for path, cat in discover_sdcard_comm_databases(session, log=log):
        if path not in seen:
            targets.append((path, cat))
            seen.add(path)
    for path, cat in discover_sdcard_comm_xml(session, log=log):
        if path not in seen:
            targets.append((path, cat))
            seen.add(path)

    for remote, category in targets:
        if categories and category not in categories:
            continue
        if not session.exists(remote):
            continue
        if remote.lower().endswith((".xml", ".xml.gz", ".vcf", ".vcard")):
            local = dest / "comms_export" / Path(remote).name
        else:
            local = dest / "databases" / remote.lstrip("/").replace("/", "_")
        ok, msg = session.pull(remote, local, verify=False, log=log)
        if ok:
            result.pulled.append(remote)
            try:
                result.bytes_total += local.stat().st_size
            except OSError:
                pass
            for side in SIDECARS:
                side_remote = remote + side
                if session.exists(side_remote):
                    session.pull(side_remote, Path(str(local) + side),
                                   verify=False, log=log)
            if log:
                log("adb.comms", "ok",
                    f"Pulled {remote.split('/')[-1]} ({category})",
                    category=category)
        elif log and "permission" not in msg.lower():
            log("adb.comms", "skipped", f"{remote}: {msg[:80]}")
    return result


def export_contact_lookups(session: AdbSession, dest: Path,
                           log: Optional[Callable[..., None]] = None
                           ) -> PullResult:
    """Batch contact phone/email lookups via content query."""
    from .android_adb import _content_query_paginated

    result = PullResult()
    out_dir = dest / "contacts_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    queries = [
        ("phones", "content://com.android.contacts/contacts",
         "--projection display_name:_id"),
        ("phone_data", "content://com.android.contacts/data/phones",
         "--projection display_name:data1:mimetype"),
        ("emails", "content://com.android.contacts/data/emails",
         "--projection display_name:data1"),
        ("vivo_contacts", "content://com.vivo.contacts/contacts",
         "--projection display_name:_id"),
        ("bbk_contacts", "content://com.bbk.contacts/contacts",
         "--projection display_name:_id"),
        ("icc_adn", "content://icc/adn",
         "--projection name:number"),
        ("samsung_phones", "content://com.android.contacts/data/phones",
         "--projection display_name:data1:mimetype"),
    ]
    for name, uri, projection in queries:
        try:
            text = session.shell(
                f"content query --uri {uri} {projection}", timeout=300)
        except Exception:
            continue
        if not text.strip() or "Row:" not in text:
            text = _content_query_paginated(session, uri, timeout=300)
        if not text.strip() or "Row:" not in text:
            continue
        target = out_dir / f"{name}.txt"
        target.write_text(text, encoding="utf-8")
        result.pulled.append(uri)
        result.bytes_total += target.stat().st_size
        if log:
            log("adb.comms", "ok",
                f"Contact export {name}: {text.count('Row:'):,} row(s)",
                category="Contacts")
    return result


def acquire_communications_deep(session: AdbSession, dest: Path,
                                categories: Optional[List[str]] = None,
                                log: Optional[Callable[..., None]] = None,
                                skip_existing: bool = False,
                                vendor_providers: Optional[
                                    List[Tuple[str, str, str]]] = None,
                                vendor_comm_paths: Optional[
                                    List[Tuple[str, str]]] = None
                                ) -> PullResult:
    """Full communications pass — providers, dumpsys, DBs, contact exports."""
    overall = PullResult()
    if not _wants_comms(categories):
        return overall

    grant_comms_runtime(session, log=log)

    comm_cats = [c for c in (categories or [])
                 if c in ("Messages", "Contacts", "Calls", "Chats")]
    if not comm_cats:
        comm_cats = ["Messages", "Contacts", "Calls"]

    _merge_pull(overall, capture_telephony_identity(session, dest, log=log))

    # Dedicated logical pass with all comm providers.
    extras = list(COMMS_PROVIDERS)
    seen = {k for k, _, _ in extras}
    for item in (vendor_providers or []):
        if item[0] not in seen:
            extras.append(item)
            seen.add(item[0])

    logical = logical_query(
        session, dest / "comms_logical", comm_cats, log=log,
        comms_only=False, skip_existing=skip_existing,
        extra_providers=extras, providers_only=extras)
    _merge_pull(overall, logical)
    try:
        _write_comms_yield(dest, logical, log=log)
    except Exception:
        pass

    dumpsys_targets = list(_COMMS_DUMPSYS)
    _merge_pull(overall, export_dumpsys(
        session, dest, dumpsys_targets, categories=comm_cats, log=log))

    if _wants_contacts(categories):
        _merge_pull(overall, export_contact_lookups(session, dest, log=log))

    _merge_pull(overall, pull_comm_databases(
        session, dest, categories=comm_cats, log=log))

    extra_comm = list(vendor_comm_paths or [])
    pkg = default_sms_package(session)
    if pkg and _wants_messages(categories):
        extra_comm.append((f"/sdcard/Android/data/{pkg}", "Messages"))
        extra_comm.append((f"/storage/emulated/0/Android/data/{pkg}", "Messages"))
        if log:
            log("adb.comms", "ok", f"Default SMS app: {pkg}")

    from .android_adb import pull_communication_exports
    _merge_pull(overall, pull_communication_exports(
        session, dest, categories=comm_cats, log=log,
        extra_paths=extra_comm))

    overall.passes.append("comms_deep")
    if log:
        log("adb.comms", "ok",
            f"Deep communications pass — {len(overall.pulled)} source(s), "
            f"{overall.bytes_total:,} bytes")
    return overall
