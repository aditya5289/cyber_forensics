"""Dedicated communications acquisition — SMS, MMS, contacts, calls, SIM.

Supplements the general logical query with provider URIs and shell fallbacks
tuned for OEM skins (Vivo/Funtouch, Samsung, MIUI) where standard AOSP URIs
return empty rows.
"""

from __future__ import annotations

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
    ("calls", "content://call_log/calls", "Calls"),
    ("contacts", "content://com.android.contacts/data/phones", "Contacts"),
    ("contacts_all", "content://com.android.contacts/contacts", "Contacts"),
    ("contacts_data", "content://com.android.contacts/data", "Contacts"),
    ("contacts_email", "content://com.android.contacts/data/emails", "Contacts"),
    ("contacts_lookup", "content://com.android.contacts/phone_lookup", "Contacts"),
    ("contacts_structured", "content://com.android.contacts/data/postals", "Contacts"),
    ("icc_adn", "content://icc/adn", "Contacts"),
    ("icc_sms", "content://icc/sms", "Messages"),
    ("vivo_sms", "content://com.vivo.mms/sms", "Messages"),
    ("bbk_sms", "content://com.android.bbksms/sms", "Messages"),
    ("sec_calls", "content://logs/calls", "Calls"),
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
    ("iccphonebook", "dumpsys iccphonebook", "Contacts"),
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
    ("/data/data/com.samsung.android.dialer/databases/phone.db", "Calls"),
    ("/data/data/com.miui.smsextra/databases/sms.db", "Messages"),
    ("/data/data/com.coloros.mms/databases", "Messages"),
    ("/data/data/com.transsion.smartmessage/databases", "Messages"),
    ("/data/data/com.tencent.mm/MicroMsg", "Messages"),
]

_SDCARD_DB_HINTS = re.compile(
    r"(mmssms|sms|message|contact|calllog|call_log|telephony|bugle)",
    re.IGNORECASE)


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

    for remote, category in targets:
        if categories and category not in categories:
            continue
        if not session.exists(remote):
            continue
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

    comm_cats = [c for c in (categories or [])
                 if c in ("Messages", "Contacts", "Calls", "Chats")]
    if not comm_cats:
        comm_cats = ["Messages", "Contacts", "Calls"]

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

    dumpsys_targets = list(_COMMS_DUMPSYS)
    _merge_pull(overall, export_dumpsys(
        session, dest, dumpsys_targets, categories=comm_cats, log=log))

    if _wants_contacts(categories):
        _merge_pull(overall, export_contact_lookups(session, dest, log=log))

    _merge_pull(overall, pull_comm_databases(
        session, dest, categories=comm_cats, log=log))

    from .android_adb import pull_communication_exports
    _merge_pull(overall, pull_communication_exports(
        session, dest, categories=comm_cats, log=log,
        extra_paths=vendor_comm_paths))

    overall.passes.append("comms_deep")
    if log:
        log("adb.comms", "ok",
            f"Deep communications pass — {len(overall.pulled)} source(s), "
            f"{overall.bytes_total:,} bytes")
    return overall
