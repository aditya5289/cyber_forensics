"""Android system telemetry, mail, payments and location history.

These sources answer a question the messaging apps cannot: *was the handset in
the owner's hand at that moment?* App-usage records and notification history
place a human at the device at a specific second, which is often what
distinguishes "the phone sent it" from "the owner sent it" — and that
distinction decides cases.

Covered here:

* **usagestats** — which app was in the foreground, and when.
* **notification history** — every notification posted, including the text of
  messages from apps whose own databases are encrypted. A Signal notification
  preserves a preview of a message ARGUS cannot otherwise read.
* **Gmail** — message metadata and snippets from the local mail store.
* **Payment apps** — UPI and wallet transaction records.
* **Google Maps** — search and navigation history.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_float, as_int, as_text, clean_number,
                      pick, rows_with_deleted, valid_coord)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

# android.app.usage.UsageEvents.Event
USAGE_EVENT = {
    1: "moved to foreground", 2: "moved to background",
    5: "configuration change", 7: "user interaction",
    11: "notification seen", 12: "notification interruption",
    15: "screen interactive", 16: "screen non-interactive",
    17: "keyguard shown", 18: "keyguard hidden",
    19: "foreground service start", 20: "foreground service stop",
    23: "activity stopped", 26: "device startup", 27: "device shutdown",
}

PACKAGE_LABELS = {
    "com.whatsapp": "WhatsApp", "com.instagram.android": "Instagram",
    "org.telegram.messenger": "Telegram", "com.snapchat.android": "Snapchat",
    "org.thoughtcrime.securesms": "Signal", "com.facebook.orca": "Messenger",
    "com.google.android.gm": "Gmail", "com.android.chrome": "Chrome",
    "net.one97.paytm": "Paytm", "com.phonepe.app": "PhonePe",
    "com.google.android.apps.nbu.paisa.user": "Google Pay",
    "com.google.android.apps.maps": "Google Maps",
    "com.discord": "Discord", "com.viber.voip": "Viber",
}


def _label(package: str) -> str:
    return PACKAGE_LABELS.get(package, package.split(".")[-1].title()
                              if package else "Unknown")


# ═══════════════════════════════════════════════════════ app usage statistics
@register(
    name="android.usagestats",
    patterns=["usagestats*.xml", "*.usagestats", "usage-history.xml"],
    platform="android", priority=72,
    description="App foreground/background events — places a user at the device",
)
def parse_usagestats(path: Path, ctx: ParseContext) -> ParseResult:
    """Android usage statistics."""
    res = ParseResult(parser="android.usagestats", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    # The XML carries a base timestamp; each event is an offset from it.
    base_match = re.search(r'<usagestats[^>]*\bbeginTime="(\d+)"', text)
    base = int(base_match.group(1)) if base_match else 0

    count = 0
    for match in re.finditer(
            r'<event\b([^>]*)/?>', text):
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
        package = attrs.get("package", "")
        if not package:
            continue
        offset = as_int(attrs.get("time")) or 0
        ts = guess(base + offset if base else offset, "time")
        if not ctx.in_span(ts):
            continue
        event_type = as_int(attrs.get("type")) or 0
        description = USAGE_EVENT.get(event_type, f"event type {event_type}")
        art = Artifact(
            category=Category.ACTIVITY, subtype="App usage event",
            timestamp=ts, body=f"{_label(package)} {description}",
            app=_label(package), source_path=ctx.rel(path),
            attributes={
                "package": package, "event_type": event_type,
                "event": description,
                "class": attrs.get("class", ""),
                "note": ("Foreground and interaction events indicate a person "
                         "was operating the device at this moment, not merely "
                         "that it was powered on."),
            },
        )
        res.artifacts.append(art)
        count += 1
        if count >= 20000:
            res.notes.append(f"{ctx.rel(path)}: truncated at 20 000 usage events")
            break
    if count:
        res.notes.append(f"{ctx.rel(path)}: {count} app usage event(s) — useful "
                         f"for establishing device use at a specific time")
    return res


# ═══════════════════════════════════════════════════════ notification history
@register(
    name="android.notifications",
    patterns=["notification_log.db", "notification_history*", "*notifications.db"],
    platform="android", priority=80,
    probe=any_table_probe(("notifications",), ("notification",), ("log",)),
    description="Notification history — often previews messages from encrypted apps",
)
def parse_notifications(path: Path, ctx: ParseContext) -> ParseResult:
    """Android notification history.

    This is one of the highest-value sources on a modern handset, precisely
    because it sidesteps app encryption. A Signal or WhatsApp notification
    contains a preview of the message text, written by the OS to its own
    store — so content that is unreadable in the app's encrypted database is
    frequently readable here.
    """
    res = ParseResult(parser="android.notifications", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("notifications", "notification", "log")
        if not table:
            res.notes.append(f"{path.name}: no notification table")
            return res

        pkg_col = _col(db, table, "pkg", "package", "package_name")
        title_col = _col(db, table, "title", "notification_title", "extra_title")
        text_col = _col(db, table, "text", "body", "extra_text", "content")
        ts_col = _col(db, table, "post_time", "posted_time", "timestamp", "when")
        key_col = _col(db, table, "key", "notification_key")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            package = as_text(row.get(pkg_col)) if pkg_col else ""
            title = as_text(row.get(title_col)) if title_col else ""
            body = as_text(row.get(text_col)) if text_col else ""
            if not (title or body):
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            label = _label(package)
            encrypted_app = package in (
                "org.thoughtcrime.securesms", "com.wickr.me", "ch.threema.app",
                "org.telegram.messenger")
            art = Artifact(
                category=Category.MESSAGE if body else Category.ACTIVITY,
                subtype=f"{label} notification",
                timestamp=ts,
                body=f"{title}: {body}".strip(": ") if title else body,
                app=label, direction=Direction.INCOMING,
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={
                    "package": package, "title": title, "text": body,
                    "notification_key": as_text(row.get(key_col)) if key_col else "",
                    "previews_encrypted_app": encrypted_app,
                    "note": ("This notification previews content from an app "
                             "whose own store is encrypted — it may be the only "
                             "readable copy of this message."
                             if encrypted_app else ""),
                },
            )
            if title and not title.lower().startswith(("you ", "new ")):
                art.add_participant("", title, role="from")
            art.add_participant("", ctx.owner_name, role="to", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        previews = sum(1 for a in res.artifacts
                       if a.attributes.get("previews_encrypted_app"))
        if previews:
            res.notes.append(
                f"{ctx.rel(path)}: {previews} notification(s) preview content "
                f"from encrypted messaging apps — check these against the "
                f"encrypted-store findings")
        res.warnings.extend(db.warnings)
    return res


def _col(db: ForensicSQLite, table: str, *candidates: str) -> str:
    columns = {c.lower(): c for c in db.columns(table)}
    for name in candidates:
        if name.lower() in columns:
            return columns[name.lower()]
    return ""


# ═══════════════════════════════════════════════════════════════ Gmail
@register(
    name="android.gmail",
    patterns=["mailstore.*.db", "bigTop*.db", "gmail.db", "EmailProvider.db"],
    platform="android", priority=80,
    probe=any_table_probe(("messages",), ("message",), ("conversations",)),
    description="Gmail local mail store — headers and snippets",
)
def parse_gmail(path: Path, ctx: ParseContext) -> ParseResult:
    """Gmail."""
    res = ParseResult(parser="android.gmail", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("messages", "message")
        if not table:
            return res
        subj_col = _col(db, table, "subject")
        snip_col = _col(db, table, "snippet", "bodySnippet", "body")
        from_col = _col(db, table, "fromAddress", "from_address", "sender")
        to_col = _col(db, table, "toAddresses", "to_address", "toList")
        ts_col = _col(db, table, "dateSentMs", "dateReceivedMs", "timestamp",
                     "date")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            subject = as_text(row.get(subj_col)) if subj_col else ""
            snippet = as_text(row.get(snip_col)) if snip_col else ""
            if not (subject or snippet):
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            sender = _first_email(as_text(row.get(from_col)) if from_col else "")
            recipients = _emails(as_text(row.get(to_col)) if to_col else "")
            art = Artifact(
                category=Category.MESSAGE, subtype="Email (Gmail)",
                timestamp=ts,
                body=(f"{subject}\n{snippet}" if subject and snippet
                      else subject or snippet),
                app="Gmail", source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={
                    "subject": subject, "snippet": snippet,
                    "from": sender, "to": recipients,
                    "note": ("The local store holds headers and a snippet; the "
                             "full body normally remains server-side."),
                    "schema_variant": table,
                },
            )
            if sender:
                art.add_participant(sender, "", role="from")
            for addr in recipients[:6]:
                art.add_participant(addr, "", role="to")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}")


def _first_email(raw: str) -> str:
    match = _EMAIL.search(raw or "")
    return match.group(0) if match else ""


def _emails(raw: str) -> List[str]:
    return list(dict.fromkeys(_EMAIL.findall(raw or "")))[:20]


# ═══════════════════════════════════════════════════════════ payment apps
@register(
    name="android.payments",
    patterns=["*paytm*.db", "*phonepe*.db", "*upi*.db", "transactions.db",
              "*wallet*.db", "*payment*.db"],
    platform="android", priority=78,
    probe=any_table_probe(("transactions",), ("transaction",),
                          ("payment_history",), ("txn",)),
    description="UPI and wallet transaction records",
)
def parse_payments(path: Path, ctx: ParseContext) -> ParseResult:
    """Payment application transactions."""
    res = ParseResult(parser="android.payments", source=ctx.rel(path))
    app = _app_from_path(path)
    with ForensicSQLite(path) as db:
        table = db.first_table("transactions", "transaction", "payment_history",
                               "txn")
        if not table:
            return res
        amount_col = _col(db, table, "amount", "txn_amount", "value")
        ts_col = _col(db, table, "timestamp", "txn_date", "date", "created_at")
        party_col = _col(db, table, "payee", "beneficiary", "vpa", "upi_id",
                        "counterparty", "merchant")
        dir_col = _col(db, table, "type", "txn_type", "direction")
        status_col = _col(db, table, "status", "txn_status")
        ref_col = _col(db, table, "txn_id", "reference", "utr", "order_id")
        note_col = _col(db, table, "remarks", "note", "description")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            amount = as_float(row.get(amount_col)) if amount_col else None
            party = as_text(row.get(party_col)) if party_col else ""
            if amount is None and not party:
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            raw_dir = (as_text(row.get(dir_col)) if dir_col else "").lower()
            outgoing = any(k in raw_dir for k in
                           ("debit", "sent", "pay", "out", "dr"))
            note = as_text(row.get(note_col)) if note_col else ""
            art = Artifact(
                category=Category.ACCOUNT,
                subtype=f"{app} transaction",
                timestamp=ts,
                direction=Direction.OUTGOING if outgoing else Direction.INCOMING,
                body=(f"{'Paid' if outgoing else 'Received'} "
                      f"{amount if amount is not None else '?'} "
                      f"{'to' if outgoing else 'from'} {party or 'unknown'}"
                      + (f" — {note}" if note else "")),
                app=app, source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={
                    "amount": amount, "counterparty": party,
                    "transaction_type": raw_dir,
                    "status": as_text(row.get(status_col)) if status_col else "",
                    "reference": as_text(row.get(ref_col)) if ref_col else "",
                    "remarks": note, "schema_variant": table,
                },
            )
            art.add_participant("", ctx.owner_name, role="owner", is_owner=True)
            if party:
                art.add_participant(party, "",
                                    role="to" if outgoing else "from")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _app_from_path(path: Path) -> str:
    text = path.as_posix().lower()
    for marker, name in (("paytm", "Paytm"), ("phonepe", "PhonePe"),
                         ("paisa", "Google Pay"), ("gpay", "Google Pay"),
                         ("bhim", "BHIM"), ("amazonpay", "Amazon Pay")):
        if marker in text:
            return name
    return "Payment app"


# ═══════════════════════════════════════════════════════════ Google Maps
@register(
    name="android.maps",
    patterns=["gmm_storage.db", "gmm_myplaces.db", "search_history.db",
              "da_destination_history"],
    platform="android", priority=76,
    probe=any_table_probe(("gmm_storage_table",), ("destinations",),
                          ("suggestions",), ("search_history",)),
    description="Google Maps search and navigation history",
)
def parse_maps(path: Path, ctx: ParseContext) -> ParseResult:
    """Google Maps history."""
    res = ParseResult(parser="android.maps", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        for table in ("destinations", "search_history", "suggestions",
                      "gmm_storage_table"):
            if not db.has_table(table):
                continue
            query_col = _col(db, table, "query", "text", "destination",
                            "_key", "title")
            ts_col = _col(db, table, "time", "timestamp", "date", "_timestamp")
            lat_col = _col(db, table, "latitude", "lat")
            lon_col = _col(db, table, "longitude", "lng", "lon")
            blob_col = _col(db, table, "_data", "value", "data")

            for row, recovery, conf in rows_with_deleted(db, table, ctx):
                label = as_text(row.get(query_col)) if query_col else ""
                if not label and blob_col:
                    from .social import _strings_from_blob
                    found = _strings_from_blob(row.get(blob_col), limit=3)
                    label = found[0] if found else ""
                if not label or len(label) < 3:
                    continue
                ts = guess(row.get(ts_col), ts_col) if ts_col else None
                if not ctx.in_span(ts):
                    continue
                lat, lon = valid_coord(row.get(lat_col) if lat_col else None,
                                       row.get(lon_col) if lon_col else None)
                art = Artifact(
                    category=Category.PLACE if lat is not None else Category.WEB,
                    subtype="Maps search / destination",
                    timestamp=ts, body=label, app="Google Maps",
                    latitude=lat, longitude=lon,
                    source_path=ctx.rel(path), source_table=table,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf,
                    attributes={
                        "query": label, "schema_variant": table,
                        "map_url": (f"https://www.openstreetmap.org/?mlat={lat}"
                                    f"&mlon={lon}#map=16/{lat}/{lon}")
                                   if lat is not None else "",
                        "note": ("A searched destination shows intent to travel "
                                 "there, which is distinct from a recorded "
                                 "position showing presence."),
                    },
                )
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res
