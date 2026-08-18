"""ADB ``content query`` dumps saved during opportunistic logical acquisition.

When USB debugging is available alongside MTP, ARGUS can pull live calls,
contacts, and SMS via content providers. This parser turns those row dumps
into artifacts.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ...core.models import Artifact, Category, Direction
from ..common import clean_number
from ..registry import ParseContext, ParseResult, register
from ..timestamps import guess

_ROW = re.compile(r"^Row:\s*\d+\s+(.*)$", re.MULTILINE)
_FIELD_LEGACY = re.compile(r"(\w+)=([^,]+?)(?:,\s*|$)")

SMS_TYPE = {
    "1": (Direction.INCOMING, "SMS (inbox)"),
    "2": (Direction.OUTGOING, "SMS (sent)"),
    "3": (Direction.DRAFT, "SMS (draft)"),
    "4": (Direction.OUTGOING, "SMS (outbox)"),
    "5": (Direction.OUTGOING, "SMS (failed)"),
}
CALL_TYPE = {
    "1": (Direction.INCOMING, "Incoming call"),
    "2": (Direction.OUTGOING, "Outgoing call"),
    "3": (Direction.MISSED, "Missed call"),
    "4": (Direction.UNKNOWN, "Voicemail"),
    "5": (Direction.REJECTED, "Rejected call"),
}
MMS_BOX = {
    "1": (Direction.INCOMING, "MMS (inbox)"),
    "2": (Direction.OUTGOING, "MMS (sent)"),
}


def _probe_content_dump(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:800]
    except OSError:
        return False
    return "Row:" in head and "=" in head


def _parse_row_fields(blob: str) -> Dict[str, str]:
    """Parse ``key=value`` pairs — handles commas inside message bodies."""
    fields: Dict[str, str] = {}
    markers = list(re.finditer(r"(\w+)=", blob))
    if not markers:
        return fields
    for index, match in enumerate(markers):
        key = match.group(1).lower()
        start = match.end()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(blob)
        value = blob[start:end].rstrip(", ").strip()
        fields[key] = value
    return fields


def _parse_rows(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for match in _ROW.finditer(text):
        blob = match.group(1)
        fields = _parse_row_fields(blob)
        if not fields:
            for key, val in _FIELD_LEGACY.findall(blob):
                fields[key.lower()] = val.strip()
        if fields:
            rows.append(fields)
    return rows


@register(
    name="android.adb_content",
    patterns=["content/sms.txt", "content/sms_inbox.txt", "content/sms_sent.txt",
              "content/sms_draft.txt", "content/sms_outbox.txt",
              "content/sms_failed.txt", "content/mms.txt",
              "content/mms_part.txt", "content/mms_addr.txt",
              "content/calls.txt", "content/threads.txt",
              "content/contacts.txt", "content/contacts_all.txt",
              "content/contacts_data.txt", "content/contacts_email.txt",
              "content/contacts_lookup.txt", "content/contacts_structured.txt",
              "content/icc_adn.txt", "content/icc_sms.txt",
              "content/vivo_sms.txt", "content/bbk_sms.txt",
              "content/sec_calls.txt",
              "contacts_export/phones.txt", "contacts_export/phone_data.txt",
              "contacts_export/emails.txt", "contacts_export/vivo_contacts.txt",
              "contacts_export/bbk_contacts.txt"],
    platform="android",
    priority=90,
    probe=_probe_content_dump,
    description="ADB content-provider dumps (SMS, MMS, calls, contacts)",
)
def parse_adb_content(path: Path, ctx: ParseContext) -> ParseResult:
    """ADB logical content dumps."""
    res = ParseResult(parser="android.adb_content", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(str(exc))
        return res

    name = path.stem.lower()
    parent = path.parent.name.lower()
    if parent == "contacts_export":
        name = path.stem.lower()
    rows = _parse_rows(text)
    if not rows:
        res.notes.append(f"{path.name}: no content-provider rows")
        return res

    if name in ("sms", "mms", "threads", "sms_inbox", "sms_sent", "sms_draft",
                "sms_outbox", "sms_failed", "icc_sms", "vivo_sms", "bbk_sms"):
        _parse_sms_rows(rows, path, ctx, res, mms=name in ("mms", "threads"))
    elif name == "mms_part":
        _parse_mms_part_rows(rows, path, ctx, res)
    elif name == "mms_addr":
        _parse_mms_addr_rows(rows, path, ctx, res)
    elif name in ("calls", "sec_calls"):
        _parse_call_rows(rows, path, ctx, res)
    elif name in ("contacts", "contacts_all", "contacts_data", "contacts_email",
                  "contacts_lookup", "contacts_structured", "icc_adn",
                  "phones", "phone_data", "emails", "vivo_contacts",
                  "bbk_contacts"):
        _parse_contact_rows(rows, path, ctx, res)
    else:
        res.notes.append(f"{path.name}: unhandled content dump type")
    return res


def _parse_sms_rows(rows: List[Dict[str, str]], path: Path,
                    ctx: ParseContext, res: ParseResult,
                    *, mms: bool = False) -> None:
    for row in rows:
        ts = guess(row.get("date") or row.get("date_sent"), "date")
        if not ctx.in_span(ts):
            continue
        if mms or row.get("msg_box") or row.get("m_type"):
            box, subtype = MMS_BOX.get(
                row.get("msg_box") or row.get("m_type") or "1",
                (Direction.UNKNOWN, "MMS"))
            body = row.get("sub") or row.get("subject") or row.get("text") or ""
            subtype = "MMS"
        else:
            box, subtype = SMS_TYPE.get(row.get("type", "1"),
                                        (Direction.UNKNOWN, "SMS"))
            body = row.get("body") or row.get("text") or ""
        number = clean_number(
            row.get("address") or row.get("recipient") or row.get("contact_id"))
        art = Artifact(
            category=Category.MESSAGE, subtype=subtype, timestamp=ts,
            direction=box, body=body,
            app="Android Messaging (ADB logical)",
            source_path=ctx.rel(path),
            attributes=dict(row),
        )
        if number:
            art.add_participant(number, row.get("person") or "", role="party")
        res.artifacts.append(art)


def _parse_mms_part_rows(rows: List[Dict[str, str]], path: Path,
                         ctx: ParseContext, res: ParseResult) -> None:
    for row in rows:
        ct = (row.get("ct") or row.get("content_type") or "").lower()
        body = row.get("text") or row.get("name") or row.get("fn") or ""
        if not body and "text" not in ct and "plain" not in ct:
            continue
        ts = guess(row.get("date") or row.get("_id"), "date")
        art = Artifact(
            category=Category.MESSAGE, subtype="MMS part",
            timestamp=ts, direction=Direction.UNKNOWN,
            body=body[:4000],
            app="Android MMS (ADB logical)",
            source_path=ctx.rel(path),
            attributes=dict(row),
        )
        res.artifacts.append(art)


def _parse_mms_addr_rows(rows: List[Dict[str, str]], path: Path,
                         ctx: ParseContext, res: ParseResult) -> None:
    for row in rows:
        number = clean_number(row.get("address") or row.get("number"))
        if not number:
            continue
        ts = guess(row.get("date"), "date")
        art = Artifact(
            category=Category.MESSAGE, subtype="MMS address",
            timestamp=ts, direction=Direction.UNKNOWN,
            body=f"MMS participant — {number}",
            app="Android MMS (ADB logical)",
            source_path=ctx.rel(path),
            attributes=dict(row),
        )
        art.add_participant(number, row.get("name") or "", role="party")
        res.artifacts.append(art)


def _parse_call_rows(rows: List[Dict[str, str]], path: Path,
                     ctx: ParseContext, res: ParseResult) -> None:
    for row in rows:
        ts = guess(row.get("date"), "date")
        if not ctx.in_span(ts):
            continue
        direction, subtype = CALL_TYPE.get(row.get("type", "1"),
                                           (Direction.UNKNOWN, "Call"))
        number = clean_number(row.get("number") or row.get("cached_number")
                              or row.get("phone_number"))
        duration = row.get("duration") or "0"
        art = Artifact(
            category=Category.CALL, subtype=subtype, timestamp=ts,
            direction=direction,
            body=f"{subtype} — {number or 'unknown'} ({duration}s)",
            app="Android Call Log (ADB logical)",
            source_path=ctx.rel(path),
            attributes=dict(row),
        )
        if number:
            art.add_participant(number, row.get("name") or "", role="party")
        res.artifacts.append(art)


def _parse_contact_rows(rows: List[Dict[str, str]], path: Path,
                        ctx: ParseContext, res: ParseResult) -> None:
    seen: set[Tuple[str, str]] = set()
    for row in rows:
        name = (row.get("display_name") or row.get("name")
                or row.get("data1") or "")
        mimetype = (row.get("mimetype") or "").lower()
        if "email" in mimetype or path.stem.lower() in ("emails", "contacts_email"):
            number = ""
            email = row.get("data1") or row.get("email") or ""
            label = email
        else:
            number = clean_number(
                row.get("data1") or row.get("number") or row.get("address"))
            email = row.get("data2") or ""
            label = name or number
        if not (name or number or email):
            continue
        key = (name, number or email)
        if key in seen:
            continue
        seen.add(key)
        art = Artifact(
            category=Category.CONTACT, subtype="Contact",
            timestamp=guess(row.get("last_time_contacted"), "last_time_contacted"),
            body=label,
            app="Android Contacts (ADB logical)",
            source_path=ctx.rel(path),
            attributes=dict(row),
        )
        if number:
            art.add_participant(number, name, role="party")
        if email:
            art.add_participant(email, name, role="party")
        res.artifacts.append(art)
