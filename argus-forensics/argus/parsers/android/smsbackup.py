"""SMS Backup+ / Titanium Backup XML dumps.

These XML files sit on shared storage (often ``sms-YYYYMMDD.xml`` and
``calls-YYYYMMDD.xml``) and are the only message/call records available when
the handset is extracted over MTP without USB debugging.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import clean_number
from ..registry import ParseContext, ParseResult, register
from ..timestamps import from_epoch, guess


def _probe_smsbackup(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return False
    low = head.lower()
    return (b"<smses" in low or b"<calls" in low or b"<sms " in low
            or b"<vivobackup" in low or b"bbkbackup" in low)


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
    "6": (Direction.INCOMING, "Refused list"),
}


@register(
    name="android.smsbackup",
    patterns=["sms-*.xml", "calls-*.xml", "sms.xml", "calls.xml",
              "*smsbackup*.xml", "*call-log*.xml",
              "**/.vivobackup/**/*.xml", "**/VivoBackup/**/*.xml",
              "**/EasyShare/**/*.xml", "**/vivo/**/*.xml"],
    platform="android", priority=78,
    probe=_probe_smsbackup,
    description="SMS Backup+ / XML dumps of SMS and call logs from shared storage",
)
def parse_smsbackup(path: Path, ctx: ParseContext) -> ParseResult:
    res = ParseResult(parser="android.smsbackup", source=ctx.rel(path))
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as exc:
        res.warnings.append(f"{path.name}: XML parse failed ({exc})")
        return res
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    tag = (root.tag or "").lower()
    if tag.endswith("calls") or path.name.lower().startswith("calls"):
        _parse_calls(root, path, ctx, res)
    else:
        _parse_sms(root, path, ctx, res)
        _parse_calls(root, path, ctx, res)
    return res


def _parse_sms(root: ET.Element, path: Path, ctx: ParseContext,
               res: ParseResult) -> None:
    for el in root.iter():
        name = (el.tag or "").lower()
        if name not in ("sms", "mms"):
            continue
        body = el.get("body") or el.get("text") or ""
        address = el.get("address") or el.get("from") or ""
        date = from_epoch(el.get("date"), "unix_ms") or guess(el.get("date"), "date")
        if not ctx.in_span(date):
            continue
        box, subtype = SMS_TYPE.get(el.get("type") or "1",
                                    (Direction.UNKNOWN, name.upper()))
        if name == "mms":
            subtype = "MMS"
            if not body:
                body = el.get("sub") or el.get("subject") or "(MMS, no text)"
        if not body and not address:
            continue
        art = Artifact(
            category=Category.MESSAGE, subtype=subtype, timestamp=date,
            body=body, app="SMS Backup+", direction=box,
            source_path=ctx.rel(path), source_table=name,
            recovery=Recovery.ALLOCATED, confidence=0.95,
            attributes={
                "address": address,
                "contact_name": el.get("contact_name") or "",
                "read": el.get("read"),
                "protocol": name,
            },
        )
        if address:
            ident = clean_number(address) or address
            art.add_participant(
                ident, el.get("contact_name") or address,
                role="correspondent",
                is_owner=ctx.is_owner(ident))
        res.artifacts.append(art)


def _parse_calls(root: ET.Element, path: Path, ctx: ParseContext,
                 res: ParseResult) -> None:
    for el in root.iter():
        if (el.tag or "").lower() != "call":
            continue
        number = el.get("number") or el.get("address") or ""
        date = from_epoch(el.get("date"), "unix_ms") or guess(el.get("date"), "date")
        if not ctx.in_span(date):
            continue
        direction, subtype = CALL_TYPE.get(el.get("type") or "1",
                                           (Direction.UNKNOWN, "Call"))
        duration = el.get("duration") or "0"
        name = el.get("name") or el.get("contact_name") or number
        body = f"{subtype} · {name} · {duration}s"
        art = Artifact(
            category=Category.CALL, subtype=subtype, timestamp=date,
            body=body, app="SMS Backup+", direction=direction,
            source_path=ctx.rel(path), source_table="call",
            recovery=Recovery.ALLOCATED, confidence=0.95,
            attributes={
                "number": number,
                "duration_s": duration,
                "contact_name": name,
            },
        )
        if number:
            ident = clean_number(number) or number
            art.add_participant(ident, name, role="correspondent",
                                is_owner=ctx.is_owner(ident))
        res.artifacts.append(art)
