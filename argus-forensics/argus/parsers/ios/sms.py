"""iOS Messages (``sms.db``) — SMS, MMS and iMessage.

Three subtleties that catch out naive parsers, all handled here:

1. **Two epochs in one column.** ``message.date`` is Apple absolute time in
   *seconds* on iOS ≤ 10 and *nanoseconds* from iOS 11 onward. The magnitude
   test in :mod:`argus.parsers.timestamps` resolves it per row.

2. **Body may be empty.** From iOS 16 the visible text often lives only in
   ``attributedBody``, an NSKeyedArchiver blob. If ``text`` is empty this
   parser extracts the string from that blob rather than reporting a blank
   message.

3. **Group chats need the join tables.** Participants come from
   ``chat_handle_join`` → ``handle``; reading only ``message.handle_id`` loses
   every other member of a group thread.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Dict, List

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_int, as_text, clean_number, pick,
                      rows_with_deleted)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

SERVICE_LABEL = {"iMessage": "iMessage", "SMS": "SMS", "RCS": "RCS"}


@register(
    name="ios.sms",
    patterns=["sms.db", "3d0d7e5fb2ce288813306e4d4636395e047a3d28"],
    platform="ios", priority=85,
    probe=any_table_probe(("message", "handle")),
    description="iOS Messages database (SMS / MMS / iMessage)",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS Messages."""
    res = ParseResult(parser="ios.sms", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        handles = _handles(db)
        chat_members = _chat_members(db)
        msg_chat = _message_to_chat(db)
        attachments = _attachments(db)

        for row, recovery, conf in rows_with_deleted(db, "message", ctx):
            ts = guess(pick(row, "date"), "ZDATE")
            if not ctx.in_span(ts):
                continue
            mid = as_int(row.get("_rowid") or row.get("ROWID"))
            from_me = bool(as_int(pick(row, "is_from_me")))
            service = as_text(pick(row, "service", default="SMS"))
            text = as_text(pick(row, "text", default="")).replace("￼", "").strip()
            if not text:
                text = _from_attributed_body(row.get("attributedBody"))

            handle_id = as_int(pick(row, "handle_id"))
            counterparty = handles.get(handle_id or 0, "")
            chat_id = msg_chat.get(mid)
            members = chat_members.get(chat_id, []) if chat_id else []
            is_group = len(members) > 1
            atts = attachments.get(mid, [])

            art = Artifact(
                category=Category.MESSAGE,
                subtype=f"{SERVICE_LABEL.get(service, service)}"
                        + (" (group)" if is_group else ""),
                timestamp=ts,
                direction=Direction.OUTGOING if from_me else Direction.INCOMING,
                body=text or (f"[{len(atts)} attachment(s)]" if atts else ""),
                app="Apple Messages", source_path=ctx.rel(path),
                source_table="message", source_row=mid,
                recovery=recovery, confidence=conf,
                attributes={
                    "service": service,
                    "chat_id": chat_id,
                    "is_group": is_group,
                    "group_members": members,
                    "is_read": as_int(pick(row, "is_read")),
                    "is_delivered": as_int(pick(row, "is_delivered")),
                    "is_sent": as_int(pick(row, "is_sent")),
                    "date_read": guess(pick(row, "date_read"), "date_read"),
                    "date_delivered": guess(pick(row, "date_delivered"),
                                            "date_delivered"),
                    "associated_message_type": as_int(
                        pick(row, "associated_message_type")),
                    "expressive_send_style": as_text(
                        pick(row, "expressive_send_style_id", default="")),
                    "attachments": atts,
                    "attachment_count": len(atts),
                    "guid": as_text(pick(row, "guid", default="")),
                    "country": as_text(pick(row, "country", default="")),
                },
            )
            if from_me:
                art.add_participant("", ctx.owner_name, role="from", is_owner=True)
                for m in (members or [counterparty]):
                    if m:
                        art.add_participant(m, "", role="to")
            else:
                art.add_participant(counterparty, "", role="from")
                art.add_participant("", ctx.owner_name, role="to", is_owner=True)
                for m in members:
                    if m and m != counterparty:
                        art.add_participant(m, "", role="to")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        if db.has_table("attachment"):
            res.notes.append(
                f"{path.name}: {len(attachments)} messages carry attachments; "
                f"their payloads live under Library/SMS/Attachments/")
        res.warnings.extend(db.warnings)
    return res


def _handles(db: ForensicSQLite) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if db.has_table("handle"):
        for r in db.rows("handle"):
            rid = as_int(r.get("_rowid") or r.get("ROWID"))
            if rid is not None:
                out[rid] = clean_number(r.get("id", ""))
    return out


def _chat_members(db: ForensicSQLite) -> Dict[int, List[str]]:
    out: Dict[int, List[str]] = {}
    if db.has_table("chat_handle_join") and db.has_table("handle"):
        handles = _handles(db)
        for r in db.rows("chat_handle_join"):
            cid = as_int(r.get("chat_id"))
            hid = as_int(r.get("handle_id"))
            if cid is None:
                continue
            ident = handles.get(hid or 0, "")
            if ident:
                out.setdefault(cid, []).append(ident)
    return out


def _message_to_chat(db: ForensicSQLite) -> Dict[int, int]:
    out: Dict[int, int] = {}
    if db.has_table("chat_message_join"):
        for r in db.rows("chat_message_join"):
            mid, cid = as_int(r.get("message_id")), as_int(r.get("chat_id"))
            if mid is not None and cid is not None:
                out[mid] = cid
    return out


def _attachments(db: ForensicSQLite) -> Dict[int, List[dict]]:
    out: Dict[int, List[dict]] = {}
    if not (db.has_table("attachment") and db.has_table("message_attachment_join")):
        return out
    meta: Dict[int, dict] = {}
    for r in db.rows("attachment"):
        rid = as_int(r.get("_rowid") or r.get("ROWID"))
        if rid is not None:
            meta[rid] = {
                "filename": as_text(r.get("filename", "")),
                "mime_type": as_text(r.get("mime_type", "")),
                "total_bytes": as_int(r.get("total_bytes")),
                "transfer_name": as_text(r.get("transfer_name", "")),
            }
    for r in db.rows("message_attachment_join"):
        mid = as_int(r.get("message_id"))
        aid = as_int(r.get("attachment_id"))
        if mid is not None and aid in meta:
            out.setdefault(mid, []).append(meta[aid])
    return out


_STR_RE = re.compile(rb"[\x20-\x7e\xc2-\xf4][\x20-\x7e\x80-\xbf]{3,}")


def _from_attributed_body(blob) -> str:
    """Extract the visible message text from an ``attributedBody`` blob.

    iOS 16+ frequently leaves ``message.text`` NULL and stores the string only
    inside this NSKeyedArchiver payload. Falling back to a strings sweep is
    ugly but it is what recovers the message content, and returning an empty
    body instead would misrepresent the evidence as an empty message.
    """
    if not blob:
        return ""
    if isinstance(blob, str):
        blob = blob.encode("utf-8", errors="ignore")
    if not isinstance(blob, (bytes, bytearray)):
        return ""
    data = bytes(blob)
    try:
        plist = plistlib.loads(data)
        objs = plist.get("$objects") if isinstance(plist, dict) else None
        if objs:
            candidates = [o for o in objs if isinstance(o, str)
                          and len(o) > 1 and not o.startswith("NS")
                          and o not in ("$null",)]
            if candidates:
                return max(candidates, key=len)
    except Exception:
        pass
    marker = data.find(b"NSString")
    region = data[marker:] if marker >= 0 else data
    cleaned: list[str] = []
    for match in _STR_RE.finditer(region):
        # Decode leniently: these runs are delimited by typed-stream control
        # bytes that are not valid UTF-8, so a strict decode throws away the
        # very string being recovered.
        s = match.group(0).decode("utf-8", errors="replace")
        s = "".join(ch for ch in s if ch.isprintable() or ch in "\n\t")
        s = s.strip("+*� \x01\x02\x84\x86")
        if len(s) < 3:
            continue
        if s.startswith(("NS", "__k", "streamtyped", "iI", "NSDictionary")):
            continue
        if s.replace(" ", "").isalnum() and len(s) < 6:
            continue
        cleaned.append(s)
    return max(cleaned, key=len) if cleaned else ""
