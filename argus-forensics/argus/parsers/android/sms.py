"""Android SMS/MMS (``mmssms.db``, ``bugle_db`` for Google Messages).

Covers lab manual Step 19 / §6.6 — message artifacts and the participants
needed to build the message connection graph.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_int, as_text, clean_number, pick,
                      rows_with_deleted)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

# Telephony.TextBasedSmsColumns message box constants
SMS_BOX = {
    1: (Direction.INCOMING, "SMS (inbox)"),
    2: (Direction.OUTGOING, "SMS (sent)"),
    3: (Direction.DRAFT, "SMS (draft)"),
    4: (Direction.OUTGOING, "SMS (outbox)"),
    5: (Direction.OUTGOING, "SMS (failed)"),
    6: (Direction.OUTGOING, "SMS (queued)"),
}
MMS_BOX = {
    1: (Direction.INCOMING, "MMS (inbox)"),
    2: (Direction.OUTGOING, "MMS (sent)"),
    3: (Direction.DRAFT, "MMS (draft)"),
    4: (Direction.OUTGOING, "MMS (outbox)"),
}


@register(
    name="android.sms",
    patterns=["mmssms.db", "messages.db", "telephony.db", "bugle_db"],
    platform="android", priority=80,
    probe=any_table_probe(("sms",), ("pdu",), ("messages", "parts"), ("messages",), ("message",)),
    description="Android SMS and MMS store",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """Android SMS/MMS."""
    res = ParseResult(parser="android.sms", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        addr_book = _address_index(db)

        # ------------------------------------------------------------- SMS
        sms_table = db.first_table("sms")
        if sms_table:
            for row, recovery, conf in rows_with_deleted(db, sms_table, ctx):
                ts = guess(pick(row, "date", "date_sent"), "date")
                if not ctx.in_span(ts):
                    continue
                box = as_int(pick(row, "type")) or 0
                direction, subtype = SMS_BOX.get(box, (Direction.UNKNOWN, "SMS"))
                number = clean_number(pick(row, "address"))
                body = as_text(pick(row, "body", default=""))
                art = Artifact(
                    category=Category.MESSAGE, subtype=subtype, timestamp=ts,
                    direction=direction, body=body, app="Android Messaging",
                    source_path=ctx.rel(path), source_table=sms_table,
                    source_row=as_int(row.get("_rowid") or row.get("_id")),
                    recovery=recovery, confidence=conf,
                    attributes={
                        "thread_id": as_int(pick(row, "thread_id")),
                        "read": as_int(pick(row, "read")),
                        "seen": as_int(pick(row, "seen")),
                        "status": as_int(pick(row, "status")),
                        "service_center": as_text(pick(row, "service_center",
                                                       default="")),
                        "protocol": as_int(pick(row, "protocol")),
                        "subject": as_text(pick(row, "subject", default="")),
                        "date_sent": guess(pick(row, "date_sent"), "date_sent"),
                        "sim_slot": as_int(pick(row, "sub_id")),
                    },
                )
                _attach_parties(art, ctx, number,
                                as_text(pick(row, "creator", default="")),
                                direction)
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        # Samsung Messages / OEM stores a `messages` table without bugle `parts`.
        if not sms_table:
            oem_table = db.first_table("messages", "message")
            if oem_table and not db.has_table("parts"):
                app_name = ("Samsung Messages"
                            if "samsung" in path.as_posix().lower()
                            else "Android Messaging")
                for row, recovery, conf in rows_with_deleted(db, oem_table, ctx):
                    ts = guess(pick(row, "date", "date_sent", "created_at"),
                               "date")
                    if not ctx.in_span(ts):
                        continue
                    box = as_int(pick(row, "type", "msg_type", "message_type")) or 0
                    direction, subtype = SMS_BOX.get(
                        box, (Direction.UNKNOWN, "SMS"))
                    number = clean_number(pick(row, "address", "recipient",
                                               "sender"))
                    body = as_text(pick(row, "body", "text", "content",
                                        default=""))
                    art = Artifact(
                        category=Category.MESSAGE, subtype=subtype,
                        timestamp=ts, direction=direction, body=body,
                        app=app_name, source_path=ctx.rel(path),
                        source_table=oem_table,
                        source_row=as_int(row.get("_rowid") or row.get("_id")),
                        recovery=recovery, confidence=conf,
                        attributes={
                            "thread_id": as_int(pick(row, "thread_id")),
                            "read": as_int(pick(row, "read")),
                        },
                    )
                    _attach_parties(art, ctx, number,
                                    as_text(pick(row, "creator", default="")),
                                    direction)
                    res.artifacts.append(art)
                    if recovery != Recovery.ALLOCATED:
                        res.deleted_recovered += 1

        # ------------------------------------------------------------- MMS
        pdu_table = db.first_table("pdu")
        if pdu_table:
            parts = _mms_parts(db)
            recipients = _mms_addresses(db)
            for row, recovery, conf in rows_with_deleted(db, pdu_table, ctx):
                ts = guess(pick(row, "date"), "date")
                if not ctx.in_span(ts):
                    continue
                box = as_int(pick(row, "msg_box")) or 0
                direction, subtype = MMS_BOX.get(box, (Direction.UNKNOWN, "MMS"))
                mid = as_int(row.get("_rowid") or row.get("_id"))
                text = " ".join(parts.get(mid, {}).get("text", []))
                attachments = parts.get(mid, {}).get("files", [])
                art = Artifact(
                    category=Category.MESSAGE, subtype=subtype, timestamp=ts,
                    direction=direction,
                    body=text or as_text(pick(row, "sub", default="")),
                    app="Android Messaging",
                    source_path=ctx.rel(path), source_table=pdu_table,
                    source_row=mid, recovery=recovery, confidence=conf,
                    attributes={
                        "thread_id": as_int(pick(row, "thread_id")),
                        "message_size": as_int(pick(row, "m_size")),
                        "attachments": attachments,
                        "attachment_count": len(attachments),
                        "subject": as_text(pick(row, "sub", default="")),
                    },
                )
                for role, number in recipients.get(mid, []):
                    _attach_parties(art, ctx, number, "", direction, role=role)
                if not art.participants:
                    art.add_participant("", ctx.owner_name, role="owner",
                                        is_owner=True)
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        # ------------------------------- Google Messages (bugle_db) schema
        bugle = db.first_table("messages")
        if bugle and db.has_table("parts") and not sms_table:
            # In bugle the message row carries only metadata. The text lives in
            # `parts`, one row per part, and the correspondent lives in
            # `participants` two joins away. Reading `messages.text` — a column
            # that does not exist — yields an empty body for every message,
            # which in a report reads as "the messages were blank" rather than
            # "this parser does not understand this schema". Google Messages is
            # the default SMS app on modern Android, so that silence covers the
            # majority of current handsets.
            parts_text, parts_deleted = _bugle_parts(db, ctx)
            senders = _bugle_participants(db)

            for row, recovery, conf in rows_with_deleted(db, bugle, ctx):
                ts = guess(pick(row, "received_timestamp", "sent_timestamp"),
                           "received_timestamp")
                if not ctx.in_span(ts):
                    continue
                status = as_int(pick(row, "message_status")) or 0
                direction = (Direction.INCOMING if status in (100, 101, 102)
                             else Direction.OUTGOING)
                row_id = as_int(row.get("_id") or row.get("_rowid"))
                body = as_text(pick(row, "text", "message_text", default=""))
                recovered_body = False
                if not body and row_id is not None:
                    body = parts_text.get(row_id, "")
                    recovered_body = bool(body) and row_id in parts_deleted

                number = senders.get(as_int(pick(row, "sender_id")), "")
                attributes = {
                    "conversation_id": as_text(pick(row, "conversation_id",
                                                    default="")),
                    "message_status": status,
                }
                if row_id is not None and row_id not in parts_text:
                    # The row survived but its text did not. Say so, rather than
                    # presenting an empty body as though the message was empty.
                    attributes["body_unrecoverable"] = True
                    attributes["note"] = (
                        "The message row is intact but its text part was not "
                        "recoverable. An empty body here means the content is "
                        "gone, not that the message was blank.")
                if recovered_body:
                    attributes["content_recovered"] = True
                    attributes["note"] = (
                        "Body recovered by carving the deleted `parts` row; "
                        "the message row itself was still allocated.")

                art = Artifact(
                    category=Category.MESSAGE,
                    subtype="RCS / SMS (Google Messages)",
                    timestamp=ts, direction=direction, body=body,
                    app="Google Messages", source_path=ctx.rel(path),
                    source_table=bugle, source_row=row_id,
                    recovery=(Recovery.CARVED if recovered_body else recovery),
                    confidence=round(conf * 0.9, 3) if recovered_body else conf,
                    attributes=attributes,
                )
                _attach_parties(art, ctx, number, "", direction)
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED or recovered_body:
                    res.deleted_recovered += 1

        if not res.artifacts:
            res.notes.append(
                f"{path.name}: no message tables recognised "
                f"(found: {', '.join(sorted(db.schemas()))[:200]})")
        res.warnings.extend(db.warnings)
    return res


def _bugle_parts(db: ForensicSQLite, ctx: ParseContext):
    """Message text from the `parts` table, including deleted parts.

    Returns ``(text_by_message_id, ids_whose_text_was_carved)``. Deleting a
    conversation in Google Messages frequently removes the part rows while the
    message rows survive, so carving `parts` is what recovers the content of an
    apparently-empty deleted thread.
    """
    text_by_message: Dict[int, str] = {}
    carved: set = set()
    if not db.has_table("parts"):
        return text_by_message, carved

    for row, recovery, _conf in rows_with_deleted(db, "parts", ctx):
        message_id = as_int(pick(row, "message_id"))
        if message_id is None:
            continue
        text = as_text(pick(row, "text", default="")).strip()
        if not text:
            continue
        existing = text_by_message.get(message_id, "")
        # A message may have several parts; keep them in the order found.
        text_by_message[message_id] = (existing + "\n" + text).strip() \
            if existing else text
        if recovery != Recovery.ALLOCATED:
            carved.add(message_id)
    return text_by_message, carved


def _bugle_participants(db: ForensicSQLite) -> Dict[int, str]:
    """`participants._id` to a dialable number."""
    out: Dict[int, str] = {}
    if not db.has_table("participants"):
        return out
    for row in db.rows("participants"):
        row_id = as_int(row.get("_id") or row.get("_rowid"))
        if row_id is None:
            continue
        number = clean_number(pick(row, "normalized_destination",
                                   "display_destination", "send_destination",
                                   default=""))
        if number:
            out[row_id] = number
    return out


def _attach_parties(art: Artifact, ctx: ParseContext, number: str,
                    name: str, direction: Direction, role: str = "") -> None:
    art.add_participant("", ctx.owner_name, role="owner", is_owner=True)
    if number:
        art.add_participant(
            number, name,
            role=role or ("to" if direction == Direction.OUTGOING else "from"))


def _address_index(db: ForensicSQLite) -> Dict[int, str]:
    """canonical_addresses lookup used by thread tables."""
    out: Dict[int, str] = {}
    if db.has_table("canonical_addresses"):
        for r in db.rows("canonical_addresses"):
            rid = as_int(r.get("_id") or r.get("_rowid"))
            if rid is not None:
                out[rid] = as_text(r.get("address", ""))
    return out


def _mms_parts(db: ForensicSQLite) -> Dict[int, Dict[str, list]]:
    """Collect MMS text parts and attachment references keyed by message id."""
    out: Dict[int, Dict[str, list]] = {}
    if not db.has_table("part"):
        return out
    for r in db.rows("part"):
        mid = as_int(r.get("mid"))
        if mid is None:
            continue
        entry = out.setdefault(mid, {"text": [], "files": []})
        ct = as_text(r.get("ct", "")).lower()
        if ct.startswith("text/"):
            txt = as_text(r.get("text", ""))
            if txt:
                entry["text"].append(txt)
        else:
            data = as_text(r.get("_data", "")) or as_text(r.get("cl", ""))
            if data:
                entry["files"].append({"path": data, "content_type": ct,
                                       "name": as_text(r.get("name", ""))})
    return out


def _mms_addresses(db: ForensicSQLite) -> Dict[int, list]:
    """MMS ``addr`` table: type 137=from, 151=to, 130=cc, 129=bcc."""
    role_map = {137: "from", 151: "to", 130: "cc", 129: "bcc"}
    out: Dict[int, list] = {}
    if not db.has_table("addr"):
        return out
    for r in db.rows("addr"):
        mid = as_int(r.get("msg_id"))
        if mid is None:
            continue
        addr = clean_number(r.get("address"))
        if addr and addr != "insert-address-token":
            out.setdefault(mid, []).append(
                (role_map.get(as_int(r.get("type")) or 0, "party"), addr))
    return out
