"""WhatsApp on Android (``msgstore.db`` + ``wa.db``).

WhatsApp changed its schema substantially around 2021: the legacy ``messages``
table was replaced by ``message`` + ``chat`` + ``jid``.  Both are handled here,
because a real caseload contains both.

The ``jid`` column encodes the account type:
``<number>@s.whatsapp.net`` individual, ``<id>@g.us`` group,
``<id>@broadcast`` broadcast list, ``status@broadcast`` status posts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_int, as_text, clean_number, pick,
                      rows_with_deleted, valid_coord)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

MEDIA_TYPE = {0: "text", 1: "image", 2: "audio", 3: "video", 4: "contact",
              5: "location", 9: "document", 13: "animated GIF", 14: "deleted",
              15: "sticker", 20: "sticker"}

STATUS = {0: "pending", 4: "sent to server", 5: "delivered", 6: "read",
          13: "played"}


def _jid_label(jid: str) -> tuple[str, str]:
    """Return ``(identifier, kind)`` for a WhatsApp JID."""
    j = as_text(jid)
    if not j:
        return "", ""
    local, _, domain = j.partition("@")
    if domain == "g.us":
        return j, "group"
    if domain == "broadcast":
        return j, "broadcast"
    if domain in ("s.whatsapp.net", "c.us"):
        return f"+{local}" if local.isdigit() else local, "individual"
    return j, "unknown"


@register(
    name="android.whatsapp",
    patterns=["msgstore.db", "msgstore*.db", "wa.db"],
    platform="android", priority=85,
    probe=any_table_probe(("message", "chat"), ("messages",), ("wa_contacts",)),
    description="WhatsApp message store and contact list (Android)",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """WhatsApp (Android)."""
    res = ParseResult(parser="android.whatsapp", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        # ------------------------------------------------- wa.db contact list
        if db.has_table("wa_contacts"):
            for row, recovery, conf in rows_with_deleted(db, "wa_contacts", ctx):
                ident, kind = _jid_label(pick(row, "jid", default=""))
                name = as_text(pick(row, "display_name", "wa_name",
                                    "given_name", default=""))
                if not (ident or name):
                    continue
                art = Artifact(
                    category=Category.CONTACT, subtype="WhatsApp contact",
                    body=name or ident, app="WhatsApp",
                    source_path=ctx.rel(path), source_table="wa_contacts",
                    source_row=as_int(row.get("_rowid")),
                    recovery=recovery, confidence=conf,
                    attributes={
                        "jid": as_text(pick(row, "jid", default="")),
                        "jid_kind": kind,
                        "status": as_text(pick(row, "status", default="")),
                        "is_whatsapp_user": as_int(pick(row, "is_whatsapp_user")),
                        "phone_number": clean_number(pick(row, "number",
                                                          default=ident)),
                    },
                )
                art.add_participant(ident, name, role="party")
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        jid_index = _jid_index(db)
        chat_index = _chat_index(db, jid_index)

        # ------------------------------------------------- modern schema
        if db.has_table("message"):
            for row, recovery, conf in rows_with_deleted(db, "message", ctx):
                art = _modern_message(row, recovery, conf, ctx, path,
                                      chat_index, jid_index)
                if art and ctx.in_span(art.timestamp):
                    res.artifacts.append(art)
                    if recovery != Recovery.ALLOCATED:
                        res.deleted_recovered += 1

        # ------------------------------------------------- legacy schema
        elif db.has_table("messages"):
            for row, recovery, conf in rows_with_deleted(db, "messages", ctx):
                art = _legacy_message(row, recovery, conf, ctx, path)
                if art and ctx.in_span(art.timestamp):
                    res.artifacts.append(art)
                    if recovery != Recovery.ALLOCATED:
                        res.deleted_recovered += 1

        # ------------------------------------------------- call log
        call_table = db.first_table("call_log", "call_logs")
        if call_table:
            for row, recovery, conf in rows_with_deleted(db, call_table, ctx):
                ts = guess(pick(row, "timestamp"), "timestamp")
                if not ctx.in_span(ts):
                    continue
                outgoing = bool(as_int(pick(row, "from_me")))
                duration = as_int(pick(row, "duration")) or 0
                jid_row = jid_index.get(as_int(pick(row, "jid_row_id")), "")
                ident, _ = _jid_label(jid_row)
                video = bool(as_int(pick(row, "video_call")))
                art = Artifact(
                    category=Category.CALL,
                    subtype=f"WhatsApp {'video' if video else 'voice'} call",
                    timestamp=ts,
                    timestamp_end=(ts + duration * 1_000_000) if ts and duration else None,
                    direction=Direction.OUTGOING if outgoing else Direction.INCOMING,
                    app="WhatsApp", source_path=ctx.rel(path),
                    source_table=call_table,
                    source_row=as_int(row.get("_rowid")),
                    recovery=recovery, confidence=conf,
                    body=f"WhatsApp {'video' if video else 'voice'} call with "
                         f"{ident or 'unknown'}" + (f" ({duration}s)" if duration else ""),
                    attributes={"duration_seconds": duration,
                                "video_call": video,
                                "call_result": as_int(pick(row, "call_result")),
                                "group_call": bool(as_int(pick(row, "is_joinable_group_call")))},
                )
                art.add_participant("", ctx.owner_name, role="owner", is_owner=True)
                if ident:
                    art.add_participant(ident, "", role="to" if outgoing else "from")
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        if not res.artifacts:
            res.notes.append(
                f"{path.name}: recognised as WhatsApp but no messages decoded. "
                f"If this is a '.crypt14' file it is encrypted and requires the "
                f"key from /data/data/com.whatsapp/files/key.")
        res.warnings.extend(db.warnings)
    return res


def _jid_index(db: ForensicSQLite) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if db.has_table("jid"):
        for r in db.rows("jid"):
            rid = as_int(r.get("_rowid") or r.get("_id"))
            user = as_text(r.get("user", ""))
            server = as_text(r.get("server", ""))
            raw = as_text(r.get("raw_string", "")) or (
                f"{user}@{server}" if user and server else "")
            if rid is not None and raw:
                out[rid] = raw
    return out


def _chat_index(db: ForensicSQLite, jid_index: Dict[int, str]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if db.has_table("chat"):
        for r in db.rows("chat"):
            rid = as_int(r.get("_rowid") or r.get("_id"))
            jrid = as_int(r.get("jid_row_id"))
            if rid is not None:
                out[rid] = jid_index.get(jrid, "")
    return out


def _modern_message(row, recovery, conf, ctx: ParseContext, path: Path,
                    chat_index: Dict[int, str],
                    jid_index: Dict[int, str]):
    ts = guess(pick(row, "timestamp"), "timestamp")
    from_me = bool(as_int(pick(row, "from_me")))
    chat_jid = chat_index.get(as_int(pick(row, "chat_row_id")), "")
    sender_jid = jid_index.get(as_int(pick(row, "sender_jid_row_id")), "")
    text = as_text(pick(row, "text_data", default=""))
    mt = as_int(pick(row, "message_type")) or 0
    kind = MEDIA_TYPE.get(mt, f"type {mt}")
    status = as_int(pick(row, "status"))

    chat_ident, chat_kind = _jid_label(chat_jid)
    sender_ident, _ = _jid_label(sender_jid)
    lat, lon = valid_coord(pick(row, "latitude"), pick(row, "longitude"))

    art = Artifact(
        category=Category.MESSAGE,
        subtype=f"WhatsApp {kind}" if kind != "text" else "WhatsApp message",
        timestamp=ts,
        direction=Direction.OUTGOING if from_me else Direction.INCOMING,
        body=text or (f"[{kind}]" if kind != "text" else ""),
        app="WhatsApp", source_path=ctx.rel(path), source_table="message",
        source_row=as_int(row.get("_rowid")), recovery=recovery,
        confidence=conf, latitude=lat, longitude=lon,
        attributes={
            "chat_jid": chat_jid, "chat_kind": chat_kind,
            "message_type": mt, "media_kind": kind,
            "delivery_status": STATUS.get(status or 0, str(status or "")),
            "starred": as_int(pick(row, "starred")),
            "key_id": as_text(pick(row, "key_id", default="")),
            "recipient_count": as_int(pick(row, "recipient_count")),
            "is_group": chat_kind == "group",
            "revoked": mt == 14,
        },
    )
    if from_me:
        art.add_participant("", ctx.owner_name, role="from", is_owner=True)
        art.add_participant(chat_ident, "", role="to")
    else:
        art.add_participant(sender_ident or chat_ident, "", role="from")
        art.add_participant("", ctx.owner_name, role="to", is_owner=True)
        if chat_kind == "group" and sender_ident:
            art.attributes["group_jid"] = chat_jid
    return art


def _legacy_message(row, recovery, conf, ctx: ParseContext, path: Path):
    ts = guess(pick(row, "timestamp"), "timestamp")
    from_me = bool(as_int(pick(row, "key_from_me")))
    remote = as_text(pick(row, "key_remote_jid", default=""))
    ident, kind = _jid_label(remote)
    text = as_text(pick(row, "data", default=""))
    mt = as_int(pick(row, "media_wa_type")) or 0
    media = MEDIA_TYPE.get(mt, f"type {mt}")
    lat, lon = valid_coord(pick(row, "latitude"), pick(row, "longitude"))

    art = Artifact(
        category=Category.MESSAGE,
        subtype=f"WhatsApp {media}" if media != "text" else "WhatsApp message",
        timestamp=ts,
        direction=Direction.OUTGOING if from_me else Direction.INCOMING,
        body=text or (f"[{media}]" if media != "text" else ""),
        app="WhatsApp", source_path=ctx.rel(path), source_table="messages",
        source_row=as_int(row.get("_rowid")), recovery=recovery,
        confidence=conf, latitude=lat, longitude=lon,
        attributes={
            "chat_jid": remote, "chat_kind": kind, "media_kind": media,
            "media_name": as_text(pick(row, "media_name", default="")),
            "media_caption": as_text(pick(row, "media_caption", default="")),
            "media_size": as_int(pick(row, "media_size")),
            "media_mime_type": as_text(pick(row, "media_mime_type", default="")),
            "remote_resource": as_text(pick(row, "remote_resource", default="")),
            "is_group": kind == "group",
        },
    )
    if from_me:
        art.add_participant("", ctx.owner_name, role="from", is_owner=True)
        art.add_participant(ident, "", role="to")
    else:
        sender = as_text(pick(row, "remote_resource", default="")) or remote
        sident, _ = _jid_label(sender)
        art.add_participant(sident, "", role="from")
        art.add_participant("", ctx.owner_name, role="to", is_owner=True)
    return art
