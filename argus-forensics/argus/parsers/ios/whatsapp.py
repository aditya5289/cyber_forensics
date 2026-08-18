"""WhatsApp on iOS (``ChatStorage.sqlite``).

Core Data schema: ``ZWAMESSAGE`` joined to ``ZWACHATSESSION`` and
``ZWAGROUPMEMBER``. Timestamps are Apple absolute time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_int, as_text, pick, rows_with_deleted,
                      valid_coord)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch

MESSAGE_TYPE = {0: "text", 1: "image", 2: "video", 3: "audio", 4: "contact",
                5: "location", 6: "system", 8: "document", 11: "sticker",
                14: "deleted", 15: "sticker"}


def _jid(raw: str) -> str:
    raw = as_text(raw)
    local, _, domain = raw.partition("@")
    if domain == "g.us":
        return raw
    return f"+{local}" if local.isdigit() else (raw or "")


@register(
    name="ios.whatsapp",
    patterns=["ChatStorage.sqlite", "ChatSearchV*.sqlite",
              "7c7fba66680ef796b916b067077cc246adacf01d"],
    platform="ios", priority=85,
    probe=any_table_probe(("ZWAMESSAGE",)),
    description="WhatsApp message store (iOS)",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """WhatsApp (iOS)."""
    res = ParseResult(parser="ios.whatsapp", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        sessions: Dict[int, dict] = {}
        if db.has_table("ZWACHATSESSION"):
            for r in db.rows("ZWACHATSESSION"):
                pk = as_int(r.get("Z_PK"))
                if pk is not None:
                    sessions[pk] = {
                        "jid": as_text(r.get("ZCONTACTJID", "")),
                        "name": as_text(r.get("ZPARTNERNAME", "")),
                        "is_group": "@g.us" in as_text(r.get("ZCONTACTJID", "")),
                    }

        media: Dict[int, dict] = {}
        if db.has_table("ZWAMEDIAITEM"):
            for r in db.rows("ZWAMEDIAITEM"):
                mid = as_int(r.get("ZMESSAGE"))
                if mid is not None:
                    lat, lon = valid_coord(r.get("ZLATITUDE"), r.get("ZLONGITUDE"))
                    media[mid] = {
                        "local_path": as_text(r.get("ZMEDIALOCALPATH", "")),
                        "file_size": as_int(r.get("ZFILESIZE")),
                        "title": as_text(r.get("ZTITLE", "")),
                        "latitude": lat, "longitude": lon,
                    }

        if not db.has_table("ZWAMESSAGE"):
            res.notes.append(f"{path.name}: no ZWAMESSAGE table")
            return res

        for row, recovery, conf in rows_with_deleted(db, "ZWAMESSAGE", ctx):
            ts = from_epoch(pick(row, "ZMESSAGEDATE", "ZSENTDATE"), "apple")
            if not ctx.in_span(ts):
                continue
            pk = as_int(row.get("Z_PK") or row.get("_rowid"))
            from_me = bool(as_int(pick(row, "ZISFROMME")))
            session = sessions.get(as_int(pick(row, "ZCHATSESSION")), {})
            mtype = as_int(pick(row, "ZMESSAGETYPE")) or 0
            kind = MESSAGE_TYPE.get(mtype, f"type {mtype}")
            text = as_text(pick(row, "ZTEXT", default=""))
            m = media.get(pk, {})
            chat_jid = session.get("jid", "")
            from_jid = as_text(pick(row, "ZFROMJID", default=""))
            to_jid = as_text(pick(row, "ZTOJID", default=""))

            art = Artifact(
                category=Category.MESSAGE,
                subtype=f"WhatsApp {kind}" if kind != "text" else "WhatsApp message",
                timestamp=ts,
                direction=Direction.OUTGOING if from_me else Direction.INCOMING,
                body=text or (f"[{kind}]" if kind != "text" else ""),
                app="WhatsApp", source_path=ctx.rel(path),
                source_table="ZWAMESSAGE", source_row=pk,
                recovery=recovery, confidence=conf,
                latitude=m.get("latitude"), longitude=m.get("longitude"),
                attributes={
                    "chat_jid": chat_jid,
                    "chat_name": session.get("name", ""),
                    "is_group": session.get("is_group", False),
                    "message_type": mtype, "media_kind": kind,
                    "media_local_path": m.get("local_path", ""),
                    "media_size": m.get("file_size"),
                    "starred": as_int(pick(row, "ZISSTARRED")),
                    "sent_date": from_epoch(pick(row, "ZSENTDATE"), "apple"),
                    "group_member": as_int(pick(row, "ZGROUPMEMBER")),
                    "stanza_id": as_text(pick(row, "ZSTANZAID", default="")),
                },
            )
            if from_me:
                art.add_participant("", ctx.owner_name, role="from", is_owner=True)
                art.add_participant(_jid(to_jid or chat_jid),
                                    session.get("name", ""), role="to")
            else:
                art.add_participant(_jid(from_jid or chat_jid),
                                    session.get("name", ""), role="from")
                art.add_participant("", ctx.owner_name, role="to", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res
