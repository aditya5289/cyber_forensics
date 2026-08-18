"""Social and messaging applications on Android.

Telegram, Instagram, Snapchat, Facebook Messenger, Discord, Viber and Signal.

Two things make these harder than SMS, and both are handled explicitly rather
than papered over:

**Schemas move.** These apps ship every fortnight and rename columns freely.
Every parser here resolves its table and column names at runtime against what
is actually in the file, and records which schema variant it matched. A parser
hard-coded to one version silently returns nothing against the next, which is
the worst possible failure: it looks like an empty chat rather than a broken
parser.

**Much of the content is not in columns.** Telegram stores whole messages as
serialised TL objects in a BLOB; Instagram and Messenger use JSON or protobuf
payloads. Where the text is not in a text column, it is extracted from the blob
and the artifact records *how* it was recovered, so an examiner can weigh it.

What is deliberately not attempted: Signal's message store is SQLCipher and
Telegram's secret chats never touch disk in readable form. Those are reported as
present-and-encrypted by :mod:`argus.parsers.antiforensics` rather than being
quietly omitted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import (any_table_probe, as_int, as_text, clean_number, pick,
                      rows_with_deleted, valid_coord)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

_PRINTABLE = re.compile(rb"[\x20-\x7e\xc2-\xf4][\x20-\x7e\x80-\xbf]{3,}")


def _strings_from_blob(blob: Any, min_length: int = 4,
                       limit: int = 12) -> List[str]:
    """Recover readable text from an opaque serialised payload.

    Used where an application stores its message body inside a BLOB whose
    format is undocumented (Telegram's TL serialisation, Snapchat's protobuf).
    Tries protobuf first because it gives structure, then falls back to a
    printable-run sweep. Anything recovered this way is marked as such on the
    artifact so it is never mistaken for a clean column read.
    """
    if not blob:
        return []
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "ignore")
    if not isinstance(blob, (bytes, bytearray)):
        return []
    data = bytes(blob)

    from .. import protobuf
    try:
        if protobuf.probe(data):
            found = protobuf.extract_text(data, min_length)
            if found:
                return found[:limit]
    except Exception:
        pass

    out: List[str] = []
    seen: set[str] = set()
    for match in _PRINTABLE.finditer(data):
        try:
            text = match.group(0).decode("utf-8")
        except UnicodeDecodeError:
            continue
        text = "".join(c for c in text if c.isprintable() or c in "\n\t").strip()
        if len(text) < min_length or text in seen:
            continue
        # Serialisation framing and class names are not message content.
        if re.fullmatch(r"[A-Za-z_]{2,}(\.[A-Za-z_]+)+", text):
            continue
        seen.add(text)
        out.append(text)
    return sorted(out, key=len, reverse=True)[:limit]


def _first_column(db: ForensicSQLite, table: str, *candidates: str) -> str:
    """Resolve a column name against the schema actually present."""
    columns = {c.lower(): c for c in db.columns(table)}
    for name in candidates:
        if name.lower() in columns:
            return columns[name.lower()]
    return ""


# ═══════════════════════════════════════════════════════════════ Telegram
@register(
    name="android.telegram",
    patterns=["cache4.db", "tgnet.dat", "cache4*.db"],
    platform="android", priority=85,
    probe=any_table_probe(("messages",), ("messages_v2",), ("users",)),
    description="Telegram messages, chats, users and calls",
)
def parse_telegram(path: Path, ctx: ParseContext) -> ParseResult:
    """Telegram (Android)."""
    res = ParseResult(parser="android.telegram", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        # ---- users, so messages can name their sender ---------------------
        users: Dict[int, Dict[str, str]] = {}
        user_table = db.first_table("users")
        if user_table:
            name_col = _first_column(db, user_table, "name", "first_name")
            data_col = _first_column(db, user_table, "data")
            for row in db.rows(user_table):
                uid = as_int(pick(row, "uid", "_id"))
                if uid is None:
                    continue
                label = as_text(row.get(name_col)) if name_col else ""
                phone = ""
                if not label and data_col:
                    blob = _strings_from_blob(row.get(data_col), limit=4)
                    label = blob[0] if blob else ""
                    for candidate in blob:
                        digits = re.sub(r"\D", "", candidate)
                        if 9 <= len(digits) <= 15:
                            phone = digits
                            break
                users[uid] = {"name": label.replace(";;;", " ").strip(),
                              "phone": phone}
                if label or phone:
                    art = Artifact(
                        category=Category.CONTACT, subtype="Telegram user",
                        body=label or phone or str(uid), app="Telegram",
                        source_path=ctx.rel(path), source_table=user_table,
                        source_row=uid,
                        attributes={"telegram_uid": uid, "display_name": label,
                                    "phone_numbers": [phone] if phone else []},
                    )
                    art.add_participant(phone or str(uid), label, role="party")
                    res.artifacts.append(art)

        # ---- messages ------------------------------------------------------
        msg_table = db.first_table("messages_v2", "messages")
        if not msg_table:
            res.notes.append(f"{path.name}: no Telegram message table found "
                             f"(schema: {', '.join(sorted(db.schemas()))[:180]})")
            return res

        data_col = _first_column(db, msg_table, "data")
        date_col = _first_column(db, msg_table, "date")
        out_col = _first_column(db, msg_table, "out")
        uid_col = _first_column(db, msg_table, "uid", "user_id")
        read_col = _first_column(db, msg_table, "read_state")

        for row, recovery, conf in rows_with_deleted(db, msg_table, ctx):
            ts = guess(row.get(date_col), date_col) if date_col else None
            if not ctx.in_span(ts):
                continue
            outgoing = bool(as_int(row.get(out_col))) if out_col else False
            peer = as_int(row.get(uid_col)) if uid_col else None
            recovered = _strings_from_blob(row.get(data_col)) if data_col else []
            body = recovered[0] if recovered else ""
            if not body:
                continue

            party = users.get(peer or -1, {})
            label = party.get("name") or (str(peer) if peer is not None else "")
            art = Artifact(
                category=Category.MESSAGE, subtype="Telegram message",
                timestamp=ts,
                direction=Direction.OUTGOING if outgoing else Direction.INCOMING,
                body=body, app="Telegram", source_path=ctx.rel(path),
                source_table=msg_table,
                source_row=as_int(row.get("_rowid") or row.get("mid")),
                recovery=recovery,
                # Blob-recovered text is less certain than a clean column read,
                # and the artifact must say so.
                confidence=round(conf * 0.9, 3),
                attributes={
                    "telegram_peer_id": peer,
                    "partial_record": bool(row.get("_partial")),
                    "columns_unrecoverable": row.get("_missing_leading") or 0,
                    "partial_note": (
                        "The leading column(s) of this row were overwritten by "
                        "SQLite's freeblock header when the row was deleted. "
                        "The message body and timestamp survived and are "
                        "reported; the destroyed columns are shown as unknown."
                        if row.get("_partial") else ""),
                    "extraction_method": "recovered from serialised TL blob",
                    "additional_strings": recovered[1:6],
                    "read_state": as_int(row.get(read_col)) if read_col else None,
                    "schema_variant": msg_table,
                },
            )
            if outgoing:
                art.add_participant("", ctx.owner_name, role="from", is_owner=True)
                art.add_participant(party.get("phone") or str(peer or ""),
                                    label, role="to")
            else:
                art.add_participant(party.get("phone") or str(peer or ""),
                                    label, role="from")
                art.add_participant("", ctx.owner_name, role="to", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        if res.artifacts:
            res.notes.append(
                f"{ctx.rel(path)}: Telegram content was recovered from "
                f"serialised blobs rather than text columns; Telegram does not "
                f"store message text in a readable column. Secret chats are "
                f"never written to disk and are absent by design.")
        res.warnings.extend(db.warnings)
    return res


# ═══════════════════════════════════════════════════════════════ Instagram
def _instagram_probe(path: Path) -> bool:
    """Distinguish Instagram from Facebook Messenger.

    Both ship a table called ``messages`` and Meta reuses ``threads_db``-style
    filenames across its apps. Without a discriminating probe both parsers
    claim the same file and every message is reported twice — a duplicate that
    inflates artifact counts and, worse, double-counts in the findings.
    Instagram uses ``thread_id`` + ``item_type``; Messenger uses ``thread_key``
    + ``timestamp_ms``.
    """
    import sqlite3 as _s
    try:
        with path.open("rb") as fh:
            if fh.read(16) != b"SQLite format 3\x00":
                return False
        conn = _s.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            tables = {r[0].lower() for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            target = next((t for t in ("messages", "thread_messages")
                           if t in tables), None)
            if not target:
                return False
            cols = {r[1].lower() for r in conn.execute(
                f'PRAGMA table_info("{target}")')}
        finally:
            conn.close()
    except Exception:
        return False
    if "thread_key" in cols or "timestamp_ms" in cols:
        return False                     # this is Messenger
    return bool(cols & {"thread_id", "item_type", "user_id"})


@register(
    name="android.instagram",
    patterns=["direct.db", "*_direct.db", "instagram.db", "threads_db*"],
    platform="android", priority=82,
    probe=_instagram_probe,
    description="Instagram direct messages and threads",
)
def parse_instagram(path: Path, ctx: ParseContext) -> ParseResult:
    """Instagram direct messages."""
    res = ParseResult(parser="android.instagram", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("messages", "thread_messages")
        if not table:
            res.notes.append(f"{path.name}: no Instagram message table")
            return res

        text_col = _first_column(db, table, "text", "message_text", "content")
        ts_col = _first_column(db, table, "timestamp", "server_timestamp",
                              "created_at")
        sender_col = _first_column(db, table, "user_id", "sender_id")
        thread_col = _first_column(db, table, "thread_id", "thread_key")
        payload_col = _first_column(db, table, "message", "payload", "data")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            body = as_text(row.get(text_col)) if text_col else ""
            method = "text column"
            if not body and payload_col:
                # Instagram stores richer messages as a JSON payload.
                raw = row.get(payload_col)
                body, method = _from_json_payload(raw)
            if not body:
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            sender = as_text(row.get(sender_col)) if sender_col else ""
            art = Artifact(
                category=Category.MESSAGE, subtype="Instagram direct message",
                timestamp=ts, body=body, app="Instagram",
                direction=Direction.UNKNOWN,
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf if method == "text column" else round(conf * 0.9, 3),
                attributes={
                    "thread_id": as_text(row.get(thread_col)) if thread_col else "",
                    "sender_id": sender,
                    "extraction_method": method,
                    "schema_variant": table,
                },
            )
            if sender:
                art.add_participant(sender, "", role="from")
            art.add_participant("", ctx.owner_name, role="party", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _from_json_payload(raw: Any) -> Tuple[str, str]:
    """Pull the visible text out of a JSON message payload."""
    if not raw:
        return "", ""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return (_strings_from_blob(raw, limit=1) or [""])[0], "binary payload"
    if not isinstance(raw, str):
        return "", ""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return "", ""
    for key in ("text", "message", "body", "content", "caption"):
        value = obj.get(key) if isinstance(obj, dict) else None
        if isinstance(value, str) and value.strip():
            return value, f"JSON payload field '{key}'"
    return "", ""


# ═══════════════════════════════════════════════════════════════ Snapchat
@register(
    name="android.snapchat",
    patterns=["tcspahn.db", "main.db", "arroyo.db", "core.db"],
    platform="android", priority=82,
    probe=any_table_probe(("Chat",), ("conversation_message",), ("Friend",),
                          ("messages",)),
    description="Snapchat chats, friends and snap metadata",
)
def parse_snapchat(path: Path, ctx: ParseContext) -> ParseResult:
    """Snapchat.

    Snapchat is deliberately ephemeral, so what survives on disk is mostly
    *metadata*: that a snap was sent, to whom, and when — rarely its content.
    That absence is itself the finding, and the artifacts say so rather than
    implying the content was recovered.
    """
    res = ParseResult(parser="android.snapchat", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        # ---- friends -------------------------------------------------------
        friend_table = db.first_table("Friend", "friends")
        if friend_table:
            for row in db.rows(friend_table):
                username = as_text(pick(row, "username", "userId", "name"))
                display = as_text(pick(row, "displayName", "display_name",
                                       default=""))
                if not (username or display):
                    continue
                art = Artifact(
                    category=Category.CONTACT, subtype="Snapchat friend",
                    body=display or username, app="Snapchat",
                    source_path=ctx.rel(path), source_table=friend_table,
                    source_row=as_int(row.get("_rowid")),
                    attributes={"username": username, "display_name": display,
                                "phone_numbers": []},
                )
                art.add_participant(username, display, role="party")
                res.artifacts.append(art)

        # ---- chats / messages ----------------------------------------------
        chat_table = db.first_table("Chat", "conversation_message", "messages")
        if not chat_table:
            if not res.artifacts:
                res.notes.append(f"{path.name}: no Snapchat chat table found")
            return res

        text_col = _first_column(db, chat_table, "content", "text", "body",
                                "message_content")
        ts_col = _first_column(db, chat_table, "timestamp", "creation_timestamp",
                              "sent_timestamp")
        sender_col = _first_column(db, chat_table, "sender_id", "senderUsername",
                                  "sender")
        type_col = _first_column(db, chat_table, "content_type", "type",
                                "message_type")

        for row, recovery, conf in rows_with_deleted(db, chat_table, ctx):
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            raw = row.get(text_col) if text_col else None
            body = as_text(raw)
            method = "text column"
            if isinstance(raw, (bytes, bytearray)):
                recovered = _strings_from_blob(raw, limit=4)
                body = recovered[0] if recovered else ""
                method = "recovered from binary payload"
            sender = as_text(row.get(sender_col)) if sender_col else ""
            kind = as_text(row.get(type_col)) if type_col else ""

            has_content = bool(body)
            art = Artifact(
                category=Category.MESSAGE,
                subtype=f"Snapchat {kind or 'message'}"
                        + ("" if has_content else " (metadata only)"),
                timestamp=ts,
                body=body or f"[{kind or 'snap'} — content not retained on device]",
                app="Snapchat", source_path=ctx.rel(path),
                source_table=chat_table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf if method == "text column" else round(conf * 0.9, 3),
                attributes={
                    "sender": sender, "content_type": kind,
                    "content_recovered": has_content,
                    "extraction_method": method if has_content else "none",
                    "note": ("" if has_content else
                             "Snapchat deletes message content by design. This "
                             "record establishes that a message was exchanged, "
                             "with whom and when — not what it said."),
                    "schema_variant": chat_table,
                },
            )
            if sender:
                art.add_participant(sender, "", role="from")
            art.add_participant("", ctx.owner_name, role="party", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


# ═══════════════════════════════════════════════════════ Facebook Messenger
def _messenger_probe(path: Path) -> bool:
    """Messenger-specific columns, so Instagram's store is not claimed here."""
    import sqlite3 as _s
    try:
        with path.open("rb") as fh:
            if fh.read(16) != b"SQLite format 3\x00":
                return False
        conn = _s.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            tables = {r[0].lower() for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            target = next((t for t in ("messages", "thread_messages")
                           if t in tables), None)
            if not target:
                return False
            cols = {r[1].lower() for r in conn.execute(
                f'PRAGMA table_info("{target}")')}
        finally:
            conn.close()
    except Exception:
        return False
    return bool(cols & {"thread_key", "timestamp_ms"})


@register(
    name="android.messenger",
    patterns=["threads_db2", "msys_database*", "threads_db*"],
    platform="android", priority=82,
    probe=_messenger_probe,
    description="Facebook Messenger threads and messages",
)
def parse_messenger(path: Path, ctx: ParseContext) -> ParseResult:
    """Facebook Messenger."""
    res = ParseResult(parser="android.messenger", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("messages", "thread_messages")
        if not table:
            res.notes.append(f"{path.name}: no Messenger message table")
            return res

        text_col = _first_column(db, table, "text", "body", "snippet")
        ts_col = _first_column(db, table, "timestamp_ms", "timestamp",
                              "sent_timestamp_ms")
        sender_col = _first_column(db, table, "sender_id", "sender")
        thread_col = _first_column(db, table, "thread_key", "thread_id")
        attach_col = _first_column(db, table, "attachments")

        # Messenger stores the sender as a JSON blob in older schemas.
        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            body = as_text(row.get(text_col)) if text_col else ""
            if not body:
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            sender_raw = as_text(row.get(sender_col)) if sender_col else ""
            sender_id, sender_name = _messenger_sender(sender_raw)
            attachments = _messenger_attachments(row.get(attach_col)
                                                 if attach_col else None)
            art = Artifact(
                category=Category.MESSAGE, subtype="Messenger message",
                timestamp=ts, body=body, app="Facebook Messenger",
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={
                    "thread_key": as_text(row.get(thread_col)) if thread_col else "",
                    "sender_id": sender_id,
                    "attachments": attachments,
                    "attachment_count": len(attachments),
                    "schema_variant": table,
                },
            )
            if sender_id or sender_name:
                art.add_participant(sender_id, sender_name, role="from")
            art.add_participant("", ctx.owner_name, role="party", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _messenger_sender(raw: str) -> Tuple[str, str]:
    if not raw:
        return "", ""
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            return (str(obj.get("user_key") or obj.get("id") or ""),
                    str(obj.get("name") or ""))
        except (json.JSONDecodeError, ValueError):
            pass
    return raw, ""


def _messenger_attachments(raw: Any) -> List[Dict[str, Any]]:
    if not raw:
        return []
    text = as_text(raw)
    if not text.strip().startswith(("[", "{")):
        return []
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    items = obj if isinstance(obj, list) else [obj]
    out = []
    for item in items[:20]:
        if isinstance(item, dict):
            out.append({k: item.get(k) for k in
                        ("filename", "mimeType", "urlExpirationTimestampMs",
                         "id") if k in item})
    return out


# ═══════════════════════════════════════════════════════════════ Discord
@register(
    name="android.discord",
    patterns=["discord*.db", "store.db", "*discord*.sqlite"],
    platform="android", priority=78,
    probe=any_table_probe(("messages",), ("message",), ("channels",)),
    description="Discord messages and channels",
)
def parse_discord(path: Path, ctx: ParseContext) -> ParseResult:
    """Discord."""
    res = ParseResult(parser="android.discord", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("messages", "message")
        if not table:
            return res
        text_col = _first_column(db, table, "content", "text", "message")
        ts_col = _first_column(db, table, "timestamp", "created_at", "edited_at")
        author_col = _first_column(db, table, "author_id", "author", "user_id")
        channel_col = _first_column(db, table, "channel_id", "channel")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            body = as_text(row.get(text_col)) if text_col else ""
            if not body:
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            author = as_text(row.get(author_col)) if author_col else ""
            art = Artifact(
                category=Category.MESSAGE, subtype="Discord message",
                timestamp=ts, body=body, app="Discord",
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={
                    "channel_id": as_text(row.get(channel_col)) if channel_col else "",
                    "author_id": author, "schema_variant": table,
                },
            )
            if author:
                art.add_participant(author, "", role="from")
            art.add_participant("", ctx.owner_name, role="party", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


# ═══════════════════════════════════════════════════════════════ Viber
@register(
    name="android.viber",
    patterns=["viber_messages", "viber_data", "viber_messages*"],
    platform="android", priority=80,
    probe=any_table_probe(("messages",), ("participants_info",)),
    description="Viber messages and contacts",
)
def parse_viber(path: Path, ctx: ParseContext) -> ParseResult:
    """Viber."""
    res = ParseResult(parser="android.viber", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        # participant number lookup
        parties: Dict[int, Tuple[str, str]] = {}
        info_table = db.first_table("participants_info")
        if info_table:
            for row in db.rows(info_table):
                pid = as_int(pick(row, "_id"))
                if pid is not None:
                    parties[pid] = (clean_number(pick(row, "number")),
                                    as_text(pick(row, "display_name",
                                                 "contact_name", default="")))

        table = db.first_table("messages")
        if not table:
            return res
        text_col = _first_column(db, table, "body", "text")
        ts_col = _first_column(db, table, "date", "msg_date")
        out_col = _first_column(db, table, "send_type", "type")
        part_col = _first_column(db, table, "participant_id")

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            body = as_text(row.get(text_col)) if text_col else ""
            if not body:
                continue
            ts = guess(row.get(ts_col), ts_col) if ts_col else None
            if not ctx.in_span(ts):
                continue
            outgoing = bool(as_int(row.get(out_col))) if out_col else False
            pid = as_int(row.get(part_col)) if part_col else None
            number, name = parties.get(pid or -1, ("", ""))
            art = Artifact(
                category=Category.MESSAGE, subtype="Viber message",
                timestamp=ts, body=body, app="Viber",
                direction=Direction.OUTGOING if outgoing else Direction.INCOMING,
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid")), recovery=recovery,
                confidence=conf,
                attributes={"participant_id": pid, "schema_variant": table},
            )
            if outgoing:
                art.add_participant("", ctx.owner_name, role="from", is_owner=True)
                art.add_participant(number, name, role="to")
            else:
                art.add_participant(number, name, role="from")
                art.add_participant("", ctx.owner_name, role="to", is_owner=True)
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


# ═══════════════════════════════════════════════════════════════ Signal
@register(
    name="android.signal_meta",
    patterns=["signal-*.db", "signal_prefs.xml", "recipient*.db"],
    platform="android", priority=60,
    description="Signal metadata (the message store itself is encrypted)",
)
def parse_signal_metadata(path: Path, ctx: ParseContext) -> ParseResult:
    """Signal metadata.

    Signal's message database is SQLCipher-encrypted and ARGUS does not attempt
    to break it. What is sometimes readable is registration metadata: the
    account's own number, and when the app was set up. Recording that is useful
    even though the messages are not — it establishes that Signal was in use
    and by which account.
    """
    res = ParseResult(parser="android.signal_meta", source=ctx.rel(path))
    if path.suffix.lower() == ".xml":
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            res.warnings.append(f"{path.name}: {exc}")
            return res
        number = re.search(r'name="pref_local_number"[^>]*>([^<]+)<', text)
        registered = re.search(r'name="pref_.*registered[^"]*"[^>]*value="([^"]+)"',
                              text)
        if number or registered:
            art = Artifact(
                category=Category.ACCOUNT, subtype="Signal registration",
                body=f"Signal account {number.group(1) if number else '(unknown)'}",
                app="Signal", source_path=ctx.rel(path),
                attributes={
                    "local_number": number.group(1) if number else "",
                    "registered": registered.group(1) if registered else "",
                    "note": ("Signal's message store is SQLCipher-encrypted and "
                             "has not been decoded. This records that Signal "
                             "was installed and registered to this account."),
                },
            )
            if number:
                art.add_participant(number.group(1), ctx.owner_name,
                                    role="owner", is_owner=True)
            res.artifacts.append(art)
    return res
