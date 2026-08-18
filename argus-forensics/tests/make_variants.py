"""The same conversation, stored the way successive app versions stored it.

Apps migrate their schemas. WhatsApp moved message bodies from `messages.data`
to `message.text_data` behind a `jid` table; Android SMS gained `bugle_db`
alongside `mmssms.db`; call logs renamed and re-typed columns; several apps
switched millisecond epochs to microsecond ones partway through their history.

A parser written against one generation and tested against the same generation
proves nothing about the next handset that comes in. Worse, the usual failure is
silent: the query returns no rows, the parser reports zero artifacts, and the
report says the phone held no messages.

Each builder below plants **identical content** in a different schema. The test
asserts the same facts come out regardless, so a parser that only understands
one generation is caught rather than quietly returning nothing.

All content is invented.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable, Dict, List, Tuple

# (peer, body, outgoing, unix_millis)
CONVERSATION: List[Tuple[str, str, bool, int]] = [
    ("+447700900112", "Are we still on for tonight", False, 1700000001000),
    ("+447700900112", "Yes same place as before", True, 1700000062000),
    ("+447700900112", "Bring the second bag with you", False, 1700000123000),
    ("+447700900455", "He wants the money by Friday", False, 1700000184000),
    ("+447700900455", "Tell him it will be ready", True, 1700000245000),
]

# Deleted from every variant, so recovery is comparable across schemas.
DELETED = ("+447700900112", "Wipe this thread when you are done", False,
           1700000306000)

ALL_MESSAGES = CONVERSATION + [DELETED]


def _new(path: Path) -> sqlite3.Connection:
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA secure_delete=OFF")
    return con


def _finish(con: sqlite3.Connection, delete_sql: str, params: tuple) -> None:
    """Commit, then delete the planted row so it must be carved back."""
    con.commit()
    con.execute(delete_sql, params)
    con.commit()
    con.close()


# ──────────────────────────────────────────────────────── Android SMS, gen 1
def sms_legacy(path: Path) -> Path:
    """`mmssms.db` as shipped for most of Android's life."""
    con = _new(path)
    con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, "
                "address TEXT, date INTEGER, body TEXT, type INTEGER, "
                "read INTEGER)")
    con.executemany(
        "INSERT INTO sms (thread_id,address,date,body,type,read) "
        "VALUES (?,?,?,?,?,1)",
        [(1, peer, ts, body, 2 if out else 1)
         for peer, body, out, ts in ALL_MESSAGES])
    _finish(con, "DELETE FROM sms WHERE body = ?", (DELETED[1],))
    return path


# ──────────────────────────────────────────────────────── Android SMS, gen 2
def sms_bugle(path: Path) -> Path:
    """`bugle_db`, the Google Messages store, which splits parts from rows.

    Note the epoch: microseconds, not milliseconds. A parser that assumes
    milliseconds here dates every message to 1970 — and a timeline silently
    anchored to the wrong decade is worse than no timeline.
    """
    con = _new(path)
    con.execute("CREATE TABLE participants (_id INTEGER PRIMARY KEY, "
                "normalized_destination TEXT, display_destination TEXT)")
    con.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, "
                "conversation_id INTEGER, sender_id INTEGER, "
                "received_timestamp INTEGER, message_status INTEGER)")
    con.execute("CREATE TABLE parts (_id INTEGER PRIMARY KEY, "
                "message_id INTEGER, text TEXT, content_type TEXT)")

    peers = sorted({peer for peer, _b, _o, _t in ALL_MESSAGES})
    for index, peer in enumerate(peers, start=1):
        con.execute("INSERT INTO participants (_id,normalized_destination,"
                    "display_destination) VALUES (?,?,?)", (index, peer, peer))
    for row_id, (peer, body, out, ts) in enumerate(ALL_MESSAGES, start=1):
        con.execute("INSERT INTO messages (_id,conversation_id,sender_id,"
                    "received_timestamp,message_status) VALUES (?,?,?,?,?)",
                    (row_id, 1, peers.index(peer) + 1, ts * 1000,
                     4 if out else 100))
        con.execute("INSERT INTO parts (message_id,text,content_type) "
                    "VALUES (?,?,'text/plain')", (row_id, body))
    _finish(con, "DELETE FROM parts WHERE text = ?", (DELETED[1],))
    return path


# ───────────────────────────────────────────────────────── WhatsApp, gen 1
def whatsapp_legacy(path: Path) -> Path:
    """`msgstore.db` with the flat `messages` table and a JID string column."""
    con = _new(path)
    con.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, "
                "key_remote_jid TEXT, key_from_me INTEGER, data TEXT, "
                "timestamp INTEGER, media_wa_type INTEGER)")
    con.executemany(
        "INSERT INTO messages (key_remote_jid,key_from_me,data,timestamp,"
        "media_wa_type) VALUES (?,?,?,?,0)",
        [(peer.lstrip("+") + "@s.whatsapp.net", 1 if out else 0, body, ts)
         for peer, body, out, ts in ALL_MESSAGES])
    _finish(con, "DELETE FROM messages WHERE data = ?", (DELETED[1],))
    return path


# ───────────────────────────────────────────────────────── WhatsApp, gen 2
def whatsapp_modern(path: Path) -> Path:
    """The normalised layout: `message` joined to `chat` and `jid`.

    The body column changed name to `text_data`, and the correspondent moved
    two joins away. A parser matching on `messages.data` finds no such table
    and reports an empty handset.
    """
    con = _new(path)
    con.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, "
                "server TEXT, raw_string TEXT)")
    con.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
    con.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, "
                "chat_row_id INTEGER, from_me INTEGER, text_data TEXT, "
                "timestamp INTEGER, message_type INTEGER)")

    peers = sorted({peer for peer, _b, _o, _t in ALL_MESSAGES})
    for index, peer in enumerate(peers, start=1):
        user = peer.lstrip("+")
        con.execute("INSERT INTO jid (_id,user,server,raw_string) "
                    "VALUES (?,?,'s.whatsapp.net',?)",
                    (index, user, f"{user}@s.whatsapp.net"))
        con.execute("INSERT INTO chat (_id,jid_row_id) VALUES (?,?)",
                    (index, index))
    for peer, body, out, ts in ALL_MESSAGES:
        con.execute("INSERT INTO message (chat_row_id,from_me,text_data,"
                    "timestamp,message_type) VALUES (?,?,?,?,0)",
                    (peers.index(peer) + 1, 1 if out else 0, body, ts))
    _finish(con, "DELETE FROM message WHERE text_data = ?", (DELETED[1],))
    return path


# ─────────────────────────────────────────────────────────── call log, gen 1
CALLS: List[Tuple[str, int, int, int]] = [
    ("+447700900112", 1700000400000, 128, 1),   # incoming
    ("+447700900455", 1700000500000, 44, 2),    # outgoing
    ("+447700900771", 1700000600000, 0, 3),     # missed
]
DELETED_CALL = ("+447700900999", 1700000700000, 9, 1)
ALL_CALLS = CALLS + [DELETED_CALL]


def calls_legacy(path: Path) -> Path:
    con = _new(path)
    con.execute("CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, "
                "date INTEGER, duration INTEGER, type INTEGER, name TEXT)")
    con.executemany(
        "INSERT INTO calls (number,date,duration,type,name) VALUES (?,?,?,?,'')",
        ALL_CALLS)
    _finish(con, "DELETE FROM calls WHERE number = ?", (DELETED_CALL[0],))
    return path


def calls_renamed(path: Path) -> Path:
    """A vendor build that renamed the columns but kept the meaning."""
    con = _new(path)
    con.execute("CREATE TABLE logs (_id INTEGER PRIMARY KEY, address TEXT, "
                "timestamp INTEGER, duration_sec INTEGER, call_type INTEGER)")
    con.executemany(
        "INSERT INTO logs (address,timestamp,duration_sec,call_type) "
        "VALUES (?,?,?,?)", ALL_CALLS)
    _finish(con, "DELETE FROM logs WHERE address = ?", (DELETED_CALL[0],))
    return path


MESSAGE_VARIANTS: Dict[str, Tuple[str, Callable[[Path], Path]]] = {
    "android_sms_legacy": ("mmssms.db", sms_legacy),
    "android_sms_bugle": ("bugle_db", sms_bugle),
    "whatsapp_legacy": ("msgstore.db", whatsapp_legacy),
    "whatsapp_modern": ("msgstore.db", whatsapp_modern),
}

CALL_VARIANTS: Dict[str, Tuple[str, Callable[[Path], Path]]] = {
    "calls_legacy": ("calllog.db", calls_legacy),
    "calls_renamed": ("calllog.db", calls_renamed),
}


def build_all(directory: Path) -> Dict[str, Path]:
    """Every variant, each in its own subdirectory to avoid name collisions."""
    directory = Path(directory)
    out: Dict[str, Path] = {}
    for label, (filename, builder) in {**MESSAGE_VARIANTS,
                                       **CALL_VARIANTS}.items():
        sub = directory / label
        sub.mkdir(parents=True, exist_ok=True)
        out[label] = builder(sub / filename)
    return out


if __name__ == "__main__":
    import sys
    built = build_all(Path(sys.argv[1] if len(sys.argv) > 1 else "variants"))
    for label, path in built.items():
        print(f"{label:24} {path}")
