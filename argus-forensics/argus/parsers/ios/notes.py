"""iOS Notes (``NoteStore.sqlite``) and Calendar (``Calendar.sqlitedb``).

Note bodies are gzip-compressed protobuf inside ``ZICNOTEDATA.ZDATA``. Full
protobuf decoding is overkill for evidential purposes — the readable text is
recovered by inflating the blob and extracting its printable runs, which is
what an examiner needs to see.
"""

from __future__ import annotations

import re
import zlib
from pathlib import Path

from ...core.models import Artifact, Category, Recovery
from ..common import any_table_probe, as_int, as_text, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch


@register(
    name="ios.notes",
    patterns=["NoteStore.sqlite", "notes.sqlite",
              "4f98687d8ab0d6d1a371110e6b7300f6e465bef2"],
    platform="ios", priority=80,
    probe=any_table_probe(("ZICCLOUDSYNCINGOBJECT",), ("ZNOTE",)),
    description="iOS Notes",
)
def parse_notes(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS Notes."""
    res = ParseResult(parser="ios.notes", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        bodies = {}
        if db.has_table("ZICNOTEDATA"):
            for r in db.rows("ZICNOTEDATA"):
                nid = as_int(r.get("ZNOTE"))
                if nid is not None:
                    bodies[nid] = _inflate_note(r.get("ZDATA"))

        table = db.first_table("ZICCLOUDSYNCINGOBJECT", "ZNOTE")
        if not table:
            return res
        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            title = as_text(pick(row, "ZTITLE", "ZTITLE1", default="")).strip()
            pk = as_int(row.get("Z_PK") or row.get("_rowid"))
            body = bodies.get(pk, "")
            if not (title or body):
                continue
            ts = from_epoch(pick(row, "ZMODIFICATIONDATE1", "ZMODIFICATIONDATE",
                                 "ZCREATIONDATE1", "ZCREATIONDATE"), "apple")
            if not ctx.in_span(ts):
                continue
            art = Artifact(
                category=Category.NOTE, subtype="Note", timestamp=ts,
                body=(f"{title}\n{body}" if title and body else title or body)[:20000],
                app="Apple Notes", source_path=ctx.rel(path),
                source_table=table, source_row=pk, recovery=recovery,
                confidence=conf,
                attributes={
                    "title": title,
                    "created": from_epoch(pick(row, "ZCREATIONDATE1",
                                               "ZCREATIONDATE"), "apple"),
                    "modified": ts,
                    "pinned": as_int(pick(row, "ZISPINNED")),
                    "marked_deleted": as_int(pick(row, "ZMARKEDFORDELETION")),
                    "password_protected": bool(pick(row, "ZISPASSWORDPROTECTED")),
                },
            )
            if as_int(pick(row, "ZMARKEDFORDELETION")) == 1:
                art.subtype = "Note (marked for deletion)"
                res.deleted_recovered += 1
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


@register(
    name="ios.calendar",
    patterns=["Calendar.sqlitedb", "calendar.sqlitedb"],
    platform="ios", priority=75,
    probe=any_table_probe(("CalendarItem",)),
    description="iOS Calendar events",
)
def parse_calendar(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS Calendar."""
    res = ParseResult(parser="ios.calendar", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        if not db.has_table("CalendarItem"):
            return res
        for row, recovery, conf in rows_with_deleted(db, "CalendarItem", ctx):
            summary = as_text(pick(row, "summary", default=""))
            if not summary:
                continue
            start = from_epoch(pick(row, "start_date"), "apple")
            end = from_epoch(pick(row, "end_date"), "apple")
            if not ctx.in_span(start):
                continue
            art = Artifact(
                category=Category.CALENDAR, subtype="Calendar event",
                timestamp=start, timestamp_end=end, body=summary,
                app="Apple Calendar", source_path=ctx.rel(path),
                source_table="CalendarItem",
                source_row=as_int(row.get("_rowid") or row.get("ROWID")),
                recovery=recovery, confidence=conf,
                attributes={
                    "summary": summary,
                    "location": as_text(pick(row, "location_id", default="")),
                    "description": as_text(pick(row, "description", default="")),
                    "all_day": as_int(pick(row, "all_day")),
                    "status": as_int(pick(row, "status")),
                },
            )
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


_PRINTABLE = re.compile(rb"[\x20-\x7e\n\r\t]{4,}")


def _inflate_note(blob) -> str:
    if not blob:
        return ""
    if isinstance(blob, str):
        blob = blob.encode("utf-8", errors="ignore")
    if not isinstance(blob, (bytes, bytearray)):
        return ""
    data = bytes(blob)
    for wbits in (16 + zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS):
        try:
            data = zlib.decompress(data, wbits)
            break
        except zlib.error:
            continue
    runs = [m.group(0).decode("utf-8", errors="replace")
            for m in _PRINTABLE.finditer(data)]
    text = "\n".join(r.strip() for r in runs if len(r.strip()) > 3)
    return text[:20000]
