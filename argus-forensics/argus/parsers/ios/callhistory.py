"""iOS call history (``CallHistory.storedata``).

Lab manual Step 16 / §6.3 — "Apple Calls" category.

The Core Data store uses ``Z``-prefixed column names and Apple absolute time
(seconds since 2001-01-01), which is why a naive reader shows every call as
having happened in 1970.
"""

from __future__ import annotations

from pathlib import Path

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import any_table_probe, as_int, as_text, clean_number, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch

SERVICE = {"com.apple.Telephony": "Cellular", "com.apple.FaceTime": "FaceTime",
           "com.apple.telephonyutilities.callservicesd": "Cellular"}


@register(
    name="ios.callhistory",
    patterns=["CallHistory.storedata", "call_history.db", "CallHistory.db",
              "5a4935c78a5255723f707230a451d79c540d2741"],
    platform="ios", priority=85,
    probe=any_table_probe(("ZCALLRECORD",), ("call",)),
    description="iOS call history (Core Data store)",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS call history."""
    res = ParseResult(parser="ios.callhistory", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("ZCALLRECORD", "call")
        if not table:
            res.notes.append(f"{path.name}: no call table found")
            return res

        legacy = table.lower() == "call"
        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            if legacy:
                ts = from_epoch(pick(row, "date"), "unix_s")
                number = clean_number(pick(row, "address"))
                duration = as_int(pick(row, "duration")) or 0
                flags = as_int(pick(row, "flags")) or 0
                outgoing = bool(flags & 0x01)
                answered = bool(as_int(pick(row, "answered")))
                service = "Cellular"
            else:
                ts = from_epoch(pick(row, "ZDATE"), "apple")
                number = clean_number(pick(row, "ZADDRESS", "ZISO_COUNTRY_CODE"))
                duration = as_int(pick(row, "ZDURATION")) or 0
                outgoing = bool(as_int(pick(row, "ZORIGINATED")))
                answered = bool(as_int(pick(row, "ZANSWERED")))
                service = SERVICE.get(as_text(pick(row, "ZSERVICE_PROVIDER",
                                                   default="")), "Cellular")
            if not ctx.in_span(ts):
                continue

            if outgoing:
                direction, subtype = Direction.OUTGOING, "Outgoing call"
            elif answered:
                direction, subtype = Direction.INCOMING, "Incoming call"
            else:
                direction, subtype = Direction.MISSED, "Missed call"

            face_time = as_int(pick(row, "ZCALLTYPE")) in (8, 16)
            art = Artifact(
                category=Category.CALL,
                subtype=f"{subtype} (FaceTime)" if face_time else subtype,
                timestamp=ts,
                timestamp_end=(ts + duration * 1_000_000) if ts and duration else None,
                direction=direction, app="Apple Phone",
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid") or row.get("Z_PK")),
                recovery=recovery, confidence=conf,
                body=f"{subtype} — {number or 'unknown number'}"
                     + (f" ({duration}s)" if duration else ""),
                attributes={
                    "duration_seconds": duration,
                    "duration_display": _hms(duration),
                    "answered": answered,
                    "service": service,
                    "facetime": face_time,
                    "country_code": as_text(pick(row, "ZISO_COUNTRY_CODE",
                                                 default="")),
                    "location": as_text(pick(row, "ZLOCATION", default="")),
                    "read": as_int(pick(row, "ZREAD")),
                    "call_type": as_int(pick(row, "ZCALLTYPE")),
                },
            )
            art.add_participant("", ctx.owner_name, role="owner", is_owner=True)
            if number:
                art.add_participant(
                    number, "", role="to" if outgoing else "from")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _hms(seconds: int) -> str:
    if not seconds:
        return "00:00:00"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"
