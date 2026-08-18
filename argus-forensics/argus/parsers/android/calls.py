"""Android call log (``calllog.db`` / ``contacts2.db`` ``calls`` table).

Maps to lab manual Step 16 / §6.3 — chronological call records with
caller identity, duration and direction.
"""

from __future__ import annotations

from pathlib import Path

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import as_int, as_text, clean_number, pick, rows_with_deleted, any_table_probe
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

# android.provider.CallLog.Calls.TYPE
CALL_TYPE = {
    1: (Direction.INCOMING, "Incoming call"),
    2: (Direction.OUTGOING, "Outgoing call"),
    3: (Direction.MISSED, "Missed call"),
    4: (Direction.INCOMING, "Voicemail"),
    5: (Direction.REJECTED, "Rejected call"),
    6: (Direction.MISSED, "Blocked call"),
    7: (Direction.INCOMING, "Answered externally"),
}

# PRESENTATION_* constants — why a number is absent matters evidentially
PRESENTATION = {1: "allowed", 2: "restricted", 3: "unknown", 4: "payphone"}


@register(
    name="android.calllog",
    patterns=["calllog.db", "contacts2.db", "calls.db", "logs.db"],
    platform="android", priority=80,
    probe=any_table_probe(("calls",)),
    description="Android call log (calls table)",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """Android call log."""
    res = ParseResult(parser="android.calllog", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        table = db.first_table("calls")
        if not table:
            res.notes.append(f"{path.name}: no 'calls' table present")
            return res

        for row, recovery, conf in rows_with_deleted(db, table, ctx):
            number = clean_number(pick(row, "number", "normalized_number",
                                       "matched_number"))
            ts = guess(pick(row, "date"), "date")
            if not ctx.in_span(ts):
                continue
            ctype = as_int(pick(row, "type")) or 0
            direction, subtype = CALL_TYPE.get(ctype, (Direction.UNKNOWN, "Call"))
            duration = as_int(pick(row, "duration")) or 0
            name = as_text(pick(row, "name", "cached_name", default=""))
            presentation = as_int(pick(row, "presentation"))

            art = Artifact(
                category=Category.CALL, subtype=subtype, timestamp=ts,
                timestamp_end=(ts + duration * 1_000_000) if ts and duration else None,
                direction=direction,
                app=as_text(pick(row, "subscription_component_name",
                                 default="Android Phone")).split("/")[0]
                    or "Android Phone",
                source_path=ctx.rel(path), source_table=table,
                source_row=as_int(row.get("_rowid") or row.get("_id")),
                recovery=recovery, confidence=conf,
                body=f"{subtype} — {name or number or 'unknown number'}"
                     + (f" ({duration}s)" if duration else ""),
                attributes={
                    "duration_seconds": duration,
                    "duration_display": _hms(duration),
                    "call_type_code": ctype,
                    "presentation": PRESENTATION.get(presentation or 0, ""),
                    "is_read": as_int(pick(row, "is_read")),
                    "geocoded_location": as_text(pick(row, "geocoded_location",
                                                      default="")),
                    "via_number": as_text(pick(row, "via_number", default="")),
                    "sim_slot": as_int(pick(row, "subscription_id")),
                },
            )
            art.add_participant("", ctx.owner_name, role="owner", is_owner=True)
            if number or name:
                art.add_participant(number, name,
                                    role="to" if direction == Direction.OUTGOING
                                    else "from")
            elif presentation in (2, 3, 4):
                art.add_participant("", f"({PRESENTATION[presentation]})",
                                    role="from")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        res.warnings.extend(db.warnings)
        info = db.integrity()
        if info["integrity_check"] != "ok":
            res.warnings.append(
                f"{path.name}: integrity check reported "
                f"'{info['integrity_check']}' — some records may be unreadable")
    return res


def _hms(seconds: int) -> str:
    if not seconds:
        return "00:00:00"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"
