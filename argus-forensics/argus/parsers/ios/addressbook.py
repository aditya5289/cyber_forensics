"""iOS contacts (``AddressBook.sqlitedb``) and Notes.

Lab manual Step 20 / §6.7 — contact list in column view.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from ...core.models import Artifact, Category, Recovery
from ..common import any_table_probe, as_int, as_text, clean_number, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch

# ABMultiValue property identifiers
PROPERTY = {3: "phone", 4: "email", 5: "address", 22: "url", 23: "date",
            13: "social", 46: "instant_message"}


@register(
    name="ios.addressbook",
    patterns=["AddressBook.sqlitedb", "31bb7ba8914766d4ba40d6dfb6113c8b614be442"],
    platform="ios", priority=85,
    probe=any_table_probe(("ABPerson",)),
    description="iOS AddressBook contacts",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS contacts."""
    res = ParseResult(parser="ios.addressbook", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        if not db.has_table("ABPerson"):
            res.notes.append(f"{path.name}: no ABPerson table")
            return res

        multi: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        deleted_mv = 0
        if db.has_table("ABMultiValue"):
            for row, recovery, conf in rows_with_deleted(db, "ABMultiValue", ctx):
                rid = as_int(row.get("record_id"))
                prop = PROPERTY.get(as_int(row.get("property")) or 0, "")
                val = as_text(row.get("value", "")).strip()
                if rid is None or not prop or not val:
                    continue
                v = clean_number(val) if prop == "phone" else val
                if v and v not in multi[rid][prop]:
                    multi[rid][prop].append(v)
                if recovery != Recovery.ALLOCATED:
                    deleted_mv += 1

        for row, recovery, conf in rows_with_deleted(db, "ABPerson", ctx):
            rid = as_int(row.get("_rowid") or row.get("ROWID"))
            first = as_text(pick(row, "First", default=""))
            last = as_text(pick(row, "Last", default=""))
            org = as_text(pick(row, "Organization", default=""))
            display = " ".join(filter(None, [first, last])) or org
            fields = multi.get(rid, {})
            phones = fields.get("phone", [])
            emails = fields.get("email", [])
            if not (display or phones or emails):
                continue

            art = Artifact(
                category=Category.CONTACT, subtype="Contact",
                timestamp=from_epoch(pick(row, "ModificationDate",
                                          "CreationDate"), "apple"),
                body=display or (phones[0] if phones else ""),
                app="Apple Contacts", source_path=ctx.rel(path),
                source_table="ABPerson", source_row=rid,
                recovery=recovery, confidence=conf,
                attributes={
                    "display_name": display,
                    "first_name": first, "last_name": last,
                    "middle_name": as_text(pick(row, "Middle", default="")),
                    "nickname": as_text(pick(row, "Nickname", default="")),
                    "organisation": org,
                    "job_title": as_text(pick(row, "JobTitle", default="")),
                    "department": as_text(pick(row, "Department", default="")),
                    "note": as_text(pick(row, "Note", default="")),
                    "phone_numbers": phones,
                    "emails": emails,
                    "urls": fields.get("url", []),
                    "addresses": fields.get("address", []),
                    "social": fields.get("social", []),
                    "birthday": from_epoch(pick(row, "Birthday"), "apple"),
                    "created": from_epoch(pick(row, "CreationDate"), "apple"),
                    "modified": from_epoch(pick(row, "ModificationDate"), "apple"),
                },
            )
            for p in phones:
                art.add_participant(p, display, role="party")
            for e in emails:
                art.add_participant(e, display, role="party")
            if not art.participants:
                art.add_participant("", display, role="party")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        if deleted_mv:
            res.notes.append(
                f"{path.name}: {deleted_mv} deleted ABMultiValue rows recovered "
                f"(phone numbers/emails belonging to removed contacts)")
        res.warnings.extend(db.warnings)
    return res
