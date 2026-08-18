"""Android contacts (``contacts2.db``).

Lab manual Step 20 / §6.7 — the contact list in column view, with participant
identity and source account.

Android normalises contacts across three tables: ``raw_contacts`` (one row per
source account), ``data`` (typed values keyed by ``mimetype``) and ``contacts``
(the aggregated person).  Reading only ``raw_contacts`` gives you names with no
numbers, which is a common and unhelpful mistake.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from ...core.models import Artifact, Category, Recovery
from ..common import any_table_probe, as_int, as_text, clean_number, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

MIME = {
    "vnd.android.cursor.item/phone_v2": "phone",
    "vnd.android.cursor.item/email_v2": "email",
    "vnd.android.cursor.item/name": "name",
    "vnd.android.cursor.item/postal-address_v2": "address",
    "vnd.android.cursor.item/organization": "organisation",
    "vnd.android.cursor.item/note": "note",
    "vnd.android.cursor.item/nickname": "nickname",
    "vnd.android.cursor.item/website": "website",
    "vnd.android.cursor.item/im": "im",
}

PHONE_TYPE = {1: "Home", 2: "Mobile", 3: "Work", 4: "Work Fax", 5: "Home Fax",
              6: "Pager", 7: "Other", 12: "Main", 17: "Work Mobile"}


@register(
    name="android.contacts",
    patterns=["contacts2.db", "contacts.db", "profile.db"],
    platform="android", priority=80,
    probe=any_table_probe(("raw_contacts", "data"), ("contacts",)),
    description="Android contacts provider",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """Android contacts."""
    res = ParseResult(parser="android.contacts", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        if not db.has_table("raw_contacts"):
            res.notes.append(f"{path.name}: no raw_contacts table")
            return res

        mimetypes = {}
        if db.has_table("mimetypes"):
            for r in db.rows("mimetypes"):
                mimetypes[as_int(r.get("_id"))] = as_text(r.get("mimetype"))

        # Bucket the data table by raw_contact_id
        data_by_contact: Dict[int, List[dict]] = defaultdict(list)
        deleted_data = 0
        if db.has_table("data"):
            for row, recovery, conf in rows_with_deleted(db, "data", ctx):
                rcid = as_int(row.get("raw_contact_id"))
                if rcid is None:
                    continue
                row["__recovery"] = recovery
                row["__confidence"] = conf
                data_by_contact[rcid].append(row)
                if recovery != Recovery.ALLOCATED:
                    deleted_data += 1

        for row, recovery, conf in rows_with_deleted(db, "raw_contacts", ctx):
            rcid = as_int(row.get("_rowid") or row.get("_id"))
            display = as_text(pick(row, "display_name",
                                   "display_name_alt", default="")).strip()
            fields = _collect(data_by_contact.get(rcid, []), mimetypes)
            if not display:
                display = (fields.get("name") or [""])[0]
            numbers = fields.get("phone", [])
            emails = fields.get("email", [])
            if not (display or numbers or emails):
                continue

            worst_conf = min([conf] + [d.get("__confidence", 1.0)
                                       for d in data_by_contact.get(rcid, [])])
            art = Artifact(
                category=Category.CONTACT, subtype="Contact",
                timestamp=guess(pick(row, "contact_last_updated_timestamp"),
                                "contact_last_updated_timestamp"),
                body=display or (numbers[0] if numbers else ""),
                app=as_text(pick(row, "account_type", default="")) or "Android Contacts",
                source_path=ctx.rel(path), source_table="raw_contacts",
                source_row=rcid, recovery=recovery, confidence=worst_conf,
                attributes={
                    "display_name": display,
                    "phone_numbers": numbers,
                    "phone_labels": fields.get("phone_labels", []),
                    "emails": emails,
                    "addresses": fields.get("address", []),
                    "organisation": fields.get("organisation", []),
                    "note": fields.get("note", []),
                    "nickname": fields.get("nickname", []),
                    "websites": fields.get("website", []),
                    "im_handles": fields.get("im", []),
                    "account_name": as_text(pick(row, "account_name", default="")),
                    "account_type": as_text(pick(row, "account_type", default="")),
                    "starred": as_int(pick(row, "starred")),
                    "times_contacted": as_int(pick(row, "times_contacted")),
                    "last_time_contacted": guess(pick(row, "last_time_contacted"),
                                                 "last_time_contacted"),
                    "deleted_flag": as_int(pick(row, "deleted")),
                },
            )
            for n in numbers:
                art.add_participant(n, display, role="party")
            for e in emails:
                art.add_participant(e, display, role="party")
            if not art.participants:
                art.add_participant("", display, role="party")
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED or as_int(pick(row, "deleted")) == 1:
                res.deleted_recovered += 1

        if deleted_data:
            res.notes.append(
                f"{path.name}: {deleted_data} deleted rows recovered from the "
                f"'data' table (phone numbers/emails of removed contacts)")
        res.warnings.extend(db.warnings)
    return res


def _collect(rows: List[dict], mimetypes: Dict[int, str]) -> Dict[str, list]:
    out: Dict[str, list] = defaultdict(list)
    for r in rows:
        mt = mimetypes.get(as_int(r.get("mimetype_id")), "") or as_text(r.get("mimetype"))
        kind = MIME.get(mt, "")
        d1 = as_text(r.get("data1", ""))
        if not d1:
            continue
        if kind == "phone":
            num = clean_number(d1)
            if num and num not in out["phone"]:
                out["phone"].append(num)
                out["phone_labels"].append(
                    PHONE_TYPE.get(as_int(r.get("data2")) or 0, "Other"))
        elif kind and d1 not in out[kind]:
            out[kind].append(d1)
    return dict(out)
