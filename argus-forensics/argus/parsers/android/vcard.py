"""vCard contacts exported to shared storage (common on MTP-only handsets).

Manufacturers and backup apps often drop ``.vcf`` files under ``Download``,
``Backup``, or ``Contacts`` folders. These are frequently the only contact
export reachable without USB debugging.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

from ...core.models import Artifact, Category
from ..registry import ParseContext, ParseResult, register
from ..timestamps import guess

_UNFOLD = re.compile(r"\r?\n[ \t]")
_VCARD_SPLIT = re.compile(r"BEGIN:VCARD", re.IGNORECASE)


def _probe_vcard(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return False
    low = head.lower()
    return b"begin:vcard" in low or b"vcard.version" in low


@register(
    name="android.vcard",
    patterns=["*.vcf", "*.vcard", "**/Contacts/**/*.vcf",
              "**/contacts/**/*.vcf", "**/Download/**/*.vcf"],
    platform="android",
    priority=75,
    probe=_probe_vcard,
    description="vCard contact exports on shared storage",
)
def parse_vcard(path: Path, ctx: ParseContext) -> ParseResult:
    """vCard contacts."""
    res = ParseResult(parser="android.vcard", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    text = _UNFOLD.sub("", text)
    cards = 0
    for block in _VCARD_SPLIT.split(text):
        block = block.strip()
        if not block:
            continue
        if not block.upper().startswith("VCARD"):
            block = "BEGIN:VCARD\n" + block
        entry = _parse_card(block)
        if not entry:
            continue
        name, phones, emails, org, note = entry
        if not (name or phones or emails):
            continue
        art = Artifact(
            category=Category.CONTACT,
            subtype="vCard contact",
            timestamp=guess(int(path.stat().st_mtime), "mtime"),
            body=name or (phones[0] if phones else ""),
            app="vCard export",
            source_path=ctx.rel(path),
            attributes={
                "display_name": name,
                "phone_numbers": phones,
                "emails": emails,
                "organisation": org,
                "note": note,
            },
        )
        for n in phones:
            art.add_participant(n, name, role="party")
        for e in emails:
            art.add_participant(e, name, role="party")
        res.artifacts.append(art)
        cards += 1

    if cards:
        res.notes.append(f"{ctx.rel(path)}: {cards} vCard contact(s)")
    return res


def _parse_card(block: str) -> Tuple[str, List[str], List[str], str, str] | None:
    name = ""
    phones: List[str] = []
    emails: List[str] = []
    org = ""
    note = ""
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.split(";")[0].upper()
        value = value.strip()
        if key == "FN":
            name = value
        elif key == "N" and not name:
            parts = value.split(";")
            name = " ".join(p for p in parts if p).strip()
        elif key == "TEL":
            if value and value not in phones:
                phones.append(value)
        elif key == "EMAIL":
            if value and value not in emails:
                emails.append(value)
        elif key == "ORG":
            org = value
        elif key == "NOTE":
            note = value
    return name, phones, emails, org, note
