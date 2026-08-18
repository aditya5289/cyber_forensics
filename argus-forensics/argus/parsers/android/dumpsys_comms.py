"""Parse ``dumpsys`` fallbacks when content providers are blocked (Vivo/BBK)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.models import Artifact, Category, Direction
from ..common import clean_number
from ..registry import ParseContext, ParseResult, register
from ..timestamps import guess

_CALL_LINE = re.compile(
    r"(?:number|addr|phone)=([^,\s]+).*?(?:date|time|when)=([0-9]+)",
    re.IGNORECASE)
_COORD = re.compile(
    r"(?:lat(?:itude)?|lon(?:gitude)?|lng)\s*[=:]\s*(-?\d+\.\d+)",
    re.IGNORECASE)
_PHONE = re.compile(r"(?:\+?\d[\d\s\-()]{6,}\d)")


def _probe_dumpsys(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:600].lower()
    except OSError:
        return False
    return "dumpsys" in path.as_posix() or "last known" in head or "call log" in head


@register(
    name="android.dumpsys_comms",
    patterns=["dumpsys/call_log.txt", "dumpsys/telephony.txt",
              "dumpsys/telecom.txt", "dumpsys/phone.txt",
              "dumpsys/contacts.txt", "dumpsys/location.txt",
              "dumpsys/fused.txt", "dumpsys/notification.txt",
              "dumpsys/isub.txt"],
    platform="android",
    priority=85,
    probe=_probe_dumpsys,
    description="ADB dumpsys fallbacks for calls, contacts and GPS",
)
def parse_dumpsys(path: Path, ctx: ParseContext) -> ParseResult:
    res = ParseResult(parser="android.dumpsys_comms", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(str(exc))
        return res

    name = path.stem.lower()
    if name in ("call_log", "telephony"):
        _parse_calls(text, path, ctx, res)
    elif name == "contacts":
        _parse_contacts(text, path, ctx, res)
    elif name in ("location", "fused"):
        _parse_location(text, path, ctx, res)
    else:
        _parse_calls(text, path, ctx, res)
        _parse_location(text, path, ctx, res)
    return res


def _parse_calls(text: str, path: Path, ctx: ParseContext,
                 res: ParseResult) -> None:
    seen: set = set()
    for match in _CALL_LINE.finditer(text):
        number = clean_number(match.group(1))
        ts = guess(match.group(2), "date")
        if not number or (number, ts) in seen:
            continue
        seen.add((number, ts))
        if ts and not ctx.in_span(ts):
            continue
        art = Artifact(
            category=Category.CALL, subtype="Call (dumpsys)",
            timestamp=ts, direction=Direction.UNKNOWN,
            body=f"Call — {number}",
            app="Android (dumpsys)",
            source_path=ctx.rel(path),
        )
        art.add_participant(number, "", role="party")
        res.artifacts.append(art)


def _parse_contacts(text: str, path: Path, ctx: ParseContext,
                    res: ParseResult) -> None:
    for line in text.splitlines():
        if "display" not in line.lower() and "name" not in line.lower():
            continue
        phones = _PHONE.findall(line)
        if not phones:
            continue
        name = line.split("=", 1)[-1].strip()[:120]
        for raw in phones[:3]:
            number = clean_number(raw)
            if not number:
                continue
            art = Artifact(
                category=Category.CONTACT, subtype="Contact (dumpsys)",
                body=name or number,
                app="Android (dumpsys)",
                source_path=ctx.rel(path),
                attributes={"display_name": name, "phone_numbers": [number]},
            )
            art.add_participant(number, name, role="party")
            res.artifacts.append(art)


def _parse_location(text: str, path: Path, ctx: ParseContext,
                    res: ParseResult) -> None:
    for line in text.splitlines():
        low = line.lower()
        if "lat" not in low or "lon" not in low:
            continue
        nums = re.findall(r"-?\d+\.\d+", line)
        if len(nums) < 2:
            continue
        lat, lon = float(nums[0]), float(nums[1])
        if abs(lat) > 90 or abs(lon) > 180:
            continue
        art = Artifact(
            category=Category.PLACE, subtype="Last known location",
            latitude=lat, longitude=lon,
            body=f"{lat:.5f}, {lon:.5f}",
            app="Android Location (dumpsys)",
            source_path=ctx.rel(path),
            attributes={
                "map_url": (f"https://www.openstreetmap.org/?mlat={lat}"
                            f"&mlon={lon}#map=16/{lat}/{lon}"),
            },
        )
        res.artifacts.append(art)
