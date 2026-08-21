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
    return ("dumpsys" in path.as_posix()
            or "telephony_identity" in path.as_posix()
            or "last known" in head or "call log" in head
            or "notificationrecord" in head or "subscriptioninfo" in head)


@register(
    name="android.dumpsys_comms",
    patterns=["dumpsys/call_log.txt", "dumpsys/telephony.txt",
              "dumpsys/telecom.txt", "dumpsys/telecom_dump.txt",
              "dumpsys/phone.txt",
              "dumpsys/contacts.txt", "dumpsys/location.txt",
              "dumpsys/fused.txt", "dumpsys/notification.txt",
              "dumpsys/isub.txt", "dumpsys/sms.txt", "dumpsys/mms.txt",
              "dumpsys/iphonesubinfo.txt", "dumpsys/simphonebook.txt",
              "dumpsys/iccphonebook.txt", "dumpsys/shortcut.txt",
              "dumpsys/activity_recents.txt",
              "dumpsys/logs.txt", "dumpsys/incallui.txt",
              "comms/telephony_identity.txt"],
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
    if name in ("call_log", "telephony", "logs", "incallui"):
        _parse_calls(text, path, ctx, res)
        _parse_telecom(text, path, ctx, res)
        _parse_keyed_calls(text, path, ctx, res)
    elif name in ("telecom", "telecom_dump", "phone"):
        _parse_telecom(text, path, ctx, res)
        _parse_calls(text, path, ctx, res)
        _parse_keyed_calls(text, path, ctx, res)
    elif name == "contacts":
        _parse_contacts(text, path, ctx, res)
    elif name in ("location", "fused"):
        _parse_location(text, path, ctx, res)
    elif name == "notification":
        _parse_notifications(text, path, ctx, res)
    elif name in ("sms", "mms"):
        _parse_sms_dump(text, path, ctx, res)
        _parse_notifications(text, path, ctx, res)
    elif name in ("isub", "iphonesubinfo", "telephony_identity"):
        _parse_subscription(text, path, ctx, res)
    elif name in ("shortcut", "activity_recents"):
        _parse_notifications(text, path, ctx, res)
        _parse_contacts(text, path, ctx, res)
    elif name in ("simphonebook", "iccphonebook"):
        _parse_contacts(text, path, ctx, res)
    else:
        _parse_calls(text, path, ctx, res)
        _parse_telecom(text, path, ctx, res)
        _parse_location(text, path, ctx, res)
        _parse_subscription(text, path, ctx, res)
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


def _parse_keyed_calls(text: str, path: Path, ctx: ParseContext,
                       res: ParseResult) -> None:
    """Samsung/AOSP dumpsys often puts number and date on separate lines."""
    seen: set = set()
    current: Dict[str, str] = {}

    def flush() -> None:
        number = clean_number(current.get("number") or current.get("addr")
                              or current.get("phone") or "")
        if not number:
            return
        ts = guess(current.get("date") or current.get("time")
                   or current.get("when"), "date")
        if ts and not ctx.in_span(ts):
            return
        key = (number, ts, current.get("type", ""), current.get("duration", ""))
        if key in seen:
            return
        seen.add(key)
        duration = current.get("duration") or ""
        body = f"Call — {number}"
        if duration:
            body += f" ({duration}s)"
        name = (current.get("name") or current.get("cname") or "").strip()
        art = Artifact(
            category=Category.CALL, subtype="Call (dumpsys)",
            timestamp=ts, direction=Direction.UNKNOWN,
            body=body,
            app="Android (dumpsys)",
            source_path=ctx.rel(path),
            attributes={"duration": duration, "type": current.get("type", "")},
        )
        art.add_participant(number, name, role="party")
        res.artifacts.append(art)

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                flush()
                current = {}
            continue
        match = re.match(
            r"(number|addr|phone|date|time|when|duration|type|name|cname)"
            r"\s*[=:]\s*(.+)$",
            stripped, re.IGNORECASE)
        if not match:
            continue
        key = match.group(1).lower()
        if key == "number" and current.get("number"):
            flush()
            current = {}
        current[key] = match.group(2).strip().strip(",")
    if current:
        flush()


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


_MSG_PKGS = (
    "com.samsung.android.messaging",
    "com.google.android.apps.messaging",
    "com.android.mms",
    "com.android.messaging",
    "com.google.android.apps.dynamite",
    "com.whatsapp",
    "org.telegram.messenger",
    "com.facebook.orca",
    "com.instagram.android",
    "com.android.incallui",
    "com.samsung.android.incallui",
    "com.google.android.dialer",
    "com.samsung.android.dialer",
    "com.android.dialer",
)

_MSG_PKG_HINTS = ("messaging", "mms", "sms", "dialer", "incallui", "whatsapp",
                  "telegram", "signal")


def _is_messaging_pkg(pkg: str) -> bool:
    p = (pkg or "").lower()
    if p in _MSG_PKGS:
        return True
    return any(h in p for h in _MSG_PKG_HINTS)


def _extra_field(block: str, key: str) -> str:
    match = re.search(
        rf"{re.escape(key)}\s*[=:]\s*(?:String\s+\()?(.*)",
        block, re.IGNORECASE)
    if not match:
        return ""
    value = match.group(1).strip().strip(")").strip()
    value = value.split("\n", 1)[0].strip().strip(",")
    if value.lower() in ("null", "none", "(null)", ""):
        return ""
    return value[:2000]


def _parse_telecom(text: str, path: Path, ctx: ParseContext,
                   res: ParseResult) -> None:
    current: Dict[str, str] = {}
    seen: set = set()

    def flush() -> None:
        if not current:
            return
        handle = current.get("handle") or current.get("number") or ""
        number = clean_number(
            re.sub(r"^(tel:|sip:)", "", handle, flags=re.I).strip())
        if not number:
            return
        ts = guess(current.get("connect") or current.get("create")
                   or current.get("disconnect"), "date")
        if ts and not ctx.in_span(ts):
            return
        key = (number, ts, current.get("state", ""))
        if key in seen:
            return
        seen.add(key)
        incoming = (current.get("incoming") or "").lower() in ("true", "1")
        direction = Direction.INCOMING if incoming else Direction.OUTGOING
        state = current.get("state") or ""
        if "miss" in state.lower() or "ringing" in state.lower():
            direction = Direction.MISSED
            subtype = "Missed call (telecom)"
        else:
            subtype = "Call (telecom)"
        duration = ""
        try:
            c = int(current.get("connect") or 0)
            d = int(current.get("disconnect") or 0)
            if c and d and d > c:
                duration = str(int((d - c) / 1000))
        except (TypeError, ValueError):
            pass
        body = f"{subtype} — {number}"
        if duration:
            body += f" ({duration}s)"
        art = Artifact(
            category=Category.CALL, subtype=subtype,
            timestamp=ts, direction=direction, body=body,
            app="Android Telecom (dumpsys)",
            source_path=ctx.rel(path),
            attributes={
                "state": state,
                "handle": handle,
                "duration_seconds": duration,
            },
        )
        art.add_participant(number, "", role="party")
        res.artifacts.append(art)

    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("call ") or low.startswith("call:"):
            flush()
            current = {}
            continue
        if low.startswith("handle:"):
            current["handle"] = stripped.split(":", 1)[-1].strip()
        elif "connecttimemillis" in low.replace(" ", ""):
            current["connect"] = stripped.split(":")[-1].strip()
        elif "createtimemillis" in low.replace(" ", ""):
            current["create"] = stripped.split(":")[-1].strip()
        elif "disconnecttimemillis" in low.replace(" ", ""):
            current["disconnect"] = stripped.split(":")[-1].strip()
        elif low.startswith("state:"):
            current["state"] = stripped.split(":", 1)[-1].strip()
        elif "isincoming" in low.replace(" ", ""):
            current["incoming"] = stripped.split(":")[-1].strip()
        elif low.startswith("number=") or low.startswith("number:"):
            current["number"] = re.split(r"[=:]", stripped, maxsplit=1)[-1].strip()
    flush()


def _parse_notifications(text: str, path: Path, ctx: ParseContext,
                         res: ParseResult) -> None:
    seen: set = set()
    chunks = re.split(r"NotificationRecord", text)
    for chunk in chunks[1:]:
        pkg_m = re.search(r"opPkg=(\S+)", chunk)
        pkg = pkg_m.group(1) if pkg_m else ""
        if not _is_messaging_pkg(pkg):
            continue
        title = _extra_field(chunk, "android.title")
        body = (_extra_field(chunk, "android.bigText")
                or _extra_field(chunk, "android.text")
                or _extra_field(chunk, "android.subText"))
        if not body and not title:
            continue
        when_m = re.search(r"when=(\d{10,13})", chunk)
        ts = guess(when_m.group(1) if when_m else None, "date")
        if ts and not ctx.in_span(ts):
            continue
        key = (pkg, title, body[:80], ts)
        if key in seen:
            continue
        seen.add(key)
        phones = _PHONE.findall(title + " " + body)
        number = clean_number(phones[0]) if phones else ""
        is_call = "dialer" in pkg or "incallui" in pkg
        art = Artifact(
            category=Category.CALL if is_call else Category.MESSAGE,
            subtype=("Call notification" if is_call
                     else "SMS / chat notification"),
            timestamp=ts, direction=Direction.INCOMING,
            body=body or title,
            app=pkg or "Android Notification",
            source_path=ctx.rel(path),
            attributes={"title": title, "package": pkg},
        )
        if number:
            art.add_participant(number, title, role="party")
        elif title:
            art.add_participant("", title, role="party")
        res.artifacts.append(art)


def _parse_sms_dump(text: str, path: Path, ctx: ParseContext,
                    res: ParseResult) -> None:
    seen: set = set()

    def add(number: str, body: str, ts: Optional[int] = None) -> None:
        number = clean_number(number)
        body = re.sub(r"\s+", " ", body or "").strip()[:2000]
        if not number or not body:
            return
        if ts and not ctx.in_span(ts):
            return
        key = (number, body[:80], ts)
        if key in seen:
            return
        seen.add(key)
        art = Artifact(
            category=Category.MESSAGE, subtype="SMS (dumpsys)",
            timestamp=ts, direction=Direction.UNKNOWN, body=body,
            app="Android SMS (dumpsys)",
            source_path=ctx.rel(path),
        )
        art.add_participant(number, "", role="party")
        res.artifacts.append(art)

    for match in re.finditer(
            r"(?:address|addr|from|originatingAddress)=([+\d][\d\- ]{5,}\d)"
            r".{0,400}?(?:body|text|msg|messageBody)=(.+?)(?:,\s*\w+=|$)",
            text, re.IGNORECASE | re.DOTALL):
        add(match.group(1), match.group(2))
    current: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                add(current.get("address") or current.get("originatingaddress")
                    or "", current.get("body") or current.get("messagebody")
                    or current.get("text") or "",
                    guess(current.get("date"), "date"))
                current = {}
            continue
        match = re.match(
            r"(address|addr|originatingAddress|body|text|msg|messageBody|date)"
            r"\s*[=:]\s*(.+)$",
            stripped, re.IGNORECASE)
        if not match:
            continue
        current[match.group(1).lower()] = match.group(2).strip().strip(",")
    if current:
        add(current.get("address") or current.get("originatingaddress") or "",
            current.get("body") or current.get("messagebody")
            or current.get("text") or "",
            guess(current.get("date"), "date"))


def _parse_subscription(text: str, path: Path, ctx: ParseContext,
                        res: ParseResult) -> None:
    seen: set = set()
    # SubscriptionInfo dumps and getprop msisdn lines.
    for match in re.finditer(
            r"(?:number|msisdn|line1Number|mNumber)\s*[=:]\s*([+\d][\d\- ]{6,}\d)",
            text, re.IGNORECASE):
        number = clean_number(match.group(1))
        if not number or number in seen:
            continue
        seen.add(number)
        art = Artifact(
            category=Category.DEVICE, subtype="Subscriber number",
            body=f"MSISDN / line number — {number}",
            app="Android Telephony",
            source_path=ctx.rel(path),
            attributes={"msisdn": number},
        )
        art.add_participant(number, "", role="owner")
        res.artifacts.append(art)
    for match in re.finditer(
            r"(?:iccId|iccid|mIccId)\s*[=:]\s*([0-9A-Fa-f]{10,})",
            text, re.IGNORECASE):
        iccid = match.group(1).strip()
        if iccid in seen:
            continue
        seen.add(iccid)
        art = Artifact(
            category=Category.DEVICE, subtype="SIM ICCID",
            body=f"ICCID — {iccid}",
            app="Android Telephony",
            source_path=ctx.rel(path),
            attributes={"iccid": iccid},
        )
        res.artifacts.append(art)
