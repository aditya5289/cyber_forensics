"""Timestamp normalisation.

Mobile platforms disagree about what "a time" is.  A single WhatsApp database
can contain Unix milliseconds, an iOS companion table can contain Apple
absolute time, and a browser history table sitting next to it can contain
WebKit microseconds.  Comparing them naively produces timelines that are wrong
by decades, which is a much worse failure than producing no timeline at all.

ARGUS normalises everything to **integer microseconds since 1970-01-01 UTC**
and refuses conversions that fall outside a plausibility window.

Supported epochs
----------------
==================  =============================  =====================
Name                Epoch                          Unit
==================  =============================  =====================
``unix_s``          1970-01-01                     seconds
``unix_ms``         1970-01-01                     milliseconds
``unix_us``         1970-01-01                     microseconds
``unix_ns``         1970-01-01                     nanoseconds
``apple``           2001-01-01 (Mac absolute)      seconds (may be float)
``apple_ns``        2001-01-01                     nanoseconds
``webkit``          1601-01-01 (Chrome/Safari)     microseconds
``filetime``        1601-01-01 (Windows)           100-nanoseconds
``julian``          -4713-11-24 12:00 (SQLite)     days (float)
``gps``             1980-01-06                     seconds
==================  =============================  =====================
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

US = 1_000_000

APPLE_OFFSET_US = 978_307_200 * US          # 2001-01-01 - 1970-01-01
WEBKIT_OFFSET_US = 11_644_473_600 * US      # 1970-01-01 - 1601-01-01
GPS_OFFSET_US = 315_964_800 * US            # 1980-01-06 - 1970-01-01
JULIAN_UNIX_EPOCH = 2_440_587.5             # Julian day of 1970-01-01T00:00Z

# Plausibility window for mobile evidence: 1995-01-01 .. 2065-01-01
MIN_US = 789_004_800 * US
MAX_US = 3_000_000_000 * US


def _plausible(us: Optional[int]) -> Optional[int]:
    if us is None:
        return None
    return us if MIN_US <= us <= MAX_US else None


def from_epoch(value, epoch: str) -> Optional[int]:
    """Convert ``value`` in the named ``epoch`` to microseconds since 1970 UTC."""
    if value is None or value == "":
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v == 0:
        return None

    match epoch:
        case "unix_s":    us = int(round(v * US))
        case "unix_ms":   us = int(round(v * 1000))
        case "unix_us":   us = int(round(v))
        case "unix_ns":   us = int(round(v / 1000))
        case "apple":     us = int(round(v * US)) + APPLE_OFFSET_US
        case "apple_ns":  us = int(round(v / 1000)) + APPLE_OFFSET_US
        case "webkit":    us = int(round(v)) - WEBKIT_OFFSET_US
        case "filetime":  us = int(round(v / 10)) - WEBKIT_OFFSET_US
        case "julian":    us = int(round((v - JULIAN_UNIX_EPOCH) * 86400 * US))
        case "gps":       us = int(round(v * US)) + GPS_OFFSET_US
        case _:
            raise ValueError(f"unknown epoch {epoch!r}")
    return _plausible(us)


def guess(value, hint: str = "") -> Optional[int]:
    """Infer the epoch from magnitude, then convert.

    ``hint`` is the originating column name; names containing 'apple', 'z',
    'webkit' or 'chrome' bias the guess. Returns ``None`` when no
    interpretation lands inside the plausibility window — silence is better
    than a fabricated 1601 timestamp.
    """
    if value is None or value == "":
        return None

    if isinstance(value, str):
        parsed = from_iso(value)
        if parsed is not None:
            return parsed
        try:
            value = float(value)
        except ValueError:
            return None

    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None

    h = (hint or "").lower()
    order: list[str]
    if "webkit" in h or "chrome" in h or "visit" in h:
        order = ["webkit", "unix_us", "unix_ms", "unix_s", "apple"]
    elif h.startswith("z") or "apple" in h or "mac" in h:
        order = ["apple", "unix_s", "unix_ms", "unix_us", "apple_ns", "webkit"]
    elif 2_400_000 < v < 2_600_000:
        order = ["julian"]
    else:
        order = ["unix_s", "unix_ms", "unix_us", "unix_ns",
                 "apple", "webkit", "filetime", "apple_ns"]

    for epoch in order:
        got = from_epoch(v, epoch)
        if got is not None:
            return got
    return None


def from_iso(text: str) -> Optional[int]:
    """Parse common ISO-8601 / SQL datetime spellings."""
    s = (text or "").strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    candidates = [s]
    if " " in s and "T" not in s:
        candidates.append(s.replace(" ", "T", 1))
    for cand in candidates:
        try:
            dt = datetime.fromisoformat(cand)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _plausible(int(dt.timestamp() * US))
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S",
                "%Y%m%dT%H%M%S", "%a %b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return _plausible(int(dt.timestamp() * US))
        except ValueError:
            continue
    return None


def to_iso(us: Optional[int], tz_offset_minutes: int = 0) -> str:
    """Render microseconds-since-epoch as an ISO string in the given offset."""
    if us is None:
        return ""
    tz = timezone(timedelta(minutes=tz_offset_minutes))
    return (datetime.fromtimestamp(us / US, tz=timezone.utc)
            .astimezone(tz).isoformat(timespec="seconds"))


def to_datetime(us: Optional[int]) -> Optional[datetime]:
    if us is None:
        return None
    return datetime.fromtimestamp(us / US, tz=timezone.utc)


def now_us() -> int:
    return int(datetime.now(timezone.utc).timestamp() * US)


def span_to_range(span: str, reference: Optional[int] = None
                  ) -> Tuple[Optional[int], Optional[int]]:
    """Lab manual Step 9 — turn a time-span selection into a bounded window.

    Accepts ``all``, ``24h``, ``7d``, ``30d``, ``365d``, or an explicit
    ``YYYY-MM-DD..YYYY-MM-DD`` custom range.
    """
    ref = reference or now_us()
    s = (span or "all").strip().lower()
    if s in ("all", "", "*"):
        return None, None
    presets = {"24h": 1, "1d": 1, "7d": 7, "30d": 30, "90d": 90,
               "365d": 365, "1y": 365}
    if s in presets:
        return ref - presets[s] * 86400 * US, ref
    if ".." in s:
        lo_s, _, hi_s = s.partition("..")
        lo = from_iso(lo_s.strip()) if lo_s.strip() else None
        hi = from_iso(hi_s.strip()) if hi_s.strip() else None
        if hi is not None and len(hi_s.strip()) <= 10:
            hi += 86400 * US - 1          # inclusive end-of-day
        return lo, hi
    raise ValueError(
        f"unrecognised time span {span!r}; use all | 24h | 7d | 30d | 365d | "
        f"YYYY-MM-DD..YYYY-MM-DD")
