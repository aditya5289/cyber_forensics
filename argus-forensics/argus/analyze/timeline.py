"""Timeline construction and behavioural statistics.

The timeline is the backbone of a mobile examination: it is what lets an
examiner say "at 02:14 the handset was here, and four minutes later it messaged
this number".

Beyond a sorted list, this module produces:

* **Activity histograms** by hour-of-day and day-of-week — the device owner's
  routine, and therefore the anomalies in it.
* **Bursts** — clusters of activity separated by quiet periods, computed with a
  gap threshold rather than fixed buckets, so a conversation is one burst
  regardless of where the hour boundary falls.
* **Gaps** — long silences. A device that is normally busy and then goes quiet
  for eleven hours is a finding, not an absence of one.
* **Timestamp anomalies** — artifacts dated in the future, or before the
  device existed, which usually mean a clock change or tampering.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.db import ArtifactDB
from ..core.models import Artifact, Category, Direction, Recovery
from ..parsers.timestamps import to_datetime, to_iso, now_us

US = 1_000_000
DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
             "Saturday", "Sunday"]


@dataclass
class TimelineEntry:
    timestamp: int
    iso: str
    category: str
    subtype: str
    app: str
    direction: str
    summary: str
    parties: List[str] = field(default_factory=list)
    artifact_id: str = ""
    recovery: str = "allocated"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build(artifacts: Iterable[Artifact], tz_offset_minutes: int = 0
          ) -> List[TimelineEntry]:
    """Produce a chronologically ordered timeline."""
    entries: List[TimelineEntry] = []
    for art in artifacts:
        if art.timestamp is None:
            continue
        entries.append(TimelineEntry(
            timestamp=art.timestamp,
            iso=to_iso(art.timestamp, tz_offset_minutes),
            category=art.category.value,
            subtype=art.subtype,
            app=art.app,
            direction=art.direction.value,
            summary=art.summary(160),
            parties=[p.label() for p in art.counterparties()][:6],
            artifact_id=art.artifact_id,
            recovery=art.recovery.value,
            latitude=art.latitude, longitude=art.longitude,
            tags=list(art.tags),
        ))
    entries.sort(key=lambda e: e.timestamp)
    return entries


def histogram(entries: List[TimelineEntry], tz_offset_minutes: int = 0
              ) -> Dict[str, Any]:
    """Activity by hour of day, day of week and calendar day."""
    tz = timezone(timedelta(minutes=tz_offset_minutes))
    by_hour = Counter()
    by_weekday = Counter()
    by_day: Counter = Counter()
    by_category_day: Dict[str, Counter] = defaultdict(Counter)

    for e in entries:
        dt = datetime.fromtimestamp(e.timestamp / US, tz=timezone.utc).astimezone(tz)
        by_hour[dt.hour] += 1
        by_weekday[dt.weekday()] += 1
        day = dt.strftime("%Y-%m-%d")
        by_day[day] += 1
        by_category_day[e.category][day] += 1

    night = sum(by_hour[h] for h in list(range(0, 6)))
    total = sum(by_hour.values()) or 1
    return {
        "by_hour": [{"hour": h, "count": by_hour.get(h, 0)} for h in range(24)],
        "by_weekday": [{"day": DAY_NAMES[d], "count": by_weekday.get(d, 0)}
                       for d in range(7)],
        "by_day": [{"date": d, "count": c} for d, c in sorted(by_day.items())],
        "by_category_day": {k: dict(sorted(v.items()))
                            for k, v in by_category_day.items()},
        "peak_hour": max(by_hour, key=by_hour.get) if by_hour else None,
        "peak_day": max(by_day, key=by_day.get) if by_day else None,
        "night_activity_pct": round(100.0 * night / total, 1),
        "active_days": len(by_day),
        "timezone_offset_minutes": tz_offset_minutes,
    }


def bursts(entries: List[TimelineEntry], gap_minutes: int = 45,
           min_size: int = 3) -> List[Dict[str, Any]]:
    """Cluster activity into sessions separated by quiet gaps."""
    if not entries:
        return []
    gap = gap_minutes * 60 * US
    clusters: List[List[TimelineEntry]] = [[entries[0]]]
    for prev, cur in zip(entries, entries[1:]):
        if cur.timestamp - prev.timestamp <= gap:
            clusters[-1].append(cur)
        else:
            clusters.append([cur])

    out: List[Dict[str, Any]] = []
    for c in clusters:
        if len(c) < min_size:
            continue
        apps = Counter(e.app for e in c if e.app)
        parties = Counter(p for e in c for p in e.parties)
        out.append({
            "start": c[0].timestamp, "start_iso": c[0].iso,
            "end": c[-1].timestamp, "end_iso": c[-1].iso,
            "duration_minutes": round((c[-1].timestamp - c[0].timestamp) / (60 * US), 1),
            "count": len(c),
            "categories": dict(Counter(e.category for e in c)),
            "apps": dict(apps.most_common(5)),
            "top_parties": [p for p, _ in parties.most_common(5)],
            "deleted_in_burst": sum(1 for e in c if e.recovery != "allocated"),
        })
    return sorted(out, key=lambda b: -b["count"])


def gaps(entries: List[TimelineEntry], min_hours: float = 8.0
         ) -> List[Dict[str, Any]]:
    """Find unusually long silences in device activity."""
    out: List[Dict[str, Any]] = []
    threshold = int(min_hours * 3600 * US)
    for prev, cur in zip(entries, entries[1:]):
        delta = cur.timestamp - prev.timestamp
        if delta >= threshold:
            out.append({
                "from": prev.timestamp, "from_iso": prev.iso,
                "to": cur.timestamp, "to_iso": cur.iso,
                "hours": round(delta / (3600 * US), 1),
                "before": prev.summary[:80],
                "after": cur.summary[:80],
            })
    return sorted(out, key=lambda g: -g["hours"])


def anomalies(entries: List[TimelineEntry]) -> List[Dict[str, Any]]:
    """Timestamps that cannot be right — clock changes or tampering."""
    out: List[Dict[str, Any]] = []
    now = now_us()
    horizon = now + 86_400 * US            # tolerate a day of clock skew
    ancient = int(datetime(2007, 1, 1, tzinfo=timezone.utc).timestamp() * US)

    for e in entries:
        if e.timestamp > horizon:
            out.append({"artifact_id": e.artifact_id, "iso": e.iso,
                        "reason": "timestamp is in the future",
                        "summary": e.summary[:100], "severity": "high"})
        elif e.timestamp < ancient:
            out.append({"artifact_id": e.artifact_id, "iso": e.iso,
                        "reason": "timestamp predates modern smartphones",
                        "summary": e.summary[:100], "severity": "medium"})

    # Backwards jumps within a single application's own sequence
    per_app: Dict[str, List[TimelineEntry]] = defaultdict(list)
    for e in entries:
        if e.app:
            per_app[e.app].append(e)
    for app, items in per_app.items():
        if len(items) < 10:
            continue
        drops = 0
        for prev, cur in zip(items, items[1:]):
            if cur.timestamp < prev.timestamp - 3600 * US:
                drops += 1
        if drops > len(items) * 0.05:
            out.append({
                "artifact_id": "", "iso": "", "severity": "medium",
                "reason": f"{app}: {drops} backwards time jumps — the device "
                          f"clock may have been changed during this period",
                "summary": app,
            })
    return out


def summarise(artifacts: List[Artifact], tz_offset_minutes: int = 0
              ) -> Dict[str, Any]:
    """One call that produces everything the analysis dashboard needs."""
    entries = build(artifacts, tz_offset_minutes)
    cats = Counter(a.category.value for a in artifacts)
    apps = Counter(a.app for a in artifacts if a.app)
    recovery = Counter(a.recovery.value for a in artifacts)
    directions = Counter(a.direction.value for a in artifacts
                         if a.direction != Direction.UNKNOWN)

    call_seconds = sum(int(a.attributes.get("duration_seconds") or 0)
                       for a in artifacts if a.category == Category.CALL)
    geo = [a for a in artifacts if a.latitude is not None]

    lo = entries[0].timestamp if entries else None
    hi = entries[-1].timestamp if entries else None

    return {
        "total_artifacts": len(artifacts),
        "timestamped": len(entries),
        "undated": len(artifacts) - len(entries),
        "first_activity": to_iso(lo, tz_offset_minutes) if lo else "",
        "last_activity": to_iso(hi, tz_offset_minutes) if hi else "",
        "span_days": round((hi - lo) / (86400 * US), 1) if lo and hi else 0,
        "categories": dict(cats.most_common()),
        "applications": dict(apps.most_common(25)),
        "recovery": dict(recovery),
        "directions": dict(directions),
        "deleted_recovered": sum(v for k, v in recovery.items()
                                 if k != Recovery.ALLOCATED.value),
        "total_call_seconds": call_seconds,
        "total_call_display": _hms(call_seconds),
        "geolocated_artifacts": len(geo),
        "histogram": histogram(entries, tz_offset_minutes),
        "bursts": bursts(entries)[:20],
        "gaps": gaps(entries)[:15],
        "anomalies": anomalies(entries)[:25],
    }


def from_db(db: ArtifactDB, where: str = "", params: tuple = (),
            tz_offset_minutes: int = 0) -> Dict[str, Any]:
    return summarise(list(db.iter_artifacts(where, params)), tz_offset_minutes)


def _hms(seconds: int) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s"
