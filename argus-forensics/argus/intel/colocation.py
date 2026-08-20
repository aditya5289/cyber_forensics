"""Co-location — were two devices in the same place at the same *time*?

:mod:`~argus.intel.correlate` already reports locations recorded on more than
one exhibit, and states its own limitation plainly: two devices logging
positions in the same 1 km cell six months apart is not co-location, it is a
coincidence of geography. The question that actually matters in a multi-device
case is narrower and much stronger — *were these two handsets in the same place
at the same moment?* That is what this module answers.

It is deliberately conservative, because the failure mode is severe. A tool
that reports a meeting which never happened puts two people in a room together
on the strength of a parsing artefact.

**Not every coordinate is a position.** Three distinctions are enforced before
a point is allowed to contribute:

* A **searched destination** shows an intent to travel, not a presence. Two
  people looking up the same restaurant did not meet at it. Google Maps
  history is excluded outright.
* A **received** location message is the *sender's* position. Counting it
  would make every shared pin look like both parties were standing there —
  precisely backwards. Only sent locations count.
* A **geotagged photograph** places the camera, not necessarily this handset.
  Forwarded and downloaded media carry the original photographer's
  coordinates, so only camera originals (in ``DCIM`` and carrying maker EXIF)
  are treated as presence.

Points whose stated accuracy is worse than the match radius are dropped rather
than matched loosely: a cell-tower fix good to 3 km cannot support a claim
about a 500 m meeting, and quietly widening the radius to accommodate it would
turn the weakest evidence into the most productive.

What comes out is a list of :class:`Encounter` objects, each with when, where,
how close, how many independent point pairs supported it, and which kinds of
record they came from.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.models import Artifact, Category, Direction
from ..parsers.timestamps import to_iso

US = 1_000_000
EARTH_RADIUS_M = 6_371_000.0

# Defaults. 500 m is about the useful floor for consumer handset positioning,
# and 15 minutes is short enough that "at the same time" means something while
# still tolerating the clock drift between two devices.
DEFAULT_RADIUS_M = 500.0
DEFAULT_WINDOW_S = 900


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in metres.

    Used rather than a degree-grid comparison because a degree of longitude is
    111 km at the equator and 20 km at 80 degrees north; a fixed grid would
    mean the match radius silently changed with latitude.
    """
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


@dataclass
class PresencePoint:
    """One record that places a *device* somewhere at a known time."""

    exhibit: str
    artifact_id: str
    timestamp: int                      # microseconds, UTC
    latitude: float
    longitude: float
    source: str                         # human-readable kind of record
    weight: float = 1.0                 # how well it evidences presence
    accuracy_m: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp_iso"] = to_iso(self.timestamp)
        return d


@dataclass
class Encounter:
    """Two exhibits placed together in space and time."""

    exhibit_a: str
    exhibit_b: str
    start: int
    end: int
    latitude: float
    longitude: float
    closest_m: float
    median_gap_s: float
    point_pairs: int
    sources: List[str] = field(default_factory=list)
    artifact_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5

    @property
    def duration_s(self) -> float:
        return (self.end - self.start) / US

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["start_iso"] = to_iso(self.start)
        d["end_iso"] = to_iso(self.end)
        d["duration_s"] = round(self.duration_s, 1)
        d["map_url"] = (f"https://www.openstreetmap.org/?mlat={self.latitude}"
                        f"&mlon={self.longitude}"
                        f"#map=16/{self.latitude}/{self.longitude}")
        return d


def _accuracy(art: Artifact) -> Optional[float]:
    raw = art.attributes.get("horizontal_accuracy")
    try:
        acc = float(raw)
    except (TypeError, ValueError):
        return None
    return acc if acc > 0 else None


def _camera_original(art: Artifact) -> bool:
    """Was this photograph taken *by this handset*?

    Received and downloaded images keep the original photographer's GPS tags,
    so the presence of coordinates says nothing about where this device was.
    A camera original lives in the camera roll and carries maker tags written
    by the capturing device.
    """
    path = (art.source_path or "").lower().replace("\\", "/")
    exif = art.attributes.get("exif") or {}
    if not isinstance(exif, dict):
        return False
    return "dcim" in path and bool(exif.get("Make") or exif.get("Model"))


def presence_point(art: Artifact, exhibit: str,
                   radius_m: float = DEFAULT_RADIUS_M
                   ) -> Optional[PresencePoint]:
    """Classify one artifact as evidence of the device's own presence, or not.

    Returns ``None`` for every coordinate that does not place *this* device
    somewhere — which is most of them.
    """
    if art.latitude is None or art.longitude is None or not art.timestamp:
        return None

    sub = (art.subtype or "").lower()
    app = (art.app or "").lower()

    if art.category is Category.PLACE:
        # Maps history is search and navigation intent. The parser records
        # both under Places; neither is a recorded position.
        if "maps" in app or "search" in sub or "destination" in sub:
            return None
        weight, source = 1.0, art.subtype or "Device position fix"
    elif art.category in (Category.MESSAGE, Category.CHAT):
        if art.direction is not Direction.OUTGOING:
            return None                 # the other party's position, not ours
        weight = 0.8                    # a pin can be dropped anywhere
        source = f"{art.app or 'Message'} location sent"
    elif art.category is Category.FILE:
        if not _camera_original(art):
            return None
        weight, source = 0.9, "Geotagged camera original"
    else:
        return None

    acc = _accuracy(art)
    if acc is not None and acc > radius_m:
        return None                     # cannot localise to the match radius

    return PresencePoint(
        exhibit=exhibit, artifact_id=art.artifact_id, timestamp=art.timestamp,
        latitude=float(art.latitude), longitude=float(art.longitude),
        source=source,
        # A carved row is still evidence, but a less certain one, and that
        # uncertainty belongs in the encounter's confidence rather than in a
        # footnote nobody reads.
        weight=round(weight * max(0.1, float(art.confidence or 1.0)), 3),
        accuracy_m=acc)


class ColocationAnalyser:
    """Find the times when two exhibits were in the same place."""

    def __init__(self, radius_m: float = DEFAULT_RADIUS_M,
                 window_s: int = DEFAULT_WINDOW_S):
        self.radius_m = float(radius_m)
        self.window_s = int(window_s)
        self.exhibits: List[str] = []
        self.points: Dict[str, List[PresencePoint]] = defaultdict(list)
        self.rejected: Dict[str, int] = defaultdict(int)

    # -------------------------------------------------------------- ingest
    def add_exhibit(self, name: str, artifacts: Iterable[Artifact]) -> None:
        if name not in self.exhibits:
            self.exhibits.append(name)
        for art in artifacts:
            point = presence_point(art, name, self.radius_m)
            if point is None:
                if art.latitude is not None and art.longitude is not None:
                    self.rejected[name] += 1
                continue
            self.points[name].append(point)
        self.points[name].sort(key=lambda p: p.timestamp)

    # ------------------------------------------------------------- matching
    def _pair_hits(self, a: str, b: str
                   ) -> List[Tuple[PresencePoint, PresencePoint, float]]:
        """Every point pair within both the radius and the time window."""
        pa, pb = self.points.get(a, []), self.points.get(b, [])
        window = self.window_s * US
        hits: List[Tuple[PresencePoint, PresencePoint, float]] = []
        lo = 0
        # ponytail: linear sweep with a quadratic worst case inside a single
        # window (both devices logging densely at the same instant). Handset
        # volumes make that irrelevant; add a spatial index if it ever bites.
        for point_a in pa:
            while lo < len(pb) and pb[lo].timestamp < point_a.timestamp - window:
                lo += 1
            j = lo
            while j < len(pb) and pb[j].timestamp <= point_a.timestamp + window:
                dist = haversine_m(point_a.latitude, point_a.longitude,
                                   pb[j].latitude, pb[j].longitude)
                if dist <= self.radius_m:
                    hits.append((point_a, pb[j], dist))
                j += 1
        return hits

    def _merge(self, a: str, b: str,
               hits: Sequence[Tuple[PresencePoint, PresencePoint, float]]
               ) -> List[Encounter]:
        """Group point pairs into encounters, splitting on a real gap.

        Without this, a device logging every five minutes for an hour beside
        another would be reported as twelve separate meetings.
        """
        if not hits:
            return []
        window = self.window_s * US
        ordered = sorted(hits,
                         key=lambda h: (h[0].timestamp + h[1].timestamp) // 2)

        groups: List[List[Tuple[PresencePoint, PresencePoint, float]]] = [[]]
        last: Optional[Tuple[int, float, float]] = None
        for hit in ordered:
            mid = (hit[0].timestamp + hit[1].timestamp) // 2
            lat = (hit[0].latitude + hit[1].latitude) / 2
            lon = (hit[0].longitude + hit[1].longitude) / 2
            if last is not None and (
                    mid - last[0] > window
                    # Two devices together at one place and, ten minutes
                    # later, together at another are two encounters. Merging
                    # them would report a single meeting at a centroid where
                    # neither device ever was.
                    or haversine_m(lat, lon, last[1], last[2]) > self.radius_m):
                groups.append([])
            groups[-1].append(hit)
            last = (mid, lat, lon)

        out: List[Encounter] = []
        for group in groups:
            stamps = [p.timestamp for h in group for p in (h[0], h[1])]
            lats = [p.latitude for h in group for p in (h[0], h[1])]
            lons = [p.longitude for h in group for p in (h[0], h[1])]
            gaps = [abs(h[0].timestamp - h[1].timestamp) / US for h in group]
            closest = min(h[2] for h in group)
            weight = max(min(h[0].weight, h[1].weight) for h in group)
            out.append(Encounter(
                exhibit_a=a, exhibit_b=b,
                start=min(stamps), end=max(stamps),
                latitude=round(sum(lats) / len(lats), 6),
                longitude=round(sum(lons) / len(lons), 6),
                closest_m=round(closest, 1),
                median_gap_s=round(statistics.median(gaps), 1),
                point_pairs=len(group),
                sources=sorted({p.source for h in group for p in (h[0], h[1])}),
                artifact_ids=sorted({p.artifact_id for h in group
                                     for p in (h[0], h[1])})[:60],
                confidence=self._confidence(closest,
                                            statistics.median(gaps),
                                            len(group), weight),
            ))
        return out

    def _confidence(self, closest_m: float, median_gap_s: float,
                    pairs: int, weight: float) -> float:
        """How much the encounter deserves to be believed.

        Tightness in space and time carries most of it, corroboration by
        several independent point pairs a little more, and the whole thing is
        scaled by the quality of the record type that placed each device
        there.
        """
        score = 0.45
        score += 0.20 * (1.0 - min(1.0, closest_m / self.radius_m))
        score += 0.15 * (1.0 - min(1.0, median_gap_s / self.window_s))
        score += min(0.15, 0.03 * (pairs - 1))
        return round(min(0.95, score) * weight, 3)

    # -------------------------------------------------------------- results
    def encounters(self) -> List[Encounter]:
        out: List[Encounter] = []
        for i, a in enumerate(self.exhibits):
            for b in self.exhibits[i + 1:]:
                out.extend(self._merge(a, b, self._pair_hits(a, b)))
        return sorted(out, key=lambda e: (-e.confidence, e.start))

    def summary(self) -> Dict[str, Any]:
        found = self.encounters()
        by_pair: Dict[str, Dict[str, Any]] = {}
        for enc in found:
            key = f"{enc.exhibit_a} + {enc.exhibit_b}"
            entry = by_pair.setdefault(key, {"encounters": 0, "days": set(),
                                             "best_confidence": 0.0})
            entry["encounters"] += 1
            entry["days"].add(_day(enc.start))
            entry["best_confidence"] = max(entry["best_confidence"],
                                           enc.confidence)
        for entry in by_pair.values():
            entry["distinct_days"] = len(entry["days"])
            entry.pop("days")
        return {
            "exhibits": list(self.exhibits),
            "radius_m": self.radius_m,
            "window_s": self.window_s,
            "presence_points": {k: len(v) for k, v in self.points.items()},
            "coordinates_rejected": dict(self.rejected),
            "encounters": [e.as_dict() for e in found[:60]],
            "encounter_count": len(found),
            "by_pair": by_pair,
            "note": ("Only records that place the device itself are used: "
                     "position fixes, sent location messages and camera "
                     "originals. Searched destinations, received locations "
                     "and downloaded media are excluded because none of them "
                     "shows where this handset was. No encounter found is not "
                     "evidence the devices were apart — location retention "
                     "differs between handsets and is usually sparse."),
        }


def _day(ts: int) -> str:
    return datetime.fromtimestamp(ts / US, tz=timezone.utc).date().isoformat()


def colocation_findings(analyser: ColocationAnalyser) -> List[Any]:
    """Turn encounters into findings, one per pair of exhibits."""
    from .findings import Finding

    out: List[Finding] = []
    grouped: Dict[Tuple[str, str], List[Encounter]] = defaultdict(list)
    for enc in analyser.encounters():
        grouped[(enc.exhibit_a, enc.exhibit_b)].append(enc)

    for (a, b), encs in grouped.items():
        days = sorted({_day(e.start) for e in encs})
        best = max(e.confidence for e in encs)
        repeated = len(encs) >= 3 and len(days) >= 3
        # Constant co-presence is a different claim from a series of meetings,
        # and the likeliest explanation is one person carrying both handsets,
        # or two people who live together. Calling that "meetings" would be
        # wrong, so the finding says which pattern it is looking at.
        travelling_together = len(encs) >= 8 and len(days) >= 5
        out.append(Finding(
            rule_id="colocation.rendezvous",
            title=(f"{a} and {b} were in the same place at the same time "
                   f"on {len(days)} day(s)"),
            detail=("; ".join(
                f"{to_iso(e.start)} at {e.latitude:.4f}, {e.longitude:.4f} "
                f"(closest {e.closest_m:.0f} m, {e.point_pairs} point pair(s))"
                for e in encs[:6])
                + ("" if len(encs) <= 6 else f"; and {len(encs) - 6} more")),
            severity="critical" if repeated else "high",
            confidence=best,
            category="correlation",
            artifact_ids=[aid for e in encs for aid in e.artifact_ids][:300],
            evidence=[f"{to_iso(e.start)} — {', '.join(e.sources)}"
                      for e in encs[:4]],
            first_seen=min(e.start for e in encs),
            last_seen=max(e.end for e in encs),
            metrics={
                "exhibit_a": a, "exhibit_b": b,
                "encounters": len(encs), "distinct_days": len(days),
                "days": days[:20],
                "radius_m": analyser.radius_m, "window_s": analyser.window_s,
                "travelling_together": travelling_together,
                "detail": [e.as_dict() for e in encs[:12]],
            },
            why_it_matters=(
                "Two devices placed together in space and time links their "
                "users directly, without either of them having communicated. "
                "Repeated encounters at the same location establish a pattern "
                "of contact that message records alone would not show."
                + (" The density here is more consistent with the handsets "
                   "travelling together — one person carrying both, or two "
                   "people sharing a home or a vehicle — than with a series "
                   "of meetings." if travelling_together else "")),
            caveat=(
                f"Matched within {analyser.radius_m:.0f} m and "
                f"{analyser.window_s // 60} minutes. Device clocks drift and "
                "may be set to different zones, so a genuine meeting can be "
                "missed and a near miss can be matched. In a dense public "
                "place — a station, a mall — being within this radius is not "
                "being together. Co-location places the devices together, "
                "never named people: whoever was carrying each handset "
                "produces an identical record."),
        ))
    return out
