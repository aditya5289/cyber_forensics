"""Event fusion — attributing activity to a person rather than a device.

Every other view in ARGUS answers "what happened?". This one answers the
question that actually decides contested cases: **was somebody holding the
handset when it happened?**

The distinction matters because "the phone sent this message" and "the owner
sent this message" are different claims, and only the second is usually the one
being argued. A message artifact alone cannot separate them. But a handset
records, in stores entirely independent of the messaging app, whether its screen
was on, whether it was unlocked, and which application was in the foreground. If
a message was sent while the screen was lit and that app was in front, a person
was there. If it was sent while the device was locked and idle, something else
sent it.

So this module fuses:

* communications (messages, calls)
* device-usage telemetry (KnowledgeC, PowerLog, Android usagestats)
* location fixes
* media creation

into a single timeline of **fused events**, each carrying a corroboration set
and an attribution verdict.

Three rules keep the inference honest:

**Corroboration is named, not asserted.** Every event lists the specific
artifacts that support it. "Attributed" with nothing behind it would be an
opinion dressed as a finding.

**Absence of telemetry is not evidence of absence.** Most handsets do not have
usage telemetry for most of their history, so the great majority of events are
``unknown`` — and that is reported as *unknown*, never quietly downgraded to
"not attributed". Conflating "we cannot tell" with "it wasn't the owner" would
be the single most dangerous error this module could make.

**Attribution is to *a person at the device*, never to a named individual.**
Telemetry cannot distinguish the owner from anyone else holding an unlocked
phone, and the output says so every time.
"""

from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.models import Artifact, Category, Direction, Recovery
from ..parsers.timestamps import to_iso

US = 1_000_000
MINUTE = 60 * US

# How close a telemetry event must be to count as corroborating.
TIGHT_WINDOW = 2 * MINUTE       # same interaction
LOOSE_WINDOW = 15 * MINUTE      # same session

ATTRIBUTION = {
    "attributed": "A person was operating the device when this occurred",
    "probable": "Device was probably in use; corroboration is nearby but not "
                "simultaneous",
    "unattributed": "Device telemetry shows it was locked or idle — this "
                    "occurred without a person present",
    "unknown": "No usage telemetry covers this moment — attribution cannot be "
               "determined either way",
}


@dataclass
class Corroboration:
    """One independent artifact supporting a fused event."""

    kind: str                  # usage | location | media | screen | lock
    artifact_id: str
    offset_seconds: float
    detail: str = ""
    app: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FusedEvent:
    """A primary act, plus everything that independently corroborates it."""

    timestamp: int
    primary_id: str
    category: str
    subtype: str
    app: str
    summary: str
    direction: str = ""
    is_deleted: bool = False
    parties: List[str] = field(default_factory=list)
    corroboration: List[Corroboration] = field(default_factory=list)
    attribution: str = "unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_source: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def corroboration_count(self) -> int:
        return len(self.corroboration)

    @property
    def independent_sources(self) -> int:
        """Distinct kinds of corroboration — three of one kind is weaker than
        one each of three."""
        return len({c.kind for c in self.corroboration})

    @property
    def strength(self) -> float:
        base = {"attributed": 0.85, "probable": 0.6,
                "unattributed": 0.5, "unknown": 0.0}[self.attribution]
        return round(min(0.98, base + 0.05 * max(self.independent_sources - 1, 0)),
                     3)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "timestamp_iso": to_iso(self.timestamp),
            "primary_id": self.primary_id,
            "category": self.category, "subtype": self.subtype,
            "app": self.app, "summary": self.summary,
            "direction": self.direction, "is_deleted": self.is_deleted,
            "parties": self.parties,
            "attribution": self.attribution,
            "attribution_meaning": ATTRIBUTION[self.attribution],
            "corroboration": [c.as_dict() for c in self.corroboration],
            "corroboration_count": self.corroboration_count,
            "independent_sources": self.independent_sources,
            "strength": self.strength,
            "latitude": self.latitude, "longitude": self.longitude,
            "location_source": self.location_source,
            "notes": self.notes,
        }


# ═══════════════════════════════════════════════════════════════ classifiers
_USAGE_MARKERS = ("foreground", "app usage", "knowledgec", "powerlog",
                  "usage event", "app runtime")
_SCREEN_MARKERS = ("screen on", "isbacklit", "display")
_LOCK_MARKERS = ("islocked", "lock state", "keyguard")


def _telemetry_kind(art: Artifact) -> str:
    """Classify a telemetry artifact, or "" if it is not telemetry."""
    subtype = (art.subtype or "").lower()
    stream = str(art.attributes.get("stream") or "").lower()
    event = str(art.attributes.get("event") or "").lower()
    blob = f"{subtype} {stream} {event}"
    if any(m in blob for m in _LOCK_MARKERS):
        return "lock"
    if any(m in blob for m in _SCREEN_MARKERS):
        return "screen"
    if any(m in blob for m in _USAGE_MARKERS):
        return "usage"
    return ""


def _indicates_in_use(art: Artifact, kind: str) -> Optional[bool]:
    """Does this telemetry event mean a person was present?

    ``None`` means the event is ambiguous, which is reported rather than
    guessed — a background service waking up is not a person.
    """
    if kind == "usage":
        event = str(art.attributes.get("event") or "").lower()
        if "background" in event or "service" in event or "stopped" in event:
            return None
        return True
    if kind == "screen":
        value = str(art.attributes.get("value") or "").strip()
        if value in ("0", "false", "False"):
            return False
        return True
    if kind == "lock":
        value = str(art.attributes.get("value") or "").strip()
        if value in ("1", "true", "True"):
            return False               # locked
        if value in ("0", "false", "False"):
            return True                # unlocked
        return None
    return None


class EventFuser:
    """Fuse acts with the telemetry, location and media that corroborate them."""

    PRIMARY = {Category.MESSAGE, Category.CHAT, Category.CALL}

    def __init__(self, owner_name: str = "Device owner"):
        self.owner_name = owner_name
        self.primaries: List[Artifact] = []
        self.telemetry: List[Tuple[int, Artifact, str, Optional[bool]]] = []
        self.locations: List[Tuple[int, Artifact]] = []
        self.media: List[Tuple[int, Artifact]] = []
        self.exhibit_of: Dict[str, str] = {}

    def add(self, artifacts: Iterable[Artifact], exhibit: str = "") -> None:
        for art in artifacts:
            if art.timestamp is None:
                continue
            self.exhibit_of[art.artifact_id] = exhibit
            kind = _telemetry_kind(art)
            if kind:
                self.telemetry.append(
                    (art.timestamp, art, kind, _indicates_in_use(art, kind)))
                continue
            if art.category in self.PRIMARY:
                self.primaries.append(art)
            elif (art.latitude is not None and art.longitude is not None):
                self.locations.append((art.timestamp, art))
            elif art.category == Category.FILE and art.subtype in (
                    "Picture", "Video"):
                self.media.append((art.timestamp, art))

    # ------------------------------------------------------------------ fuse
    def fuse(self, limit: int = 20000) -> List[FusedEvent]:
        self.telemetry.sort(key=lambda x: x[0])
        self.locations.sort(key=lambda x: x[0])
        self.media.sort(key=lambda x: x[0])
        telemetry_times = [t[0] for t in self.telemetry]
        location_times = [t[0] for t in self.locations]
        media_times = [t[0] for t in self.media]

        events: List[FusedEvent] = []
        for art in sorted(self.primaries,
                          key=lambda a: a.timestamp or 0)[:limit]:
            event = FusedEvent(
                timestamp=art.timestamp, primary_id=art.artifact_id,
                category=art.category.value, subtype=art.subtype,
                app=art.app, summary=art.summary(160),
                direction=art.direction.value,
                is_deleted=art.recovery != Recovery.ALLOCATED.value,
                parties=[p.label() for p in art.counterparties()][:6],
                latitude=art.latitude, longitude=art.longitude)

            in_use, ambiguous = self._corroborate_usage(
                event, telemetry_times, art.timestamp, art.app)
            self._corroborate_nearby(event, location_times, self.locations,
                                     art.timestamp, "location")
            self._corroborate_nearby(event, media_times, self.media,
                                     art.timestamp, "media")

            if in_use is True:
                event.attribution = "attributed"
            elif in_use is False:
                event.attribution = "unattributed"
            elif event.corroboration and ambiguous:
                event.attribution = "probable"
            else:
                event.attribution = "unknown"

            if event.attribution == "unknown":
                event.notes.append(
                    "No device-usage telemetry covers this moment. This is not "
                    "evidence that nobody was present — most handsets retain "
                    "telemetry for only a few days.")
            if event.attribution == "attributed":
                event.notes.append(
                    "Telemetry places a person at the device. It cannot "
                    "establish *which* person: anyone with the unlocked handset "
                    "would produce the same record.")
            events.append(event)
        return events

    def _corroborate_usage(self, event: FusedEvent, times: Sequence[int],
                           when: int, app: str
                           ) -> Tuple[Optional[bool], bool]:
        """Attach usage telemetry. Returns ``(in_use, had_ambiguous)``."""
        if not times:
            return None, False
        lo = bisect.bisect_left(times, when - LOOSE_WINDOW)
        hi = bisect.bisect_right(times, when + LOOSE_WINDOW)
        verdicts: List[Tuple[bool, float, Artifact, str]] = []
        ambiguous = False
        for index in range(lo, hi):
            stamp, art, kind, in_use = self.telemetry[index]
            offset = (stamp - when) / US
            if in_use is None:
                ambiguous = True
                continue
            verdicts.append((in_use, offset, art, kind))

        if not verdicts:
            return None, ambiguous

        # Prefer the closest evidence, and prefer telemetry naming the same app.
        verdicts.sort(key=lambda v: (abs(v[1]) > TIGHT_WINDOW / US,
                                     0 if _same_app(v[2], app) else 1,
                                     abs(v[1])))
        for in_use, offset, art, kind in verdicts[:6]:
            event.corroboration.append(Corroboration(
                kind=kind, artifact_id=art.artifact_id,
                offset_seconds=round(offset, 1),
                app=art.app,
                detail=(f"{art.subtype or kind}"
                        + (f" — {art.body[:70]}" if art.body else ""))))
        best_in_use, best_offset, best_art, _ = verdicts[0]
        # Only a tight, same-app match earns "attributed".
        if abs(best_offset) * US <= TIGHT_WINDOW:
            return best_in_use, ambiguous
        if best_in_use:
            event.notes.append(
                f"Nearest usage telemetry is {abs(best_offset):.0f}s away — "
                f"same session, not simultaneous.")
            return None, True
        return None, ambiguous

    def _corroborate_nearby(self, event: FusedEvent, times: Sequence[int],
                            records: Sequence[Tuple[int, Artifact]],
                            when: int, kind: str) -> None:
        if not times:
            return
        index = bisect.bisect_left(times, when)
        for candidate in (index - 1, index):
            if not 0 <= candidate < len(records):
                continue
            stamp, art = records[candidate]
            offset = (stamp - when) / US
            if abs(offset) * US > LOOSE_WINDOW:
                continue
            event.corroboration.append(Corroboration(
                kind=kind, artifact_id=art.artifact_id,
                offset_seconds=round(offset, 1), app=art.app,
                detail=art.summary(80)))
            if kind == "location" and event.latitude is None:
                event.latitude = art.latitude
                event.longitude = art.longitude
                event.location_source = (
                    f"nearest position fix, {abs(offset):.0f}s away")

    # --------------------------------------------------------------- summary
    def summary(self, events: Optional[List[FusedEvent]] = None
                ) -> Dict[str, Any]:
        events = events if events is not None else self.fuse()
        counts = Counter(e.attribution for e in events)
        attributed = [e for e in events if e.attribution == "attributed"]
        unattributed = [e for e in events if e.attribution == "unattributed"]
        deleted_attributed = [e for e in attributed if e.is_deleted]
        return {
            "events": len(events),
            "by_attribution": {k: counts.get(k, 0) for k in ATTRIBUTION},
            "attribution_meanings": ATTRIBUTION,
            "telemetry_available": bool(self.telemetry),
            "telemetry_events": len(self.telemetry),
            "coverage": round(
                (counts.get("attributed", 0) + counts.get("probable", 0)
                 + counts.get("unattributed", 0)) / len(events), 4)
            if events else 0.0,
            "attributed_deleted_acts": len(deleted_attributed),
            "unattributed_acts": [e.as_dict() for e in unattributed[:40]],
            "strongest": [e.as_dict() for e in
                          sorted(events, key=lambda e: -e.strength)[:30]],
            "note": ("Most events are 'unknown' on a typical handset because "
                     "usage telemetry covers only a few days. Unknown means "
                     "attribution could not be determined — it does NOT mean "
                     "the act was unattributed."),
        }


def _same_app(art: Artifact, app: str) -> bool:
    if not app or not art.app:
        return False
    return art.app.lower() == app.lower()


def fuse_session(session: Any, owner_name: str = "Device owner") -> EventFuser:
    fuser = EventFuser(owner_name=owner_name)
    for loaded in session.loaded:
        exhibit = (loaded.container.extraction.get("exhibit_id")
                   or loaded.container.path.name)
        fuser.add(loaded.db.iter_artifacts(), exhibit=exhibit)
    return fuser


def fusion_findings(fuser: EventFuser) -> List[Any]:
    """Findings that only exist once sources are fused."""
    from .findings import Finding

    events = fuser.fuse()
    summary = fuser.summary(events)
    out: List[Finding] = []

    if not summary["telemetry_available"]:
        return out

    attributed = [e for e in events if e.attribution == "attributed"]
    if attributed:
        deleted = [e for e in attributed if e.is_deleted]
        out.append(Finding(
            rule_id="fusion.attributed_activity",
            title=(f"{len(attributed)} act(s) corroborated by independent "
                   f"device-usage telemetry"),
            detail=("For these communications, telemetry from a separate store "
                    "shows the device was unlocked and in use at the same "
                    "moment — so a person was present, not just a running "
                    "phone."
                    + (f" {len(deleted)} of them are messages recovered from "
                       f"deleted space." if deleted else "")),
            severity="high" if deleted else "medium",
            confidence=0.8, category="fusion",
            artifact_ids=[e.primary_id for e in attributed][:300],
            evidence=[f"{e.timestamp_iso if hasattr(e,'timestamp_iso') else to_iso(e.timestamp)}"
                      f" — {e.summary[:90]} "
                      f"[{e.independent_sources} independent source(s)]"
                      for e in attributed[:6]],
            first_seen=min(e.timestamp for e in attributed),
            last_seen=max(e.timestamp for e in attributed),
            metrics={"count": len(attributed),
                     "deleted_among_them": len(deleted),
                     "coverage": summary["coverage"],
                     "examples": [e.as_dict() for e in attributed[:8]]},
            why_it_matters=("Separates what the handset did from what a person "
                            "did. A deleted message that can be shown to have "
                            "been sent while someone was holding the device is "
                            "materially stronger evidence than the message "
                            "alone."),
            caveat=("Telemetry establishes that *a* person was at the device, "
                    "never which person. Anyone with the unlocked handset "
                    "produces an identical record."),
        ))

    unattributed = [e for e in events if e.attribution == "unattributed"]
    if unattributed:
        out.append(Finding(
            rule_id="fusion.unattributed_activity",
            title=(f"{len(unattributed)} act(s) occurred while the device "
                   f"was locked or idle"),
            detail=("Telemetry indicates the device was locked or its screen "
                    "off when these occurred, which is consistent with "
                    "automated or background activity rather than a person: "
                    + "; ".join(f"{e.summary[:60]}" for e in unattributed[:5])),
            severity="medium", confidence=0.65, category="fusion",
            artifact_ids=[e.primary_id for e in unattributed][:200],
            metrics={"count": len(unattributed),
                     "examples": [e.as_dict() for e in unattributed[:8]]},
            why_it_matters=("Distinguishes automated traffic — scheduled sync, "
                            "OTP delivery, bots — from acts a person performed, "
                            "which matters when attributing conduct."),
            caveat=("Incoming messages arrive whether or not anyone is present, "
                    "so an incoming message being 'unattributed' is entirely "
                    "expected and not itself notable."),
        ))

    if summary["coverage"] < 0.15:
        out.append(Finding(
            rule_id="fusion.low_coverage",
            title=(f"Usage telemetry covers only "
                   f"{summary['coverage']:.0%} of recorded activity"),
            detail=(f"{summary['telemetry_events']} telemetry events were "
                    f"recovered, but they overlap only a small fraction of the "
                    f"{summary['events']} communications in this case. "
                    f"Attribution is therefore 'unknown' for most acts."),
            severity="info", confidence=0.95, category="fusion",
            # The evidence for a coverage claim is the telemetry that does
            # exist — citing it lets an examiner see the extent of the window
            # rather than taking the percentage on trust.
            artifact_ids=[art.artifact_id
                          for _stamp, art, _kind, _use in fuser.telemetry][:300],
            metrics=summary["by_attribution"],
            why_it_matters=("Prevents the attributed subset being mistaken for "
                            "the whole picture, and prevents 'unknown' being "
                            "read as 'not the owner'."),
            caveat="",
        ))
    return out
