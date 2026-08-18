"""The findings engine — turning artifacts into leads.

An extraction produces tens of thousands of artifacts. An examiner has hours,
not weeks. The gap between "here is everything" and "here is what matters" is
where most of the real work in an examination happens, and it is the part
tools usually leave entirely to the human.

This module runs a set of explicit, auditable rules over a case and emits
ranked :class:`Finding` objects. Three principles keep it honest:

**Every finding cites its evidence.** A finding without artifact IDs behind it
is an assertion, and an assertion an examiner cannot check is worse than
nothing. Each one carries the artifacts that produced it so it can be opened,
verified, and — if the rule got it wrong — dismissed.

**Rules describe, they do not accuse.** A rule reports *"contact reached only
via a deleted thread, at unusual hours, with no address-book entry"*. It does
not report *"co-conspirator"*. Inference from evidence is the investigator's
job and the court's; the tool's job is to make the evidence visible.

**Confidence is stated and calibrated.** Every rule declares how much weight
its finding deserves and why, so a weak signal cannot masquerade as a strong
one just because it appeared in a list.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from ..core.models import Artifact, Category, Direction, Recovery
from ..parsers.timestamps import to_iso

US = 1_000_000
DAY = 86_400 * US

# Severity ordering used for ranking and display.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    """One investigative lead."""

    rule_id: str
    title: str
    detail: str
    severity: str = "medium"           # critical|high|medium|low|info
    confidence: float = 0.7            # 0–1, how sure the rule is
    category: str = "general"          # grouping for the UI
    artifact_ids: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    parties: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)   # human-readable excerpts
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    why_it_matters: str = ""
    caveat: str = ""                   # what would make this finding wrong

    @property
    def score(self) -> float:
        """Ranking score: severity dominates, confidence breaks ties."""
        return round(SEVERITY_ORDER.get(self.severity, 1) + self.confidence, 3)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["score"] = self.score
        d["first_seen_iso"] = to_iso(self.first_seen) if self.first_seen else ""
        d["last_seen_iso"] = to_iso(self.last_seen) if self.last_seen else ""
        d["artifact_ids"] = self.artifact_ids[:200]
        return d


@dataclass
class CaseContext:
    """Everything the rules need, computed once."""

    artifacts: List[Artifact]
    owner_name: str = "Device owner"
    owner_keys: Set[str] = field(default_factory=set)
    entities: Any = None                     # EntityExtractor, optional
    graph: Any = None                        # ConnectionGraph, optional

    # Derived
    by_category: Dict[str, List[Artifact]] = field(default_factory=dict)
    contacts_by_key: Dict[str, Artifact] = field(default_factory=dict)
    timestamps: List[int] = field(default_factory=list)

    def __post_init__(self):
        self.by_category = defaultdict(list)
        for art in self.artifacts:
            self.by_category[art.category.value].append(art)
        self.by_category = dict(self.by_category)

        for art in self.by_category.get(Category.CONTACT.value, []):
            for p in art.participants:
                key = p.normalised()
                if key:
                    self.contacts_by_key.setdefault(key, art)

        self.timestamps = sorted(a.timestamp for a in self.artifacts
                                 if a.timestamp is not None)

    def comms(self) -> List[Artifact]:
        return [a for a in self.artifacts
                if a.category in (Category.MESSAGE, Category.CALL,
                                  Category.CHAT)]

    def is_known_contact(self, key: str) -> bool:
        return key in self.contacts_by_key

    def span_days(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        return (self.timestamps[-1] - self.timestamps[0]) / DAY


# --------------------------------------------------------------------- rules
RULES: List[Callable[[CaseContext], List[Finding]]] = []


def rule(fn: Callable[[CaseContext], List[Finding]]):
    RULES.append(fn)
    return fn


def _hour(ts: int) -> int:
    return datetime.fromtimestamp(ts / US, tz=timezone.utc).hour


def _party_label(art: Artifact) -> str:
    parties = [p.label() for p in art.counterparties() if p.label()]
    return parties[0] if parties else "(unknown)"


# ----------------------------------------------------------- deleted content
@rule
def deleted_communications(ctx: CaseContext) -> List[Finding]:
    """Recovered deleted messages are, by construction, what someone removed."""
    deleted = [a for a in ctx.comms() if a.recovery != Recovery.ALLOCATED]
    if not deleted:
        return []
    by_party: Dict[str, List[Artifact]] = defaultdict(list)
    for art in deleted:
        for p in art.counterparties():
            key = p.normalised()
            if key:
                by_party[key].append(art)

    findings = [Finding(
        rule_id="deleted.volume",
        title=f"{len(deleted)} deleted communications recovered",
        detail=(f"{len(deleted)} messages or calls were recovered from "
                f"deleted or unallocated database space across "
                f"{len(by_party)} correspondent(s). These were not visible on "
                f"the handset at the time of seizure."),
        severity="high" if len(deleted) > 20 else "medium",
        confidence=0.95, category="deleted",
        artifact_ids=[a.artifact_id for a in deleted],
        first_seen=min((a.timestamp for a in deleted if a.timestamp), default=None),
        last_seen=max((a.timestamp for a in deleted if a.timestamp), default=None),
        metrics={"count": len(deleted), "correspondents": len(by_party)},
        why_it_matters=("Content a user took steps to remove is frequently the "
                        "most probative material in an examination."),
        caveat=("Deletion is not necessarily deliberate concealment — apps "
                "auto-expire messages and users clear storage routinely."),
    )]

    # A correspondent whose entire thread was deleted is more notable than
    # scattered deletions across a busy chat.
    for key, arts in by_party.items():
        live = [a for a in ctx.comms()
                if a.recovery == Recovery.ALLOCATED
                and any(p.normalised() == key for p in a.counterparties())]
        if len(arts) >= 3 and not live:
            label = _party_label(arts[0])
            findings.append(Finding(
                rule_id="deleted.entire_thread",
                title=f"Entire conversation with {label} was deleted",
                detail=(f"All {len(arts)} recovered communications with "
                        f"{label} came from deleted space; no live records "
                        f"with this correspondent survive on the handset."),
                severity="critical", confidence=0.85, category="deleted",
                artifact_ids=[a.artifact_id for a in arts],
                parties=[label],
                evidence=[a.summary(120) for a in arts[:5]],
                first_seen=min((a.timestamp for a in arts if a.timestamp), default=None),
                last_seen=max((a.timestamp for a in arts if a.timestamp), default=None),
                metrics={"deleted": len(arts), "surviving": 0},
                why_it_matters=("Selective removal of one correspondent's "
                                "entire history, while other threads remain, "
                                "is a deliberate act rather than routine "
                                "housekeeping."),
                caveat=("A correspondent blocked or reported as spam can "
                        "produce the same pattern."),
            ))
    return findings


# --------------------------------------------------------- burner behaviour
@rule
def burner_contacts(ctx: CaseContext) -> List[Finding]:
    """Short-lived, high-intensity contact with a party who is not a contact."""
    by_key: Dict[str, List[Artifact]] = defaultdict(list)
    for art in ctx.comms():
        for p in art.counterparties():
            key = p.normalised()
            if key:
                by_key[key].append(art)

    findings: List[Finding] = []
    for key, arts in by_key.items():
        stamps = sorted(a.timestamp for a in arts if a.timestamp)
        if len(stamps) < 4 or ctx.is_known_contact(key):
            continue
        window_days = (stamps[-1] - stamps[0]) / DAY
        if window_days > 14:
            continue
        # Concentrated traffic in a short window with someone never saved to
        # the address book.
        intensity = len(arts) / max(window_days, 0.5)
        if intensity < 2:
            continue
        label = _party_label(arts[0])
        deleted = sum(1 for a in arts if a.recovery != Recovery.ALLOCATED)
        findings.append(Finding(
            rule_id="pattern.burner",
            title=f"Short-lived intensive contact: {label}",
            detail=(f"{len(arts)} communications with {label} concentrated "
                    f"into {window_days:.1f} day(s), and this party was never "
                    f"saved to the address book."
                    + (f" {deleted} of them were recovered from deleted space."
                       if deleted else "")),
            severity="high" if deleted else "medium",
            confidence=0.6, category="pattern",
            artifact_ids=[a.artifact_id for a in arts], parties=[label],
            evidence=[a.summary(120) for a in arts[:4]],
            first_seen=stamps[0], last_seen=stamps[-1],
            metrics={"count": len(arts), "window_days": round(window_days, 2),
                     "per_day": round(intensity, 2), "deleted": deleted},
            why_it_matters=("A burst of contact with an unsaved number that "
                            "then stops is the signature of a number used for "
                            "one purpose and abandoned."),
            caveat=("Delivery drivers, customer service, OTP senders and "
                    "one-off transactions produce the same shape. Check the "
                    "content before treating this as significant."),
        ))
    return sorted(findings, key=lambda f: -f.metrics["count"])[:15]


# ------------------------------------------------------- night-time activity
@rule
def nocturnal_activity(ctx: CaseContext) -> List[Finding]:
    """Sustained activity in the 01:00–05:00 window."""
    comms = [a for a in ctx.comms() if a.timestamp]
    if len(comms) < 30:
        return []
    night = [a for a in comms if 1 <= _hour(a.timestamp) <= 5]
    if not night:
        return []
    ratio = len(night) / len(comms)
    # 4 of 24 hours is ~17% by chance; flag only a clear excess.
    if ratio < 0.22 or len(night) < 12:
        return []
    parties = Counter(_party_label(a) for a in night)
    return [Finding(
        rule_id="pattern.nocturnal",
        title=f"{ratio:.0%} of communications occur between 01:00 and 05:00",
        detail=(f"{len(night)} of {len(comms)} communications fall in the "
                f"01:00–05:00 window (UTC). Most frequent correspondents in "
                f"that window: "
                f"{', '.join(p for p, _ in parties.most_common(3))}."),
        severity="medium", confidence=0.65, category="pattern",
        artifact_ids=[a.artifact_id for a in night],
        parties=[p for p, _ in parties.most_common(5)],
        first_seen=min(a.timestamp for a in night),
        last_seen=max(a.timestamp for a in night),
        metrics={"night": len(night), "total": len(comms),
                 "ratio": round(ratio, 3)},
        why_it_matters=("Activity concentrated in the small hours often "
                        "separates a device's routine use from its other use."),
        caveat=("Timestamps are UTC. If the device operated in a different "
                "timezone this window may be ordinary evening activity — "
                "confirm the device timezone before relying on this."),
    )]


# ----------------------------------------------------- counter-forensic signs
_COUNTER_FORENSIC_TERMS = [
    "wipe", "factory reset", "erase everything", "delete this", "burn the",
    "clear your", "don't put this in writing", "not on this phone",
    "use signal", "switch to", "new number", "burner", "airplane mode",
    "faraday", "encrypt", "vpn", "incognito", "delete the app",
    "remove the sim", "destroy the",
]


@rule
def counter_forensic_language(ctx: CaseContext) -> List[Finding]:
    """Messages discussing evidence destruction or evasion."""
    hits: List[Artifact] = []
    matched_terms: Counter = Counter()
    for art in ctx.comms():
        body = (art.body or "").lower()
        if not body:
            continue
        for term in _COUNTER_FORENSIC_TERMS:
            if term in body:
                hits.append(art)
                matched_terms[term] += 1
                break
    if not hits:
        return []
    return [Finding(
        rule_id="pattern.counter_forensic",
        title=f"{len(hits)} messages discuss deletion, evasion or device hygiene",
        detail=("Message content references destroying evidence, switching "
                "channels or avoiding written records. Most frequent phrases: "
                + ", ".join(f'"{t}" ({n})'
                            for t, n in matched_terms.most_common(4)) + "."),
        severity="high", confidence=0.55, category="pattern",
        artifact_ids=[a.artifact_id for a in hits],
        parties=sorted({_party_label(a) for a in hits})[:8],
        evidence=[a.summary(140) for a in hits[:6]],
        first_seen=min((a.timestamp for a in hits if a.timestamp), default=None),
        last_seen=max((a.timestamp for a in hits if a.timestamp), default=None),
        metrics={"count": len(hits), "terms": dict(matched_terms.most_common())},
        why_it_matters=("Awareness of evidence handling can bear on intent, "
                        "and points to where further material was destroyed."),
        caveat=("Keyword matching has no understanding of context — 'burn the "
                "CD' and 'my phone needs a factory reset' both match. Read "
                "every hit before relying on it."),
    )]


# --------------------------------------------------------- concealment/media
@rule
def concealed_files(ctx: CaseContext) -> List[Finding]:
    """Files whose extension contradicts their content."""
    hits = [a for a in ctx.by_category.get(Category.FILE.value, [])
            if a.attributes.get("extension_mismatch")]
    if not hits:
        return []
    return [Finding(
        rule_id="antiforensics.extension_mismatch",
        title=f"{len(hits)} file(s) disguised by extension",
        detail=("These files' contents do not match their filename extension "
                "— for example an image saved as a text or document file. "
                "They were identified by inspecting the file's magic bytes."),
        severity="high", confidence=0.9, category="antiforensics",
        artifact_ids=[a.artifact_id for a in hits],
        evidence=[f"{a.attributes.get('filename', a.body)} — "
                  f"{a.attributes.get('mismatch_note', '')}" for a in hits[:6]],
        first_seen=min((a.timestamp for a in hits if a.timestamp), default=None),
        last_seen=max((a.timestamp for a in hits if a.timestamp), default=None),
        metrics={"count": len(hits)},
        why_it_matters=("Renaming a file to hide it from casual inspection — "
                        "and from tools that trust extensions — is a "
                        "deliberate act."),
        caveat=("Applications sometimes store media with generic or absent "
                "extensions as a matter of course; check the file's location "
                "before treating the rename as intentional."),
    )]


# --------------------------------------------------------------- geolocation
@rule
def location_clusters(ctx: CaseContext) -> List[Finding]:
    """Repeated presence at a location outside the usual pattern."""
    points = [a for a in ctx.artifacts
              if a.latitude is not None and a.longitude is not None
              and a.timestamp]
    if len(points) < 10:
        return []

    # Grid at ~1 km, then find clusters visited on several distinct days.
    grid: Dict[tuple, List[Artifact]] = defaultdict(list)
    for a in points:
        grid[(round(a.latitude, 2), round(a.longitude, 2))].append(a)

    ranked = sorted(grid.items(), key=lambda kv: -len(kv[1]))
    if not ranked:
        return []
    home_cell = ranked[0][0]

    findings: List[Finding] = []
    for cell, arts in ranked[1:6]:
        days = {datetime.fromtimestamp(a.timestamp / US, tz=timezone.utc).date()
                for a in arts}
        if len(arts) < 4 or len(days) < 2:
            continue
        night = [a for a in arts if 0 <= _hour(a.timestamp) <= 5]
        findings.append(Finding(
            rule_id="location.cluster",
            title=f"Repeated presence at {cell[0]:.2f}, {cell[1]:.2f}",
            detail=(f"{len(arts)} geolocated artifacts across {len(days)} "
                    f"distinct days at this location"
                    + (f", {len(night)} of them between midnight and 05:00"
                       if night else "") + "."),
            severity="medium" if night else "low",
            confidence=0.6, category="location",
            artifact_ids=[a.artifact_id for a in arts],
            first_seen=min(a.timestamp for a in arts),
            last_seen=max(a.timestamp for a in arts),
            metrics={"visits": len(arts), "distinct_days": len(days),
                     "night_visits": len(night),
                     "latitude": cell[0], "longitude": cell[1],
                     "map_url": f"https://www.openstreetmap.org/?mlat={cell[0]}"
                                f"&mlon={cell[1]}#map=15/{cell[0]}/{cell[1]}"},
            why_it_matters=("A location visited repeatedly, but which is not "
                            "the device's primary location, may be a place of "
                            "work, a meeting point or a storage site."),
            caveat=("Cell-tower and Wi-Fi derived positions can be off by "
                    "hundreds of metres; treat the cluster as approximate."),
        ))
    if findings:
        findings[0].metrics["most_frequent_cell"] = list(home_cell)
    return findings


# ------------------------------------------------------------- entity leads
@rule
def high_value_entities(ctx: CaseContext) -> List[Finding]:
    """Wallets, dark-web addresses, cards and accounts found in content."""
    if ctx.entities is None:
        return []
    findings: List[Finding] = []
    interesting = {"btc": "Cryptocurrency wallet", "eth": "Cryptocurrency wallet",
                   "xmr": "Privacy-coin wallet", "onion": "Dark-web address",
                   "card": "Payment card number", "iban": "Bank account",
                   "imei": "Another handset's IMEI"}
    grouped: Dict[str, List[Any]] = defaultdict(list)
    for hit in ctx.entities.results():
        if hit.kind in interesting:
            grouped[hit.kind].append(hit)

    for kind, hits in grouped.items():
        severity = "high" if kind in ("btc", "eth", "xmr", "onion") else "medium"
        findings.append(Finding(
            rule_id=f"entity.{kind}",
            title=f"{len(hits)} {interesting[kind].lower()}(s) found in content",
            detail=("Extracted from message bodies, URLs and search terms, and "
                    "checksum-validated where the format allows: "
                    + ", ".join(h.value[:44] for h in hits[:5])
                    + ("…" if len(hits) > 5 else "")),
            severity=severity, confidence=0.85, category="entities",
            artifact_ids=[aid for h in hits for aid in h.artifact_ids][:200],
            entities=[h.value for h in hits],
            evidence=[c for h in hits for c in h.contexts][:6],
            first_seen=min((h.first_seen for h in hits if h.first_seen),
                           default=None),
            last_seen=max((h.last_seen for h in hits if h.last_seen),
                          default=None),
            metrics={"count": len(hits),
                     "apps": sorted({a for h in hits for a in h.apps})},
            why_it_matters=("Financial and dark-web identifiers found in "
                            "conversation are directly actionable — they can "
                            "be traced independently of the handset."),
            caveat=("A validated format proves the string is well-formed, not "
                    "that it belongs to the device owner or was ever used."),
        ))
    return findings


# ------------------------------------------------------- structural analysis
@rule
def one_way_relationships(ctx: CaseContext) -> List[Finding]:
    """Contact that flows in only one direction."""
    if ctx.graph is None:
        return []
    edges = ctx.graph.one_way_contacts(min_artifacts=4)
    if not edges:
        return []
    labels = {k: n.label for k, n in ctx.graph.nodes.items()}
    described = []
    for e in edges[:8]:
        a = labels.get(e["source"], e["source"])
        b = labels.get(e["target"], e["target"])
        described.append(f"{a} ↔ {b} ({e['artifact_count']} artifacts)")
    return [Finding(
        rule_id="graph.one_way",
        title=f"{len(edges)} correspondent(s) with one-directional traffic",
        detail=("Communication with these parties flows in a single direction "
                "only: " + "; ".join(described)),
        severity="medium", confidence=0.6, category="graph",
        parties=[d.split(" ↔ ")[0] for d in described],
        artifact_ids=[aid for e in edges
                      for aid in e.get("artifact_ids", [])][:300],
        metrics={"count": len(edges)},
        why_it_matters=("One-way traffic distinguishes automated senders from "
                        "real correspondents, and can reveal a party the "
                        "device owner contacted but who never replied on this "
                        "channel."),
        caveat=("Automated services, OTP senders and marketing account for "
                "most one-way traffic on an ordinary handset."),
    )]


@rule
def dormant_then_active(ctx: CaseContext) -> List[Finding]:
    """A correspondent who goes quiet and then abruptly returns."""
    by_key: Dict[str, List[int]] = defaultdict(list)
    labels: Dict[str, str] = {}
    for art in ctx.comms():
        if not art.timestamp:
            continue
        for p in art.counterparties():
            key = p.normalised()
            if key:
                by_key[key].append(art.timestamp)
                labels.setdefault(key, p.label())

    findings: List[Finding] = []
    for key, stamps in by_key.items():
        if len(stamps) < 8:
            continue
        stamps.sort()
        gaps = [(b - a, a, b) for a, b in zip(stamps, stamps[1:])]
        longest, gap_start, gap_end = max(gaps)
        gap_days = longest / DAY
        after = [t for t in stamps if t >= gap_end]
        if gap_days < 21 or len(after) < 4:
            continue
        findings.append(Finding(
            rule_id="pattern.dormant_reactivation",
            title=f"Contact with {labels[key]} resumed after {gap_days:.0f} days",
            detail=(f"Communication with {labels[key]} stopped for "
                    f"{gap_days:.0f} days and then resumed, with "
                    f"{len(after)} exchanges afterwards."),
            severity="low", confidence=0.5, category="pattern",
            parties=[labels[key]],
            first_seen=gap_start, last_seen=gap_end,
            metrics={"gap_days": round(gap_days, 1),
                     "before": len(stamps) - len(after), "after": len(after)},
            why_it_matters=("A relationship that reactivates after a long "
                            "silence often marks the start of a new episode."),
            caveat="Common and usually innocent; treat as context, not a lead.",
        ))
    return sorted(findings, key=lambda f: -f.metrics["gap_days"])[:5]


@rule
def encrypted_app_leaked_via_notifications(ctx: CaseContext) -> List[Finding]:
    """Content from an encrypted app recovered through the OS notification store.

    This is the most valuable cross-source inference the tool makes. Signal,
    Telegram secret chats and similar keep their databases encrypted, so their
    content is normally unavailable. But the operating system writes a preview
    of each incoming message into its *own* notification store, which is not
    encrypted — so the text of a message that is unreadable in the app is often
    perfectly readable a few tables away.

    An examiner working app-by-app will not see this, because it requires
    noticing that one source is encrypted *and* that another source contains
    its content.
    """
    previews = [a for a in ctx.artifacts
                if a.attributes.get("previews_encrypted_app")]
    if not previews:
        return []
    encrypted = [a for a in ctx.artifacts if a.attributes.get("encrypted")]
    apps = Counter(a.app for a in previews if a.app)
    return [Finding(
        rule_id="crosssource.notification_leak",
        title=(f"{len(previews)} message(s) from encrypted app(s) recovered "
               f"via notifications"),
        detail=("These applications keep their message stores encrypted, so "
                "their contents could not be decoded — but the operating "
                "system's notification history retained a preview of the "
                "message text. Affected applications: "
                + ", ".join(f"{app} ({n})" for app, n in apps.most_common())
                + (f". {len(encrypted)} encrypted store(s) were separately "
                   f"identified on this device." if encrypted else "")),
        severity="critical", confidence=0.85, category="crosssource",
        artifact_ids=[a.artifact_id for a in previews],
        parties=sorted({p.label() for a in previews
                        for p in a.counterparties() if p.label()})[:8],
        evidence=[a.summary(150) for a in previews[:6]],
        first_seen=min((a.timestamp for a in previews if a.timestamp),
                       default=None),
        last_seen=max((a.timestamp for a in previews if a.timestamp),
                      default=None),
        metrics={"count": len(previews), "apps": dict(apps),
                 "encrypted_stores_found": len(encrypted)},
        why_it_matters=("This is frequently the only readable copy of content "
                        "from an end-to-end encrypted application. It survives "
                        "precisely because the user secured the app but not the "
                        "operating system around it."),
        caveat=("A notification preview is a truncated copy written by the OS, "
                "not the message itself. It may be cut short, may show a "
                "sender's display name rather than their account, and cannot "
                "establish what was sent in the other direction."),
    )]


@rule
def device_in_use_at_time(ctx: CaseContext) -> List[Finding]:
    """Device-usage telemetry that attributes activity to a person.

    Message records show what a handset sent. Usage telemetry — app focus,
    screen state, unlock events — shows whether someone was *holding it*. That
    distinction is what separates "the phone sent this" from "the owner sent
    this", and it is often the contested point.
    """
    usage = [a for a in ctx.artifacts
             if a.category == Category.ACTIVITY
             and ("foreground" in (a.subtype or "").lower()
                  or "usage" in (a.subtype or "").lower()
                  or "KnowledgeC" in (a.subtype or ""))]
    if len(usage) < 10:
        return []
    apps = Counter(a.app for a in usage if a.app)
    total_seconds = sum(float(a.attributes.get("duration_seconds") or 0)
                        for a in usage)
    return [Finding(
        rule_id="activity.device_in_use",
        title=f"{len(usage)} device-usage events establish hands-on use",
        detail=("Foreground, screen and unlock telemetry recovered from the "
                "operating system's own analytics. Most-used applications: "
                + ", ".join(f"{app} ({n} events)"
                            for app, n in apps.most_common(5))
                + (f". Total recorded foreground time: "
                   f"{total_seconds/60:.0f} minutes." if total_seconds else "")),
        severity="medium", confidence=0.8, category="activity",
        artifact_ids=[a.artifact_id for a in usage][:300],
        first_seen=min((a.timestamp for a in usage if a.timestamp), default=None),
        last_seen=max((a.timestamp for a in usage if a.timestamp), default=None),
        metrics={"events": len(usage), "apps": dict(apps.most_common(15)),
                 "total_foreground_seconds": round(total_seconds, 1)},
        why_it_matters=("Places a person at the device at specific moments, "
                        "which is what allows activity to be attributed to the "
                        "owner rather than merely to the handset. It also "
                        "survives message deletion, because users who clear "
                        "their chats rarely clear the OS analytics store."),
        caveat=("Usage telemetry shows the device was operated, not who "
                "operated it. It cannot distinguish the owner from anyone else "
                "with access to the unlocked handset."),
    )]


@rule
def integrity_and_tampering(ctx: CaseContext) -> List[Finding]:
    """Timestamp anomalies suggesting a changed device clock."""
    from ..analyze.timeline import anomalies, build
    entries = build(ctx.artifacts)
    problems = anomalies(entries)
    if not problems:
        return []
    high = [p for p in problems if p.get("severity") == "high"]
    return [Finding(
        rule_id="integrity.timestamps",
        title=f"{len(problems)} timestamp anomal{'y' if len(problems)==1 else 'ies'} detected",
        detail="; ".join(p["reason"] for p in problems[:5]),
        severity="high" if high else "medium", confidence=0.7,
        category="integrity",
        artifact_ids=[p["artifact_id"] for p in problems if p.get("artifact_id")],
        evidence=[f"{p.get('iso','')} — {p['reason']}" for p in problems[:6]],
        metrics={"count": len(problems), "high_severity": len(high)},
        why_it_matters=("Timestamps that cannot be right undermine any "
                        "timeline built on them, and a changed device clock "
                        "can be deliberate."),
        caveat=("Timezone changes, dual-SIM devices and app bugs all produce "
                "benign timestamp anomalies."),
    )]


@rule
def vivo_comms_fallback(ctx: CaseContext) -> List[Finding]:
    """Vivo/Funtouch often returns 0 contacts/calls from providers."""
    msgs = ctx.by_category.get(Category.MESSAGE.value, [])
    contacts = ctx.by_category.get(Category.CONTACT.value, [])
    calls = ctx.by_category.get(Category.CALL.value, [])
    if not msgs or (contacts and calls):
        return []
    fallback = [a for a in msgs + calls + contacts
                if any(x in (a.source_path or "").lower()
                       for x in ("dumpsys", "vivobackup", "content/",
                                 "comms_logical", "smsbackup", ".vcf"))]
    if not fallback:
        return []
    dumpsys_n = sum(1 for a in fallback if "dumpsys" in (a.source_path or ""))
    return [Finding(
        rule_id="vivo.comms_fallback",
        title="Communications recovered via fallback paths (typical Vivo)",
        detail=(f"{len(msgs)} message(s) decoded but contacts/calls may be "
                f"incomplete via live providers. {len(fallback)} artifact(s) "
                f"from dumpsys/exports/logical dumps"
                + (f" ({dumpsys_n} dumpsys)" if dumpsys_n else "") + "."),
        severity="medium", confidence=0.75, category="communications",
        artifact_ids=[a.artifact_id for a in fallback[:40]],
        metrics={"messages": len(msgs), "contacts": len(contacts),
                   "calls": len(calls), "fallback_sources": len(fallback)},
        why_it_matters=("On non-root Vivo handsets, SMS often survives in "
                        "logical dumps while contacts/calls require dumpsys "
                        "or on-phone exports."),
        caveat="Pattern is common on BBK/Funtouch; not evidence of concealment.",
    )]


@rule
def vivobackup_exports(ctx: CaseContext) -> List[Finding]:
    """Artifacts from Vivo/BBK backup trees on shared storage."""
    hits = [a for a in ctx.artifacts
            if any(x in (a.source_path or "").lower()
                   for x in (".vivobackup", "vivobackup", "easyshare",
                             "bbk/backup", "vivo/backup"))]
    if not hits:
        return []
    return [Finding(
        rule_id="vivo.backup_exports",
        title=f"{len(hits)} artifact(s) from Vivo/BBK backup exports",
        detail=("Shared-storage backup folders (.vivobackup, EasyShare) may "
                "contain SMS/contact exports not visible via content providers."),
        severity="medium", confidence=0.8, category="communications",
        artifact_ids=[a.artifact_id for a in hits[:30]],
        metrics={"count": len(hits)},
        why_it_matters="OEM backup exports are a primary comms source on Vivo Y02.",
    )]


# ------------------------------------------------------------------- engine
class FindingsEngine:
    """Run every rule and rank the results."""

    def __init__(self, rules: Optional[Sequence[Callable]] = None):
        self.rules = list(rules or RULES)

    def run(self, ctx: CaseContext,
            progress: Optional[Callable[[str], None]] = None) -> List[Finding]:
        found: List[Finding] = []
        total = len(self.rules)
        for idx, fn in enumerate(self.rules, 1):
            name = getattr(fn, "__name__", "rule")
            if progress:
                progress(f"Rule {idx}/{total}: {name}…")
            try:
                found.extend(fn(ctx) or [])
            except Exception as exc:                          # pragma: no cover
                found.append(Finding(
                    rule_id=f"engine.error.{getattr(fn, '__name__', 'rule')}",
                    title=f"Rule '{getattr(fn, '__name__', '?')}' failed",
                    detail=f"{type(exc).__name__}: {exc}",
                    severity="info", confidence=1.0, category="engine",
                    why_it_matters=("A rule that did not run may mean a lead "
                                    "was missed; it is reported rather than "
                                    "silently skipped.")))
        return sorted(found, key=lambda f: (-f.score, f.rule_id))

    def analyse(self, artifacts: Iterable[Artifact], owner_name: str = "Device owner",
                owner_keys: Optional[Iterable[str]] = None,
                entities: Any = None, graph: Any = None) -> Dict[str, Any]:
        arts = list(artifacts)
        ctx = CaseContext(artifacts=arts, owner_name=owner_name,
                          owner_keys=set(owner_keys or ()), entities=entities,
                          graph=graph)
        findings = self.run(ctx)
        by_sev = Counter(f.severity for f in findings)
        return {
            "findings": [f.as_dict() for f in findings],
            "count": len(findings),
            "by_severity": {s: by_sev.get(s, 0) for s in
                            ("critical", "high", "medium", "low", "info")},
            "by_category": dict(Counter(f.category for f in findings)),
            "top": [f.as_dict() for f in findings[:10]],
            "artifacts_analysed": len(arts),
            "rules_run": len(self.rules),
        }
