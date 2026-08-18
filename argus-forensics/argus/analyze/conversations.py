"""Conversation reconstruction — reading chats as chats.

Every tool in this space presents messages as a flat, sortable table. That is
the wrong shape for the question an examiner is actually asking, which is never
"list all messages" but "what did these two people say to each other, and in
what order?"

This module threads flat artifacts back into conversations — one per
correspondent per application — and derives the things that only become visible
once the thread exists:

* **Turn-taking and response latency.** Who initiates, who answers, how fast.
  A relationship where one party always replies within seconds looks different
  from one where replies take days.
* **Where the deleted messages sit.** A deleted message inside an otherwise
  intact thread is far more informative than the same message in isolation,
  because the surviving messages either side give it context. This module marks
  the position of each gap.
* **Silences inside an active thread**, as distinct from the thread simply
  ending.
* **Cross-application threads.** The same person reached on SMS, WhatsApp and
  Telegram is one relationship conducted over three channels; the module reports
  both the per-channel threads and the merged relationship.

One deliberate limitation, stated because it affects how the output should be
read: a reconstructed thread is only as complete as the evidence. Where messages
were destroyed rather than recovered, the thread has holes that cannot be seen —
so "no gap detected" is not the same as "nothing was deleted".
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.models import Artifact, Category, Direction, Recovery
from ..parsers.timestamps import to_iso

US = 1_000_000
MINUTE = 60 * US
HOUR = 3600 * US
DAY = 86400 * US

COMMUNICATION = {Category.MESSAGE, Category.CHAT, Category.CALL}

# Voice channels are not "another messaging app". Counting a phone call as a
# separate channel makes almost every contact look like channel-switching, which
# buries the handful of cases where someone genuinely moved a conversation from
# one messaging app to another.
VOICE_CHANNELS = {"android phone", "apple phone", "phone", "dialer",
                  "cellular", "call log"}


def _is_messaging_channel(app: str) -> bool:
    return (app or "").strip().lower() not in VOICE_CHANNELS


@dataclass
class Turn:
    """One message or call in a thread."""

    artifact_id: str
    timestamp: Optional[int]
    direction: str
    body: str
    subtype: str = ""
    recovery: str = "allocated"
    confidence: float = 1.0
    latency_seconds: Optional[float] = None   # since the previous opposite turn
    app: str = ""

    @property
    def is_deleted(self) -> bool:
        return self.recovery != Recovery.ALLOCATED.value

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp_iso"] = to_iso(self.timestamp) if self.timestamp else ""
        d["is_deleted"] = self.is_deleted
        return d


@dataclass
class Conversation:
    """A threaded exchange with one correspondent in one application."""

    key: str                       # normalised correspondent identifier
    label: str                     # best display name
    app: str
    exhibit: str = ""
    turns: List[Turn] = field(default_factory=list)

    # Derived on finalise()
    first: Optional[int] = None
    last: Optional[int] = None
    incoming: int = 0
    outgoing: int = 0
    deleted: int = 0
    deleted_positions: List[int] = field(default_factory=list)
    median_reply_seconds: Optional[float] = None
    fastest_reply_seconds: Optional[float] = None
    longest_silence_hours: Optional[float] = None
    silence_at: Optional[int] = None
    initiated_by_owner: Optional[bool] = None
    call_count: int = 0
    total_call_seconds: int = 0

    @property
    def size(self) -> int:
        return len(self.turns)

    @property
    def reciprocity(self) -> float:
        if not (self.incoming or self.outgoing):
            return 0.0
        lo, hi = sorted((self.incoming, self.outgoing))
        return round(lo / hi, 3) if hi else 0.0

    @property
    def deleted_ratio(self) -> float:
        return round(self.deleted / self.size, 3) if self.size else 0.0

    @property
    def span_days(self) -> float:
        if self.first is None or self.last is None:
            return 0.0
        return round((self.last - self.first) / DAY, 2)

    def finalise(self) -> "Conversation":
        """Order the thread and derive its shape."""
        self.turns.sort(key=lambda t: (t.timestamp is None, t.timestamp or 0))
        stamps = [t.timestamp for t in self.turns if t.timestamp is not None]
        self.first = stamps[0] if stamps else None
        self.last = stamps[-1] if stamps else None

        self.incoming = sum(1 for t in self.turns
                            if t.direction == Direction.INCOMING.value)
        self.outgoing = sum(1 for t in self.turns
                            if t.direction == Direction.OUTGOING.value)
        self.deleted = sum(1 for t in self.turns if t.is_deleted)
        self.deleted_positions = [i for i, t in enumerate(self.turns)
                                  if t.is_deleted]

        # Reply latency: time from a turn to the next turn in the *opposite*
        # direction. Measuring against the previous turn regardless of direction
        # would score a burst of consecutive messages as instant replies.
        latencies: List[float] = []
        for index, turn in enumerate(self.turns):
            if turn.timestamp is None or turn.direction not in (
                    Direction.INCOMING.value, Direction.OUTGOING.value):
                continue
            for later in self.turns[index + 1:]:
                if later.timestamp is None:
                    continue
                if later.direction not in (Direction.INCOMING.value,
                                           Direction.OUTGOING.value):
                    continue
                if later.direction != turn.direction:
                    seconds = (later.timestamp - turn.timestamp) / US
                    if seconds >= 0:
                        later.latency_seconds = round(seconds, 1)
                        latencies.append(seconds)
                    break
        if latencies:
            self.median_reply_seconds = round(statistics.median(latencies), 1)
            self.fastest_reply_seconds = round(min(latencies), 1)

        # Longest silence *inside* the thread, not the trailing gap.
        if len(stamps) > 2:
            gaps = [(b - a, a) for a, b in zip(stamps, stamps[1:])]
            longest, at = max(gaps)
            if longest >= 6 * HOUR:
                self.longest_silence_hours = round(longest / HOUR, 1)
                self.silence_at = at

        directional = [t for t in self.turns
                       if t.direction in (Direction.INCOMING.value,
                                          Direction.OUTGOING.value)]
        if directional:
            self.initiated_by_owner = (
                directional[0].direction == Direction.OUTGOING.value)

        calls = [t for t in self.turns if "call" in (t.subtype or "").lower()]
        self.call_count = len(calls)
        return self

    def transcript(self, limit: int = 200, owner_name: str = "Owner") -> str:
        """Render the thread the way it would have been read on the handset."""
        lines: List[str] = []
        for turn in self.turns[:limit]:
            who = (owner_name if turn.direction == Direction.OUTGOING.value
                   else self.label)
            when = to_iso(turn.timestamp)[:19] if turn.timestamp else "unknown"
            mark = "  [RECOVERED FROM DELETED SPACE]" if turn.is_deleted else ""
            body = (turn.body or f"[{turn.subtype}]").replace("\n", " ")
            lines.append(f"{when}  {who}: {body}{mark}")
        if self.size > limit:
            lines.append(f"… {self.size - limit} further turns not shown")
        return "\n".join(lines)

    def as_dict(self, include_turns: bool = True,
                turn_limit: int = 400) -> Dict[str, Any]:
        d = {
            "key": self.key, "label": self.label, "app": self.app,
            "exhibit": self.exhibit, "size": self.size,
            "incoming": self.incoming, "outgoing": self.outgoing,
            "deleted": self.deleted, "deleted_ratio": self.deleted_ratio,
            "deleted_positions": self.deleted_positions[:100],
            "reciprocity": self.reciprocity,
            "first": self.first, "last": self.last,
            "first_iso": to_iso(self.first) if self.first else "",
            "last_iso": to_iso(self.last) if self.last else "",
            "span_days": self.span_days,
            "median_reply_seconds": self.median_reply_seconds,
            "fastest_reply_seconds": self.fastest_reply_seconds,
            "longest_silence_hours": self.longest_silence_hours,
            "silence_at_iso": to_iso(self.silence_at) if self.silence_at else "",
            "initiated_by_owner": self.initiated_by_owner,
            "call_count": self.call_count,
        }
        if include_turns:
            d["turns"] = [t.as_dict() for t in self.turns[:turn_limit]]
            d["turns_truncated"] = self.size > turn_limit
        return d


class ConversationBuilder:
    """Thread flat artifacts into conversations."""

    def __init__(self, owner_name: str = "Device owner"):
        self.owner_name = owner_name
        self._threads: Dict[Tuple[str, str, str], Conversation] = {}
        self._names: Dict[str, Counter] = defaultdict(Counter)
        self._contact_names: Dict[str, str] = {}

    def learn_contacts(self, artifacts: Iterable[Artifact]) -> None:
        for art in artifacts:
            if art.category != Category.CONTACT:
                continue
            name = str(art.attributes.get("display_name") or art.body or "").strip()
            if not name:
                continue
            for p in art.participants:
                key = p.normalised()
                if key:
                    self._contact_names.setdefault(key, name)

    def add(self, artifacts: Iterable[Artifact], exhibit: str = "") -> None:
        for art in artifacts:
            if art.category not in COMMUNICATION:
                continue
            counterparties = [p for p in art.participants if not p.is_owner]
            if not counterparties:
                continue
            # Group chats produce a thread per member, which is how an examiner
            # follows an individual through a group.
            for party in counterparties:
                key = party.normalised()
                if not key:
                    continue
                if party.display_name:
                    self._names[key][party.display_name.strip()] += 1
                thread_key = (key, art.app or "unknown", exhibit)
                thread = self._threads.get(thread_key)
                if thread is None:
                    thread = Conversation(key=key, label=key,
                                          app=art.app or "unknown",
                                          exhibit=exhibit)
                    self._threads[thread_key] = thread
                thread.turns.append(Turn(
                    artifact_id=art.artifact_id, timestamp=art.timestamp,
                    direction=art.direction.value, body=art.summary(600),
                    subtype=art.subtype, recovery=art.recovery.value,
                    confidence=art.confidence, app=art.app))
                if art.category == Category.CALL:
                    thread.total_call_seconds += int(
                        art.attributes.get("duration_seconds") or 0)

    def build(self, min_turns: int = 2) -> List[Conversation]:
        out: List[Conversation] = []
        for thread in self._threads.values():
            named = self._contact_names.get(thread.key)
            if not named and self._names.get(thread.key):
                named = self._names[thread.key].most_common(1)[0][0]
            thread.label = named or thread.key
            thread.finalise()
            if thread.size >= min_turns:
                out.append(thread)
        return sorted(out, key=lambda c: (-c.size, c.label))

    def relationships(self, min_turns: int = 2) -> List[Dict[str, Any]]:
        """Merge per-application threads into one relationship per person.

        A contact reached on SMS, WhatsApp and Telegram is one relationship
        conducted over three channels. Reporting only the channels understates
        the relationship; reporting only the merge loses which channel was used
        for what — so both are produced.
        """
        threads = self.build(min_turns=1)
        grouped: Dict[str, List[Conversation]] = defaultdict(list)
        for thread in threads:
            grouped[thread.key].append(thread)

        out: List[Dict[str, Any]] = []
        for key, group in grouped.items():
            total = sum(t.size for t in group)
            if total < min_turns:
                continue
            firsts = [t.first for t in group if t.first is not None]
            lasts = [t.last for t in group if t.last is not None]
            channels = sorted({t.app for t in group})
            messaging_channels = sorted({t.app for t in group
                                         if _is_messaging_channel(t.app)})
            deleted = sum(t.deleted for t in group)
            out.append({
                "key": key,
                "label": group[0].label,
                "channels": channels,
                "channel_count": len(channels),
                "messaging_channels": messaging_channels,
                "messaging_channel_count": len(messaging_channels),
                "exhibits": sorted({t.exhibit for t in group if t.exhibit}),
                "turns": total,
                "incoming": sum(t.incoming for t in group),
                "outgoing": sum(t.outgoing for t in group),
                "deleted": deleted,
                "deleted_ratio": round(deleted / total, 3) if total else 0.0,
                "calls": sum(t.call_count for t in group),
                "call_seconds": sum(t.total_call_seconds for t in group),
                "first_iso": to_iso(min(firsts)) if firsts else "",
                "last_iso": to_iso(max(lasts)) if lasts else "",
                "per_channel": [t.as_dict(include_turns=False) for t in group],
                # Only a switch between *messaging* apps counts.
                "multi_channel": len(messaging_channels) > 1,
            })
        return sorted(out, key=lambda r: (-r["turns"], r["label"]))

    def summary(self, min_turns: int = 2) -> Dict[str, Any]:
        threads = self.build(min_turns)
        relationships = self.relationships(min_turns)
        with_deleted = [t for t in threads if t.deleted]
        return {
            "conversations": [t.as_dict(include_turns=False) for t in threads],
            "conversation_count": len(threads),
            "relationships": relationships,
            "relationship_count": len(relationships),
            "multi_channel_relationships": sum(1 for r in relationships
                                               if r["multi_channel"]),
            "threads_with_deleted_content": len(with_deleted),
            "wholly_deleted_threads": sum(
                1 for t in threads if t.deleted == t.size),
            "note": ("A reconstructed thread is only as complete as the "
                     "evidence. Where messages were destroyed rather than "
                     "recovered the thread has holes that cannot be seen, so "
                     "the absence of a detected gap does not mean nothing was "
                     "deleted."),
        }


def build_conversations(session: Any, owner_name: str = "Device owner"
                        ) -> ConversationBuilder:
    """Build conversations across every container in a session."""
    builder = ConversationBuilder(owner_name=owner_name)
    for loaded in session.loaded:
        exhibit = (loaded.container.extraction.get("exhibit_id")
                   or loaded.container.path.name)
        artifacts = list(loaded.db.iter_artifacts())
        builder.learn_contacts(artifacts)
        builder.add(artifacts, exhibit=exhibit)
    return builder


def conversation_findings(builder: ConversationBuilder) -> List[Any]:
    """Findings that only a threaded view makes visible."""
    from ..intel.findings import Finding

    out: List[Finding] = []
    threads = builder.build(min_turns=3)
    if not threads:
        return out

    # --- deleted messages embedded inside an otherwise intact thread
    embedded = [t for t in threads
                if 0 < t.deleted < t.size
                and any(0 < p < t.size - 1 for p in t.deleted_positions)]
    if embedded:
        out.append(Finding(
            rule_id="conversation.embedded_deletions",
            title=(f"{len(embedded)} conversation(s) have deleted messages "
                   f"between surviving ones"),
            detail=("In these threads, recovered deleted messages sit between "
                    "messages that survived — so the surrounding conversation "
                    "gives them context: "
                    + "; ".join(f"{t.label} on {t.app} "
                                f"({t.deleted} of {t.size} turns deleted)"
                                for t in embedded[:6])),
            severity="high", confidence=0.85, category="conversation",
            artifact_ids=[turn.artifact_id for t in embedded
                          for turn in t.turns if turn.is_deleted][:300],
            parties=[t.label for t in embedded[:8]],
            evidence=[t.transcript(limit=6, owner_name=builder.owner_name)
                      for t in embedded[:3]],
            first_seen=min((t.first for t in embedded if t.first), default=None),
            last_seen=max((t.last for t in embedded if t.last), default=None),
            metrics={"count": len(embedded),
                     "detail": [t.as_dict(include_turns=False)
                                for t in embedded[:10]]},
            why_it_matters=("Selective deletion within a thread that was "
                            "otherwise kept indicates specific messages were "
                            "targeted, and the surviving messages either side "
                            "establish what the deleted ones were responding to."),
            caveat=("Messaging apps expire media and long threads "
                    "automatically, which produces the same pattern without "
                    "any user action."),
        ))

    # --- relationships conducted across several applications
    multi = [r for r in builder.relationships(min_turns=4)
             if r["multi_channel"] and r["messaging_channel_count"] >= 3]
    multi_keys = {r["key"] for r in multi}
    multi_turns = [turn.artifact_id for t in builder.build(min_turns=1)
                   if t.key in multi_keys and _is_messaging_channel(t.app)
                   for turn in t.turns]
    if multi:
        out.append(Finding(
            rule_id="conversation.channel_switching",
            title=(f"{len(multi)} correspondent(s) reached across multiple "
                   f"applications"),
            detail=("The same person was contacted through three or more "
                    "distinct messaging applications (voice channels excluded): "
                    + "; ".join(
                        f"{r['label']} via "
                        f"{', '.join(r['messaging_channels'])} "
                        f"({r['turns']} turns)" for r in multi[:6])),
            severity="medium", confidence=0.75, category="conversation",
            artifact_ids=multi_turns[:300],
            parties=[r["label"] for r in multi[:8]],
            metrics={"count": len(multi), "detail": multi[:10]},
            why_it_matters=("Moving a conversation from an unencrypted channel "
                            "to an encrypted one, or to a channel the owner "
                            "believed was less monitored, is often deliberate "
                            "and the timing of the switch can be significant."),
            caveat=("People use whichever app the other person is on. Multiple "
                    "channels are entirely ordinary and only become "
                    "interesting if the switch coincides with something else."),
        ))

    # --- unusually fast, sustained exchanges
    rapid = [t for t in threads
             if t.median_reply_seconds is not None
             and t.median_reply_seconds < 45 and t.size >= 8]
    if rapid:
        out.append(Finding(
            rule_id="conversation.rapid_exchange",
            title=f"{len(rapid)} conversation(s) show sustained rapid exchange",
            detail=("Median reply time under 45 seconds across a substantial "
                    "thread, indicating both parties were actively at their "
                    "devices: "
                    + "; ".join(f"{t.label} ({t.size} turns, median "
                                f"{t.median_reply_seconds:.0f}s)"
                                for t in rapid[:6])),
            severity="low", confidence=0.7, category="conversation",
            artifact_ids=[turn.artifact_id for t in rapid
                          for turn in t.turns][:300],
            parties=[t.label for t in rapid[:8]],
            metrics={"count": len(rapid),
                     "detail": [t.as_dict(include_turns=False)
                                for t in rapid[:10]]},
            why_it_matters=("Establishes both parties were present and engaged "
                            "at a specific time, which bears on attributing "
                            "the messages to people rather than to devices."),
            caveat=("Automated replies and notification-driven bursts produce "
                    "the same signature."),
        ))
    return out
