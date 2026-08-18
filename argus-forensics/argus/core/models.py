"""Canonical artifact model.

Every parser in ARGUS, regardless of platform or source application, emits the
same :class:`Artifact` record.  This is what makes cross-application analysis
(timeline, connection graph, unified search) possible: a WhatsApp message, an
iOS SMS and an Android MMS all become ``Artifact(category=MESSAGE, ...)`` with
normalised participants and a UTC timestamp.

Timestamps
----------
All timestamps are stored as **integer microseconds since the Unix epoch, UTC**.
Mobile platforms use at least six different epochs (Unix seconds, Unix
milliseconds, Apple/Mac absolute time, WebKit/Chrome time, FILETIME, Julian
day).  :mod:`argus.parsers.timestamps` converts every one of them into this
single representation so that a timeline across an iPhone and an Android
handset is actually comparable.
"""

from __future__ import annotations

import enum
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class Category(str, enum.Enum):
    """Top-level artifact categories, mirroring the lab manual's category set."""

    CALL = "Calls"
    CONTACT = "Contacts"
    MESSAGE = "Messages"
    CHAT = "Chats"
    FILE = "Files & Media"
    WEB = "Web"
    PLACE = "Places"
    SECURITY = "Security"
    ACTIVITY = "User activity log"
    ACCOUNT = "Accounts"
    APP = "Applications"
    NETWORK = "Networks"
    DEVICE = "Device info"
    CALENDAR = "Calendar"
    NOTE = "Notes"
    OTHER = "Other"

    @classmethod
    def coerce(cls, value: Any) -> "Category":
        if isinstance(value, cls):
            return value
        s = str(value or "").strip()
        for member in cls:
            if s.lower() in (member.value.lower(), member.name.lower()):
                return member
        return cls.OTHER


class Direction(str, enum.Enum):
    INCOMING = "incoming"
    OUTGOING = "outgoing"
    MISSED = "missed"
    REJECTED = "rejected"
    DRAFT = "draft"
    UNKNOWN = "unknown"


class Recovery(str, enum.Enum):
    """How the artifact was recovered from the source."""

    ALLOCATED = "allocated"          # live row in a live table
    DELETED_FREELIST = "deleted-freelist"   # carved from a freed SQLite page
    DELETED_UNALLOC = "deleted-unallocated" # carved from unallocated cell space
    WAL = "wal"                      # recovered from write-ahead log
    JOURNAL = "journal"              # recovered from rollback journal
    CARVED = "carved"                # file carved by signature


@dataclass
class Participant:
    """A party to a communication (caller, sender, recipient, group member)."""

    identifier: str = ""            # phone number, email, JID, handle
    display_name: str = ""
    role: str = "party"             # from | to | cc | bcc | party | owner
    is_owner: bool = False

    def normalised(self) -> str:
        """Return a comparison key: digits-only for phone-like identifiers."""
        raw = (self.identifier or "").strip()
        if not raw:
            return (self.display_name or "").strip().lower()
        if "@" in raw:
            return raw.split("/")[0].lower()
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) >= 7:
            return digits[-10:]          # last 10 digits: country-code agnostic
        return raw.lower()

    def label(self) -> str:
        return self.display_name or self.identifier or "(unknown)"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Artifact:
    """One normalised piece of evidence."""

    category: Category = Category.OTHER
    subtype: str = ""                       # "SMS", "WhatsApp Message", "Voice call"
    timestamp: Optional[int] = None         # microseconds since epoch, UTC
    timestamp_end: Optional[int] = None
    body: str = ""                          # message text / note / URL title
    participants: List[Participant] = field(default_factory=list)
    direction: Direction = Direction.UNKNOWN
    app: str = ""                           # "com.whatsapp" / "Apple Messages"
    source_path: str = ""                   # path inside the acquired evidence
    source_table: str = ""                  # e.g. "message" / "ZWAMESSAGE"
    source_row: Optional[int] = None        # rowid where applicable
    recovery: Recovery = Recovery.ALLOCATED
    blob_sha256: str = ""                   # payload in the blob store, if any
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    artifact_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    confidence: float = 1.0                 # 1.0 allocated, lower for carved

    # ---------------------------------------------------------------- helpers
    def add_participant(self, identifier: str, name: str = "", role: str = "party",
                        is_owner: bool = False) -> None:
        if not identifier and not name:
            return
        self.participants.append(
            Participant(identifier=identifier or "", display_name=name or "",
                        role=role, is_owner=is_owner)
        )

    def counterparties(self) -> List[Participant]:
        return [p for p in self.participants if not p.is_owner]

    def summary(self, width: int = 120) -> str:
        text = self.body.replace("\n", " ").strip()
        if len(text) > width:
            text = text[: width - 1] + "…"
        if not text:
            text = self.attributes.get("filename") or self.subtype or self.category.value
        return text

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["direction"] = self.direction.value
        d["recovery"] = self.recovery.value
        return d

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True)


@dataclass
class DataSource:
    """A single source file/stream that a parser consumed."""

    path: str
    digest_sha256: str
    size: int
    parser: str
    artifact_count: int = 0
    notes: str = ""
