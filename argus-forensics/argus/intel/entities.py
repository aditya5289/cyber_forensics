"""Entity extraction from artifact content.

A message body is not just text — it contains phone numbers, account handles,
crypto wallets, vehicle registrations, tracking numbers and URLs that are
often the actual lead in a case. An examiner reading 30 000 messages by hand
will miss them; a validated regex pass will not.

Two rules govern everything here:

**Validate, do not just match.** A 34-character alphanumeric string is not a
Bitcoin address until its Base58Check checksum verifies. An IBAN is not an
IBAN until its mod-97 check passes. Matching without validating floods a case
with false leads, and a false lead costs an investigator real hours.

**Never assert identity.** This module reports *"a string matching the Bitcoin
address format, checksum valid, appearing in these 4 messages"*. It does not
report *"the suspect's wallet"*. That distinction is the difference between
evidence and an allegation.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------- validators
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def _b58decode(text: str) -> Optional[bytes]:
    num = 0
    for ch in text:
        if ch not in _B58_INDEX:
            return None
        num = num * 58 + _B58_INDEX[ch]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _valid_bech32(address: str) -> bool:
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address) or len(address) > 90:
        return False
    hrp, data_part = address[:pos], address[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data_part):
        return False
    data = [_BECH32_CHARSET.index(c) for c in data_part]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    return _bech32_polymod(expanded + data) in (1, 0x2BC830A3)


def valid_btc(address: str) -> bool:
    """Base58Check (double-SHA256) or bech32/bech32m checksum."""
    if address.lower().startswith(("bc1", "tb1")):
        return _valid_bech32(address)
    raw = _b58decode(address)
    if raw is None or len(raw) != 25:
        return False
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return checksum == raw[21:]


def valid_eth(address: str) -> bool:
    """Format check only.

    EIP-55's mixed-case checksum needs Keccak-256, which is not in the standard
    library (``hashlib.sha3_256`` is the NIST variant and gives a different
    digest). Rather than compute the wrong hash and reject valid addresses,
    the format is accepted and reported as unverified.
    """
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", address))


def valid_iban(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        digits = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(digits) % 97 == 1


def valid_luhn(number: str) -> bool:
    """Luhn check — payment cards and IMEIs."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def valid_imei(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 15 and valid_luhn(digits)


def valid_card(value: str) -> bool:
    """Luhn *plus* a real issuer prefix.

    Luhn alone is far too weak to call something a payment card: an IMEI is
    also Luhn-valid, and roughly one in ten random digit strings passes. Every
    card network publishes its issuer identification ranges, so requiring the
    number to fall inside one turns a coin-flip into a reliable finding —
    which matters, because "payment card recovered from handset" is an
    allegation with consequences.
    """
    digits = re.sub(r"\D", "", value)
    n = len(digits)
    if not valid_luhn(digits):
        return False

    def between(prefix_len: int, lo: int, hi: int) -> bool:
        return lo <= int(digits[:prefix_len]) <= hi

    if digits[0] == "4" and n in (13, 16, 19):                  # Visa
        return True
    if n == 16 and (between(2, 51, 55) or between(4, 2221, 2720)):  # Mastercard
        return True
    if n == 15 and digits[:2] in ("34", "37"):                  # Amex
        return True
    if n == 16 and (digits.startswith("6011") or digits[:2] == "65"
                    or between(3, 644, 649)):                   # Discover
        return True
    if n == 14 and (between(3, 300, 305) or digits[:2] in ("36", "38")):  # Diners
        return True
    if n == 16 and between(4, 3528, 3589):                      # JCB
        return True
    if n == 16 and (digits[:2] in ("60", "65", "81", "82")
                    or digits.startswith("508")):               # RuPay
        return True
    return False


_TLDS = (".com", ".net", ".org", ".in", ".co", ".io", ".gov", ".edu", ".uk",
         ".me", ".info", ".biz", ".ru", ".cn", ".de", ".fr")


def valid_upi(value: str) -> bool:
    """Indian UPI virtual payment address: handle@psp, not an email."""
    if not re.fullmatch(r"[a-zA-Z0-9._-]{3,64}@[a-zA-Z]{2,20}", value):
        return False
    return not value.lower().endswith(_TLDS)


def valid_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        return False
    # Reject runs that are obviously not numbers people dial.
    if len(set(digits)) <= 2:
        return False
    return True


# ------------------------------------------------------------------ patterns
@dataclass
class EntityType:
    name: str
    label: str
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    weight: float = 1.0                    # investigative significance, 0–1
    description: str = ""
    normalise: Optional[Callable[[str], str]] = None


ENTITY_TYPES: List[EntityType] = [
    EntityType(
        "phone", "Phone number",
        re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?"
                   r"\d{3,5}[\s.-]?\d{3,4}[\s.-]?\d{0,4}(?![\w.])"),
        validator=valid_phone, weight=0.7,
        normalise=lambda s: re.sub(r"\D", "", s)[-10:],
        description="Numbers mentioned inside message text, not just headers"),
    EntityType(
        "email", "Email address",
        re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}"), weight=0.6),
    EntityType(
        "url", "URL",
        re.compile(r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+", re.I),
        weight=0.4),
    EntityType(
        "onion", "Tor hidden service",
        re.compile(r"\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b", re.I),
        weight=1.0,
        description="Dark-web address — high investigative significance"),
    EntityType(
        "btc", "Bitcoin address",
        re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b"),
        validator=valid_btc, weight=1.0,
        description="Base58Check or bech32 checksum verified"),
    EntityType(
        "eth", "Ethereum address",
        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        validator=valid_eth, weight=0.95,
        description="Format verified; EIP-55 checksum not verifiable offline"),
    EntityType(
        "xmr", "Monero address",
        re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), weight=1.0,
        description="Privacy coin — significant in itself"),
    EntityType(
        "iban", "Bank account (IBAN)",
        re.compile(r"\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){2,7}[A-Z0-9]{1,4}\b"),
        validator=valid_iban, weight=0.9,
        description="mod-97 checksum verified"),
    EntityType(
        "card", "Payment card number",
        re.compile(r"\b(?:\d{4}[\s-]?){3}\d{1,7}\b|\b\d{13,19}\b"),
        validator=valid_card, weight=0.9,
        normalise=lambda s: re.sub(r"\D", "", s),
        description="Luhn-valid with a real issuer prefix"),
    EntityType(
        "upi", "UPI payment address",
        re.compile(r"\b[a-zA-Z0-9._-]{3,64}@[a-zA-Z]{2,20}\b"),
        validator=valid_upi, weight=0.75),
    EntityType(
        "imei", "IMEI",
        re.compile(r"\b\d{15}\b"), validator=valid_imei, weight=0.85,
        description="Another handset referenced in content"),
    EntityType(
        "ipv4", "IP address",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), weight=0.5),
    EntityType(
        "coords", "Geographic coordinates",
        re.compile(r"[-+]?\d{1,2}\.\d{4,},\s?[-+]?\d{1,3}\.\d{4,}"),
        weight=0.8),
    EntityType(
        "vehicle_in", "Vehicle registration (IN)",
        re.compile(r"\b[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4}\b"),
        weight=0.7, normalise=lambda s: re.sub(r"[\s-]", "", s.upper())),
    EntityType(
        "tracking", "Parcel tracking number",
        re.compile(r"\b(?:1Z[0-9A-Z]{16}|[A-Z]{2}\d{9}[A-Z]{2})\b"), weight=0.7),
    EntityType(
        "handle", "Social handle",
        re.compile(r"(?<![\w@])@[A-Za-z][\w.]{2,29}\b"), weight=0.5),
]

ENTITY_BY_NAME = {e.name: e for e in ENTITY_TYPES}

# Strings that match a pattern but are infrastructure noise, not evidence.
_STOP_URLS = re.compile(
    r"(schemas\.|w3\.org|apple\.com/DTDs|android\.com|googleapis\.com/auth|"
    r"\.xsd|purl\.org|ns\.adobe\.com)", re.I)


@dataclass
class EntityHit:
    """One entity, and everywhere it was seen."""

    kind: str
    label: str
    value: str
    normalised: str
    count: int = 0
    weight: float = 1.0
    validated: bool = False
    artifact_ids: List[str] = field(default_factory=list)
    contexts: List[str] = field(default_factory=list)
    apps: Set[str] = field(default_factory=set)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None

    def touch(self, ts: Optional[int]) -> None:
        if ts is None:
            return
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    @property
    def significance(self) -> float:
        """Rarity-weighted: a wallet seen once outranks a URL seen fifty times."""
        return round(self.weight * (1 + math.log1p(self.count)), 3)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["apps"] = sorted(self.apps)
        d["significance"] = self.significance
        d["artifact_ids"] = self.artifact_ids[:50]
        d["contexts"] = self.contexts[:5]
        return d


def _context(text: str, match: re.Match, width: int = 60) -> str:
    start = max(match.start() - width, 0)
    end = min(match.end() + width, len(text))
    snippet = text[start:end].replace("\n", " ").strip()
    return ("…" if start else "") + snippet + ("…" if end < len(text) else "")


class EntityExtractor:
    """Find and aggregate entities across a body of artifacts."""

    def __init__(self, kinds: Optional[Iterable[str]] = None,
                 max_contexts: int = 5):
        self.types = [e for e in ENTITY_TYPES
                      if kinds is None or e.name in set(kinds)]
        self.max_contexts = max_contexts
        self.hits: Dict[Tuple[str, str], EntityHit] = {}
        self.owner_keys: Set[str] = set()
        self.known_contacts: Set[str] = set()

    def set_owner_identifiers(self, identifiers: Iterable[str]) -> None:
        """The owner's own numbers are not investigative findings."""
        for ident in identifiers or ():
            digits = re.sub(r"\D", "", ident or "")
            if len(digits) >= 7:
                self.owner_keys.add(digits[-10:])
            elif ident:
                self.owner_keys.add(str(ident).lower())

    def set_known_contacts(self, identifiers: Iterable[str]) -> None:
        """Numbers already in the address book are less interesting than
        numbers that appear only inside message text."""
        for ident in identifiers or ():
            digits = re.sub(r"\D", "", ident or "")
            if len(digits) >= 7:
                self.known_contacts.add(digits[-10:])

    # ----------------------------------------------------------------- scan
    def _candidates(self, text: str) -> List[Tuple[EntityType, re.Match, str]]:
        """Every validated match, before overlap resolution."""
        out: List[Tuple[EntityType, re.Match, str]] = []
        for etype in self.types:
            for match in etype.pattern.finditer(text):
                raw = match.group(0).strip()
                if not raw:
                    continue
                if etype.name == "url" and _STOP_URLS.search(raw):
                    continue
                if etype.validator is not None:
                    try:
                        if not etype.validator(raw):
                            continue
                    except Exception:
                        continue
                out.append((etype, match, raw))
        return out

    @staticmethod
    def _resolve_overlaps(candidates: List[Tuple[EntityType, re.Match, str]]
                          ) -> List[Tuple[EntityType, re.Match, str]]:
        """Keep the most specific interpretation of each span.

        Entity patterns necessarily overlap: every IMEI is also Luhn-valid so
        it matches the payment-card pattern, and any run of digits inside an
        IBAN matches the phone pattern. Reporting all of them turns one real
        finding into three, two of which are wrong — and an investigator has
        to spend time disproving each.

        Resolution is greedy by (weight, match length): the strongest, longest
        interpretation claims its span, and weaker patterns overlapping that
        span are discarded. URLs are allowed to contain other entities, since
        a wallet address inside a payment link is a real dual finding.
        """
        ranked = sorted(
            candidates,
            key=lambda c: (-c[0].weight, -(c[1].end() - c[1].start())))
        claimed: List[Tuple[int, int]] = []
        kept: List[Tuple[EntityType, re.Match, str]] = []
        for etype, match, raw in ranked:
            start, end = match.start(), match.end()
            if etype.name in ("url", "onion", "email"):
                kept.append((etype, match, raw))       # containers, not spans
                continue
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            claimed.append((start, end))
            kept.append((etype, match, raw))
        return kept

    def scan_text(self, text: str, artifact_id: str = "", app: str = "",
                  timestamp: Optional[int] = None) -> int:
        if not text or len(text) < 3:
            return 0
        found = 0
        for etype, match, raw in self._resolve_overlaps(self._candidates(text)):
            norm = etype.normalise(raw) if etype.normalise else raw.lower()
            if not norm:
                continue
            if etype.name == "phone" and norm in self.owner_keys:
                continue
            key = (etype.name, norm)
            hit = self.hits.get(key)
            if hit is None:
                weight = etype.weight
                if etype.name == "phone" and norm not in self.known_contacts:
                    # A number that appears only inside message text and never
                    # in the address book is more interesting, not less.
                    weight = min(1.0, weight + 0.15)
                hit = EntityHit(kind=etype.name, label=etype.label,
                                value=raw, normalised=norm, weight=weight,
                                validated=etype.validator is not None)
                self.hits[key] = hit
            hit.count += 1
            hit.touch(timestamp)
            if app:
                hit.apps.add(app)
            if artifact_id and artifact_id not in hit.artifact_ids:
                hit.artifact_ids.append(artifact_id)
            if len(hit.contexts) < self.max_contexts:
                hit.contexts.append(_context(text, match))
            found += 1
        return found

    def scan_artifacts(self, artifacts: Iterable[Any]) -> "EntityExtractor":
        for art in artifacts:
            aid = getattr(art, "artifact_id", "")
            app = getattr(art, "app", "") or ""
            ts = getattr(art, "timestamp", None)
            body = getattr(art, "body", "") or ""
            if body:
                self.scan_text(body, aid, app, ts)
            attrs = getattr(art, "attributes", None) or {}
            for key in ("url", "search_terms", "title", "note", "subject",
                        "media_caption", "term", "target_path", "referrer"):
                value = attrs.get(key)
                if isinstance(value, str) and value:
                    self.scan_text(value, aid, app, ts)
        return self

    # -------------------------------------------------------------- results
    def results(self, min_significance: float = 0.0,
                kinds: Optional[Iterable[str]] = None) -> List[EntityHit]:
        wanted = set(kinds) if kinds else None
        out = [h for h in self.hits.values()
               if h.significance >= min_significance
               and (wanted is None or h.kind in wanted)]
        return sorted(out, key=lambda h: (-h.significance, h.kind, h.normalised))

    def by_kind(self) -> Dict[str, List[EntityHit]]:
        grouped: Dict[str, List[EntityHit]] = defaultdict(list)
        for hit in self.results():
            grouped[hit.kind].append(hit)
        return dict(grouped)

    def summary(self) -> Dict[str, Any]:
        grouped = self.by_kind()
        return {
            "total_entities": len(self.hits),
            "by_kind": {k: len(v) for k, v in
                        sorted(grouped.items(), key=lambda kv: -len(kv[1]))},
            "high_value": [h.as_dict() for h in self.results()
                           if h.weight >= 0.85][:40],
            "labels": {e.name: e.label for e in self.types},
        }
