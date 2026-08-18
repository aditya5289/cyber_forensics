"""Platforms beyond Android and iOS.

A real caseload is not two operating systems. It includes SIM cards read on a
reader, KaiOS feature phones, surviving Windows Phone handsets, basic phones with
no OS to speak of, SD cards pulled from a device that was never seized, and
wearables. Each of these carries evidence, and each is invisible to a tool that
assumes a modern smartphone.

None of these need deep support to be useful. A SIM card yields the ICCID, the
IMSI, the abbreviated dialling numbers and often deleted SMS — that is a
complete, self-contained finding set. A KaiOS phone stores its messages in
IndexedDB SQLite, which the existing reader handles once the file is recognised.

The registry below records what ARGUS can and cannot do per platform, so an
examiner asking "does this tool read my evidence?" gets a specific answer rather
than silence.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.models import Artifact, Category, Direction, Recovery
from .common import any_table_probe, as_int, as_text, clean_number, pick, rows_with_deleted
from .registry import ParseContext, ParseResult, register
from .sqlite_reader import ForensicSQLite
from .timestamps import guess


# ═══════════════════════════════════════════════════════════ platform registry
@dataclass
class PlatformProfile:
    """What ARGUS can do with one class of evidence."""

    name: str
    label: str
    markers: List[str] = field(default_factory=list)
    supported: List[str] = field(default_factory=list)
    not_supported: List[str] = field(default_factory=list)
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


PLATFORMS: List[PlatformProfile] = [
    PlatformProfile(
        "android", "Android",
        markers=["data/data", "data/user/0", "system/build.prop", "sdcard",
                 "data/system/packages.list"],
        supported=["Calls", "Contacts", "SMS/MMS", "WhatsApp", "Telegram",
                   "Instagram", "Snapchat", "Messenger", "Discord", "Viber",
                   "Signal metadata", "Gmail", "Payments", "Maps",
                   "Chrome history", "Wi-Fi", "Accounts", "Notifications",
                   "Usage stats", "Media + EXIF/GPS", "Deleted-record carving"],
        not_supported=["SQLCipher-encrypted stores", "WhatsApp .crypt keys"],
    ),
    PlatformProfile(
        "ios", "Apple iOS / iPadOS",
        markers=["HomeDomain", "CameraRollDomain", "MediaDomain", "Manifest.db",
                 "AddressBook.sqlitedb", "KnowledgeC.db"],
        supported=["Calls", "Contacts", "SMS/iMessage", "WhatsApp", "Safari",
                   "Notes", "Calendar", "Location caches", "KnowledgeC",
                   "PowerLog", "Notifications", "Media + EXIF/GPS",
                   "Deleted-record carving", "attributedBody recovery"],
        not_supported=["Encrypted iTunes backups without the password",
                       "Keychain secrets"],
    ),
    PlatformProfile(
        "sim", "SIM / USIM card",
        markers=["EF_ICCID", "EF_IMSI", "EF_ADN", "EF_SMS", "sim_dump",
                 "simcard", "3F00"],
        supported=["ICCID", "IMSI", "abbreviated dialling numbers (ADN)",
                   "last-numbers-dialled (LND)", "SMS including deleted",
                   "service provider name", "location information"],
        not_supported=["Authentication keys (Ki) — never readable",
                       "PIN/PUK values"],
        note=("A SIM is a self-contained evidence source. It is often the only "
              "thing available when a handset is destroyed or absent, and it "
              "retains deleted SMS because the records are simply flagged "
              "unused rather than erased."),
    ),
    PlatformProfile(
        "kaios", "KaiOS",
        markers=["b2g", "gaia", "communications.gaiamobile.org", "idb",
                 "0+file+++"],
        supported=["Contacts", "SMS", "Call log", "Media"],
        not_supported=["Encrypted app storage"],
        note=("KaiOS is Firefox OS derived and stores app data in IndexedDB "
              "SQLite files, which ARGUS reads once they are located."),
    ),
    PlatformProfile(
        "windowsphone", "Windows Phone / Windows Mobile",
        markers=["Windows/System32", "Users/DefApps", "SharedData",
                 "store.vol", "phone.db"],
        supported=["Contacts", "SMS", "Call log (store.vol / phone.db)",
                   "Media"],
        not_supported=["BitLocker-encrypted partitions",
                       "EDB internals beyond record scraping"],
        note=("End-of-life but still encountered. Content lives in the "
              "store.vol EDB database; ARGUS recovers records by structured "
              "scraping rather than a full ESE implementation, and says so."),
    ),
    PlatformProfile(
        "featurephone", "Feature phone (Series 30+/40, MTK)",
        markers=["mtk", "s30", "nvram", "pbook", "smsdb", "MMSMSG"],
        supported=["Contacts", "SMS", "Call log where the dump is readable",
                   "Media"],
        not_supported=["Proprietary NVRAM structures without a device profile"],
        note=("Basic phones store data in vendor-specific flat files. ARGUS "
              "recovers what is structurally recognisable and reports the rest "
              "as unparsed rather than implying nothing was there."),
    ),
    PlatformProfile(
        "sdcard", "SD card / removable media",
        markers=["DCIM", "LOST.DIR", "Android/data", "MISC", "PRIVATE"],
        supported=["Media + EXIF/GPS", "Documents", "App data left on card",
                   "File carving", "Perceptual image matching"],
        not_supported=["Anything the card never held"],
        note=("A card removed from a handset is frequently the only surviving "
              "evidence, and LOST.DIR often holds recoverable orphaned files."),
    ),
    PlatformProfile(
        "wearable", "Wearable (Wear OS / watchOS / Fitbit)",
        markers=["com.google.android.wearable", "HealthKit", "fitbit",
                 "com.apple.health", "healthdb"],
        supported=["Notifications mirrored from the phone", "Health/activity",
                   "Media", "Companion app data"],
        not_supported=["Encrypted health stores"],
        note=("A watch mirrors phone notifications, so it can retain message "
              "previews after the phone itself has been wiped."),
    ),
]

PLATFORM_BY_NAME = {p.name: p for p in PLATFORMS}


def platform_report() -> Dict[str, Any]:
    """What ARGUS supports, per platform. Answers the compatibility question."""
    return {
        "platforms": [p.as_dict() for p in PLATFORMS],
        "count": len(PLATFORMS),
        "note": ("Support is listed per platform with an explicit "
                 "not-supported column. Where a store is encrypted ARGUS "
                 "identifies it and says so rather than reporting it as empty."),
    }


def detect_platform(root: Path, limit: int = 8000) -> Tuple[str, float]:
    """Infer the platform from a staged tree. Returns ``(name, confidence)``."""
    paths = [p.as_posix().lower() for p in list(Path(root).rglob("*"))[:limit]]
    blob = " ".join(paths)
    scores: Dict[str, int] = {}
    for profile in PLATFORMS:
        scores[profile.name] = sum(1 for m in profile.markers
                                   if m.lower() in blob)
    best = max(scores, key=scores.get)
    total = sum(scores.values())
    if not scores[best]:
        return "", 0.0
    return best, round(scores[best] / total, 3) if total else 0.0


# ═══════════════════════════════════════════════════════════════ SIM cards
# GSM 11.11 / 3GPP TS 51.011 elementary files.
SIM_EF = {
    "2FE2": "EF_ICCID", "6F07": "EF_IMSI", "6F3A": "EF_ADN",
    "6F3C": "EF_SMS", "6F44": "EF_LND", "6F46": "EF_SPN",
    "6F7E": "EF_LOCI", "6F3B": "EF_FDN", "6F49": "EF_SDN",
}

# SMS status byte, TS 51.011 §10.5.3
_ONLY_DIGITS = re.compile(r"\D")
_WORDLIKE = re.compile(r"[A-Za-z\u00c0-\u024f]{2,}")

SMS_STATUS = {0x00: "deleted (record free)", 0x01: "read", 0x03: "unread",
              0x05: "sent", 0x07: "unsent"}


def _decode_bcd_swapped(data: bytes) -> str:
    """Decode swapped-nibble BCD, as used for ICCID and IMSI."""
    out = []
    for byte in data:
        low, high = byte & 0x0F, byte >> 4
        for nibble in (low, high):
            if nibble == 0x0F:
                continue
            out.append(str(nibble) if nibble < 10 else "")
    return "".join(out)


def _decode_gsm7(data: bytes, septets: int) -> str:
    """Unpack GSM 03.38 7-bit packed text."""
    alphabet = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./"
                "0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
                "¿abcdefghijklmnopqrstuvwxyzäöñüà")
    bits = 0
    value = 0
    out: List[str] = []
    for byte in data:
        value |= byte << bits
        bits += 8
        while bits >= 7 and len(out) < septets:
            index = value & 0x7F
            value >>= 7
            bits -= 7
            out.append(alphabet[index] if index < len(alphabet) else "?")
    return "".join(out).replace("\x1b", "")


def _plausible_sms_text(text: str) -> bool:
    """Reject decodes that are really padding or noise.

    A SIM pads unused space with 0xFF, and 0xFF unpacks to a valid GSM-7 index,
    so padding decodes to a long run of one repeated character. Random bytes
    decode to a jumble that is statistically unremarkable — roughly the right
    mix of letters, digits and punctuation — which is why character frequency
    alone cannot tell noise from a message.

    What separates them is *structure*. Human text is made of words: runs of
    letters, containing vowels, separated by spaces. Noise is not. Fabricating a
    message from unallocated bytes and attributing it to a real phone number is
    the worst thing this parser could do, so the bar is set high enough that
    some genuine short messages are lost. That trade is deliberate.
    """
    stripped = text.strip()
    if len(stripped) < 6:
        return False

    counts: Dict[str, int] = {}
    for ch in stripped:
        counts[ch] = counts.get(ch, 0) + 1
    if max(counts.values()) / len(stripped) > 0.35:
        return False                     # dominated by one repeated character
    if len(counts) < 5:
        return False

    # Non-ASCII is legitimate in GSM-7 (£, é, ñ) but rare. A decode that is
    # peppered with Greek and currency symbols is a mis-decode, not a message.
    non_ascii = sum(1 for ch in stripped if not ch.isascii())
    if non_ascii / len(stripped) > 0.10:
        return False

    words = _WORDLIKE.findall(stripped)
    if len(words) < 2:
        return False
    # A message with no spaces at all is unusual enough to demand more evidence.
    if " " not in stripped and len(words) < 3:
        return False

    # Vowels are what make a letter run a word rather than a hash fragment.
    letters = [c for c in stripped if c.isalpha()]
    if not letters:
        return False
    vowels = sum(1 for c in letters if c.lower() in "aeiou")
    if vowels / len(letters) < 0.20:
        return False

    # The words should account for a fair share of the text; otherwise this is
    # punctuation and digits with a couple of letter pairs embedded in it.
    covered = sum(len(w) for w in words)
    return covered / len(stripped) >= 0.45


def _decode_semi_octet_number(data: bytes) -> str:
    """Decode a TS 23.040 address field (length, type, swapped BCD digits)."""
    if len(data) < 2:
        return ""
    digits_len = data[0]
    type_of_address = data[1]
    body = data[2:2 + (digits_len + 1) // 2]
    number = _decode_bcd_swapped(body)
    if type_of_address & 0x70 == 0x10:      # international
        number = "+" + number
    return number


@register(
    name="platform.sim",
    patterns=["*.sim", "sim_dump*", "*simcard*", "EF_*", "*.bin"],
    platform="", priority=68,
    description="SIM / USIM card dump — ICCID, IMSI, contacts and deleted SMS",
)
def parse_sim(path: Path, ctx: ParseContext) -> ParseResult:
    """SIM / USIM card dump.

    A SIM retains deleted SMS because the record is only flagged unused — the
    bytes stay in place. That makes a SIM one of the most reliable sources of
    deleted messages available, and it is often the only evidence left when the
    handset has been destroyed.
    """
    res = ParseResult(parser="platform.sim", source=ctx.rel(path))
    try:
        data = path.read_bytes()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    # A SIM dump is small and structured; refuse anything that clearly is not one.
    if len(data) < 64 or len(data) > 8 << 20:
        return res
    name_hint = path.name.lower()
    looks_like_sim = (any(k.lower() in name_hint for k in
                          ("sim", "iccid", "imsi", "ef_", "usim"))
                      or b"\x98" == data[:1])
    if not looks_like_sim:
        return res

    identity: Dict[str, str] = {}

    # --- ICCID: 10 bytes of swapped BCD, conventionally starting 0x98
    for offset in range(0, min(len(data) - 10, 4096)):
        if data[offset] in (0x98, 0x89):
            candidate = _decode_bcd_swapped(data[offset:offset + 10])
            if len(candidate) >= 18 and candidate.startswith("89"):
                identity["iccid"] = candidate[:20]
                break

    # --- IMSI: 9 bytes, first is length
    match = re.search(rb"\x08[\x09\x19\x29\x39\x49\x59\x69\x79\x89\x99]",
                      data[:8192])
    if match:
        raw = data[match.start():match.start() + 9]
        imsi = _decode_bcd_swapped(raw[1:])[1:]
        if 14 <= len(imsi) <= 16:
            identity["imsi"] = imsi[:15]

    if identity:
        art = Artifact(
            category=Category.DEVICE, subtype="SIM card identity",
            body=" ".join(f"{k.upper()} {v}" for k, v in identity.items()),
            app="SIM", source_path=ctx.rel(path),
            attributes={**identity,
                        "mcc": identity.get("imsi", "")[:3],
                        "mnc": identity.get("imsi", "")[3:5],
                        "note": ("ICCID identifies the card; IMSI identifies the "
                                 "subscription. Together they tie this card to a "
                                 "network account independently of the "
                                 "handset.")},
        )
        res.artifacts.append(art)

    # SMS is decoded first so the phonebook scan can exclude the byte ranges
    # those records occupy.
    messages = _sim_sms(data)
    claimed = [m.pop("_range") for m in messages if "_range" in m]

    # --- ADN / LND records: alpha tag + number
    contacts = _sim_phonebook(data, claimed=claimed)
    for entry in contacts:
        art = Artifact(
            category=Category.CONTACT, subtype="SIM contact (ADN)",
            body=entry["name"] or entry["number"], app="SIM",
            source_path=ctx.rel(path),
            recovery=(Recovery.DELETED_UNALLOC if entry["deleted"]
                      else Recovery.ALLOCATED),
            confidence=0.8 if entry["deleted"] else 1.0,
            attributes={"display_name": entry["name"],
                        "phone_numbers": [entry["number"]],
                        "record": entry["record"],
                        "note": ("Recovered from an unused SIM record — the "
                                 "entry was deleted but its bytes remain."
                                 if entry["deleted"] else "")},
        )
        art.add_participant(entry["number"], entry["name"], role="party")
        res.artifacts.append(art)
        if entry["deleted"]:
            res.deleted_recovered += 1

    # --- SMS records
    for entry in messages:
        art = Artifact(
            category=Category.MESSAGE,
            subtype=f"SIM SMS ({entry['status_text']})",
            timestamp=entry["timestamp"], body=entry["text"], app="SIM",
            direction=(Direction.OUTGOING if "sent" in entry["status_text"]
                       else Direction.INCOMING),
            source_path=ctx.rel(path),
            recovery=(Recovery.DELETED_UNALLOC if entry["deleted"]
                      else Recovery.ALLOCATED),
            confidence=0.8 if entry["deleted"] else 1.0,
            attributes={"status_byte": entry["status"],
                        "status": entry["status_text"],
                        "record": entry["record"],
                        "service_centre": entry["smsc"],
                        "note": ("Recovered from a SIM record flagged free. A "
                                 "deleted SIM SMS is not erased — only its "
                                 "status byte is cleared — so the message text "
                                 "survives intact."
                                 if entry["deleted"] else "")},
        )
        if entry["number"]:
            art.add_participant(entry["number"], "", role="from")
        res.artifacts.append(art)
        if entry["deleted"]:
            res.deleted_recovered += 1

    if res.artifacts:
        res.notes.append(
            f"{ctx.rel(path)}: SIM dump decoded — {len(contacts)} phonebook "
            f"entr(ies), {len(messages)} SMS, of which "
            f"{res.deleted_recovered} were recovered from records flagged as "
            f"free. Authentication keys (Ki) are never readable from a dump.")
    return res


def _plausible_alpha_tag(name: str) -> bool:
    """Is this recovered text really a contact name?

    Short tags are the hard case. "Ma" and "Jo" are real entries people put in a
    SIM phonebook, so length alone cannot be the test — but two random uppercase
    letters landing next to a plausible BCD field is exactly what noise produces.
    A vowel is what distinguishes them: real short names have one, random letter
    pairs usually do not.
    """
    if len(name) < 2:
        return False
    letters = [c for c in name if c.isalpha()]
    if len(letters) < 2:
        return False
    allowed = sum(1 for c in name if c.isalnum() or c in " .,\'&()-_@+/")
    if allowed / len(name) < 0.8 or not name[0].isalnum():
        return False
    if len(name) <= 3 and not any(c.lower() in "aeiou" for c in letters):
        return False
    return True


def _sim_phonebook(data: bytes,
                   claimed: Optional[List[Tuple[int, int]]] = None
                   ) -> List[Dict[str, Any]]:
    """Recover EF_ADN / EF_LND entries by locating their dialling-number fields.

    A monolithic SIM dump has no guaranteed alignment: elementary files sit at
    card-specific offsets, so scanning in fixed strides from byte zero misses
    almost everything on a real card. This instead matches the fixed 14-byte
    tail every ADN record ends with, and reads the alpha tag backwards from it.

    The length byte here counts *bytes* of TON/NPI plus dialling number
    (TS 51.011 10.5.1). EF_SMS address fields count semi-octets instead. The two
    conventions differ by roughly a factor of two, so decoding an ADN record
    with the SMS rule silently truncates every number it returns.
    """
    found: List[Dict[str, Any]] = []
    seen: set = set()
    # SMS TPDUs contain address fields too. Without excluding the ranges the SMS
    # scan already claimed, every message's sender is re-reported as a phonebook
    # entry - inventing contacts that are not in the address book.
    blocked = sorted(claimed or [])

    def is_claimed(position: int) -> bool:
        for begin, stop in blocked:
            if begin <= position < stop:
                return True
            if begin > position:
                break
        return False

    limit = len(data)
    index = 0
    while index < limit - 14:
        if is_claimed(index):
            index += 1
            continue

        length = data[index]
        ton_npi = data[index + 1]
        # Length covers TON/NPI + up to 10 bytes of BCD; bit 7 of TON/NPI is
        # always set on a valid field.
        if not (2 <= length <= 11) or not (ton_npi & 0x80):
            index += 1
            continue

        digit_bytes = length - 1
        number_field = data[index + 2:index + 12]
        # Everything past the stated length must be 0xFF padding. This is what
        # separates a real record from a digit run that happens to look like one.
        if any(b != 0xFF for b in number_field[digit_bytes:]):
            index += 1
            continue

        number = _decode_semi_octet_number(
            bytes([digit_bytes * 2, ton_npi]) + number_field[:digit_bytes])
        digits = _ONLY_DIGITS.sub("", number)
        if not 6 <= len(digits) <= 15:
            index += 1
            continue

        # The alpha tag precedes the number field, right-padded with 0xFF to the
        # record width. Skip that padding before reading backwards - otherwise
        # the read stops on the first pad byte and every contact looks nameless.
        cursor = index
        pad = 0
        while cursor > 0 and data[cursor - 1] in (0xFF, 0x00) and pad < 24:
            cursor -= 1
            pad += 1
        begin = cursor
        while begin > 0 and (0x20 <= data[begin - 1] < 0x7F) \
                and cursor - begin < 32:
            begin -= 1
        name = data[begin:cursor].decode("ascii", "replace").strip()
        name = "".join(c for c in name if c.isprintable()).strip()
        # Records sit back to back, so a cleared alpha tag lets the backward
        # read run into the *previous* record's BCD digits and return a scrap
        # like " w". That scrap is neither a name nor empty, which would sink
        # the entry between both branches below. Treat an implausible tag as
        # absent rather than reporting a fragment of adjacent binary as a name.
        if not _plausible_alpha_tag(name):
            name = ""

        looks_named = bool(name)
        # A wholly-padded alpha tag means the entry was deleted: the SIM clears
        # the name and leaves the dialling number in place.
        was_cleared = pad >= 4 and not name
        if not (looks_named or was_cleared):
            index += 1
            continue

        key = digits[-10:]
        if key not in seen:
            seen.add(key)
            found.append({"name": name if looks_named else "",
                          "number": number,
                          "record": len(found) + 1,
                          "deleted": was_cleared})
        index += 14
    return found[:2000]


def _sim_sms(data: bytes) -> List[Dict[str, Any]]:
    """Recover EF_SMS records by sliding over every offset.

    Each record is a status byte followed by a TPDU. Because a dump's elementary
    files are not aligned to any fixed boundary, every offset whose byte is a
    valid status value is tried and accepted only if the TPDU that follows
    decodes to plausible text. A status byte of 0x00 means the record is free —
    the SIM marks it unused without erasing it, which is why deleted SIM
    messages survive intact.
    """
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    limit = len(data)
    index = 0
    while index < limit - 24:
        status = data[index]
        if status not in SMS_STATUS:
            index += 1
            continue
        try:
            entry = _decode_sms_tpdu(data[index + 1:index + 1 + 175])
        except Exception:
            entry = None
        if not entry or not entry.get("text"):
            index += 1
            continue
        fingerprint = entry["text"][:60]
        if fingerprint in seen:
            index += 1
            continue
        seen.add(fingerprint)
        entry.update({
            "status": status,
            "status_text": SMS_STATUS[status],
            "deleted": status == 0x00,
            "record": len(out) + 1,
        })
        entry["_range"] = (index, min(index + 176, limit))
        out.append(entry)
        index += 176 if index + 176 < limit else 1
    return out[:2000]


def _decode_sms_tpdu(body: bytes) -> Optional[Dict[str, Any]]:
    """Decode a deliver-type SMS TPDU preceded by its service-centre address."""
    if len(body) < 12:
        return None
    pos = 0
    smsc_len = body[pos]
    pos += 1
    smsc = ""
    if 0 < smsc_len <= 12:
        smsc = _decode_bcd_swapped(body[pos + 1:pos + smsc_len])
        pos += smsc_len
    if pos >= len(body):
        return None
    pos += 1                                       # TP-MTI / flags
    if pos + 1 >= len(body):
        return None
    addr_digits = body[pos]
    addr_bytes = 2 + (addr_digits + 1) // 2
    number = _decode_semi_octet_number(body[pos:pos + addr_bytes])
    pos += addr_bytes
    if pos + 9 > len(body):
        return None
    pos += 1                                       # protocol identifier
    dcs = body[pos]
    pos += 1
    stamp = body[pos:pos + 7]
    pos += 7
    timestamp = _decode_sms_timestamp(stamp)
    if pos >= len(body):
        return None
    udl = body[pos]
    pos += 1
    payload = body[pos:]
    if dcs & 0x0C == 0x08:                         # UCS-2
        text = payload[:udl * 2].decode("utf-16-be", errors="replace")
    else:
        text = _decode_gsm7(payload, udl)
    text = "".join(c for c in text if c.isprintable() or c in "\n\t").strip()
    if not _plausible_sms_text(text):
        return None
    return {"text": text[:1000], "number": number, "smsc": smsc,
            "timestamp": timestamp}


def _decode_sms_timestamp(stamp: bytes) -> Optional[int]:
    """TS 23.040 service-centre timestamp: 7 bytes of swapped BCD."""
    if len(stamp) < 7:
        return None
    try:
        parts = []
        for byte in stamp[:6]:
            parts.append((byte & 0x0F) * 10 + (byte >> 4))
        year, month, day, hour, minute, second = parts
        year += 2000 if year < 70 else 1900
        from datetime import datetime, timezone
        return int(datetime(year, month, day, hour, minute, second,
                            tzinfo=timezone.utc).timestamp() * 1_000_000)
    except (ValueError, OverflowError):
        return None


# ═══════════════════════════════════════════════════════════════ KaiOS
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _clone_strings(blob: Any, limit: int = 6) -> List[str]:
    """Readable text from a Firefox/KaiOS structured-clone blob.

    The clone format stores JavaScript strings as UTF-16LE. A UTF-8 printable
    sweep sees those as isolated single characters separated by NULs and returns
    nothing, so the UTF-16 pass below is what makes KaiOS readable at all.
    """
    from .android.social import _strings_from_blob

    if not blob:
        return []
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "ignore")
    if not isinstance(blob, (bytes, bytearray)):
        return []
    data = bytes(blob)

    found: List[str] = []
    seen: set = set()
    for match in _UTF16_RUN.finditer(data):
        text = match.group(0).decode("utf-16-le", "replace").strip()
        text = "".join(c for c in text if c.isprintable()).strip()
        if len(text) >= 4 and text not in seen:
            seen.add(text)
            found.append(text)
    for text in _strings_from_blob(data, limit=limit):
        if text not in seen:
            seen.add(text)
            found.append(text)
    # Longest first: the message body is the substantive string in the clone.
    return sorted(found, key=len, reverse=True)[:limit]


@register(
    name="platform.kaios",
    patterns=["*.sqlite", "sms.sqlite", "contacts.sqlite", "*idb*.sqlite"],
    platform="", priority=64,
    probe=any_table_probe(("object_data",), ("sms",), ("contacts",)),
    description="KaiOS / Firefox OS IndexedDB stores",
)
def parse_kaios(path: Path, ctx: ParseContext) -> ParseResult:
    """KaiOS IndexedDB.

    KaiOS inherits Firefox OS's IndexedDB, which stores each record as a
    structured-clone BLOB in an ``object_data`` table. The clone format is not
    documented for third parties, so readable text is recovered from the blob and
    the artifact records that it came from a blob sweep rather than a typed read.
    """
    res = ParseResult(parser="platform.kaios", source=ctx.rel(path))
    text_marker = path.as_posix().lower()
    if "gaia" not in text_marker and "idb" not in text_marker \
            and "kaios" not in text_marker:
        # Only claim files that plausibly belong to a KaiOS device; the generic
        # app survey handles anything else.
        with ForensicSQLite(path) as db:
            if not db.has_table("object_data"):
                return res

    with ForensicSQLite(path) as db:
        table = db.first_table("object_data", "sms", "contacts")
        if not table:
            return res
        if table == "object_data":
            from .android.social import _strings_from_blob
            # Preference order matters. Iterating the schema and taking the
            # first column whose name is in a set picks `file_ids` — which is
            # almost always NULL — ahead of `data`, and the parser then reports
            # a KaiOS handset as containing nothing at all.
            columns = {c.lower(): c for c in db.columns(table)}
            data_col = next((columns[name] for name in ("data", "value", "blob")
                             if name in columns), "")
            if not data_col:
                return res
            for row, recovery, conf in rows_with_deleted(db, table, ctx):
                strings = _clone_strings(row.get(data_col))
                if not strings:
                    continue
                body = strings[0]
                if len(body) < 3:
                    continue
                number = next((re.sub(r"\D", "", s) for s in strings
                               if 7 <= len(re.sub(r"\D", "", s)) <= 15), "")
                art = Artifact(
                    category=Category.MESSAGE, subtype="KaiOS record",
                    body=body, app="KaiOS", source_path=ctx.rel(path),
                    source_table=table,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=round(conf * 0.85, 3),
                    attributes={
                        "extraction_method":
                            "recovered from IndexedDB structured-clone blob",
                        "additional_strings": strings[1:5],
                        "platform": "kaios",
                    },
                )
                if number:
                    art.add_participant(number, "", role="party")
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
        res.warnings.extend(db.warnings)

    if res.artifacts:
        res.notes.append(
            f"{ctx.rel(path)}: KaiOS IndexedDB records recovered from "
            f"structured-clone blobs. The clone format is undocumented, so "
            f"content is extracted by blob sweep and carries reduced "
            f"confidence.")
    return res


# ═══════════════════════════════════════════════════════ Windows Phone
@register(
    name="platform.windowsphone",
    patterns=["store.vol", "phone.db", "*.vol"],
    platform="", priority=66,
    description="Windows Phone store.vol / phone.db",
)
def parse_windows_phone(path: Path, ctx: ParseContext) -> ParseResult:
    """Windows Phone message and call store.

    ``store.vol`` is a Microsoft ESE (JET Blue) database. ARGUS does not
    implement an ESE engine, so records are recovered by structured scraping of
    the long-value pages. That yields message text and numbers but not the full
    relational structure — stated on every artifact so it is never mistaken for
    a clean database read.
    """
    res = ParseResult(parser="platform.windowsphone", source=ctx.rel(path))
    try:
        data = path.read_bytes()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    is_ese = data[4:8] == b"\xef\xcd\xab\x89" or b"store.vol" in path.name.encode()
    if path.name.lower() == "phone.db" and data[:15] == b"SQLite format 3":
        # Some builds use SQLite; the normal reader handles that properly.
        with ForensicSQLite(path) as db:
            table = db.first_table("Message", "messages", "Call", "calls")
            if not table:
                return res
            for row, recovery, conf in rows_with_deleted(db, table, ctx):
                body = as_text(pick(row, "Body", "body", "Text", default=""))
                if not body:
                    continue
                ts = guess(pick(row, "Timestamp", "timestamp", "Date"),
                           "timestamp")
                if not ctx.in_span(ts):
                    continue
                art = Artifact(
                    category=Category.MESSAGE, subtype="Windows Phone message",
                    timestamp=ts, body=body, app="Windows Phone",
                    source_path=ctx.rel(path), source_table=table,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf, attributes={"platform": "windowsphone"})
                number = clean_number(pick(row, "Address", "Number",
                                           default=""))
                if number:
                    art.add_participant(number, "", role="party")
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
        return res

    if not is_ese:
        return res

    # ESE scraping: UTF-16LE runs are how Windows Phone stores message text.
    found = 0
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){8,}", data):
        try:
            text = match.group(0).decode("utf-16-le", errors="replace").strip()
        except UnicodeDecodeError:
            continue
        text = "".join(c for c in text if c.isprintable())
        if not looks_like_message(text):
            continue
        art = Artifact(
            category=Category.MESSAGE, subtype="Windows Phone record (scraped)",
            body=text[:800], app="Windows Phone", source_path=ctx.rel(path),
            recovery=Recovery.CARVED, confidence=0.55,
            attributes={
                "platform": "windowsphone",
                "byte_offset": match.start(),
                "extraction_method": "UTF-16 text scraped from an ESE database",
                "note": ("ARGUS does not implement an ESE (JET Blue) engine. "
                         "This text was recovered by structured scraping, so it "
                         "has no reliable timestamp or correspondent and must "
                         "be corroborated before use."),
            },
        )
        res.artifacts.append(art)
        found += 1
        if found >= 5000:
            break

    if found:
        res.notes.append(
            f"{ctx.rel(path)}: {found} text record(s) scraped from a Windows "
            f"Phone ESE store. Timestamps and correspondents are NOT recovered "
            f"by scraping — treat these as content leads, not as structured "
            f"messages.")
    return res



# ══════════════════════════════════════════════ scraped-text quality gate
# Windows Phone ESE stores and feature-phone flat files are scraped rather than
# parsed, and a scrape returns every printable run in the file. Most of those
# runs are firmware banners, table and column names, registry keys, MIME type
# lists and file paths. Reporting them as recovered messages puts fabricated
# evidence in front of an examiner who has no way to tell them from real
# records, so the gate below is the difference between a useful scraper and a
# dangerous one.

# Deliberately unanchored. A carved fragment can begin mid-word, so a marker
# that only matches at a word boundary is defeated by the very truncation this
# gate exists to survive: "Copyright MediaTek" arrived as "kCopyright MediaTek"
# and sailed through. The cost of matching anywhere is rejecting a genuine
# message that happens to contain "copyright" or "software", which is a trade
# worth making — losing one real message costs a lead, while admitting a
# firmware banner as evidence costs the credibility of every record beside it.
_STRUCTURAL_MARKERS = re.compile(
    r"SOFTWARE|SYSTEM|HKEY_|MSys|APPDATA|Program Files|Copyright|"
    r"All rights reserved|NVRAM|BIN VER|[A-Za-z]:\\|MediaTek|Qualcomm|"
    r"Spreadtrum|Unisoc|Broadcom|firmware|bootloader",
    re.I)
_MIME_OR_PATH = re.compile(
    r"(?:[a-z]+/[a-z0-9.+-]+\b.*){2,}|[A-Za-z]:\\|\\[A-Za-z]+\\[A-Za-z]+|"
    r"(?:/[A-Za-z0-9_.-]+){3,}")
_WORD = re.compile(r"[A-Za-z']+")


def looks_like_message(text: str) -> bool:
    """Is this scraped run plausibly something a person wrote?

    Deliberately conservative. Losing a genuine message to this gate costs one
    lead; passing a schema string costs the credibility of every record in the
    report.
    """
    text = (text or "").strip()
    if len(text) < 12:
        return False
    if _STRUCTURAL_MARKERS.search(text) or _MIME_OR_PATH.search(text):
        return False
    if any(ch in text for ch in "\\{}<>|\t"):
        return False

    words = _WORD.findall(text)
    if len(words) < 3:
        return False

    # Identifier lists ("Message Recipient Attachment ConversationEntry") and
    # firmware banners ("SETTING PROFILE RINGTONE VOLUME") are dominated by
    # capitalised or shouted tokens. Prose is not.
    shouty = sum(1 for w in words
                 if w.isupper() and len(w) > 1 or (w[:1].isupper() and len(w) > 3))
    if shouty / len(words) > 0.5:
        return False

    # Prose is mostly lowercase letters.
    letters = [c for c in text if c.isalpha()]
    if not letters or sum(1 for c in letters if c.islower()) / len(letters) < 0.6:
        return False

    # A run of unbroken alphanumerics with no spaces is an identifier.
    return " " in text


# ═══════════════════════════════════════════════════════ feature phones
@register(
    name="platform.featurephone",
    patterns=["pbook*", "smsdb*", "*.pbk", "nvram*", "MMSMSG*", "sms.dat",
              "contacts.dat"],
    platform="", priority=58,
    description="Feature-phone flat-file stores (Series 30+/40, MTK)",
)
def parse_feature_phone(path: Path, ctx: ParseContext) -> ParseResult:
    """Feature-phone flat files.

    Basic phones use vendor-specific structures with no public documentation.
    ARGUS recovers text and numbers that are structurally recognisable and
    reports the rest as unparsed — which is honest, and still often produces the
    contacts and SMS that matter.
    """
    res = ParseResult(parser="platform.featurephone", source=ctx.rel(path))
    try:
        data = path.read_bytes()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res
    if len(data) < 32 or len(data) > 64 << 20:
        return res

    # Phonebook entries first. These stores lay a UCS-2 name field immediately
    # before the ASCII number field, so a name can be paired with its number by
    # locality. Scraping them separately loses that association and reports the
    # name as though it were a message, which is both wrong and unhelpful.
    consumed: List[Tuple[int, int]] = []
    contacts: List[Dict[str, str]] = []
    seen_numbers: set = set()
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){2,}", data):
        name = match.group(0).decode("utf-16-le", "replace")
        name = "".join(c for c in name if c.isprintable()).strip()
        if not _plausible_alpha_tag(name):
            continue
        window = data[match.end():match.end() + 96]
        number_match = re.search(rb"\+?\d{9,15}", window)
        if not number_match:
            continue
        number = number_match.group(0).decode("ascii")
        if number in seen_numbers:
            continue
        seen_numbers.add(number)
        contacts.append({"name": name, "number": number})
        consumed.append((match.start(),
                         match.end() + number_match.end()))

    for entry in contacts:
        art = Artifact(
            category=Category.CONTACT, subtype="Feature-phone contact",
            body=f"{entry['name']} — {entry['number']}",
            app="Feature phone", source_path=ctx.rel(path),
            recovery=Recovery.CARVED, confidence=0.6,
            attributes={
                "platform": "featurephone",
                "name": entry["name"],
                "phone_numbers": [entry["number"]],
                "extraction_method":
                    "UCS-2 name field paired with the adjacent number field",
                "note": ("Feature-phone phonebook structures are vendor "
                         "specific. The name/number pairing is by adjacency in "
                         "the file, not by a documented record layout."),
            },
        )
        art.add_participant(entry["number"], entry["name"], role="party")
        res.artifacts.append(art)

    def is_consumed(position: int) -> bool:
        return any(lo <= position < hi for lo, hi in consumed)

    # Message bodies: UCS-2 and ASCII runs that are not part of a phonebook
    # entry and read as something a person wrote.
    texts: List[Tuple[int, str]] = []
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
        if not is_consumed(match.start()):
            texts.append((match.start(),
                          match.group(0).decode("utf-16-le", "replace")))
    for match in re.finditer(rb"[\x20-\x7e]{8,}", data):
        if not is_consumed(match.start()):
            texts.append((match.start(),
                          match.group(0).decode("ascii", "replace")))

    emitted = 0
    seen_text: set = set()
    for offset, text in sorted(texts):
        clean = "".join(c for c in text if c.isprintable()).strip()
        if clean in seen_text or not looks_like_message(clean):
            continue
        seen_text.add(clean)
        art = Artifact(
            category=Category.MESSAGE,
            subtype="Feature-phone record (scraped)",
            body=clean[:600], app="Feature phone", source_path=ctx.rel(path),
            recovery=Recovery.CARVED, confidence=0.5,
            attributes={
                "platform": "featurephone", "byte_offset": offset,
                "extraction_method": "text scraped from a vendor flat file",
                "note": ("Feature-phone structures are undocumented. This text "
                         "was scraped, so it has no reliable timestamp or "
                         "correspondent."),
            },
        )
        res.artifacts.append(art)
        emitted += 1
        if emitted >= 3000:
            break

    # Numbers that were never paired with a name are still worth reporting, but
    # only as unattributed digit strings.
    loose = {m.group(0).decode() for m in re.finditer(rb"\+?\d{9,15}", data)}
    loose -= seen_numbers
    if loose:
        res.artifacts.append(Artifact(
            category=Category.CONTACT,
            subtype="Feature-phone numbers (unattributed)",
            body=f"{len(loose)} phone-shaped number(s) with no adjacent name",
            app="Feature phone", source_path=ctx.rel(path),
            recovery=Recovery.CARVED, confidence=0.4,
            attributes={"phone_numbers": sorted(loose)[:400],
                        "platform": "featurephone",
                        "note": ("Digit strings of plausible phone-number "
                                 "length. No name was adjacent, so these are "
                                 "not attributed to anyone.")}))

    if res.artifacts:
        res.notes.append(
            f"{ctx.rel(path)}: {len(contacts)} phonebook entr(ies) and "
            f"{emitted} text record(s) scraped from a feature-phone store. "
            f"Structure is vendor-specific and undocumented — treat as leads.")
    return res


def platform_findings(root: Path, staged_platform: str = "") -> List[Any]:
    """A finding stating which platform was identified and what that implies."""
    from ..intel.findings import Finding

    name, confidence = detect_platform(root)
    name = staged_platform or name
    if not name:
        return [Finding(
            rule_id="platform.unrecognised",
            title="Device platform could not be identified from the evidence",
            detail=("No recognised platform layout was found. Platform-specific "
                    "parsers did not run; generic and content-based parsers "
                    "still did."),
            severity="info", confidence=0.8, category="platform",
            metrics={"supported": [p.name for p in PLATFORMS]},
            why_it_matters=("Prevents a thin result being read as an empty "
                            "device when it may simply be an unrecognised "
                            "layout."),
            caveat="",
        )]
    profile = PLATFORM_BY_NAME.get(name)
    if profile is None:
        return []
    return [Finding(
        rule_id="platform.identified",
        title=f"Platform identified as {profile.label}",
        detail=(f"Recognised from the evidence layout (confidence "
                f"{confidence:.0%}). ARGUS decodes: "
                + ", ".join(profile.supported[:10])
                + (f". Not supported: " + ", ".join(profile.not_supported)
                   if profile.not_supported else "")),
        severity="info", confidence=max(confidence, 0.6), category="platform",
        metrics=profile.as_dict(),
        why_it_matters=("Tells an examiner exactly which capabilities applied "
                        "to this evidence, so a gap in the results can be "
                        "attributed to a stated limitation rather than assumed "
                        "to be an absence of data."),
        caveat=profile.note or "",
    )]
