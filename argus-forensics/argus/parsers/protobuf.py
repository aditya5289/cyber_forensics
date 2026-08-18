"""Schema-less protobuf decoder.

Modern mobile applications increasingly store their data as protobuf blobs
inside a SQLite column rather than as normal typed columns — Apple Notes,
Google Maps, Signal, Telegram, iOS `KnowledgeC` stream data and Android
`usagestats` all do it. A parser that reads only the columns therefore sees a
row that exists but contains nothing readable, and reports "no content" when
the content is right there.

We do not have the applications' `.proto` schemas, and we should not pretend
to: guessing field *names* would be fabrication. What the wire format does let
us do — losslessly and without any schema — is recover the *structure* and the
*values*: field numbers, wire types, integers, strings, nested messages.

That is enough to be evidentially useful. A message body is a string in there
somewhere, and this module finds it, tells you which field number it came
from, and never invents a name for it.

Wire format reference: https://protobuf.dev/programming-guides/encoding/
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

# Wire types
VARINT, FIXED64, LENGTH_DELIMITED, START_GROUP, END_GROUP, FIXED32 = 0, 1, 2, 3, 4, 5

MAX_DEPTH = 12
MAX_FIELDS = 4000


@dataclass
class Field:
    """One decoded protobuf field."""

    number: int
    wire_type: int
    value: Any
    # For length-delimited fields we keep every plausible interpretation,
    # because without a schema we cannot know which one the app intended.
    as_text: Optional[str] = None
    as_message: Optional["Message"] = None
    as_bytes: Optional[bytes] = None

    def summary(self) -> Any:
        if self.as_message is not None:
            return self.as_message.as_dict()
        if self.as_text is not None:
            return self.as_text
        if self.as_bytes is not None:
            return (f"<{len(self.as_bytes)} bytes>" if len(self.as_bytes) > 48
                    else self.as_bytes.hex())
        return self.value


@dataclass
class Message:
    """A decoded protobuf message."""

    fields: List[Field] = field(default_factory=list)
    trailing: bytes = b""          # bytes we could not account for

    def get(self, number: int) -> List[Field]:
        return [f for f in self.fields if f.number == number]

    def first(self, number: int) -> Optional[Field]:
        for f in self.fields:
            if f.number == number:
                return f
        return None

    def as_dict(self) -> Dict[str, Any]:
        """Field numbers as keys — never invented names."""
        out: Dict[str, Any] = {}
        for f in self.fields:
            key = f"f{f.number}"
            value = f.summary()
            if key in out:
                if not isinstance(out[key], list):
                    out[key] = [out[key]]
                out[key].append(value)
            else:
                out[key] = value
        return out

    def strings(self, min_length: int = 2) -> List[Tuple[str, str]]:
        """Every text value in the tree, with its dotted field path."""
        found: List[Tuple[str, str]] = []

        def walk(msg: "Message", path: str) -> None:
            for f in msg.fields:
                here = f"{path}.f{f.number}" if path else f"f{f.number}"
                if f.as_message is not None:
                    walk(f.as_message, here)
                elif f.as_text and len(f.as_text) >= min_length:
                    found.append((here, f.as_text))
        walk(self, "")
        return found

    def integers(self) -> List[Tuple[str, int]]:
        out: List[Tuple[str, int]] = []

        def walk(msg: "Message", path: str) -> None:
            for f in msg.fields:
                here = f"{path}.f{f.number}" if path else f"f{f.number}"
                if f.as_message is not None:
                    walk(f.as_message, here)
                elif f.wire_type in (VARINT, FIXED32, FIXED64) and \
                        isinstance(f.value, int):
                    out.append((here, f.value))
        walk(self, "")
        return out

    def __len__(self) -> int:
        return len(self.fields)

    def __bool__(self) -> bool:
        return bool(self.fields)


# --------------------------------------------------------------------- varint
def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Little-endian base-128 varint (protobuf order, not SQLite's)."""
    result = 0
    shift = 0
    start = pos
    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return result, pos - start
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("varint runs past end of buffer")


def zigzag(value: int) -> int:
    """Undo zig-zag encoding used by sint32/sint64."""
    return (value >> 1) ^ -(value & 1)


# -------------------------------------------------------------------- decoder
_NATURAL = set(" .,:;!?@#$%&*+-_/'\"()[]{}<>=~|\\")


def _text_score(text: str) -> float:
    """How convincingly does this look like human-readable text?

    A length-delimited protobuf field is ambiguous by design — the same bytes
    can be a string, a nested message or an opaque blob. Almost any short
    ASCII string *also* parses as a syntactically valid protobuf message, so
    trying "nested message" first shreds real message bodies into nonsense
    fields. This score is what breaks the tie.
    """
    if not text:
        return 0.0
    good = sum(1 for ch in text
               if ch.isalnum() or ch in _NATURAL)
    return good / len(text)


def _looks_like_text(raw: bytes) -> Optional[str]:
    """Decode as UTF-8 only if the result is convincingly text.

    Being strict here matters: treating arbitrary bytes as a string produces
    mojibake that then appears in a report as though it were a recovered
    message.
    """
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return text if printable / len(text) >= 0.9 else None


def _try_nested(raw: bytes, depth: int) -> Optional[Message]:
    """A length-delimited field may itself be a message. Try it."""
    if depth >= MAX_DEPTH or len(raw) < 2:
        return None
    try:
        nested = decode(raw, depth=depth + 1, strict=True)
    except ValueError:
        return None
    if not nested or nested.trailing or len(nested.fields) > 200:
        return None
    # A "message" whose fields are all zero-length or whose field numbers run
    # wild is the signature of coincidence, not structure.
    if any(f.number > 2000 for f in nested.fields):
        return None
    substantive = sum(1 for f in nested.fields
                      if f.wire_type != LENGTH_DELIMITED or f.value)
    return nested if substantive else None


def _resolve_length_delimited(raw: bytes, depth: int) -> Tuple[
        Optional[str], Optional[Message]]:
    """Decide what a length-delimited field actually is.

    Text wins when it reads like text. Only bytes that do *not* read as text
    are offered to the nested-message parser. Where both are plausible, both
    are kept so nothing is lost — but the text interpretation is the one
    reported, because a fabricated field tree is far more misleading in a
    report than a string that happened to also be valid protobuf.
    """
    text = _looks_like_text(raw)
    # A real string does not begin with a control byte. When it appears to,
    # those bytes are almost always a nested message's field header.
    starts_clean = bool(text) and (ord(text[0]) >= 0x20)
    if text is not None and starts_clean and _text_score(text) >= 0.85 \
            and len(text) >= 2:
        return text, None
    nested = _try_nested(raw, depth)
    if nested is not None:
        return None, nested
    return text, None


def decode(data: bytes, depth: int = 0, strict: bool = False) -> Message:
    """Decode a protobuf message.

    ``strict`` raises on malformed input (used when probing whether a blob is
    a nested message); otherwise decoding stops at the first bad byte and the
    remainder is kept in ``Message.trailing`` so nothing is silently lost.
    """
    msg = Message()
    pos = 0
    if isinstance(data, memoryview):
        data = bytes(data)

    while pos < len(data):
        if len(msg.fields) >= MAX_FIELDS:
            msg.trailing = data[pos:]
            break
        try:
            key, consumed = read_varint(data, pos)
        except ValueError:
            if strict:
                raise
            msg.trailing = data[pos:]
            break
        pos += consumed
        number, wire = key >> 3, key & 0x07
        if number == 0:
            if strict:
                raise ValueError("field number 0 is invalid")
            msg.trailing = data[pos - consumed:]
            break

        try:
            if wire == VARINT:
                value, used = read_varint(data, pos)
                pos += used
                msg.fields.append(Field(number, wire, value))

            elif wire == FIXED64:
                if pos + 8 > len(data):
                    raise ValueError("truncated fixed64")
                raw = data[pos:pos + 8]
                pos += 8
                msg.fields.append(Field(
                    number, wire, struct.unpack("<q", raw)[0],
                    as_bytes=raw))

            elif wire == FIXED32:
                if pos + 4 > len(data):
                    raise ValueError("truncated fixed32")
                raw = data[pos:pos + 4]
                pos += 4
                msg.fields.append(Field(
                    number, wire, struct.unpack("<i", raw)[0],
                    as_bytes=raw))

            elif wire == LENGTH_DELIMITED:
                length, used = read_varint(data, pos)
                pos += used
                if length < 0 or pos + length > len(data):
                    raise ValueError("length-delimited field overruns buffer")
                raw = data[pos:pos + length]
                pos += length
                f = Field(number, wire, raw, as_bytes=raw)
                f.as_text, f.as_message = _resolve_length_delimited(raw, depth)
                msg.fields.append(f)

            elif wire == START_GROUP:
                # Deprecated groups: skip to the matching END_GROUP.
                sub_start = pos
                nesting = 1
                while pos < len(data) and nesting:
                    k, u = read_varint(data, pos)
                    pos += u
                    w = k & 0x07
                    if w == START_GROUP:
                        nesting += 1
                    elif w == END_GROUP:
                        nesting -= 1
                    elif w == VARINT:
                        _, u2 = read_varint(data, pos); pos += u2
                    elif w == FIXED64:
                        pos += 8
                    elif w == FIXED32:
                        pos += 4
                    elif w == LENGTH_DELIMITED:
                        ln, u2 = read_varint(data, pos); pos += u2 + ln
                msg.fields.append(Field(number, wire, data[sub_start:pos]))

            elif wire == END_GROUP:
                break

            else:
                raise ValueError(f"unknown wire type {wire}")

        except (ValueError, struct.error, IndexError):
            if strict:
                raise
            msg.trailing = data[pos:]
            break

    return msg


def probe(data: bytes) -> bool:
    """Is this blob plausibly protobuf? Cheap check before full decoding."""
    if not data or len(data) < 4:
        return False
    if data[:2] in (b"\x1f\x8b", b"PK", b"\xff\xd8", b"\x89P", b"BM"):
        return False                      # gzip / zip / jpeg / png / bmp
    if data[:4] in (b"bplist", b"%PDF", b"SQLi"):
        return False
    # Plain text parses as syntactically valid protobuf surprisingly often.
    # If the whole buffer reads as text, it is text.
    whole = _looks_like_text(data)
    if whole is not None and _text_score(whole) >= 0.9:
        return False
    try:
        msg = decode(data, strict=True)
    except ValueError:
        return False
    return bool(msg.fields) and not msg.trailing


def extract_text(data: bytes, min_length: int = 3) -> List[str]:
    """Convenience: every string in a protobuf blob, longest first.

    This is what most parsers actually want — the message body is in there and
    the field number it lives under varies by app version.
    """
    try:
        msg = decode(data)
    except Exception:
        return []
    seen: set[str] = set()
    out: List[str] = []
    for _, text in msg.strings(min_length):
        stripped = text.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            out.append(stripped)
    return sorted(out, key=len, reverse=True)


def extract_timestamps(data: bytes) -> List[int]:
    """Integer fields that fall in a plausible modern timestamp range.

    Returns microseconds since epoch. Protobuf gives us no type information
    beyond 'varint', so magnitude is the only signal available — which is why
    every candidate is run through the same plausibility window the rest of
    ARGUS uses rather than being trusted.
    """
    from .timestamps import guess
    try:
        msg = decode(data)
    except Exception:
        return []
    out: List[int] = []
    for _, value in msg.integers():
        if value <= 0:
            continue
        got = guess(value)
        if got is not None:
            out.append(got)
    return sorted(set(out))
