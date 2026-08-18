"""File carving by signature — recovering deleted files from raw bytes.

When a photo is deleted the file system forgets where it was, but the bytes
stay on the flash until that space is reused. Carving finds them again by
looking for the file's own header and footer rather than asking the file
system, which is why it works on unallocated space, on a formatted partition,
and on a phone that has been factory reset.

Design decisions that matter:

**Validate, do not just match.** A four-byte header match is a hypothesis, not
a file. Every carved candidate is validated by parsing its actual structure —
JPEG segment markers are walked to the real EOI, PNG chunks are walked with
their CRC-declared lengths, MP4 boxes are walked by size, SQLite headers are
checked for a self-consistent page count. A carver that skips this emits
thousands of 20-byte "files" and buries the real evidence.

**Report where it came from.** Every result carries its absolute offset, so a
finding can be re-derived from the original image by an opposing expert.

**Bounded output.** Carving a 256 GB image can yield millions of candidates.
Limits are explicit and reported, so a truncated run is never mistaken for a
complete one.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from ..core.hashing import hash_bytes


@dataclass
class Signature:
    """A carvable file type."""

    name: str
    extension: str
    header: bytes
    footer: Optional[bytes] = None
    max_size: int = 32 << 20
    min_size: int = 64
    mime: str = "application/octet-stream"
    validator: Optional[Callable[[bytes], Optional[int]]] = None
    description: str = ""

    def __post_init__(self):
        if not self.mime or self.mime == "application/octet-stream":
            guess = {
                "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif",
                "mp4": "video/mp4", "pdf": "application/pdf",
                "db": "application/x-sqlite3", "webp": "image/webp",
                "heic": "image/heic", "zip": "application/zip",
                "mp3": "audio/mpeg", "amr": "audio/amr",
            }.get(self.extension, self.mime)
            self.mime = guess


@dataclass
class CarvedFile:
    """A file recovered from raw bytes."""

    signature: str
    extension: str
    mime: str
    offset: int
    size: int
    sha256: str
    data: bytes = field(repr=False, default=b"")
    validated: bool = False
    confidence: float = 0.5
    note: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "signature": self.signature, "extension": self.extension,
            "mime": self.mime, "offset": self.offset, "size": self.size,
            "sha256": self.sha256, "validated": self.validated,
            "confidence": self.confidence, "note": self.note,
        }


# ------------------------------------------------------------------ validators
def validate_jpeg(data: bytes) -> Optional[int]:
    """Walk JPEG segments to the real end-of-image. Returns the true length."""
    if len(data) < 4 or data[:3] != b"\xff\xd8\xff":
        return None
    pos = 2
    seen_sos = False
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:                       # EOI
            return pos + 2
        if marker in (0x01, 0xFF) or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue
        if pos + 4 > len(data):
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if seg_len < 2:
            break
        if marker == 0xDA:                        # start of scan
            seen_sos = True
            pos += 2 + seg_len
            # Entropy-coded data follows; scan for the next real marker.
            while pos < len(data) - 1:
                if data[pos] == 0xFF and data[pos + 1] not in (
                        0x00, 0xFF) and not (0xD0 <= data[pos + 1] <= 0xD7):
                    break
                pos += 1
            continue
        pos += 2 + seg_len
    # Truncated but structurally real: still worth recovering if it had a scan.
    return len(data) if seen_sos else None


def validate_png(data: bytes) -> Optional[int]:
    """Walk PNG chunks to IEND using declared lengths."""
    magic = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(magic):
        return None
    pos = len(magic)
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        if length > len(data):
            return None
        end = pos + 8 + length + 4               # + CRC
        if ctype == b"IEND":
            return min(end, len(data))
        if end > len(data):
            return None
        pos = end
    return None


def validate_gif(data: bytes) -> Optional[int]:
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    end = data.find(b"\x00\x3b", 6)
    return end + 2 if end > 0 else None


def validate_mp4(data: bytes) -> Optional[int]:
    """Walk ISO base-media boxes by declared size."""
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    pos = 0
    total = 0
    while pos + 8 <= len(data):
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        box = data[pos + 4:pos + 8]
        if not all(32 <= b < 127 for b in box):
            break
        if size == 1:                            # 64-bit extended size
            if pos + 16 > len(data):
                break
            size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
        if size == 0:                            # extends to end of file
            total = len(data)
            break
        if size < 8 or pos + size > len(data):
            break
        pos += size
        total = pos
    return total if total >= 512 else None


def validate_pdf(data: bytes) -> Optional[int]:
    if not data.startswith(b"%PDF"):
        return None
    idx = data.rfind(b"%%EOF")
    return idx + 5 if idx > 0 else None


def validate_sqlite(data: bytes) -> Optional[int]:
    """Determine a SQLite database's true length from its header.

    The in-header page count at offset 28 is only authoritative when the file
    change counter (offset 24) equals the "version-valid-for" number (offset
    92). SQLite leaves it stale otherwise, and it is zero on files written by
    older versions. Trusting it unconditionally throws away perfectly
    recoverable databases — which, given a carved application database is
    often the single richest artifact on a handset, is an expensive mistake.

    When the count is untrustworthy the header is still validated structurally
    and the size is derived by walking whole pages to the end of the buffer.
    """
    if not data.startswith(b"SQLite format 3\x00") or len(data) < 100:
        return None
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or (page_size & (page_size - 1)):
        return None                              # must be a power of two

    write_version, read_version = data[18], data[19]
    if write_version not in (1, 2) or read_version not in (1, 2):
        return None
    if data[21:24] != b"\x40\x20\x20":           # fixed payload constants
        return None
    encoding = struct.unpack(">I", data[56:60])[0]
    if encoding not in (0, 1, 2, 3):
        return None

    change_counter = struct.unpack(">I", data[24:28])[0]
    page_count = struct.unpack(">I", data[28:32])[0]
    valid_for = struct.unpack(">I", data[92:96])[0]

    if 0 < page_count < (1 << 28) and change_counter == valid_for:
        declared = page_size * page_count
        if declared <= len(data):
            return declared
        return None                              # truncated: header disagrees

    # Header size is stale or absent. Fall back to whole pages available.
    usable = (len(data) // page_size) * page_size
    return usable if usable >= page_size else None


def validate_zip(data: bytes) -> Optional[int]:
    if data[:4] != b"PK\x03\x04":
        return None
    idx = data.rfind(b"PK\x05\x06")               # end of central directory
    if idx < 0 or idx + 22 > len(data):
        return None
    comment_len = struct.unpack("<H", data[idx + 20:idx + 22])[0]
    return idx + 22 + comment_len


def validate_gzip(data: bytes) -> Optional[int]:
    if data[:2] != b"\x1f\x8b":
        return None
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        d.decompress(data)
        return len(data) - len(d.unused_data)
    except zlib.error:
        return None


# ------------------------------------------------------------------ catalogue
SIGNATURES: List[Signature] = [
    Signature("JPEG image", "jpg", b"\xff\xd8\xff", b"\xff\xd9",
              max_size=32 << 20, min_size=512, validator=validate_jpeg,
              description="Photographs, including deleted camera roll images"),
    Signature("PNG image", "png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82",
              max_size=32 << 20, min_size=128, validator=validate_png,
              description="Screenshots and app graphics"),
    Signature("GIF image", "gif", b"GIF8", b"\x00\x3b",
              max_size=16 << 20, min_size=64, validator=validate_gif),
    Signature("MP4/QuickTime video", "mp4", b"\x00\x00\x00\x18ftyp",
              max_size=512 << 20, min_size=4096, validator=validate_mp4),
    Signature("MP4/QuickTime video", "mp4", b"\x00\x00\x00\x20ftyp",
              max_size=512 << 20, min_size=4096, validator=validate_mp4),
    Signature("PDF document", "pdf", b"%PDF-", b"%%EOF",
              max_size=64 << 20, min_size=256, validator=validate_pdf),
    Signature("SQLite database", "db", b"SQLite format 3\x00",
              max_size=256 << 20, min_size=512, validator=validate_sqlite,
              description="Application databases — often the richest find"),
    Signature("ZIP / Office document", "zip", b"PK\x03\x04",
              max_size=128 << 20, min_size=128, validator=validate_zip),
    Signature("GZIP stream", "gz", b"\x1f\x8b\x08",
              max_size=64 << 20, min_size=32, validator=validate_gzip),
    Signature("WebP image", "webp", b"RIFF", max_size=16 << 20, min_size=64),
    Signature("HEIC image", "heic", b"\x00\x00\x00\x18ftypheic",
              max_size=32 << 20, min_size=1024, validator=validate_mp4),
    Signature("MP3 audio", "mp3", b"ID3", max_size=32 << 20, min_size=1024),
    Signature("AMR audio", "amr", b"#!AMR", max_size=8 << 20, min_size=64,
              description="Voice notes and call recordings"),
    Signature("Android backup", "ab", b"ANDROID BACKUP",
              max_size=2 << 30, min_size=64),
    Signature("Binary plist", "plist", b"bplist00",
              max_size=16 << 20, min_size=32,
              description="iOS preferences and app state"),
]

# Signatures whose header is short or common enough to need care.
_WEAK = {"RIFF", "ID3", "PK\x03\x04"}


@dataclass
class CarveReport:
    files: List[CarvedFile] = field(default_factory=list)
    bytes_scanned: int = 0
    candidates_seen: int = 0
    rejected: int = 0
    truncated: bool = False
    by_type: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, object]:
        return {
            "recovered": len(self.files),
            "candidates_seen": self.candidates_seen,
            "rejected_by_validation": self.rejected,
            "bytes_scanned": self.bytes_scanned,
            "by_type": dict(sorted(self.by_type.items(),
                                   key=lambda kv: -kv[1])),
            "truncated": self.truncated,
            "notes": self.notes,
        }


class FileCarver:
    """Signature-based file carver with structural validation."""

    def __init__(self, signatures: Optional[Sequence[Signature]] = None,
                 max_files: int = 20000,
                 require_validation: bool = True,
                 keep_data: bool = True):
        self.signatures = list(signatures or SIGNATURES)
        self.max_files = max_files
        self.require_validation = require_validation
        self.keep_data = keep_data
        self._seen_hashes: set[str] = set()
        self.report = CarveReport()
        # Longest header determines how much overlap a block scan needs.
        self.max_header = max(len(s.header) for s in self.signatures)
        # Set while carving an image, so a file that starts near the end of a
        # block can still be read in full. Without this every file larger than
        # the remaining block tail is silently truncated and then rejected by
        # its own validator — the carver would appear to work while quietly
        # dropping exactly the large files that matter most.
        self._fetch: Optional[Callable[[int, int], bytes]] = None
        self._image_size: int = 0

    # ------------------------------------------------------------- scanning
    def carve_bytes(self, data: bytes, base_offset: int = 0) -> List[CarvedFile]:
        """Carve a buffer. ``base_offset`` makes reported offsets absolute."""
        found: List[CarvedFile] = []
        for sig in self.signatures:
            start = 0
            while True:
                if len(self.report.files) >= self.max_files:
                    self.report.truncated = True
                    return found
                idx = data.find(sig.header, start)
                if idx < 0:
                    break
                start = idx + 1
                self.report.candidates_seen += 1
                carved = self._extract(sig, data, idx, base_offset)
                if carved is not None:
                    found.append(carved)
                    self.report.files.append(carved)
                    self.report.by_type[sig.name] = \
                        self.report.by_type.get(sig.name, 0) + 1
                    # Skip past what we just recovered — overlapping carves of
                    # the same file are noise.
                    start = idx + max(carved.size, 1)
                else:
                    self.report.rejected += 1
        return found

    def _window(self, sig: Signature, data: bytes, idx: int,
                base_offset: int) -> bytes:
        """The bytes available for this candidate, extended from the image
        if the in-memory block cuts the file short."""
        window = data[idx:idx + sig.max_size]
        truncated_by_block = (idx + len(window)) >= len(data)
        if truncated_by_block and self._fetch is not None:
            absolute = base_offset + idx
            want = min(sig.max_size, max(self._image_size - absolute, 0))
            if want > len(window):
                bigger = self._fetch(absolute, want)
                if len(bigger) > len(window):
                    return bigger
        return window

    def _extract(self, sig: Signature, data: bytes, idx: int,
                 base_offset: int) -> Optional[CarvedFile]:
        window = self._window(sig, data, idx, base_offset)
        if len(window) < sig.min_size:
            return None

        size: Optional[int] = None
        validated = False
        note = ""

        if sig.validator is not None:
            size = sig.validator(window)
            validated = size is not None
        if size is None and sig.footer:
            pos = window.find(sig.footer, len(sig.header))
            if pos >= 0:
                size = pos + len(sig.footer)
                note = "located by footer; structure not validated"
        if size is None:
            if self.require_validation:
                return None
            size = min(len(window), sig.max_size)
            note = "unbounded carve — size is a guess"

        if size < sig.min_size or size > sig.max_size:
            return None

        payload = window[:size]
        if sig.header in (b"RIFF",) and payload[8:12] not in (b"WEBP",):
            return None                          # RIFF container, not WebP

        digest = hash_bytes(payload)
        if digest.sha256 in self._seen_hashes:
            return None                          # same file carved twice
        self._seen_hashes.add(digest.sha256)

        confidence = 0.95 if validated else (0.6 if sig.footer else 0.35)
        if sig.header.decode("latin-1", "ignore") in _WEAK and not validated:
            confidence *= 0.7

        return CarvedFile(
            signature=sig.name, extension=sig.extension, mime=sig.mime,
            offset=base_offset + idx, size=size, sha256=digest.sha256,
            data=payload if self.keep_data else b"",
            validated=validated, confidence=round(confidence, 3), note=note)

    # ---------------------------------------------------------------- image
    def carve_image(self, reader, progress=None,
                    should_stop: Optional[Callable[[], bool]] = None
                    ) -> CarveReport:
        """Carve a whole :class:`~argus.core.streaming.ImageReader`.

        Blocks overlap by the longest header so a file starting near a block
        boundary is still detected.
        """
        overlap = self.max_header + 16
        self._fetch = reader.read
        self._image_size = reader.size
        for offset, block in reader.blocks(overlap=overlap):
            if should_stop and should_stop():
                self.report.truncated = True
                self.report.notes.append("carve stopped on request")
                break
            self.carve_bytes(block, base_offset=offset)
            self.report.bytes_scanned += len(block)
            if progress:
                progress.advance(len(block))
            if len(self.report.files) >= self.max_files:
                self.report.truncated = True
                self.report.notes.append(
                    f"stopped at the {self.max_files} file limit — raise "
                    f"max_files to recover more")
                break
        return self.report

    def carve_file(self, path: Path | str) -> CarveReport:
        """Carve a file on disk (useful for unallocated-space dumps)."""
        from ..core.streaming import ImageReader
        with ImageReader(path) as reader:
            return self.carve_image(reader)


def carve_slack(data: bytes, base_offset: int = 0,
                max_files: int = 500) -> List[CarvedFile]:
    """Convenience: carve a small buffer such as SQLite page slack."""
    carver = FileCarver(max_files=max_files, keep_data=True)
    return carver.carve_bytes(data, base_offset)
