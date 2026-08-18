"""Large-image support: streaming reads, chunked hashing, sparse indexing.

A physical extraction of a modern handset is 64–512 GB. Nothing in the rest of
ARGUS may assume an image fits in memory, and nothing may require a second full
pass over the bytes when one will do.

Three facilities here:

* :class:`ImageReader` — random access over a possibly-split, possibly-
  compressed image, with an LRU block cache. Handles raw/`dd`, split segments
  (`.001`, `.002`, …) and EWF-style naming *by concatenation*; it does not
  decode EWF/E01 compression, and says so rather than returning wrong bytes.

* :func:`hash_and_scan` — one pass that simultaneously computes the image
  digest and hands each block to any number of scanners. Hashing a 256 GB
  image takes ~20 minutes on spinning media; doing it twice because the
  carver wanted its own pass is 20 minutes of an examiner's life wasted.

* :class:`ProgressReporter` — throughput and ETA, because an operation with no
  visible progress is one an operator will assume has hung and kill.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .errors import ArgusError

DEFAULT_BLOCK = 1 << 20            # 1 MiB
CACHE_BLOCKS = 64                  # 64 MiB of cache


# --------------------------------------------------------------------- splits
SPLIT_RE = re.compile(r"^(?P<stem>.+?)\.(?P<idx>\d{2,4}|[a-z]{3})$", re.I)


def discover_segments(path: Path) -> List[Path]:
    """Find every segment of a split image, in order.

    Split images are the norm for anything acquired to FAT32 media. Opening
    only the first segment silently truncates the evidence at 2 or 4 GB, which
    is the kind of error that is not noticed until it is far too late.
    """
    path = Path(path)
    if not path.exists():
        raise ArgusError(f"image not found: {path}")
    m = SPLIT_RE.match(path.name)
    if not m:
        return [path]
    stem = m.group("stem")
    siblings = sorted(
        (p for p in path.parent.iterdir()
         if p.is_file() and SPLIT_RE.match(p.name)
         and SPLIT_RE.match(p.name).group("stem") == stem),
        key=lambda p: SPLIT_RE.match(p.name).group("idx"))
    return siblings or [path]


@dataclass
class Segment:
    path: Path
    offset: int          # absolute offset of this segment's first byte
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


class ImageReader:
    """Random access over a raw or split disk image.

    Usage::

        with ImageReader("phone.dd") as img:
            header = img.read(0, 512)
            for offset, block in img.blocks():
                ...
    """

    def __init__(self, path: Path | str, block_size: int = DEFAULT_BLOCK):
        self.block_size = block_size
        self.segments: List[Segment] = []
        offset = 0
        for seg_path in discover_segments(Path(path)):
            size = seg_path.stat().st_size
            self.segments.append(Segment(seg_path, offset, size))
            offset += size
        self.size = offset
        if not self.size:
            raise ArgusError(f"image {path} is empty")

        first = self.segments[0].path
        self._check_container_format(first)

        self._handles: Dict[Path, object] = {}
        self._cache: "OrderedDict[int, bytes]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _check_container_format(path: Path) -> None:
        """Refuse formats we would otherwise silently misread."""
        with path.open("rb") as fh:
            head = fh.read(16)
        if head[:3] == b"EVF" or head[:8] == b"EVF2\r\n\x81\x00":
            raise ArgusError(
                f"{path.name} is an EWF/E01 container. ARGUS reads raw (dd) "
                f"images. Convert it first, e.g.:  ewfexport -f raw "
                f"{path.name}  — reading the container as raw would return "
                f"compressed bytes and produce silently wrong results.")
        if head[:4] == b"AFF\x00" or head[:3] == b"AFD":
            raise ArgusError(f"{path.name} is an AFF container; convert to raw "
                             f"with affconvert before analysis.")
        if head[:4] == b"QFI\xfb":
            raise ArgusError(f"{path.name} is a QCOW2 image; convert with "
                             f"qemu-img convert -O raw before analysis.")

    # ------------------------------------------------------------------ read
    def _handle(self, seg: Segment):
        fh = self._handles.get(seg.path)
        if fh is None:
            fh = seg.path.open("rb")
            self._handles[seg.path] = fh
        return fh

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes from absolute ``offset``, spanning segments."""
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        remaining = length
        pos = offset
        with self._lock:
            for seg in self.segments:
                if remaining <= 0:
                    break
                if pos >= seg.end:
                    continue
                local = pos - seg.offset
                take = min(remaining, seg.size - local)
                fh = self._handle(seg)
                fh.seek(local)
                chunk = fh.read(take)
                if not chunk:
                    break
                out += chunk
                pos += len(chunk)
                remaining -= len(chunk)
        return bytes(out)

    def read_block(self, index: int) -> bytes:
        """Read one cached block by index."""
        with self._lock:
            cached = self._cache.get(index)
            if cached is not None:
                self._cache.move_to_end(index)
                return cached
        data = self.read(index * self.block_size, self.block_size)
        with self._lock:
            self._cache[index] = data
            while len(self._cache) > CACHE_BLOCKS:
                self._cache.popitem(last=False)
        return data

    def blocks(self, start: int = 0, overlap: int = 0
               ) -> Iterator[Tuple[int, bytes]]:
        """Iterate the image as ``(absolute_offset, bytes)``.

        ``overlap`` prepends the tail of the previous block so a signature or
        record straddling a block boundary is still found — without it, a
        carver silently misses every artifact that happens to span 1 MiB.
        """
        offset = start
        tail = b""
        while offset < self.size:
            chunk = self.read(offset, self.block_size)
            if not chunk:
                break
            if tail:
                yield offset - len(tail), tail + chunk
            else:
                yield offset, chunk
            if overlap:
                tail = chunk[-overlap:]
            offset += len(chunk)

    # ------------------------------------------------------------------ misc
    def describe(self) -> Dict[str, object]:
        return {
            "size": self.size,
            "size_display": human_bytes(self.size),
            "segments": [{"path": str(s.path), "size": s.size,
                          "offset": s.offset} for s in self.segments],
            "segment_count": len(self.segments),
            "block_size": self.block_size,
        }

    def close(self) -> None:
        with self._lock:
            for fh in self._handles.values():
                try:
                    fh.close()
                except Exception:
                    pass
            self._handles.clear()
            self._cache.clear()

    def __enter__(self) -> "ImageReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __len__(self) -> int:
        return self.size


# ------------------------------------------------------------------ progress
@dataclass
class ProgressReporter:
    """Throughput and ETA for long passes."""

    total: int
    label: str = ""
    callback: Optional[Callable[[Dict[str, object]], None]] = None
    interval: float = 2.0
    done: int = 0
    started: float = field(default_factory=time.time)
    _last: float = field(default_factory=time.time)

    def advance(self, amount: int) -> None:
        self.done += amount
        now = time.time()
        if now - self._last < self.interval and self.done < self.total:
            return
        self._last = now
        if self.callback:
            self.callback(self.snapshot())

    def snapshot(self) -> Dict[str, object]:
        elapsed = max(time.time() - self.started, 1e-6)
        rate = self.done / elapsed
        remaining = max(self.total - self.done, 0)
        return {
            "label": self.label,
            "done": self.done,
            "total": self.total,
            "fraction": (self.done / self.total) if self.total else 0.0,
            "percent": round(100.0 * self.done / self.total, 1) if self.total else 0.0,
            "rate_bytes_per_s": rate,
            "rate_display": f"{human_bytes(rate)}/s",
            "elapsed_s": round(elapsed, 1),
            "eta_s": round(remaining / rate, 1) if rate > 0 else None,
            "eta_display": human_duration(remaining / rate) if rate > 0 else "—",
        }


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EB"


def human_duration(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# ---------------------------------------------------------- single-pass scan
Scanner = Callable[[int, bytes], None]


def hash_and_scan(reader: ImageReader, scanners: Sequence[Scanner] = (),
                  algorithms: Sequence[str] = ("md5", "sha1", "sha256"),
                  overlap: int = 0,
                  progress: Optional[ProgressReporter] = None,
                  should_stop: Optional[Callable[[], bool]] = None
                  ) -> Dict[str, object]:
    """Hash an image and run every scanner over it in a single pass.

    Returns the digests plus timing. Scanners receive
    ``(absolute_offset, block)`` and must not modify the block.
    """
    hashers = {name: hashlib.new(name) for name in algorithms}
    started = time.time()
    consumed = 0
    tail = b""
    offset = 0
    stopped = False

    while offset < reader.size:
        if should_stop and should_stop():
            stopped = True
            break
        chunk = reader.read(offset, reader.block_size)
        if not chunk:
            break
        # Hash the true bytes exactly once, with no overlap — an overlapped
        # region hashed twice would produce a digest that matches nothing.
        for h in hashers.values():
            h.update(chunk)
        consumed += len(chunk)

        scan_block = (tail + chunk) if tail else chunk
        scan_offset = offset - len(tail)
        for scan in scanners:
            try:
                scan(scan_offset, scan_block)
            except Exception:
                # A failing scanner must not abort the hash pass; the digest
                # is the part that must always complete.
                pass
        if overlap:
            tail = chunk[-overlap:]
        offset += len(chunk)
        if progress:
            progress.advance(len(chunk))

    elapsed = time.time() - started
    return {
        "bytes_read": consumed,
        "complete": not stopped and consumed >= reader.size,
        "elapsed_s": round(elapsed, 2),
        "throughput_display": f"{human_bytes(consumed / max(elapsed, 1e-6))}/s",
        **{name: h.hexdigest() for name, h in hashers.items()},
    }


def chunked_digest(path: Path | str, algorithm: str = "sha256",
                   block: int = DEFAULT_BLOCK,
                   progress: Optional[ProgressReporter] = None) -> str:
    """Digest a file of any size without loading it."""
    h = hashlib.new(algorithm)
    p = Path(path)
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(block)
            if not chunk:
                break
            h.update(chunk)
            if progress:
                progress.advance(len(chunk))
    return h.hexdigest()
