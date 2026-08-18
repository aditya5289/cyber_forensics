"""Cryptographic integrity primitives.

Lab manual precaution 5 requires: *"Verify data integrity (hash values) after
extraction and before analysis."*  Everything ARGUS ingests is hashed at the
moment of acquisition with three algorithms simultaneously (single pass over
the bytes) and re-verified on every container open.

Design notes
------------
* MD5 is retained only because legacy case files and courts still reference it.
  It is **never** used alone for an integrity decision.
* SHA-256 is the primary identifier and the key in the blob store.
* SHA-1 is kept for cross-tool comparison (many mobile tools emit SHA-1).
* Files are streamed in 1 MiB chunks so multi-gigabyte physical images do not
  need to be resident in memory.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import BinaryIO, Dict, Iterable

CHUNK = 1024 * 1024
ALGORITHMS = ("md5", "sha1", "sha256")


@dataclass(frozen=True)
class Digest:
    """A multi-algorithm digest of a byte stream."""

    md5: str
    sha1: str
    sha256: str
    size: int

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)

    @property
    def short(self) -> str:
        return self.sha256[:16]

    def matches(self, other: "Digest") -> bool:
        """Constant-time comparison on the strongest common algorithm."""
        return hmac.compare_digest(self.sha256, other.sha256) and self.size == other.size

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"sha256:{self.sha256} ({self.size} bytes)"


def _new_hashers():
    return {name: hashlib.new(name) for name in ALGORITHMS}


def hash_stream(stream: BinaryIO) -> Digest:
    """Hash an open binary stream from its current position to EOF."""
    hashers = _new_hashers()
    size = 0
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        size += len(block)
        for h in hashers.values():
            h.update(block)
    return Digest(
        md5=hashers["md5"].hexdigest(),
        sha1=hashers["sha1"].hexdigest(),
        sha256=hashers["sha256"].hexdigest(),
        size=size,
    )


def hash_file(path: os.PathLike | str) -> Digest:
    """Hash a file on disk. Opens strictly read-only."""
    p = Path(path)
    with p.open("rb") as fh:
        return hash_stream(fh)


def hash_bytes(data: bytes) -> Digest:
    hashers = _new_hashers()
    for h in hashers.values():
        h.update(data)
    return Digest(
        md5=hashers["md5"].hexdigest(),
        sha1=hashers["sha1"].hexdigest(),
        sha256=hashers["sha256"].hexdigest(),
        size=len(data),
    )


def digest_from_dict(d: Dict[str, object]) -> Digest:
    return Digest(
        md5=str(d.get("md5", "")),
        sha1=str(d.get("sha1", "")),
        sha256=str(d.get("sha256", "")),
        size=int(d.get("size", 0) or 0),
    )


def merkle_root(digests: Iterable[str]) -> str:
    """Compute a deterministic Merkle root over a set of SHA-256 hex digests.

    Used to seal an entire extraction with one value: if any single artifact
    blob is altered, the root changes.  Leaves are sorted so the root is
    independent of insertion order.
    """
    layer = [bytes.fromhex(d) for d in sorted(set(digests)) if d]
    if not layer:
        return hashlib.sha256(b"").hexdigest()
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(hashlib.sha256(left + right).digest())
        layer = nxt
    return layer[0].hex()
