"""Perceptual image hashing — matching pictures a cryptographic hash cannot.

SHA-256 answers "is this the same file?". It cannot answer "is this the same
photograph?", and in mobile forensics those are very different questions. The
same image sent through WhatsApp, saved, screenshotted and forwarded produces
four files with four unrelated digests. An investigation that relies on
cryptographic hashing alone treats them as four unrelated pictures.

Perceptual hashes survive that. Re-encoding, resizing, small quality changes and
minor cropping leave the hash nearly unchanged, so the four copies cluster
together and the chain of forwarding becomes visible.

Three algorithms, because each fails differently and agreement between them is
what makes a match trustworthy:

**aHash** (average hash) — cheap, robust to compression, weak on low-contrast
images.

**dHash** (difference hash) — compares adjacent pixel gradients. The best
general-purpose choice; robust to brightness and gamma shifts.

**pHash-lite** (DCT hash) — a discrete cosine transform on an 8×8 low-frequency
block, implemented directly here rather than pulling in SciPy. Most robust to
rotation-free geometric change, most expensive.

Distances are Hamming distances over 64-bit hashes. The thresholds below are set
conservatively: an examiner chasing a false "these are the same image" wastes
time, and asserting that two different photographs are the same is a much worse
error than missing a match.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from PIL import Image
    _PIL = True
except ImportError:                                          # pragma: no cover
    _PIL = False

HASH_BITS = 64

# Hamming distance thresholds, calibrated to be cautious.
IDENTICAL = 0            # bit-identical perceptual hash
NEAR_DUPLICATE = 6       # re-encoded, resized or lightly edited
SIMILAR = 12             # same scene or heavy edit — review required


@dataclass
class PerceptualHashes:
    """The three hashes for one image, plus what was measurable."""

    ahash: Optional[int] = None
    dhash: Optional[int] = None
    phash: Optional[int] = None
    width: int = 0
    height: int = 0
    error: str = ""

    @property
    def available(self) -> bool:
        return any(h is not None for h in (self.ahash, self.dhash, self.phash))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ahash": f"{self.ahash:016x}" if self.ahash is not None else "",
            "dhash": f"{self.dhash:016x}" if self.dhash is not None else "",
            "phash": f"{self.phash:016x}" if self.phash is not None else "",
            "width": self.width, "height": self.height,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PerceptualHashes":
        def parse(value: Any) -> Optional[int]:
            try:
                return int(str(value), 16) if value else None
            except (TypeError, ValueError):
                return None
        return cls(ahash=parse(data.get("ahash")),
                   dhash=parse(data.get("dhash")),
                   phash=parse(data.get("phash")),
                   width=int(data.get("width") or 0),
                   height=int(data.get("height") or 0),
                   error=str(data.get("error") or ""))


def hamming(a: Optional[int], b: Optional[int]) -> Optional[int]:
    """Bit distance between two hashes, or ``None`` if either is missing."""
    if a is None or b is None:
        return None
    return bin(a ^ b).count("1")


# ═══════════════════════════════════════════════════════════════ algorithms
def _grey_matrix(image: "Image.Image", size: int) -> List[List[float]]:
    resized = image.convert("L").resize((size, size), Image.Resampling.LANCZOS)
    pixels = list(resized.getdata())
    return [[float(pixels[row * size + col]) for col in range(size)]
            for row in range(size)]


def average_hash(image: "Image.Image", size: int = 8) -> int:
    matrix = _grey_matrix(image, size)
    flat = [v for row in matrix for v in row]
    mean = sum(flat) / len(flat)
    bits = 0
    for value in flat:
        bits = (bits << 1) | (1 if value >= mean else 0)
    return bits


def difference_hash(image: "Image.Image", size: int = 8) -> int:
    """Compare each pixel with its right-hand neighbour."""
    resized = image.convert("L").resize((size + 1, size),
                                        Image.Resampling.LANCZOS)
    pixels = list(resized.getdata())
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            left = pixels[base + col]
            right = pixels[base + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def _dct_1d(vector: Sequence[float]) -> List[float]:
    """Type-II DCT. Written out rather than importing SciPy.

    ARGUS has no third-party requirement for its core, and adding one for a
    32-point transform would be a poor trade — a forensic workstation is often
    air-gapped.
    """
    n = len(vector)
    result = []
    for k in range(n):
        total = 0.0
        for i, value in enumerate(vector):
            total += value * math.cos(math.pi * k * (2 * i + 1) / (2 * n))
        result.append(total * (math.sqrt(1.0 / n) if k == 0
                               else math.sqrt(2.0 / n)))
    return result


def perceptual_hash(image: "Image.Image", size: int = 32,
                    low_freq: int = 8) -> int:
    """DCT-based hash over the low-frequency 8×8 block."""
    matrix = _grey_matrix(image, size)
    rows = [_dct_1d(row) for row in matrix]
    columns = [_dct_1d([rows[r][c] for r in range(size)])
               for c in range(low_freq)]
    # columns[c][r] is the coefficient at (r, c)
    block = [columns[c][r] for r in range(low_freq) for c in range(low_freq)]
    # Skip the DC term when computing the median: it encodes overall
    # brightness, which is exactly the thing we want the hash to ignore.
    ordered = sorted(block[1:])
    median = ordered[len(ordered) // 2] if ordered else 0.0
    bits = 0
    for value in block:
        bits = (bits << 1) | (1 if value > median else 0)
    return bits


def hash_image(path: Path | str, data: Optional[bytes] = None
               ) -> PerceptualHashes:
    """Compute all three hashes for an image on disk or in memory."""
    if not _PIL:
        return PerceptualHashes(
            error="Pillow is not installed — perceptual hashing unavailable "
                  "(pip install pillow)")
    try:
        if data is not None:
            import io
            image = Image.open(io.BytesIO(data))
        else:
            image = Image.open(Path(path))
        with image:
            image.load()
            width, height = image.size
            # Below roughly 16 px a perceptual hash carries no information and
            # would match almost anything. Refusing is better than emitting a
            # hash that produces spurious clusters.
            if min(width, height) < 16:
                return PerceptualHashes(
                    width=width, height=height,
                    error=f"image is {width}x{height}; too small for a "
                          f"meaningful perceptual hash")
            return PerceptualHashes(
                ahash=average_hash(image), dhash=difference_hash(image),
                phash=perceptual_hash(image), width=width, height=height)
    except Exception as exc:
        return PerceptualHashes(error=f"{type(exc).__name__}: {exc}")


# ═══════════════════════════════════════════════════════════════ comparison
@dataclass
class Match:
    """Two images judged to be the same picture, or nearly so."""

    a_id: str
    b_id: str
    a_label: str = ""
    b_label: str = ""
    a_exhibit: str = ""
    b_exhibit: str = ""
    dhash_distance: Optional[int] = None
    ahash_distance: Optional[int] = None
    phash_distance: Optional[int] = None
    verdict: str = ""              # identical | near-duplicate | similar
    agreement: int = 0             # how many algorithms agree
    same_bytes: bool = False       # SHA-256 also matched
    note: str = ""

    @property
    def confidence(self) -> float:
        """Agreement across independent algorithms is what earns confidence."""
        base = {"identical": 0.97, "near-duplicate": 0.85,
                "similar": 0.6}.get(self.verdict, 0.4)
        return round(min(0.99, base + 0.04 * max(self.agreement - 1, 0)), 3)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence
        return d


def compare(a: PerceptualHashes, b: PerceptualHashes) -> Tuple[str, int, Dict[str, Optional[int]]]:
    """Classify a pair. Returns ``(verdict, agreement, distances)``.

    A verdict requires the *strictest* available algorithm to agree, not the
    most permissive — otherwise one weak algorithm alone could declare two
    unrelated photographs the same.
    """
    distances = {
        "dhash": hamming(a.dhash, b.dhash),
        "ahash": hamming(a.ahash, b.ahash),
        "phash": hamming(a.phash, b.phash),
    }
    measured = [d for d in distances.values() if d is not None]
    if not measured:
        return "", 0, distances

    def agree(limit: int) -> int:
        return sum(1 for d in measured if d <= limit)

    if all(d == IDENTICAL for d in measured):
        return "identical", len(measured), distances
    # Require a majority of measurable algorithms, and at least two where more
    # than one is available.
    needed = 2 if len(measured) > 1 else 1
    if agree(NEAR_DUPLICATE) >= needed:
        return "near-duplicate", agree(NEAR_DUPLICATE), distances
    if agree(SIMILAR) >= needed:
        return "similar", agree(SIMILAR), distances
    return "", 0, distances


@dataclass
class ImageRecord:
    """One hashed image, with enough identity to report a match."""

    artifact_id: str
    hashes: PerceptualHashes
    label: str = ""
    exhibit: str = ""
    sha256: str = ""
    timestamp: Optional[int] = None


class PerceptualIndex:
    """Cluster images by visual similarity.

    Comparison is O(n²) in the worst case, which is fine for the low thousands
    of images a handset yields. Above ``max_pairs`` the index stops and says so
    rather than running for hours — a truncated result an examiner knows about
    is far better than an apparently complete one that is not.
    """

    def __init__(self, max_pairs: int = 4_000_000):
        self.records: List[ImageRecord] = []
        self.max_pairs = max_pairs
        self.truncated = False
        self.skipped: List[Dict[str, str]] = []

    def add(self, artifact_id: str, hashes: PerceptualHashes, label: str = "",
            exhibit: str = "", sha256: str = "",
            timestamp: Optional[int] = None) -> None:
        if not hashes.available:
            if hashes.error:
                self.skipped.append({"artifact_id": artifact_id,
                                     "label": label, "reason": hashes.error})
            return
        self.records.append(ImageRecord(
            artifact_id=artifact_id, hashes=hashes, label=label,
            exhibit=exhibit, sha256=sha256, timestamp=timestamp))

    def matches(self, cross_exhibit_only: bool = False) -> List[Match]:
        out: List[Match] = []
        pairs = 0
        n = len(self.records)
        for i in range(n):
            for j in range(i + 1, n):
                pairs += 1
                if pairs > self.max_pairs:
                    self.truncated = True
                    return sorted(out, key=lambda m: -m.confidence)
                a, b = self.records[i], self.records[j]
                if cross_exhibit_only and a.exhibit == b.exhibit:
                    continue
                verdict, agreement, distances = compare(a.hashes, b.hashes)
                if not verdict:
                    continue
                same_bytes = bool(a.sha256) and a.sha256 == b.sha256
                note = ""
                if verdict == "identical" and not same_bytes:
                    note = ("Visually identical but the files differ — the same "
                            "picture was re-encoded, resized or re-saved. A "
                            "cryptographic hash would not have linked these.")
                elif same_bytes:
                    note = "Byte-identical; the perceptual match is expected."
                out.append(Match(
                    a_id=a.artifact_id, b_id=b.artifact_id,
                    a_label=a.label, b_label=b.label,
                    a_exhibit=a.exhibit, b_exhibit=b.exhibit,
                    dhash_distance=distances["dhash"],
                    ahash_distance=distances["ahash"],
                    phash_distance=distances["phash"],
                    verdict=verdict, agreement=agreement,
                    same_bytes=same_bytes, note=note))
        return sorted(out, key=lambda m: (-m.confidence, m.a_label))

    def clusters(self) -> List[Dict[str, Any]]:
        """Group images into sets of the same picture (union-find on matches)."""
        parent: Dict[str, str] = {r.artifact_id: r.artifact_id
                                  for r in self.records}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[ry] = rx

        strong = [m for m in self.matches()
                  if m.verdict in ("identical", "near-duplicate")]
        for m in strong:
            union(m.a_id, m.b_id)

        groups: Dict[str, List[ImageRecord]] = {}
        by_id = {r.artifact_id: r for r in self.records}
        for artifact_id in parent:
            groups.setdefault(find(artifact_id), []).append(by_id[artifact_id])

        out = []
        for members in groups.values():
            if len(members) < 2:
                continue
            exhibits = sorted({m.exhibit for m in members if m.exhibit})
            distinct_bytes = len({m.sha256 for m in members if m.sha256})
            out.append({
                "size": len(members),
                "exhibits": exhibits,
                "spans_exhibits": len(exhibits) > 1,
                "distinct_files": distinct_bytes,
                "re_encoded": distinct_bytes > 1,
                "members": [{"artifact_id": m.artifact_id, "label": m.label,
                             "exhibit": m.exhibit, "sha256": m.sha256,
                             "timestamp": m.timestamp} for m in members],
                "note": ("The same picture exists as "
                         f"{distinct_bytes} different files — it was re-encoded "
                         f"or re-saved between copies, so cryptographic hashing "
                         f"would treat them as unrelated."
                         if distinct_bytes > 1 else
                         "All copies are byte-identical."),
            })
        return sorted(out, key=lambda c: (-c["size"], -c["distinct_files"]))

    def summary(self) -> Dict[str, Any]:
        matches = self.matches()
        clusters = self.clusters()
        return {
            "images_hashed": len(self.records),
            "images_skipped": len(self.skipped),
            "skipped_detail": self.skipped[:20],
            "matches": len(matches),
            "identical": sum(1 for m in matches if m.verdict == "identical"),
            "near_duplicates": sum(1 for m in matches
                                   if m.verdict == "near-duplicate"),
            "similar": sum(1 for m in matches if m.verdict == "similar"),
            "re_encoded_matches": sum(1 for m in matches
                                      if m.verdict == "identical"
                                      and not m.same_bytes),
            "clusters": clusters[:60],
            "cluster_count": len(clusters),
            "cross_exhibit_clusters": sum(1 for c in clusters
                                          if c["spans_exhibits"]),
            "truncated": self.truncated,
            "thresholds": {"identical": IDENTICAL,
                           "near_duplicate": NEAR_DUPLICATE,
                           "similar": SIMILAR},
        }


def build_index(session: Any, hash_missing: bool = True) -> PerceptualIndex:
    """Build a perceptual index from an analysis session's stored images."""
    from ...core.models import Category

    index = PerceptualIndex()
    for loaded in session.loaded:
        exhibit = (loaded.container.extraction.get("exhibit_id")
                   or loaded.container.path.name)
        for art in loaded.db.iter_artifacts(
                "category = ? AND blob_sha256 <> ''", (Category.FILE.value,)):
            mime = str(art.attributes.get("mime_type") or "")
            if not mime.startswith("image/"):
                continue
            stored = art.attributes.get("perceptual")
            hashes = (PerceptualHashes.from_dict(stored)
                      if isinstance(stored, dict) else None)
            if (hashes is None or not hashes.available) and hash_missing:
                try:
                    hashes = hash_image(
                        loaded.container.blob_file(art.blob_sha256))
                except Exception as exc:
                    hashes = PerceptualHashes(error=str(exc))
            if hashes is None:
                continue
            index.add(art.artifact_id, hashes,
                      label=str(art.attributes.get("filename") or art.body),
                      exhibit=exhibit, sha256=art.blob_sha256,
                      timestamp=art.timestamp)
    return index


def perceptual_findings(index: PerceptualIndex) -> List[Any]:
    """Findings from visual matching."""
    from ...intel.findings import Finding

    out: List[Finding] = []
    summary = index.summary()

    re_encoded = [c for c in index.clusters() if c["re_encoded"]]
    if re_encoded:
        members = [m["artifact_id"] for c in re_encoded for m in c["members"]]
        out.append(Finding(
            rule_id="media.re_encoded_duplicates",
            title=(f"{len(re_encoded)} picture(s) exist as multiple "
                   f"non-identical files"),
            detail=("These images are visually the same picture but are "
                    "different files — re-encoded, resized or re-saved between "
                    "copies. Cryptographic hashing treats them as unrelated: "
                    + "; ".join(
                        f"{(c['members'][0]['label'] or 'unnamed')} "
                        f"({c['distinct_files']} files"
                        + (f", across {', '.join(c['exhibits'])}"
                           if c["spans_exhibits"] else "") + ")"
                        for c in re_encoded[:6])),
            severity="high" if any(c["spans_exhibits"] for c in re_encoded)
                     else "medium",
            confidence=0.85, category="media",
            artifact_ids=members[:300],
            metrics={"clusters": re_encoded[:12],
                     "thresholds": summary["thresholds"]},
            why_it_matters=("A picture that has been re-saved between copies "
                            "has been handled — forwarded, screenshotted, or "
                            "moved between apps. The chain of copies shows how "
                            "it travelled, which a byte-level hash cannot."),
            caveat=("Perceptual matching identifies the same *image*, not the "
                    "same *file*. Thumbnails, stock graphics and app assets "
                    "legitimately recur. Confirm visually before relying on a "
                    "match."),
        ))

    cross = [c for c in index.clusters() if c["spans_exhibits"]]
    if cross:
        out.append(Finding(
            rule_id="media.cross_exhibit_images",
            title=f"{len(cross)} picture(s) present on more than one exhibit",
            detail=("The same image appears on multiple seized devices, "
                    "including where the files are not byte-identical: "
                    + "; ".join(f"{(c['members'][0]['label'] or 'unnamed')} "
                                f"on {', '.join(c['exhibits'])}"
                                for c in cross[:6])),
            severity="high", confidence=0.8, category="media",
            artifact_ids=[m["artifact_id"] for c in cross
                          for m in c["members"]][:300],
            metrics={"clusters": cross[:12]},
            why_it_matters=("Links devices to each other through shared imagery "
                            "even when the file was recompressed in transit — "
                            "which is what happens to every photograph sent "
                            "through a messaging app."),
            caveat=("Widely-circulated images, memes and forwards match across "
                    "entirely unrelated devices. Check what the picture "
                    "actually depicts."),
        ))

    if summary["images_skipped"]:
        out.append(Finding(
            rule_id="media.perceptual_unavailable",
            title=(f"{summary['images_skipped']} image(s) could not be "
                   f"perceptually hashed"),
            detail=("These images were excluded from visual matching, so any "
                    "duplicate among them would not have been found: "
                    + "; ".join(f"{s.get('label') or s['artifact_id'][:8]} — "
                                f"{s['reason'][:70]}"
                                for s in summary["skipped_detail"][:5])),
            severity="info", confidence=0.9, category="media",
            metrics={"skipped": summary["skipped_detail"]},
            why_it_matters=("Prevents an absence of visual matches being read "
                            "as evidence that no duplicates exist."),
            caveat="",
        ))
    return out
