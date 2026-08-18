"""Hash-set filtering — known-good suppression and known-bad flagging.

An extraction of a modern handset yields tens of thousands of files, and the
overwhelming majority are operating-system components, application assets and
stock media. An examiner who has to look at all of them will not look carefully
at any of them.

Hash sets fix that by triage:

* A **known-good** set (NSRL-style) suppresses files whose digest matches a
  published, unmodified system or application file. Nothing is deleted — the
  artifact stays in the container with a flag — but it is filtered out of the
  default review view.
* A **known-bad** set flags files whose digest matches a curated list of
  material of interest. A hit here is a finding in its own right.

Two things this module is careful about.

**Known-good is a filter, never a deletion.** A malicious file placed at a
system path, or a system file that has been modified, will not match the set
and so will not be suppressed — that is the point. But an examiner must still be
able to see what was suppressed and why, so every suppression is recorded and
counted, and the reason is attached to the artifact.

**A known-bad list is only as good as its provenance.** This module stores where
each set came from and when it was loaded, and puts that in the report. A hit
against an unattributed list is not evidence of anything.

Set formats accepted: NSRL RDS (CSV), plain digest-per-line, HashKeeper CSV, and
ARGUS's own JSON. Digests may be MD5, SHA-1 or SHA-256; matching is per
algorithm, so a set of MD5s only ever matches on MD5.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_HEX = re.compile(r"^[0-9a-fA-F]+$")
ALGORITHM_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}


def _classify(digest: str) -> Tuple[str, str]:
    """Return ``(algorithm, normalised_digest)`` or ``("", "")``."""
    value = (digest or "").strip().lower()
    if not value or not _HEX.match(value):
        return "", ""
    return ALGORITHM_BY_LENGTH.get(len(value), ""), value


@dataclass
class HashSet:
    """One loaded set of digests, with its provenance."""

    name: str
    kind: str                       # "known-good" | "known-bad"
    source: str = ""                # where it came from
    description: str = ""
    loaded_at: str = field(default_factory=lambda:
                           datetime.now(timezone.utc).isoformat(timespec="seconds"))
    digests: Dict[str, Set[str]] = field(
        default_factory=lambda: {"md5": set(), "sha1": set(), "sha256": set()})
    labels: Dict[str, str] = field(default_factory=dict)
    malformed: int = 0

    @property
    def size(self) -> int:
        return sum(len(v) for v in self.digests.values())

    @property
    def algorithms(self) -> List[str]:
        return [a for a, v in self.digests.items() if v]

    def add(self, digest: str, label: str = "") -> bool:
        algorithm, value = _classify(digest)
        if not algorithm:
            self.malformed += 1
            return False
        self.digests[algorithm].add(value)
        if label:
            self.labels[value] = label[:200]
        return True

    def contains(self, md5: str = "", sha1: str = "",
                 sha256: str = "") -> Tuple[bool, str, str]:
        """Match on any algorithm this set actually holds.

        Returns ``(hit, algorithm, label)``. Matching per-algorithm matters: a
        set of MD5s must never appear to "not match" simply because the caller
        led with SHA-256.
        """
        for algorithm, value in (("sha256", sha256), ("sha1", sha1),
                                 ("md5", md5)):
            value = (value or "").strip().lower()
            if value and value in self.digests[algorithm]:
                return True, algorithm, self.labels.get(value, "")
        return False, "", ""

    def provenance(self) -> Dict[str, Any]:
        return {
            "name": self.name, "kind": self.kind, "source": self.source,
            "description": self.description, "loaded_at": self.loaded_at,
            "entries": self.size, "algorithms": self.algorithms,
            "malformed_lines": self.malformed,
        }

    def as_dict(self) -> Dict[str, Any]:
        return self.provenance()


# ═══════════════════════════════════════════════════════════════ loaders
def load_hashset(path: Path | str, kind: str = "known-good",
                 name: str = "", description: str = "") -> HashSet:
    """Load a hash set, detecting the file format.

    Recognised: NSRL RDS CSV (``"SHA-1","MD5","CRC32","FileName",…``),
    HashKeeper CSV, plain digest-per-line, and ARGUS JSON.
    """
    path = Path(path)
    hashset = HashSet(name=name or path.stem, kind=kind, source=str(path),
                      description=description)
    if not path.exists():
        raise FileNotFoundError(f"hash set not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()

    # ---- ARGUS JSON
    if stripped.startswith("{"):
        data = json.loads(text)
        hashset.kind = data.get("kind", kind)
        hashset.description = data.get("description", hashset.description)
        hashset.source = data.get("source", hashset.source)
        for entry in data.get("entries", []):
            if isinstance(entry, str):
                hashset.add(entry)
            elif isinstance(entry, dict):
                for key in ("sha256", "sha1", "md5", "digest", "hash"):
                    if entry.get(key):
                        hashset.add(str(entry[key]),
                                    str(entry.get("label")
                                        or entry.get("name") or ""))
        return hashset

    # ---- CSV (NSRL / HashKeeper): find the digest columns by header or shape
    first_line = stripped.split("\n", 1)[0]
    looks_csv = ("," in first_line and
                 (first_line.count(",") >= 2 or '"' in first_line))
    if looks_csv:
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            return hashset
        header = [h.strip().strip('"').lower() for h in rows[0]]
        digest_columns: List[int] = []
        label_column: Optional[int] = None
        for index, column in enumerate(header):
            if column.replace("-", "").replace("_", "") in (
                    "sha1", "sha256", "md5", "hash", "digest"):
                digest_columns.append(index)
            if column in ("filename", "file_name", "name", "product",
                          "description"):
                label_column = index if label_column is None else label_column
        start = 1
        if not digest_columns:
            # No usable header — infer from the first data row's shape.
            start = 0
            for index, cell in enumerate(rows[0]):
                if _classify(cell.strip().strip('"'))[0]:
                    digest_columns.append(index)
        for row in rows[start:]:
            if not row:
                continue
            label = ""
            if label_column is not None and label_column < len(row):
                label = row[label_column].strip().strip('"')
            for index in digest_columns:
                if index < len(row):
                    hashset.add(row[index].strip().strip('"'), label)
        return hashset

    # ---- plain digest per line, optionally "<digest>  <label>"
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        hashset.add(parts[0], parts[1] if len(parts) > 1 else "")
    return hashset


def write_hashset(hashset: HashSet, path: Path | str) -> Path:
    """Write a set in ARGUS JSON form, preserving provenance."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries: List[Dict[str, str]] = []
    for algorithm, values in hashset.digests.items():
        for value in sorted(values):
            entry = {algorithm: value}
            if hashset.labels.get(value):
                entry["label"] = hashset.labels[value]
            entries.append(entry)
    path.write_text(json.dumps({
        "name": hashset.name, "kind": hashset.kind,
        "source": hashset.source, "description": hashset.description,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": entries,
    }, indent=2), encoding="utf-8")
    return path


# ═══════════════════════════════════════════════════════════════ the registry
@dataclass
class Verdict:
    """The result of screening one artifact."""

    status: str = "unknown"        # known-good | known-bad | unknown
    set_name: str = ""
    algorithm: str = ""
    label: str = ""
    reason: str = ""

    @property
    def suppress(self) -> bool:
        return self.status == "known-good"

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["suppress"] = self.suppress
        return d


class HashSetRegistry:
    """Screen artifacts against every loaded set."""

    def __init__(self):
        self.sets: List[HashSet] = []
        self.stats = {"screened": 0, "known_good": 0, "known_bad": 0,
                      "unknown": 0, "no_digest": 0}

    def add(self, hashset: HashSet) -> None:
        self.sets.append(hashset)

    def load(self, path: Path | str, kind: str = "known-good",
             name: str = "", description: str = "") -> HashSet:
        hashset = load_hashset(path, kind=kind, name=name,
                              description=description)
        self.add(hashset)
        return hashset

    def load_directory(self, directory: Path | str) -> List[HashSet]:
        """Load every set in a directory.

        Convention: a filename containing ``bad``, ``block`` or ``alert`` is
        treated as known-bad, everything else as known-good. The classification
        is reported so a mislabelled file is visible rather than silently
        inverting the filter — which would suppress exactly what should be
        flagged.
        """
        directory = Path(directory)
        loaded: List[HashSet] = []
        if not directory.exists():
            return loaded
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix.lower() not in (
                    ".txt", ".csv", ".json", ".hash", ".nsrl"):
                continue
            lowered = path.name.lower()
            kind = ("known-bad" if any(m in lowered for m in
                                       ("bad", "block", "alert", "hostile"))
                    else "known-good")
            try:
                loaded.append(self.load(path, kind=kind))
            except Exception:
                continue
        return loaded

    @property
    def empty(self) -> bool:
        return not any(s.size for s in self.sets)

    def screen(self, md5: str = "", sha1: str = "",
               sha256: str = "") -> Verdict:
        """Screen one digest. Known-bad always wins over known-good."""
        self.stats["screened"] += 1
        if not (md5 or sha1 or sha256):
            self.stats["no_digest"] += 1
            return Verdict(status="unknown",
                           reason="no digest available to screen")

        # Check bad sets first: a file that appears in both lists must be
        # flagged, never suppressed.
        for hashset in self.sets:
            if hashset.kind != "known-bad":
                continue
            hit, algorithm, label = hashset.contains(md5, sha1, sha256)
            if hit:
                self.stats["known_bad"] += 1
                return Verdict(
                    status="known-bad", set_name=hashset.name,
                    algorithm=algorithm, label=label,
                    reason=(f"{algorithm.upper()} digest matches known-bad set "
                            f"'{hashset.name}'"
                            + (f" ({label})" if label else "")))

        for hashset in self.sets:
            if hashset.kind != "known-good":
                continue
            hit, algorithm, label = hashset.contains(md5, sha1, sha256)
            if hit:
                self.stats["known_good"] += 1
                return Verdict(
                    status="known-good", set_name=hashset.name,
                    algorithm=algorithm, label=label,
                    reason=(f"{algorithm.upper()} digest matches known-good set "
                            f"'{hashset.name}' — a published, unmodified file"
                            + (f" ({label})" if label else "")))

        self.stats["unknown"] += 1
        return Verdict(status="unknown",
                       reason="not present in any loaded hash set")

    def provenance(self) -> List[Dict[str, Any]]:
        return [s.provenance() for s in self.sets]

    def summary(self) -> Dict[str, Any]:
        good = self.stats["known_good"]
        screened = max(self.stats["screened"], 1)
        return {
            "sets_loaded": len(self.sets),
            "total_entries": sum(s.size for s in self.sets),
            "provenance": self.provenance(),
            **self.stats,
            "suppression_rate": round(good / screened, 4),
            "note": ("Known-good matches are filtered from the default review "
                     "view but remain in the container and in every export. "
                     "Nothing is removed from the evidence."),
        }


# ═══════════════════════════════════════════════════════ session integration
def screen_session(session: Any, registry: HashSetRegistry
                   ) -> Dict[str, Any]:
    """Screen every stored blob in a session against the loaded sets."""
    from .models import Category

    if registry.empty:
        return {
            "performed": False,
            "reason": ("No hash sets are loaded. Load an NSRL known-good set "
                       "to suppress operating-system and application files, "
                       "and a known-bad set to flag material of interest."),
            "summary": registry.summary(),
        }

    good: List[Dict[str, Any]] = []
    bad: List[Dict[str, Any]] = []
    for loaded in session.loaded:
        exhibit = (loaded.container.extraction.get("exhibit_id")
                   or loaded.container.path.name)
        for art in loaded.db.iter_artifacts("blob_sha256 <> ''"):
            info = loaded.db.blob_info(art.blob_sha256) or {}
            verdict = registry.screen(md5=info.get("md5", ""),
                                      sha1=info.get("sha1", ""),
                                      sha256=art.blob_sha256)
            if verdict.status == "unknown":
                continue
            record = {
                "artifact_id": art.artifact_id,
                "exhibit": exhibit,
                "filename": str(art.attributes.get("filename") or art.body),
                "sha256": art.blob_sha256,
                **verdict.as_dict(),
            }
            (bad if verdict.status == "known-bad" else good).append(record)

    return {
        "performed": True,
        "known_good": good,
        "known_bad": bad,
        "known_good_count": len(good),
        "known_bad_count": len(bad),
        "summary": registry.summary(),
    }


def hashset_findings(result: Dict[str, Any]) -> List[Any]:
    """Findings from hash-set screening."""
    from ..intel.findings import Finding

    out: List[Finding] = []
    if not result.get("performed"):
        return out

    bad = result.get("known_bad") or []
    if bad:
        sets = sorted({b["set_name"] for b in bad})
        out.append(Finding(
            rule_id="hashset.known_bad",
            title=f"{len(bad)} file(s) match a known-bad hash set",
            detail=("These files' digests appear in curated sets of material of "
                    "interest ("
                    + ", ".join(sets) + "): "
                    + "; ".join(f"{b['filename']}"
                                + (f" [{b['label']}]" if b["label"] else "")
                                for b in bad[:8])),
            severity="critical", confidence=0.9, category="hashset",
            artifact_ids=[b["artifact_id"] for b in bad],
            evidence=[f"{b['filename']} — {b['reason']}" for b in bad[:6]],
            metrics={"count": len(bad), "sets": sets, "detail": bad[:30]},
            why_it_matters=("A digest match against a curated set is an exact "
                            "identification of the file, independent of its "
                            "name or location on the device."),
            caveat=("The strength of this finding rests entirely on the "
                    "provenance of the set. Check where the set came from and "
                    "when it was compiled before relying on a hit — an "
                    "unattributed list proves nothing."),
        ))

    good = result.get("known_good") or []
    if good:
        out.append(Finding(
            rule_id="hashset.known_good",
            title=f"{len(good)} file(s) identified as known system content",
            detail=(f"{len(good)} files matched a published known-good set and "
                    f"are filtered from the default review view. They remain in "
                    f"the container and in every export."),
            severity="info", confidence=0.9, category="hashset",
            artifact_ids=[g["artifact_id"] for g in good][:300],
            metrics={"count": len(good),
                     "suppression_rate": result["summary"]["suppression_rate"],
                     "sets": sorted({g["set_name"] for g in good})},
            why_it_matters=("Reduces review volume so attention goes to files "
                            "that are not accounted for. A system file that had "
                            "been modified would *not* match, and so would not "
                            "be suppressed."),
            caveat=("Suppression is a review convenience, not a judgement that "
                    "a file is irrelevant. A known-good file at an unexpected "
                    "path may still matter."),
        ))
    return out
