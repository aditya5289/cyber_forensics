"""Verify the tool itself before it is used on evidence.

An examiner will be asked, under cross-examination, which version of which tool
produced an exhibit and how they know it had not been altered. "It said 1.0 in
the corner" is not an answer. Validation is performed against a specific build,
so the build has to be identifiable and its integrity checkable — otherwise the
validation certificate describes software that may no longer be what is
installed.

This module gives three things:

* ``build_manifest`` — a content hash of every shipped source file.
* ``verify_installation`` — compares the installed tree against the manifest
  recorded at release, and names every file that differs.
* ``installation_id`` — a short, stable digest of the whole tree, suitable for
  printing on a report so the build is identified in one line.

The manifest deliberately covers source, templates and data files, and
deliberately excludes caches, evidence and anything the examiner creates. A
manifest that flagged the examiner's own case folder would be noise, and noise
gets ignored — which is how a genuine mismatch gets missed.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_ROOT.parent
MANIFEST_PATH = PACKAGE_ROOT / "MANIFEST.json"

# What counts as "the tool". Everything else is either generated or belongs to
# the examiner.
INCLUDE_SUFFIXES = {".py", ".html", ".json", ".css", ".js"}
EXCLUDE_PARTS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache",
                 "node_modules", ".venv", "venv"}
EXCLUDE_NAMES = {"MANIFEST.json"}


def _iter_source_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_PARTS for part in path.parts):
            continue
        if path.name in EXCLUDE_NAMES:
            continue
        if path.suffix.lower() not in INCLUDE_SUFFIXES:
            continue
        out.append(path)
    return out


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 18), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Optional[Path] = None) -> Dict[str, Any]:
    """Hash every shipped file. Paths are recorded relative and POSIX-style so
    a manifest built on one platform verifies on another."""
    root = Path(root or PACKAGE_ROOT)
    files: Dict[str, str] = {}
    source_files = _iter_source_files(root)

    # Parallel hashing with ThreadPoolExecutor — IO-bound, GIL released in
    # hashlib / file I/O. Fallback to sequential on any executor failure.
    if source_files:
        try:
            max_workers = min(32, (os.cpu_count() or 4) * 2, len(source_files))
            # ThreadPoolExecutor is optimal for IO-bound hashing; bounded
            # workers avoid thread explosion on large trees.
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_path = {
                    executor.submit(_digest, path): path for path in source_files
                }
                for future in concurrent.futures.as_completed(future_to_path):
                    path = future_to_path[future]
                    rel = path.relative_to(root).as_posix()
                    files[rel] = future.result()
        except Exception:
            # Fallback: sequential hashing guarantees correctness even if
            # threading is unavailable or filesystem is unstable.
            files.clear()
            for path in source_files:
                files[path.relative_to(root).as_posix()] = _digest(path)
    # A single digest over the sorted (path, hash) pairs identifies the build.
    roll = hashlib.sha256()
    for name in sorted(files):
        roll.update(name.encode("utf-8"))
        roll.update(files[name].encode("ascii"))

    return {
        "format": "argus-manifest/1",
        "version": __version__,
        "file_count": len(files),
        "installation_id": roll.hexdigest(),
        "files": files,
        "note": ("Content hashes of every shipped source file. Generated at "
                 "release by tools/build_release.py. Verify with "
                 "`argus selfcheck`."),
    }


@dataclass
class VerificationResult:
    """The outcome of comparing an installation against its manifest."""

    ok: bool = True
    manifest_present: bool = True
    expected_id: str = ""
    actual_id: str = ""
    version: str = ""
    modified: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)
    checked: int = 0
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "manifest_present": self.manifest_present,
            "expected_installation_id": self.expected_id,
            "actual_installation_id": self.actual_id,
            "version": self.version,
            "files_checked": self.checked,
            "modified": self.modified,
            "missing": self.missing,
            "unexpected": self.unexpected,
            "note": self.note,
        }

    def summary(self) -> str:
        if not self.manifest_present:
            return ("No manifest is present, so this installation cannot be "
                    "verified. It was not produced by a release build.")
        if self.ok:
            return (f"Installation verified. {self.checked} files match the "
                    f"manifest for version {self.version} "
                    f"(build {self.actual_id[:16]}).")
        bits = []
        if self.modified:
            bits.append(f"{len(self.modified)} modified")
        if self.missing:
            bits.append(f"{len(self.missing)} missing")
        if self.unexpected:
            bits.append(f"{len(self.unexpected)} unexpected")
        return ("Installation does NOT match its manifest: "
                + ", ".join(bits) + ".")


@lru_cache(maxsize=32)
def verify_installation(root: Optional[Path] = None,
                        manifest_path: Optional[Path] = None
                        ) -> VerificationResult:
    """Compare the installed tree against the manifest recorded at release.

    Cached via ``lru_cache`` — repeated calls (e.g. report() → verify →
    installation_id) avoid re-hashing the entire tree. Cache key is
    (root, manifest_path); mutate the tree and call ``verify_installation.cache_clear()``.
    """
    root = Path(root or PACKAGE_ROOT)
    manifest_path = Path(manifest_path or (root / "MANIFEST.json"))

    if not manifest_path.exists():
        current = build_manifest(root)
        return VerificationResult(
            ok=False, manifest_present=False,
            actual_id=current["installation_id"],
            version=__version__, checked=current["file_count"],
            note=("This is a source checkout or an unpackaged copy. Run "
                  "`python tools/build_release.py` to produce a manifest, or "
                  "install from a release archive. Until then the build cannot "
                  "be identified on a report."))

    try:
        recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return VerificationResult(
            ok=False, manifest_present=False, version=__version__,
            note=f"Manifest could not be read: {exc}")

    expected: Dict[str, str] = recorded.get("files", {})
    current = build_manifest(root)
    actual: Dict[str, str] = current["files"]

    modified = sorted(name for name in expected
                      if name in actual and actual[name] != expected[name])
    missing = sorted(name for name in expected if name not in actual)
    unexpected = sorted(name for name in actual if name not in expected)

    result = VerificationResult(
        ok=not (modified or missing),
        expected_id=recorded.get("installation_id", ""),
        actual_id=current["installation_id"],
        version=recorded.get("version", __version__),
        modified=modified, missing=missing, unexpected=unexpected,
        checked=len(expected),
    )
    if modified or missing:
        result.note = (
            "Do not use this installation for casework until the discrepancy "
            "is explained. A validation certificate describes a specific "
            "build; if the files differ, the certificate no longer describes "
            "what is installed.")
    elif unexpected:
        # Extra files do not invalidate the build, but they are worth naming:
        # a stray module on the path can shadow a real one.
        result.note = (
            "Files are present that were not part of the release. This does "
            "not alter the verified files, but a module added to the package "
            "directory can shadow a released one — confirm they are intended.")
    return result


def installation_id(root: Optional[Path] = None) -> str:
    """Short digest identifying this build, for printing on reports."""
    return build_manifest(root)["installation_id"]


def optional_features() -> Dict[str, Dict[str, Any]]:
    """Which optional capabilities are available in this environment.

    Every one of these degrades rather than fails, so an air-gapped install
    with none of them still works — but an examiner needs to know which parts
    of the tool are inert before they conclude a device held no images.
    """
    checks: List[Tuple[str, str, str, str]] = [
        ("Pillow", "PIL", "Image decoding",
         "EXIF, GPS and perceptual image matching are unavailable; media is "
         "still hashed and catalogued, but not decoded or compared."),
        ("adb", "", "Live Android acquisition",
         "Import of an existing extraction still works."),
        ("libimobiledevice", "", "Live iOS acquisition",
         "Import of an existing iTunes backup still works."),
    ]
    out: Dict[str, Dict[str, Any]] = {}
    for label, module, provides, consequence in checks:
        available = False
        detail = ""
        if module:
            try:
                mod = __import__(module)
                available = True
                detail = getattr(mod, "__version__", "")
            except ImportError:
                available = False
        else:
            import shutil as _shutil
            binary = "adb" if label == "adb" else "idevicebackup2"
            found = _shutil.which(binary)
            available = bool(found)
            detail = found or ""
        out[label] = {"available": available, "detail": detail,
                      "provides": provides,
                      "consequence_if_absent": consequence}
    return out


def report(root: Optional[Path] = None) -> Dict[str, Any]:
    """Everything an examiner should record about the tool they used."""
    verification = verify_installation(root)
    return {
        "product": "ARGUS Forensics",
        "version": __version__,
        "installation_id": verification.actual_id,
        "verification": verification.as_dict(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "optional_features": optional_features(),
        "note": ("Record the version and installation ID in the case notes. "
                 "They identify exactly which build produced the exhibit, "
                 "which is what a validation certificate is issued against."),
    }
