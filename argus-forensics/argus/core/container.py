"""The ARGUS Forensic Container (``.afc``).

This is the ARGUS equivalent of the ``.xry`` file: one self-describing unit
holding an extraction's raw bytes, its decoded artifacts, and its provenance.

Layout (a directory, so multi-gigabyte extractions do not require repacking)::

    EXH-001_20260729T110402.afc/
        manifest.json          container metadata + seal
        artifacts.db           SQLite artifact store (see argus.core.db)
        audit.jsonl            hash-chained custody log for this extraction
        extraction.log.jsonl   live acquisition log (module/status/ts/message)
        blobs/ab/cd/<sha256>   content-addressed blob store
        raw/                   verbatim copies of pulled source files

Content addressing means the same photo appearing in three application caches
is stored once, and any blob can be verified independently by re-hashing its
own filename.  ``seal()`` freezes the container: it computes a Merkle root over
every blob plus the artifact DB, writes it into the manifest, and marks the
container read-only.  ``verify()`` re-derives that root.
"""

from __future__ import annotations

import concurrent.futures
import json
import mimetypes
import os
import shutil
import stat
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .audit import AuditLog
from .db import ArtifactDB
from .errors import ContainerError, IntegrityError, WriteBlockViolation
from .hashing import Digest, hash_bytes, hash_file, merkle_root

CONTAINER_VERSION = "1.2"
MANIFEST_NAME = "manifest.json"
CONTAINER_ZIP_MARKER = "argus-container/1"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_argus_container_dir(path: Path) -> bool:
    return path.is_dir() and (path / MANIFEST_NAME).is_file()


def zip_contains_manifest(path: Path) -> bool:
    """True when a ZIP holds an ARGUS container (manifest.json at root or below)."""
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                norm = name.replace("\\", "/").lstrip("./")
                if norm == MANIFEST_NAME or norm.endswith(f"/{MANIFEST_NAME}"):
                    return True
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def is_argus_container_archive(path: Path | str) -> bool:
    """An on-disk ``.afc`` folder or a portable ``.afc.zip`` export."""
    p = Path(path).expanduser()
    if is_argus_container_dir(p):
        return True
    return p.is_file() and p.suffix.lower() == ".zip" and zip_contains_manifest(p)


def default_zip_path(container_dir: Path) -> Path:
    """Portable ZIP path for a container folder — ``name.afc.zip``."""
    name = container_dir.name
    if name.endswith(".afc"):
        return container_dir.parent / f"{name}.zip"
    return container_dir.parent / f"{name}.afc.zip"


def resolve_container_path(path: Path | str,
                           cache_root: Optional[Path] = None) -> Path:
    """Return a directory path that :class:`EvidenceContainer` can open.

    ``.afc`` folders are returned as-is. Portable ``.afc.zip`` archives are
    extracted once into ``cache_root`` and reused on subsequent opens.
    """
    p = Path(path).expanduser()
    try:
        p = p.resolve()
    except OSError:
        pass
    if is_argus_container_dir(p):
        return p
    if p.is_file() and p.suffix.lower() == ".zip" and zip_contains_manifest(p):
        digest = hash_file(p).sha256[:16]
        base = cache_root or (p.parent / ".argus-cache")
        cache_dir = base / f"{p.stem}-{digest}"
        if is_argus_container_dir(cache_dir):
            return cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(p) as zf:
            zf.extractall(cache_dir)
        if is_argus_container_dir(cache_dir):
            return cache_dir
        # Some exports nest everything under a single top-level ``.afc`` folder.
        for child in cache_dir.iterdir():
            if child.is_dir() and is_argus_container_dir(child):
                return child
        raise ContainerError(
            f"{p.name} does not contain a valid ARGUS container "
            f"(manifest.json not found after extraction)")
    raise ContainerError(f"not an ARGUS container: {p}")


def import_container_archive(case: "Case", exhibit_id: str,
                             archive: Path | str) -> Path:
    """Copy a portable ``.afc`` folder or ``.afc.zip`` into a case exhibit."""
    from .case import safe_id

    src = Path(archive).expanduser()
    if not is_argus_container_archive(src):
        raise ContainerError(f"not an ARGUS container archive: {src}")
    eid = safe_id(exhibit_id)
    if eid not in case.data["exhibits"]:
        raise ContainerError(f"exhibit {eid} is not registered; add it first")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="argus-import-") as tmp:
        resolved = resolve_container_path(src, Path(tmp))
        dest_name = resolved.name
        if not dest_name.endswith(".afc"):
            stem = src.stem
            dest_name = stem if stem.endswith(".afc") else f"{stem}.afc"
        dest = case.exhibit_dir(eid) / dest_name
        counter = 2
        while dest.exists():
            base = dest_name[:-4] if dest_name.endswith(".afc") else dest_name
            dest = case.exhibit_dir(eid) / f"{base}-{counter}.afc"
            counter += 1
        shutil.copytree(resolved, dest)
    case.audit.record("extraction.import", {
        "exhibit_id": eid,
        "container": dest.name,
        "source": str(src),
    })
    return dest


@dataclass
class ExtractionMeta:
    """The header block an examiner reads before touching any data."""

    case_id: str = ""
    exhibit_id: str = ""
    operator: str = ""
    method: str = ""                 # logical | filesystem | backup | import
    device_make: str = ""
    device_model: str = ""
    device_os: str = ""
    device_serial: str = ""
    imei: str = ""
    iccid: str = ""
    phone_number: str = ""
    lock_state: str = ""
    time_span: str = "all"
    categories: List[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    tool: str = "ARGUS Forensics"
    tool_version: str = ""
    # Where the evidence came from when it was not acquired by ARGUS. Recorded
    # because an examiner must be able to see which tool produced the source.
    source_format: str = ""
    import_adapter: str = ""
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceContainer:
    """Create, open, seal and verify an ``.afc`` container."""

    def __init__(self, path: Path | str, mode: str = "r",
                 meta: Optional[ExtractionMeta] = None,
                 actor: str = ""):
        self.path = Path(path)
        self.mode = mode
        if mode not in ("r", "w", "a"):
            raise ContainerError(f"invalid mode {mode!r}; use 'r', 'w' or 'a'")

        if mode == "w":
            if self.path.exists():
                raise ContainerError(f"container already exists: {self.path}")
            self._scaffold()
            self.manifest: Dict[str, Any] = {
                "container_version": CONTAINER_VERSION,
                "created_at": _utc(),
                "sealed": False,
                "seal": {},
                "extraction": (meta or ExtractionMeta()).as_dict(),
                "statistics": {},
            }
            self._write_manifest()
        else:
            if not (self.path / MANIFEST_NAME).exists():
                raise ContainerError(f"not an ARGUS container: {self.path}")
            self.manifest = json.loads(
                (self.path / MANIFEST_NAME).read_text(encoding="utf-8"))
            if mode == "a" and self.manifest.get("sealed"):
                raise ContainerError(
                    "container is sealed; open read-only or clone it first")

        self.audit = AuditLog(self.path / "audit.jsonl", actor=actor or None)
        self.db = ArtifactDB(self.path / "artifacts.db",
                             read_only=(mode == "r"))
        self._log_path = self.path / "extraction.log.jsonl"
        if mode == "w":
            self.audit.record("container.create", {
                "path": str(self.path),
                "case_id": self.extraction.get("case_id"),
                "exhibit_id": self.extraction.get("exhibit_id"),
            })

    # --------------------------------------------------------------- scaffold
    def _scaffold(self) -> None:
        for sub in ("blobs", "raw"):
            (self.path / sub).mkdir(parents=True, exist_ok=True)

    def _write_manifest(self) -> None:
        (self.path / MANIFEST_NAME).write_text(
            json.dumps(self.manifest, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8")

    # ------------------------------------------------------------- properties
    @property
    def extraction(self) -> Dict[str, Any]:
        return self.manifest.setdefault("extraction", {})

    @property
    def sealed(self) -> bool:
        return bool(self.manifest.get("sealed"))

    def update_extraction(self, **kwargs: Any) -> None:
        self._assert_writable()
        self.extraction.update({k: v for k, v in kwargs.items() if v is not None})
        self._write_manifest()

    def _assert_writable(self) -> None:
        if self.mode == "r":
            raise WriteBlockViolation(
                f"container {self.path.name} is open read-only")
        if self.sealed:
            raise WriteBlockViolation(
                f"container {self.path.name} is sealed and cannot be modified")

    # ------------------------------------------------------------ blob store
    def _blob_path(self, sha256: str) -> Path:
        return self.path / "blobs" / sha256[:2] / sha256[2:4] / sha256

    def store_blob(self, data: bytes, orig_path: str = "",
                   mime: str = "") -> Digest:
        """Store raw bytes content-addressed. Idempotent."""
        self._assert_writable()
        dig = hash_bytes(data)
        dest = self._blob_path(dig.sha256)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(".partial")
            tmp.write_bytes(data)
            tmp.replace(dest)
            os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        self.db.register_blob(
            dig.sha256, dig.size, dig.md5, dig.sha1,
            mime or mimetypes.guess_type(orig_path or "")[0] or
            "application/octet-stream",
            orig_path)
        return dig

    def store_file(self, src: Path | str, orig_path: str = "") -> Digest:
        """Copy a file into the blob store without ever writing to the source."""
        self._assert_writable()
        src = Path(src)
        dig = hash_file(src)
        dest = self._blob_path(dig.sha256)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(".partial")
            shutil.copyfile(src, tmp)        # copyfile: never copies over source
            tmp.replace(dest)
            os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            verify = hash_file(dest)
            if not verify.matches(dig):
                dest.unlink(missing_ok=True)
                raise IntegrityError(
                    f"copy of {src} did not verify (source {dig.sha256[:12]}… "
                    f"vs copy {verify.sha256[:12]}…)")
        self.db.register_blob(
            dig.sha256, dig.size, dig.md5, dig.sha1,
            mimetypes.guess_type(str(src))[0] or "application/octet-stream",
            orig_path or str(src))
        return dig

    def open_blob(self, sha256: str) -> bytes:
        p = self._blob_path(sha256)
        if not p.exists():
            raise ContainerError(f"blob {sha256[:16]}… not present in container")
        return p.read_bytes()

    def blob_file(self, sha256: str) -> Path:
        p = self._blob_path(sha256)
        if not p.exists():
            raise ContainerError(f"blob {sha256[:16]}… not present in container")
        return p

    def has_blob(self, sha256: str) -> bool:
        return self._blob_path(sha256).exists()

    def iter_blobs(self) -> Iterable[Path]:
        root = self.path / "blobs"
        if root.exists():
            for p in root.rglob("*"):
                if p.is_file() and not p.name.endswith(".partial"):
                    yield p

    # -------------------------------------------------------- extraction log
    def log(self, module: str, status: str, message: str,
            level: str = "info", **extra: Any) -> Dict[str, Any]:
        """Append to the live extraction log (Fig. 5.10 equivalent)."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "module": module, "status": status, "level": level,
            "message": message, **extra,
        }
        if self.mode != "r":
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def log_entries(self) -> List[Dict[str, Any]]:
        if not self._log_path.exists():
            return []
        out = []
        for line in self._log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    # -------------------------------------------------------------- statistics
    def refresh_statistics(self) -> Dict[str, Any]:
        lo, hi = self.db.time_bounds()
        stats = {
            "artifacts": self.db.count(),
            "categories": self.db.category_counts(),
            "applications": self.db.app_counts(),
            "recovery": self.db.recovery_counts(),
            "blobs": len(self.db.all_blob_hashes()),
            "sources": len(self.db.sources()),
            "first_timestamp": lo,
            "last_timestamp": hi,
        }
        if self.mode != "r" and not self.sealed:
            self.manifest["statistics"] = stats
            self._write_manifest()
        return stats

    # ------------------------------------------------------------------- seal
    def _quiesce_db(self, *, fast: bool = False) -> None:
        """Checkpoint, compact and close the artifact DB, then reopen read-only.

        This has to happen *before* the database is hashed. SQLite in WAL mode
        writes to the main database file when the last connection closes, so a
        digest taken while a writable connection is still open would be
        invalidated by the act of closing it — the container would fail its own
        verification the moment it was put away.
        """
        if self.mode == "r":
            return
        if not fast:
            self.db.optimise()
        self.db.close()
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path / "artifacts.db") + suffix)
            sidecar.unlink(missing_ok=True)
        self.db = ArtifactDB(self.path / "artifacts.db", read_only=True)

    def seal(self, *, fast: bool = False) -> Dict[str, Any]:
        """Freeze the container and compute its cryptographic seal."""
        self._assert_writable()
        self.refresh_statistics()
        self._quiesce_db(fast=fast)

        blob_hashes = [p.name for p in self.iter_blobs()]
        db_digest = hash_file(self.path / "artifacts.db")

        # Record the custody entry *before* capturing the audit tip, so the
        # sealed tip is the true final state of the log. Capturing first and
        # writing after would leave every sealed container reporting that its
        # own log had grown since sealing.
        self.audit.record("container.seal", {
            "blobs": len(blob_hashes),
            "artifacts_db_sha256": db_digest.sha256[:32],
        })
        audit_ok, audit_problems = self.audit.verify()

        seal = {
            "sealed_at": _utc(),
            "blob_count": len(blob_hashes),
            "blob_merkle_root": merkle_root(blob_hashes),
            "artifacts_db_sha256": db_digest.sha256,
            "artifacts_db_size": db_digest.size,
            "audit_tip": self.audit.tip,
            "audit_entries": len(self.audit),
            "audit_chain_valid": audit_ok,
            "audit_problems": audit_problems,
        }
        seal["container_seal"] = hash_bytes(
            json.dumps(seal, sort_keys=True, separators=(",", ":")).encode()
        ).sha256
        self.manifest["seal"] = seal
        self.manifest["sealed"] = True
        self.manifest["sealed_at"] = seal["sealed_at"]
        self._write_manifest()
        self.mode = "r"
        return seal

    def verify(self, deep: bool = True) -> Dict[str, Any]:
        """Re-verify the container. ``deep`` re-hashes every blob."""
        problems: List[str] = []
        seal = self.manifest.get("seal") or {}

        audit_ok, audit_problems = self.audit.verify()
        problems.extend(f"audit: {p}" for p in audit_problems)
        if seal.get("audit_tip") and seal["audit_tip"] != self.audit.tip:
            problems.append("audit: log has grown since the container was sealed")

        # Collect all blob paths once — avoids re-iterating the filesystem.
        blob_paths: List[Path] = list(self.iter_blobs())
        blob_hashes: List[str] = [p.name for p in blob_paths]
        bad_blobs: List[str] = []

        if deep and blob_paths:
            # Parallel deep hashing — ThreadPool for IO-bound, ProcessPool as
            # secondary attempt, sequential as final fallback. Guarantees
            # verification never fails due to executor unavailability.
            try:
                max_workers = min(32, (os.cpu_count() or 4) * 2, len(blob_paths))
                if max_workers > 1 and len(blob_paths) > 1:
                    # Primary: ThreadPoolExecutor (optimal for file IO, GIL released)
                    try:
                        with concurrent.futures.ThreadPoolExecutor(
                            max_workers=max_workers
                        ) as executor:
                            future_to_path = {
                                executor.submit(hash_file, p): p for p in blob_paths
                            }
                            for future in concurrent.futures.as_completed(
                                future_to_path
                            ):
                                p = future_to_path[future]
                                try:
                                    actual = future.result().sha256
                                except Exception as exc:
                                    bad_blobs.append(
                                        f"{p.name[:16]}… hash failed: {exc}"
                                    )
                                    continue
                                if actual != p.name:
                                    bad_blobs.append(
                                        f"{p.name[:16]}… actual {actual[:16]}…"
                                    )
                    except Exception:
                        # Secondary: ProcessPoolExecutor (CPU-bound fallback)
                        try:
                            with concurrent.futures.ProcessPoolExecutor(
                                max_workers=max_workers
                            ) as executor:
                                future_to_path = {
                                    executor.submit(hash_file, p): p
                                    for p in blob_paths
                                }
                                bad_blobs.clear()
                                for future in concurrent.futures.as_completed(
                                    future_to_path
                                ):
                                    p = future_to_path[future]
                                    try:
                                        actual = future.result().sha256
                                    except Exception as exc:
                                        bad_blobs.append(
                                            f"{p.name[:16]}… hash failed: {exc}"
                                        )
                                        continue
                                    if actual != p.name:
                                        bad_blobs.append(
                                            f"{p.name[:16]}… actual {actual[:16]}…"
                                        )
                        except Exception:
                            raise  # trigger outer sequential fallback
                else:
                    # Single file or single worker — no parallelism overhead
                    for p in blob_paths:
                        actual = hash_file(p).sha256
                        if actual != p.name:
                            bad_blobs.append(
                                f"{p.name[:16]}… actual {actual[:16]}…"
                            )
            except Exception:
                # Ultimate fallback: sequential hashing guarantees correctness
                bad_blobs.clear()
                for p in blob_paths:
                    try:
                        actual = hash_file(p).sha256
                    except Exception as exc:
                        bad_blobs.append(f"{p.name[:16]}… hash failed: {exc}")
                        continue
                    if actual != p.name:
                        bad_blobs.append(f"{p.name[:16]}… actual {actual[:16]}…")
        problems.extend(f"blob content mismatch: {b}" for b in bad_blobs)

        if seal.get("blob_merkle_root"):
            # Sort blob_hashes before merkle_root for deterministic verification
            # regardless of filesystem iteration order (rglob is not guaranteed
            # sorted). merkle_root also sorts internally, but explicit sort here
            # ensures the local list is canonical before comparison.
            blob_hashes_sorted = sorted(blob_hashes)
            root = merkle_root(blob_hashes_sorted)
            if root != seal["blob_merkle_root"]:
                problems.append(
                    f"blob set changed since sealing (root {root[:16]}… != "
                    f"{seal['blob_merkle_root'][:16]}…)")

        if seal.get("artifacts_db_sha256"):
            db_now = hash_file(self.path / "artifacts.db").sha256
            if db_now != seal["artifacts_db_sha256"]:
                problems.append("artifacts.db has been modified since sealing")

        missing = [h for h in self.db.all_blob_hashes() if not self.has_blob(h)]
        problems.extend(f"registered blob missing from store: {h[:16]}…"
                        for h in missing)

        return {
            "container": str(self.path),
            "sealed": self.sealed,
            "verified_at": _utc(),
            "deep": deep,
            "blobs_checked": len(blob_hashes),
            "audit_entries": len(self.audit),
            "audit_chain_valid": audit_ok,
            "ok": not problems,
            "problems": problems,
        }

    # ------------------------------------------------------------------ export
    def export_zip(self, dest: Path | str) -> Path:
        """Produce a single-file portable copy of the container."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED,
                             compresslevel=6) as zf:
            zf.writestr(
                "argus-container.txt",
                f"{CONTAINER_ZIP_MARKER}\n{self.path.name}\n",
            )
            for p in sorted(self.path.rglob("*")):
                if p.is_file() and not p.name.endswith(("-wal", "-shm", ".partial")):
                    zf.write(p, p.relative_to(self.path).as_posix())
        return dest

    # ------------------------------------------------------------------- misc
    def close(self) -> None:
        try:
            self.db.close()
        finally:
            pass

    def __enter__(self) -> "EvidenceContainer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:                                # pragma: no cover
        return (f"<EvidenceContainer {self.path.name} "
                f"mode={self.mode} sealed={self.sealed}>")
