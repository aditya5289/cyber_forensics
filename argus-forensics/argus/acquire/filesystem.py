"""Evidence tree ingestion — walk acquired bytes and decode them.

This is the bridge between "we have files" and "we have artifacts".  It walks
the acquired tree once, hands every file to the parser registry, records what
each source contributed, and writes the results into the container.

Two behaviours worth calling out:

* **Nothing is skipped silently.** Files that no parser claims are still
  counted and, if they are of evidential interest (media, documents,
  databases), still recorded.  A file that is genuinely uninteresting is
  logged as such rather than vanishing.
* **One bad file never stops the run.** Parsers are already isolated in
  :func:`argus.parsers.registry.dispatch`; this layer additionally guards
  against unreadable paths, permission errors, symlink loops and files that
  grow or vanish mid-walk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..core.container import EvidenceContainer
from ..core.hashing import hash_file
from ..core.models import Artifact
from ..parsers.registry import ParseContext, dispatch, parsers_for

# Files that are pure noise in every extraction
NOISE_NAMES = {".ds_store", "thumbs.db", ".nomedia", "desktop.ini"}
NOISE_SUFFIXES = {".lock", ".tmp", ".pid", ".shm"}

# Directories that contain nothing of evidential value but millions of entries
NOISE_DIRS = {"cache/webviewcachechromium", "code_cache", "lib", "oat",
              "app_webview/gpucache", "app_textures"}

BATCH = 500


def _ingest_batch_size(batch_size: Optional[int] = None) -> int:
    return batch_size if batch_size is not None else BATCH


@dataclass
class IngestResult:
    artifacts: List[Artifact] = field(default_factory=list)
    files_seen: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    bytes_seen: int = 0
    deleted_recovered: int = 0
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    by_parser: Dict[str, int] = field(default_factory=dict)


def _dispatch_by_content(path: Path, ctx: ParseContext,
                         warnings: Optional[List[str]] = None):
    """Parse a file whose extension does not match its content.

    Returns a ``ParseResult`` if the bytes turned out to be something worth
    parsing, otherwise ``None``.  Concealment by renaming is common enough
    that treating the extension as authoritative is a real evidential gap,
    not a theoretical one.
    """
    from ..parsers.media.exif import sniff, parse as parse_media
    from ..parsers.android.apps import parse_generic_app_db

    mime, desc = sniff(path)
    if not mime:
        return None
    try:
        if mime == "application/x-sqlite3":
            parsed = parse_generic_app_db(path, ctx)
            parsed.parser = "app.generic (content-identified)"
        elif mime.startswith(("image/", "video/", "audio/")) or \
                mime == "application/pdf":
            parsed = parse_media(path, ctx)
            parsed.parser = "media.files (content-identified)"
        else:
            return None
    except Exception as exc:
        # Collected rather than written to shared state: this runs on a worker
        # thread, and the caller folds warnings in deterministically.
        if warnings is not None:
            warnings.append(
                f"{ctx.rel(path)}: content-identified as {mime} but parsing "
                f"failed ({exc})")
        return None

    if parsed.artifacts:
        for art in parsed.artifacts:
            art.attributes.setdefault("extension_mismatch", True)
            art.attributes["identified_by"] = "magic bytes"
            art.attributes.setdefault(
                "mismatch_note",
                f"Extension '{path.suffix or '(none)'}' does not match the "
                f"file's actual content ({mime}, {desc}). Files are renamed "
                f"like this to hide them from tools that trust extensions.")
        parsed.notes.append(
            f"{ctx.rel(path)}: identified as {desc} by content, not by "
            f"extension '{path.suffix or '(none)'}'")
        ctx.emit("ingest", "warning",
                 f"{path.name}: extension/content mismatch — actually {desc}",
                 level="warning")
    return parsed


def _is_noise(path: Path, root: Path) -> bool:
    name = path.name.lower()
    if name in NOISE_NAMES or path.suffix.lower() in NOISE_SUFFIXES:
        return True
    try:
        rel = path.relative_to(root).as_posix().lower()
    except ValueError:
        return False
    return any(f"/{d}/" in f"/{rel}" for d in NOISE_DIRS)


def walk_evidence(root: Path, follow_symlinks: bool = False) -> List[Path]:
    """Enumerate regular files under ``root``, resistant to symlink loops."""
    out: List[Path] = []
    seen_dirs: Set[tuple] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        d = Path(dirpath)
        try:
            st = d.stat()
            key = (st.st_dev, st.st_ino)
            if key in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(key)
        except OSError:
            continue
        for fn in filenames:
            p = d / fn
            try:
                if p.is_file() and not p.is_symlink():
                    out.append(p)
            except OSError:
                continue
    return out


def _default_workers() -> int:
    """How many files to parse at once.

    Parsing is dominated by SQLite page decoding, hashing and image work, all of
    which spend their time in C extensions that release the GIL, so threads give
    real parallelism here without the pickling constraints a process pool would
    impose on parser results and context callbacks.

    Capped rather than set to the core count: an examiner's workstation is
    usually doing something else too, and the disk becomes the limit well before
    the CPU does.
    """
    return max(1, min(24, (os.cpu_count() or 2) * 2))


def _examine(path: Path, ctx: ParseContext) -> Dict[str, Any]:
    """Parse one file. Pure with respect to shared state, so it is safe to run
    concurrently — everything it learns is returned, nothing is accumulated."""
    out: Dict[str, Any] = {"path": path, "size": 0, "parsed": None,
                           "skipped": False, "error": "", "warnings": []}
    try:
        out["size"] = path.stat().st_size
    except OSError as exc:
        out["error"] = f"{path.name}: {exc}"
        return out

    parsed = None
    if not parsers_for(path, ctx.platform):
        if ctx.skip_content_sniff:
            out["skipped"] = True
            return out
        # No parser claims this filename. Before discarding it, look at the
        # bytes: a JPEG renamed 'invoice.txt' or a database renamed '.dat'
        # is exactly the material an extension-trusting tool misses, and
        # it is renamed for a reason.
        parsed = _dispatch_by_content(path, ctx, out["warnings"])
        if parsed is None:
            out["skipped"] = True
            return out
    else:
        parsed = dispatch(path, ctx)

    out["parsed"] = parsed
    if parsed.artifacts and not ctx.skip_file_hash:
        try:
            out["sha256"] = hash_file(path).sha256
        except OSError:
            out["sha256"] = ""
    return out


def ingest_tree(root: Path, ctx: ParseContext,
                container: Optional[EvidenceContainer] = None,
                progress_every: int = 500,
                workers: Optional[int] = None,
                batch_size: Optional[int] = None,
                skip_sources: Optional[Set[str]] = None) -> IngestResult:
    """Parse every file under ``root`` and write artifacts into ``container``.

    Files are examined concurrently but reduced **in walk order**. Two runs over
    the same evidence must produce byte-identical output — an artifact ordering
    that varies with thread scheduling would make the container hash
    irreproducible, and a report that cannot be reproduced cannot be defended.
    """
    result = IngestResult()
    root = Path(root)
    if not root.exists():
        result.warnings.append(f"evidence root does not exist: {root}")
        return result

    files = walk_evidence(root)
    result.files_seen = len(files)
    candidates = [p for p in files if not _is_noise(p, root)]
    if skip_sources:
        candidates = [p for p in candidates if ctx.rel(p) not in skip_sources]
    result.files_skipped += len(files) - len(candidates)
    ctx.emit("ingest", "start", f"Scanning {len(files)} files under {root.name}",
             phase="decode", progress_current=0,
             progress_total=len(candidates) or 1, progress_pct=0)

    pending: List[Artifact] = []
    source_stats: Dict[str, Dict[str, object]] = {}
    worker_count = workers if workers is not None else _default_workers()
    worker_count = max(1, min(worker_count, len(candidates) or 1))
    db_batch = _ingest_batch_size(batch_size)

    def reduce_one(index: int, outcome: Dict[str, Any]) -> None:
        """Fold one file's findings into the result. Single-threaded."""
        nonlocal pending
        result.bytes_seen += outcome["size"]
        result.warnings.extend(outcome.get("warnings") or [])
        if outcome["error"]:
            result.warnings.append(outcome["error"])
            return
        if outcome["skipped"] or outcome["parsed"] is None:
            result.files_skipped += 1
            return

        parsed = outcome["parsed"]
        path = outcome["path"]
        if parsed.artifacts:
            result.files_parsed += 1
            result.deleted_recovered += parsed.deleted_recovered
            pending.extend(parsed.artifacts)
            name = parsed.parser or "multiple"
            source_stats[ctx.rel(path)] = {
                "sha256": outcome.get("sha256", ""), "size": outcome["size"],
                "parser": name, "count": len(parsed.artifacts),
                "notes": "; ".join(parsed.notes)[:400],
            }
            result.by_parser[name] = (result.by_parser.get(name, 0)
                                      + len(parsed.artifacts))
        result.warnings.extend(parsed.warnings)
        result.notes.extend(parsed.notes)

        if container is not None and len(pending) >= db_batch:
            container.db.add_many(pending)
            result.artifacts.extend(pending)
            pending = []

        if progress_every and index % progress_every == 0:
            total = len(candidates) or 1
            ctx.emit("ingest", "progress",
                     f"{index}/{total} files examined, "
                     f"{result.files_parsed} decoded",
                     phase="decode",
                     progress_current=index, progress_total=total,
                     progress_pct=round(100.0 * index / total, 1),
                     bytes_current=result.bytes_seen)

    if worker_count == 1:
        for index, path in enumerate(candidates, 1):
            reduce_one(index, _examine(path, ctx))
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            # Submitted in walk order and zipped back in the same order, so the
            # reduction is deterministic regardless of completion order.
            futures = [pool.submit(_examine, path, ctx) for path in candidates]
            for index, future in enumerate(futures, 1):
                try:
                    reduce_one(index, future.result())
                except Exception as exc:                  # pragma: no cover
                    result.warnings.append(
                        f"{candidates[index - 1].name}: parser failed: {exc}")

    if container is not None:
        if pending:
            container.db.add_many(pending)
        result.artifacts.extend(pending)
        for key, s in source_stats.items():
            container.db.register_source(
                key, str(s["sha256"]), int(s["size"]), str(s["parser"]),
                int(s["count"]), str(s["notes"]))
    else:
        result.artifacts.extend(pending)

    total = len(candidates) or 1
    ctx.emit("ingest", "ok",
             f"{result.files_parsed} files decoded, "
             f"{result.files_skipped} skipped as non-evidential, "
             f"{result.deleted_recovered} deleted records recovered",
             phase="decode",
             progress_current=total, progress_total=total,
             progress_pct=100.0, bytes_current=result.bytes_seen)
    return result
