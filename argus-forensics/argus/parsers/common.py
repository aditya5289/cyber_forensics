"""Shared helpers for artifact parsers.

The single most important helper here is :func:`rows_with_deleted`, which lets
any parser handle live and recovered-deleted records with the same code path.
A parser that forgets to look for deleted rows is a parser that quietly misses
the most probative evidence in the case, so the default is to always look.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..core.models import Recovery
from .registry import ParseContext
from .sqlite_reader import ForensicSQLite


def sqlite_probe(*required_tables: str):
    """Build a probe that confirms a file is SQLite and has the given tables."""
    def _probe(path: Path) -> bool:
        try:
            with path.open("rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    return False
            uri = f"file:{path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            try:
                names = {r[0].lower() for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                conn.close()
            return all(t.lower() in names for t in required_tables) if required_tables \
                else True
        except Exception:
            return False
    return _probe


def any_table_probe(*table_groups: Tuple[str, ...]):
    """Probe that passes if *any* of the given table groups is fully present."""
    def _probe(path: Path) -> bool:
        try:
            with path.open("rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    return False
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            try:
                names = {r[0].lower() for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                conn.close()
            return any(all(t.lower() in names for t in group)
                       for group in table_groups)
        except Exception:
            return False
    return _probe


def rows_with_deleted(db: ForensicSQLite, table: str, ctx: ParseContext,
                      min_confidence: Optional[float] = None
                      ) -> Iterator[Tuple[Dict[str, Any], Recovery, float]]:
    """Yield ``(row, recovery_state, confidence)`` for live *and* deleted rows."""
    if not db.has_table(table):
        return
    for row in db.rows(table):
        yield row, Recovery.ALLOCATED, 1.0
    if not ctx.recover_deleted:
        return
    conf = ctx.carve_confidence if min_confidence is None else min_confidence
    origin_map = {
        "freeblock": Recovery.DELETED_FREELIST,
        "unallocated": Recovery.DELETED_UNALLOC,
        "freelist": Recovery.DELETED_FREELIST,
        "wal": Recovery.WAL,
        "journal": Recovery.JOURNAL,
    }
    for row, rec in db.carved_rows(table, min_confidence=conf):
        # Partial records are surfaced on the row itself so a parser can record
        # that some columns were unrecoverable rather than reporting them as
        # legitimately empty.
        row["_partial"] = rec.partial
        row["_missing_leading"] = rec.missing_leading
        yield row, origin_map.get(rec.origin, Recovery.CARVED), rec.confidence


def pick(row: Dict[str, Any], *names: str, default: Any = None) -> Any:
    """First present, non-null value among ``names`` (case-insensitive)."""
    lowered = {str(k).lower(): v for k, v in row.items()}
    for n in names:
        v = lowered.get(n.lower())
        if v is not None and v != "":
            return v
    return default


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def as_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        f = float(value)
        return f
    except (TypeError, ValueError):
        return None


def valid_coord(lat: Any, lon: Any) -> Tuple[Optional[float], Optional[float]]:
    """Reject the 0,0 null-island sentinel and out-of-range values."""
    la, lo = as_float(lat), as_float(lon)
    if la is None or lo is None:
        return None, None
    if not (-90 <= la <= 90 and -180 <= lo <= 180):
        return None, None
    if abs(la) < 1e-7 and abs(lo) < 1e-7:
        return None, None
    return la, lo


def clean_number(value: Any) -> str:
    """Normalise a phone identifier for display without destroying it."""
    s = as_text(value).strip()
    if not s:
        return ""
    if s.lower() in ("unknown", "-1", "-2", "private", "restricted", "null"):
        return ""
    return s


def find_files(root: Path, patterns: List[str], limit: int = 200000) -> List[Path]:
    """Case-insensitive recursive glob over several patterns, de-duplicated."""
    seen: set[Path] = set()
    out: List[Path] = []
    for pat in patterns:
        for p in root.rglob("*"):
            if len(out) >= limit:
                return out
            if not p.is_file():
                continue
            import fnmatch as _fn
            if _fn.fnmatch(p.name.lower(), pat.lower()) and p not in seen:
                seen.add(p)
                out.append(p)
    return out
