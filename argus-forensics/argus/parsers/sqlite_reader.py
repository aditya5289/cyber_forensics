"""Forensic SQLite reader — live rows *and* deleted record recovery.

Why this module exists
----------------------
Opening an application database with ``sqlite3`` and running ``SELECT *``
returns only what the application still considers to exist.  When a user
deletes a chat, SQLite marks the row's cell as a freeblock and, unless the
database has been ``VACUUM``-ed, **the record bytes remain on the page**.
Recovering them is the single highest-value capability in mobile forensics and
it is why a file-system extraction is worth so much more than a logical one.

This reader therefore does three things a normal SQLite client will not:

1. **Reads without touching the source.** The file is opened read-only and
   also copied to a scratch path before any SQLite engine sees it, so no
   journal replay, no WAL checkpoint, no ``-shm`` creation ever mutates
   evidence.  (Precaution: the source must be bit-identical afterwards.)

2. **Carves deleted records** from
   * freeblocks (space released inside an otherwise live page),
   * the gap between the cell-pointer array and the cell content area,
   * pages on the database freelist (whole pages released to the file),
   * and page images inside the ``-wal`` and rollback ``-journal`` files.

   Carving is schema-guided: for each table ARGUS knows the column count and
   declared affinities, so a candidate byte offset is only accepted when its
   record header parses to exactly that column count *and* the serial-type
   widths sum to exactly the stated payload length.  That constraint makes
   false positives rare; each hit is still emitted with a confidence score.

3. **Reports what it could not do.** If a database is encrypted (SQLCipher),
   truncated, or has been vacuumed, the reader says so explicitly instead of
   returning an empty result that looks like "no evidence".

Reference: the SQLite file format is documented at
https://www.sqlite.org/fileformat2.html — page structure §1.5, record format
§2.1, freelist §1.4.
"""

from __future__ import annotations

import mmap
import os
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from ..core.errors import ParserError

SQLITE_MAGIC = b"SQLite format 3\x00"

# Page b-tree types
PAGE_INDEX_INTERIOR = 0x02
PAGE_TABLE_INTERIOR = 0x05
PAGE_INDEX_LEAF = 0x0A
PAGE_TABLE_LEAF = 0x0D


# --------------------------------------------------------------------- varint
def read_varint(buf: bytes, offset: int) -> Tuple[int, int]:
    """Read a SQLite big-endian base-128 varint. Returns ``(value, bytes_read)``."""
    value = 0
    for i in range(8):
        if offset + i >= len(buf):
            raise IndexError("varint runs past end of buffer")
        byte = buf[offset + i]
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, i + 1
    if offset + 8 >= len(buf):
        raise IndexError("varint runs past end of buffer")
    value = (value << 8) | buf[offset + 8]
    return value, 9


def _to_signed(value: int, bits: int) -> int:
    limit = 1 << (bits - 1)
    return value - (1 << bits) if value >= limit else value


def serial_type_size(stype: int) -> int:
    if stype == 0 or stype in (8, 9):
        return 0
    if stype <= 4:
        return stype
    if stype == 5:
        return 6
    if stype in (6, 7):
        return 8
    if stype in (10, 11):
        return 0                       # internal use; treated as zero-width
    return (stype - 12) // 2 if stype % 2 == 0 else (stype - 13) // 2


def decode_value(stype: int, data: bytes, encoding: str = "utf-8") -> Any:
    if stype == 0:
        return None
    if stype == 8:
        return 0
    if stype == 9:
        return 1
    if stype in (1, 2, 3, 4, 5, 6):
        width = serial_type_size(stype)
        raw = int.from_bytes(data[:width], "big")
        return _to_signed(raw, width * 8)
    if stype == 7:
        return struct.unpack(">d", data[:8])[0]
    if stype >= 12 and stype % 2 == 0:
        return data
    if stype >= 13:
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            return data.decode("utf-8", errors="replace")
    return None


# ------------------------------------------------------------------- records
@dataclass
class CarvedRecord:
    """A record recovered from unallocated or freed space."""

    values: List[Any]
    rowid: Optional[int]
    page: int
    offset: int
    origin: str                       # freeblock | unallocated | freelist | wal | journal
    confidence: float = 0.6
    table: str = ""
    partial: bool = False             # leading column(s) destroyed
    missing_leading: int = 0          # how many columns could not be recovered

    def as_row(self, columns: Sequence[str],
               rowid_alias: Optional[int] = None) -> Dict[str, Any]:
        """Materialise the record as a column-keyed dict.

        ``rowid_alias`` is the index of an ``INTEGER PRIMARY KEY`` column. Such
        a column is *not* stored in the record body — SQLite writes NULL there
        and keeps the value in the cell's rowid — so it has to be substituted
        back in or every carved row appears to have a null primary key.
        """
        out: Dict[str, Any] = {"_rowid": self.rowid,
                               "_partial": self.partial,
                               "_missing_leading": self.missing_leading}
        for i, col in enumerate(columns):
            val = self.values[i] if i < len(self.values) else None
            if val is None and rowid_alias is not None and i == rowid_alias:
                val = self.rowid
            out[col] = val
        return out


@dataclass
class TableSchema:
    name: str
    columns: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    rootpage: int = 0
    sql: str = ""
    rowid_alias: Optional[int] = None    # index of an INTEGER PRIMARY KEY column

    @property
    def ncols(self) -> int:
        return len(self.columns)


def _parse_create_table(sql: str) -> Tuple[List[str], List[str]]:
    """Extract column names and declared types from a CREATE TABLE statement."""
    if not sql:
        return [], []
    start = sql.find("(")
    end = sql.rfind(")")
    if start < 0 or end <= start:
        return [], []
    body = sql[start + 1:end]

    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))

    names, types = [], []
    reserved = {"primary", "unique", "check", "foreign", "constraint", "key"}
    for part in parts:
        tokens = part.strip().replace("\n", " ").split()
        if not tokens:
            continue
        if tokens[0].strip('"`[]').lower() in reserved:
            continue
        name = tokens[0].strip('"`[]')
        decl = tokens[1].strip('"`[]').upper() if len(tokens) > 1 else ""
        if "PRIMARY KEY" in part.upper() and decl.startswith("INT"):
            decl = "INTEGER PRIMARY KEY"
        names.append(name)
        types.append(decl)
    return names, types


def _find_rowid_alias(types: List[str]) -> Optional[int]:
    for i, t in enumerate(types):
        if "PRIMARY KEY" in (t or "") and (t or "").startswith("INT"):
            return i
    return None


# ---------------------------------------------------------------------- main
class MappedFile:
    """Random access to a file's bytes without loading it into memory.

    A forensic reader touches the header, then individual pages scattered
    through the file. Reading the whole database in to do that costs one byte of
    RAM per byte of evidence, which is fine on a 40 MB `mmssms.db` and fatal on
    a multi-gigabyte `msgstore.db` or a physical image. The operating system's
    page cache is already the right tool: map the file and let it fault pages in
    on demand.

    Exposes the small slice of the ``bytes`` interface the reader actually uses,
    so call sites are unchanged.
    """

    __slots__ = ("path", "size", "_fh", "_mm")

    def __init__(self, path: os.PathLike | str):
        self.path = Path(path)
        self._fh = open(self.path, "rb")
        self.size = os.fstat(self._fh.fileno()).st_size
        if self.size:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            self._mm = None

    def __len__(self) -> int:
        return self.size

    def __getitem__(self, item):
        if self._mm is None:
            return b""
        return self._mm[item]

    def startswith(self, prefix: bytes) -> bool:
        return self[:len(prefix)] == prefix

    def find(self, needle: bytes, start: int = 0, end: int = -1) -> int:
        if self._mm is None:
            return -1
        return self._mm.find(needle, start, self.size if end < 0 else end)

    def close(self) -> None:
        if self._mm is not None:
            try:
                self._mm.close()
            except (BufferError, ValueError):        # pragma: no cover
                pass
            self._mm = None
        try:
            self._fh.close()
        except Exception:                            # pragma: no cover
            pass



class ForensicSQLite:
    """Read a SQLite database forensically.

    Usage::

        with ForensicSQLite("mmssms.db") as db:
            for row in db.rows("sms"):
                ...
            for rec in db.carve("sms"):
                ...
    """

    def __init__(self, path: os.PathLike | str, sidecars: bool = True,
                 scratch_dir: Optional[Path] = None):
        self.source = Path(path)
        if not self.source.exists():
            raise ParserError(f"database not found: {self.source}")
        # Construction can fail for perfectly ordinary reasons — the file is
        # not SQLite, the header is damaged, the scratch volume is full. Every
        # one of those paths must release the memory map, or a single pass over
        # an exhibit full of unrecognised files leaks a descriptor per file and
        # the acquisition dies partway through on "too many open files". That
        # failure looks like a corrupt exhibit, not like a bug in the reader.
        self.raw = MappedFile(self.source)
        try:
            self._open(sidecars, scratch_dir)
        except Exception:
            self.raw.close()
            raise

    def _open(self, sidecars: bool, scratch_dir: Optional[Path]) -> None:
        if len(self.raw) < 100:
            raise ParserError(f"{self.source.name}: file too small to be SQLite")
        if not self.raw.startswith(SQLITE_MAGIC):
            head = self.raw[:16]
            if self.raw[:4] == b"\x53\x51\x4c\x69":
                raise ParserError(f"{self.source.name}: unexpected SQLite variant")
            raise ParserError(
                f"{self.source.name}: not a SQLite database (header is "
                f"{head!r}). If the app uses SQLCipher the file is "
                f"encrypted and requires the key.")

        self._parse_header()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="argus-sqlite-",
                                             dir=str(scratch_dir) if scratch_dir else None))
        # The working copy exists so SQLite cannot write to the evidence: even
        # a read-only query will replay a hot journal and hot-fix a corrupt page
        # header, silently altering the file under examination.
        #
        # It is only *needed* when there are sidecars to replay. Without them,
        # opening with `immutable=1` gives the same guarantee — SQLite treats
        # the file as unchangeable and never writes to it — at no cost. Copying
        # regardless meant every open of a multi-gigabyte store duplicated it on
        # the scratch volume first, which on a large exhibit is the difference
        # between minutes and hours, and can exhaust the disk outright.
        self.sidecar_paths: List[Path] = []
        present = [suffix for suffix in ("-wal", "-shm", "-journal")
                   if sidecars and Path(str(self.source) + suffix).exists()]
        self._copied = bool(present)
        if self._copied:
            self._work = self._tmpdir / self.source.name
            shutil.copyfile(self.source, self._work)
            for suffix in present:
                sc = Path(str(self.source) + suffix)
                shutil.copyfile(sc, Path(str(self._work) + suffix))
                self.sidecar_paths.append(sc)
        else:
            self._work = self.source

        self._conn: Optional[sqlite3.Connection] = None
        self._schema_cache: Optional[Dict[str, TableSchema]] = None
        self.warnings: List[str] = []

    # ------------------------------------------------------------ file header
    # The format permits a power of two from 512 to 65536, with 65536 encoded
    # as 1 because the field is only 16 bits wide.
    VALID_PAGE_SIZES = frozenset(
        [65536] + [1 << bit for bit in range(9, 16)])

    def _parse_header(self) -> None:
        h = self.raw[:100]
        self.page_size = struct.unpack(">H", h[16:18])[0]
        if self.page_size == 1:
            self.page_size = 65536
        # A damaged or zeroed header is ordinary in real evidence — a truncated
        # copy, an interrupted write, a partially overwritten page. Every later
        # calculation divides by the page size, so an invalid value here does
        # not produce a bad answer, it produces a ZeroDivisionError three frames
        # down that reads like a bug in ARGUS rather than a fact about the file.
        if self.page_size not in self.VALID_PAGE_SIZES:
            raise ParserError(
                f"{self.source.name}: page size {self.page_size} is not valid "
                f"(SQLite permits a power of two from 512 to 65536). The "
                f"header is damaged or this is not a SQLite database. If the "
                f"file was carved, the recovered fragment may not start at a "
                f"page boundary.")
        self.write_version = h[18]
        self.read_version = h[19]
        self.reserved_space = h[20]
        self.file_change_counter = struct.unpack(">I", h[24:28])[0]
        self.page_count = struct.unpack(">I", h[28:32])[0]
        self.freelist_head = struct.unpack(">I", h[32:36])[0]
        self.freelist_count = struct.unpack(">I", h[36:40])[0]
        enc = struct.unpack(">I", h[56:60])[0]
        self.encoding = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}.get(enc, "utf-8")
        self.vacuum_mode = struct.unpack(">I", h[52:56])[0]
        self.application_id = struct.unpack(">I", h[68:72])[0]
        if self.page_count == 0 or self.page_count * self.page_size > len(self.raw):
            self.page_count = max(1, len(self.raw) // self.page_size)

    def header_report(self) -> Dict[str, Any]:
        return {
            "file": str(self.source),
            "size": len(self.raw),
            "page_size": self.page_size,
            "page_count": self.page_count,
            "encoding": self.encoding,
            "freelist_pages": self.freelist_count,
            "freelist_head": self.freelist_head,
            "write_ahead_log": self.write_version == 2,
            "auto_vacuum": self.vacuum_mode != 0,
            "change_counter": self.file_change_counter,
            "sidecars": [p.name for p in self.sidecar_paths],
        }

    # --------------------------------------------------------------- live API
    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            # `immutable=1` is what makes reading the evidence in place safe.
            # A plain `mode=ro` connection still writes in two cases: replaying
            # a hot journal, and hot-fixing a page header it considers corrupt.
            uri = f"file:{self._work.as_posix()}?mode=ro"
            if not self._copied:
                uri += "&immutable=1"
            self._conn = sqlite3.connect(uri, uri=True)
            self._conn.row_factory = sqlite3.Row
            self._conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        return self._conn

    def schemas(self) -> Dict[str, TableSchema]:
        if self._schema_cache is not None:
            return self._schema_cache
        out: Dict[str, TableSchema] = {}
        try:
            rows = self.conn.execute(
                "SELECT name, rootpage, sql FROM sqlite_master WHERE type='table'"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            self.warnings.append(f"sqlite_master unreadable via engine ({exc}); "
                                 f"falling back to raw page scan")
            rows = []
        for r in rows:
            names, types = _parse_create_table(r["sql"] or "")
            if not names:
                try:
                    info = self.conn.execute(
                        f'PRAGMA table_info("{r["name"]}")').fetchall()
                    names = [i["name"] for i in info]
                    types = [(i["type"] or "").upper() for i in info]
                except sqlite3.DatabaseError:
                    pass
            out[r["name"]] = TableSchema(name=r["name"], columns=names,
                                         types=types, rootpage=r["rootpage"] or 0,
                                         sql=r["sql"] or "",
                                         rowid_alias=_find_rowid_alias(types))
        self._schema_cache = out
        return out

    def has_table(self, name: str) -> bool:
        return name in self.schemas()

    def first_table(self, *candidates: str) -> Optional[str]:
        """Return the first candidate table that exists (schema drift helper)."""
        s = self.schemas()
        for c in candidates:
            if c in s:
                return c
        lowered = {k.lower(): k for k in s}
        for c in candidates:
            if c.lower() in lowered:
                return lowered[c.lower()]
        return None

    def columns(self, table: str) -> List[str]:
        sch = self.schemas().get(table)
        return list(sch.columns) if sch else []

    def rows(self, table: str, where: str = "", params: Sequence[Any] = (),
             order: str = "") -> Iterator[Dict[str, Any]]:
        """Iterate allocated rows. Tolerates individual corrupt pages."""
        if not self.has_table(table):
            return
        sql = f'SELECT rowid AS _rowid, * FROM "{table}"'
        if where:
            sql += f" WHERE {where}"
        if order:
            sql += f" ORDER BY {order}"
        try:
            cur = self.conn.execute(sql, tuple(params))
        except sqlite3.DatabaseError as exc:
            self.warnings.append(f"table {table}: {exc}")
            return
        while True:
            try:
                row = cur.fetchone()
            except sqlite3.DatabaseError as exc:
                self.warnings.append(f"table {table}: row read aborted ({exc})")
                return
            if row is None:
                return
            yield {k: row[k] for k in row.keys()}

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        try:
            return [{k: r[k] for k in r.keys()}
                    for r in self.conn.execute(sql, tuple(params))]
        except sqlite3.DatabaseError as exc:
            self.warnings.append(f"query failed: {exc}")
            return []

    # ------------------------------------------------------------------ pages
    def page(self, number: int) -> bytes:
        """1-indexed page image."""
        if number < 1 or number > self.page_count:
            return b""
        start = (number - 1) * self.page_size
        return self.raw[start:start + self.page_size]

    def _page_body_offset(self, number: int) -> int:
        return 100 if number == 1 else 0

    def freelist_pages(self) -> List[int]:
        """Walk the freelist trunk chain and collect every freed page number."""
        pages: List[int] = []
        seen: set[int] = set()
        trunk = self.freelist_head
        while trunk and trunk not in seen and trunk <= self.page_count:
            seen.add(trunk)
            data = self.page(trunk)
            if len(data) < 8:
                break
            nxt, n_leaf = struct.unpack(">II", data[:8])
            pages.append(trunk)
            n_leaf = min(n_leaf, (self.page_size - 8) // 4)
            for i in range(n_leaf):
                off = 8 + i * 4
                leaf = struct.unpack(">I", data[off:off + 4])[0]
                if 0 < leaf <= self.page_count and leaf not in seen:
                    seen.add(leaf)
                    pages.append(leaf)
            trunk = nxt
        return pages

    def leaf_pages_for(self, rootpage: int) -> List[int]:
        """Depth-first walk of a table b-tree, returning leaf page numbers."""
        if rootpage <= 0:
            return []
        leaves: List[int] = []
        stack, seen = [rootpage], set()
        while stack:
            pno = stack.pop()
            if pno in seen or pno < 1 or pno > self.page_count:
                continue
            seen.add(pno)
            data = self.page(pno)
            if not data:
                continue
            base = self._page_body_offset(pno)
            if len(data) <= base:
                continue
            ptype = data[base]
            if ptype == PAGE_TABLE_LEAF:
                leaves.append(pno)
            elif ptype == PAGE_TABLE_INTERIOR:
                ncells = struct.unpack(">H", data[base + 3:base + 5])[0]
                right = struct.unpack(">I", data[base + 8:base + 12])[0]
                if right:
                    stack.append(right)
                for i in range(min(ncells, (self.page_size - base - 12) // 2)):
                    off = base + 12 + i * 2
                    cell_off = struct.unpack(">H", data[off:off + 2])[0]
                    if 0 < cell_off < len(data) - 4:
                        child = struct.unpack(">I", data[cell_off:cell_off + 4])[0]
                        if child:
                            stack.append(child)
        return leaves

    def _page_gaps(self, pno: int) -> List[Tuple[int, bytes]]:
        """Return ``(absolute_offset, bytes)`` for unallocated regions of a page.

        Two sources:
          * the gap between the end of the cell-pointer array and the start of
            the cell content area (holds remnants after cells are moved), and
          * every freeblock on the page's freeblock chain (deleted cells).
        """
        data = self.page(pno)
        if not data:
            return []
        base = self._page_body_offset(pno)
        if len(data) < base + 8:
            return []
        ptype = data[base]
        if ptype not in (PAGE_TABLE_LEAF, PAGE_INDEX_LEAF,
                         PAGE_TABLE_INTERIOR, PAGE_INDEX_INTERIOR):
            return []
        header_len = 12 if ptype in (PAGE_TABLE_INTERIOR, PAGE_INDEX_INTERIOR) else 8
        first_free = struct.unpack(">H", data[base + 1:base + 3])[0]
        ncells = struct.unpack(">H", data[base + 3:base + 5])[0]
        content_start = struct.unpack(">H", data[base + 5:base + 7])[0] or 65536

        gaps: List[Tuple[int, bytes]] = []
        ptr_end = base + header_len + ncells * 2
        if content_start > ptr_end and content_start <= len(data):
            chunk = data[ptr_end:content_start]
            if chunk.strip(b"\x00"):
                gaps.append((ptr_end, chunk))

        seen: set[int] = set()
        fb = first_free
        while fb and fb not in seen and fb + 4 <= len(data):
            seen.add(fb)
            nxt, size = struct.unpack(">HH", data[fb:fb + 4])
            size = max(size, 4)
            chunk = data[fb:min(fb + size, len(data))]
            if chunk.strip(b"\x00"):
                gaps.append((fb, chunk))
            fb = nxt
        return gaps

    # ----------------------------------------------------------------- carver
    def _try_record(self, buf: bytes, pos: int, schema: TableSchema,
                    has_rowid_prefix: bool) -> Optional[Tuple[List[Any], Optional[int], int]]:
        """Attempt to decode a record at ``buf[pos:]``.

        Returns ``(values, rowid, consumed)`` or ``None``.  The validation is
        deliberately strict: payload length, header length and the sum of
        serial-type widths must all agree, and the column count must equal the
        schema's.  Loose carving produces garbage that pollutes a timeline.
        """
        try:
            p = pos
            payload_len = rowid = None
            if has_rowid_prefix:
                payload_len, n = read_varint(buf, p); p += n
                rowid, n = read_varint(buf, p); p += n
                if payload_len < 2 or payload_len > self.page_size * 4:
                    return None
                if rowid < 0 or rowid > (1 << 48):
                    return None
            body_start_guess = p
            header_len, n = read_varint(buf, p); p += n
            if header_len < 2 or header_len > 4096:
                return None
            if body_start_guess + header_len > len(buf):
                return None
            header_end = body_start_guess + header_len

            stypes: List[int] = []
            while p < header_end:
                st, n = read_varint(buf, p); p += n
                stypes.append(st)
            if p != header_end:
                return None
            if len(stypes) != schema.ncols:
                return None

            body_size = sum(serial_type_size(st) for st in stypes)
            if has_rowid_prefix and payload_len is not None:
                if header_len + body_size != payload_len:
                    return None
            if header_end + body_size > len(buf):
                return None

            values: List[Any] = []
            q = header_end
            for st in stypes:
                width = serial_type_size(st)
                values.append(decode_value(st, buf[q:q + width], self.encoding))
                q += width
            return values, rowid, q - pos
        except (IndexError, struct.error, ValueError, OverflowError):
            return None

    def _try_partial(self, buf: bytes, pos: int, schema: TableSchema,
                     missing: int):
        """Recover a record whose first ``missing`` serial types were destroyed.

        When SQLite frees a cell it stamps four bytes over the start of it. For
        a compact row that erases the payload length, the rowid, the header
        length *and* the first serial type — so an exact ``ncols`` parse can
        never succeed, and the record looks unrecoverable.

        It is not. The remaining types and the entire body survive. Parsing
        ``ncols - missing`` types and shifting the values right reconstructs
        every column except the leading one(s), which are reported as unknown.

        This matters because the destroyed column is usually the rowid alias —
        an integer of no evidential interest — while the surviving columns hold
        the message text, the timestamp and the correspondent. Refusing to
        report a row because its primary key is missing would discard the
        actual evidence to protect a technicality.
        """
        want = schema.ncols - missing
        if want < 2:
            return None
        try:
            p = pos
            stypes: List[int] = []
            for _ in range(want):
                st, n = read_varint(buf, p)
                p += n
                if st in (10, 11) or st > 0x7FFFFFFF:
                    return None
                stypes.append(st)
            body_size = sum(serial_type_size(st) for st in stypes)
            if body_size <= 0 or p + body_size > len(buf):
                return None
            if body_size > self.page_size * 4:
                return None
            values: List[Any] = [None] * missing
            q = p
            for st in stypes:
                width = serial_type_size(st)
                values.append(decode_value(st, buf[q:q + width], self.encoding))
                q += width
            return values, None, q - pos
        except (IndexError, struct.error, ValueError, OverflowError):
            return None

    def _best_alignment(self, buf: bytes, pos: int, schema: TableSchema,
                        window: int = 4):
        """Score every candidate alignment in a small window; keep the best.

        Returns ``(result, offset_used)``. Ties are broken toward the earliest
        offset so the scan remains deterministic.
        """
        best = None
        best_pos = pos
        best_score = -1.0
        for delta in range(window):
            candidate = self._try_types_only(buf, pos + delta, schema)
            if not candidate:
                continue
            values, _rowid, consumed = candidate
            score = self._plausible(values, schema)
            # A surviving header-length byte is decisive corroboration.
            if consumed > 0:
                score += 0.5
            if score > best_score:
                best_score, best, best_pos = score, candidate, pos + delta
        return best, best_pos

    def _try_types_only(self, buf: bytes, pos: int, schema: TableSchema
                        ) -> Optional[Tuple[List[Any], Optional[int], int]]:
        """Decode a record whose length varints have been overwritten.

        When SQLite frees a cell it stamps a 4-byte freeblock header
        (next-pointer, size) over the beginning of that cell. For a typical
        message row the payload-length and rowid varints occupy only two or
        three bytes, so the freeblock header also swallows the *record header
        length* byte. The serial-type array and the body survive intact.

        This routine therefore starts from an assumed serial-type array,
        parses exactly ``ncols`` types, and reconstructs the row. Because the
        stated lengths are gone, the only validation available is:

        * exactly ``ncols`` well-formed serial types parse, and
        * the resulting body fits inside the region, and
        * where the preceding byte survives, it equals the header length the
          parsed types imply — a strong check that rules out most coincidences.

        Records failing that last check are still returned but the caller
        applies a higher confidence threshold to them.
        """
        try:
            p = pos
            stypes: List[int] = []
            for _ in range(schema.ncols):
                st, n = read_varint(buf, p)
                p += n
                if st in (10, 11) or st > 0x7FFFFFFF:
                    return None
                stypes.append(st)
            type_bytes = p - pos
            implied_header_len = type_bytes + 1        # + the length byte itself
            if implied_header_len > 127:
                implied_header_len = type_bytes + 2

            body_size = sum(serial_type_size(st) for st in stypes)
            if body_size <= 0 or p + body_size > len(buf):
                return None
            if body_size > self.page_size * 4:
                return None

            values: List[Any] = []
            q = p
            for st in stypes:
                width = serial_type_size(st)
                values.append(decode_value(st, buf[q:q + width], self.encoding))
                q += width

            verified = (pos >= 1 and buf[pos - 1] == implied_header_len)
            return values, None, (q - pos) if verified else -(q - pos)
        except (IndexError, struct.error, ValueError, OverflowError):
            return None

    @staticmethod
    def _text_is_clean(val: str) -> bool:
        """Reject text that ran off the end of its real field.

        When a carve mis-reads a string's length the decoded value continues
        into whatever bytes follow — producing text that starts out correct and
        then degenerates into control characters and replacement marks. Such a
        record looks convincing in a report and is partly fabricated, which is
        the worst possible failure mode for a carver. Any NUL, or more than a
        trace of unprintable content, disqualifies it outright.
        """
        if not val:
            return True
        if "\x00" in val or "�" in val:
            return False
        bad = sum(1 for ch in val if not (ch.isprintable() or ch in "\n\t"))
        return bad == 0 or bad / len(val) <= 0.02

    @classmethod
    def _plausible(cls, values: List[Any], schema: TableSchema) -> float:
        """Score a carved record against the declared column affinities."""
        if not values:
            return 0.0
        score, checked = 0.0, 0
        for val, decl in zip(values, schema.types + [""] * len(values)):
            d = (decl or "").upper()
            if val is None:
                continue
            checked += 1
            if isinstance(val, str) and not cls._text_is_clean(val):
                return 0.0                      # partially fabricated: discard
            if any(k in d for k in ("INT",)):
                score += 1.0 if isinstance(val, int) else 0.0
            elif any(k in d for k in ("CHAR", "TEXT", "CLOB")):
                score += 1.0 if isinstance(val, str) else 0.2
            elif any(k in d for k in ("REAL", "FLOA", "DOUB")):
                score += 1.0 if isinstance(val, (int, float)) else 0.0
            elif "BLOB" in d:
                score += 1.0 if isinstance(val, (bytes, bytearray)) else 0.3
            else:
                score += 0.7
        return round(min((score / checked) if checked else 0.0, 1.0), 3)

    def carve(self, table: str, min_confidence: float = 0.45,
              include_freelist: bool = True, include_wal: bool = True,
              max_records: int = 20000) -> List[CarvedRecord]:
        """Recover deleted records for ``table`` from all unallocated space."""
        schema = self.schemas().get(table)
        if not schema or not schema.columns:
            return []

        live_rowids: set[int] = set()
        try:
            for r in self.conn.execute(f'SELECT rowid FROM "{table}"'):
                live_rowids.add(r[0])
        except sqlite3.DatabaseError:
            pass

        found: List[CarvedRecord] = []
        seen_keys: set[tuple] = set()

        def scan(buf: bytes, page_no: int, base_off: int, origin: str,
                 with_prefix: bool) -> None:
            # Prefix-less scanning cannot cross-check the payload length, so it
            # must clear a higher confidence bar — otherwise a carve floods the
            # timeline with plausible-looking noise, which is worse than
            # recovering nothing.
            floor = (min_confidence if with_prefix
                     else min(0.92, min_confidence + 0.20))
            pos = 0
            limit = len(buf)
            while pos < limit - 4 and len(found) < max_records:
                got = self._try_record(buf, pos, schema, with_prefix)
                if got:
                    values, rowid, consumed = got
                    conf = self._plausible(values, schema)
                    if conf >= floor and any(
                            v not in (None, 0, "", b"") for v in values):
                        # De-duplicate on content, not rowid: the same record
                        # often survives in a freeblock *and* in the WAL.
                        key = tuple(
                            v[:64] if isinstance(v, (str, bytes)) else v
                            for v in values)
                        if key not in seen_keys and (
                                rowid is None or rowid not in live_rowids):
                            seen_keys.add(key)
                            found.append(CarvedRecord(
                                values=values, rowid=rowid, page=page_no,
                                offset=base_off + pos, origin=origin,
                                confidence=(conf if with_prefix
                                            else round(conf * 0.85, 3)),
                                table=table))
                        pos += max(consumed, 1)
                        continue
                pos += 1

        def scan_headerless(buf: bytes, page_no: int, base_off: int,
                            origin: str) -> None:
            """Third pass: records whose length varints were overwritten.

            A subtlety that decides whether this pass works at all: several
            adjacent byte offsets will each parse into the right *number* of
            serial types, but only one of them aligns the values to the real
            columns. The others shift everything by a column and produce a row
            where a BLOB lands in an integer field and a fragment of binary is
            read as text.

            Taking the first parse that clears the confidence bar therefore
            picks a misaligned row about as often as the correct one. Instead,
            every alignment in a short window is scored against the schema's
            declared affinities and the best is kept — which is the difference
            between recovering a deleted Telegram message and recovering
            nonsense that looks like one.
            """
            pos = 0
            limit = len(buf)
            while pos < limit - 2 and len(found) < max_records:
                got, pos_used = self._best_alignment(buf, pos, schema)
                missing = 0
                if got is None or self._plausible(got[0], schema) < 0.6:
                    # Exact-width parse failed or aligned badly. The leading
                    # serial type is probably inside the freeblock header.
                    for candidate_missing in (1, 2):
                        partial = self._try_partial(buf, pos, schema,
                                                    candidate_missing)
                        if partial and self._plausible(
                                partial[0], schema) >= 0.75:
                            got, pos_used = partial, pos
                            missing = candidate_missing
                            break
                if got:
                    pos = pos_used
                    values, _rowid, consumed = got
                    verified = consumed > 0
                    consumed = abs(consumed)
                    conf = self._plausible(values, schema)
                    # A surviving header-length byte is strong corroboration;
                    # without it, only near-perfect type agreement is accepted.
                    # A partial record has fewer columns to agree with, so a
                    # slightly lower bar is appropriate — but it is reported as
                    # partial and its confidence is reduced accordingly.
                    if missing:
                        floor = max(min_confidence, 0.78)
                    else:
                        floor = max(min_confidence, 0.55 if verified else 0.88)
                    # Require substantive content, but not necessarily *text*:
                    # many modern applications (Telegram, Signal, Google apps)
                    # keep their message bodies in BLOB columns, and demanding a
                    # string here made those tables silently unrecoverable.
                    substantive = any(
                        (isinstance(v, str) and len(v) > 2)
                        or (isinstance(v, (bytes, bytearray)) and len(v) > 8)
                        for v in values)
                    if conf >= floor and substantive:
                        key = tuple(
                            v[:64] if isinstance(v, (str, bytes)) else v
                            for v in values)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            found.append(CarvedRecord(
                                values=values, rowid=None, page=page_no,
                                offset=base_off + pos, origin=origin,
                                confidence=round(
                                    conf * (0.9 if verified else
                                            (0.6 if missing else 0.7)), 3),
                                table=table, partial=bool(missing),
                                missing_leading=missing))
                        pos += max(consumed, 1)
                        continue
                pos += 1

        def scan_both(buf: bytes, page_no: int, base_off: int,
                      origin: str) -> None:
            """Scan a region three ways, cheapest and strictest first.

            1. complete cells (payload length + rowid intact),
            2. records whose cell prefix is gone but whose header survives,
            3. records whose header-length byte was overwritten too.

            Each pass is strictly more permissive than the last, so each
            carries a higher confidence bar and a lower reported confidence.
            """
            scan(buf, page_no, base_off, origin, with_prefix=True)
            scan(buf, page_no, base_off, origin, with_prefix=False)
            scan_headerless(buf, page_no, base_off, origin)

        # 1. freeblocks and page slack inside the table's own b-tree pages
        for pno in self.leaf_pages_for(schema.rootpage):
            for off, chunk in self._page_gaps(pno):
                scan_both(chunk, pno, off,
                          "freeblock" if off > 100 else "unallocated")

        # 2. pages returned to the freelist (entire page content is stale)
        if include_freelist:
            for pno in self.freelist_pages():
                data = self.page(pno)
                if len(data) > 8:
                    scan_both(data[8:], pno, 8, "freelist")

        # 3. superseded page images inside the write-ahead log
        if include_wal:
            for pno, image in self.wal_page_images():
                base = self._page_body_offset(pno)
                if len(image) > base + 8 and image[base] == PAGE_TABLE_LEAF:
                    scan_both(image[base + 8:], pno, base + 8, "wal")

        # 4. rollback journal page images
        for pno, image in self.journal_page_images():
            base = self._page_body_offset(pno)
            if len(image) > base + 8 and image[base] == PAGE_TABLE_LEAF:
                scan_both(image[base + 8:], pno, base + 8, "journal")

        found.sort(key=lambda r: (-r.confidence, r.page, r.offset))
        return found

    def carved_rows(self, table: str, min_confidence: float = 0.45
                    ) -> Iterator[Tuple[Dict[str, Any], CarvedRecord]]:
        """Carve and yield ``(row_dict, provenance)`` pairs.

        This is the interface every artifact parser uses, so recovering
        deleted messages costs a parser exactly one extra loop.
        """
        sch = self.schemas().get(table)
        if not sch:
            return
        for rec in self.carve(table, min_confidence=min_confidence):
            yield rec.as_row(sch.columns, sch.rowid_alias), rec

    # -------------------------------------------------------------------- WAL
    def wal_page_images(self) -> List[Tuple[int, bytes]]:
        """Extract every page image stored in the ``-wal`` sidecar.

        A WAL holds *superseded* versions of pages. A message deleted after
        the last checkpoint frequently survives here in its pre-delete form
        even though the main database no longer contains it.
        """
        wal = Path(str(self.source) + "-wal")
        if not wal.exists():
            return []
        data = wal.read_bytes()
        if len(data) < 32:
            return []
        magic, _ver, page_size, _ckpt, _s1, _s2 = struct.unpack(">IIIIII", data[:24])
        if magic not in (0x377F0682, 0x377F0683):
            return []
        if page_size == 1:
            page_size = 65536
        if page_size <= 0 or page_size > 1 << 20:
            page_size = self.page_size
        frames: List[Tuple[int, bytes]] = []
        off = 32
        frame_size = 24 + page_size
        while off + frame_size <= len(data):
            pgno = struct.unpack(">I", data[off:off + 4])[0]
            image = data[off + 24: off + 24 + page_size]
            if 0 < pgno < (1 << 31):
                frames.append((pgno, image))
            off += frame_size
        return frames

    def journal_page_images(self) -> List[Tuple[int, bytes]]:
        """Extract page images from a legacy rollback journal."""
        jrn = Path(str(self.source) + "-journal")
        if not jrn.exists():
            return []
        data = jrn.read_bytes()
        if len(data) < 28 or data[:8] != b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
            return []
        sector = struct.unpack(">I", data[20:24])[0] or 512
        page_size = struct.unpack(">I", data[24:28])[0] or self.page_size
        out: List[Tuple[int, bytes]] = []
        off = sector
        while off + 4 + page_size + 4 <= len(data):
            pgno = struct.unpack(">I", data[off:off + 4])[0]
            image = data[off + 4: off + 4 + page_size]
            if 0 < pgno < (1 << 31):
                out.append((pgno, image))
            off += 4 + page_size + 4
        return out

    # ------------------------------------------------------------------ stats
    def integrity(self) -> Dict[str, Any]:
        try:
            res = self.conn.execute("PRAGMA integrity_check").fetchone()
            check = res[0] if res else "unknown"
        except sqlite3.DatabaseError as exc:
            check = f"failed: {exc}"
        return {
            "integrity_check": check,
            "freelist_pages": self.freelist_count,
            "wal_frames": len(self.wal_page_images()),
            "journal_pages": len(self.journal_page_images()),
            "tables": len(self.schemas()),
            "warnings": self.warnings,
        }

    def deleted_summary(self, tables: Optional[List[str]] = None
                        ) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for t in (tables or list(self.schemas())):
            if t.startswith("sqlite_"):
                continue
            try:
                out[t] = len(self.carve(t, max_records=2000))
            except Exception:                                 # pragma: no cover
                out[t] = 0
        return {k: v for k, v in out.items() if v}

    # ------------------------------------------------------------------ close
    def close(self) -> None:
        if getattr(self, "raw", None) is not None:
            self.raw.close()
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:                                 # pragma: no cover
                pass
            self._conn = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def __enter__(self) -> "ForensicSQLite":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:                                # pragma: no cover
        return (f"<ForensicSQLite {self.source.name} pages={self.page_count} "
                f"tables={len(self.schemas())}>")
