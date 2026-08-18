"""Artifact database — the analytical store inside an evidence container.

A single SQLite file holds every normalised artifact plus a full-text index.
It is written once during acquisition/parsing and thereafter opened read-only
by the analysis layer.

Why SQLite and not a document store: an evidence container has to be a *single
portable file set* that opens on an air-gapped workstation ten years from now
with no server process.  SQLite is the only format that credibly meets that
bar, and it gives us FTS5 for free.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

from .models import Artifact, Category, Direction, Participant, Recovery

SCHEMA_VERSION = 3

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT
);

CREATE TABLE IF NOT EXISTS artifact (
    artifact_id   TEXT PRIMARY KEY,
    category      TEXT NOT NULL,
    subtype       TEXT NOT NULL DEFAULT '',
    timestamp     INTEGER,
    timestamp_end INTEGER,
    body          TEXT NOT NULL DEFAULT '',
    direction     TEXT NOT NULL DEFAULT 'unknown',
    app           TEXT NOT NULL DEFAULT '',
    source_path   TEXT NOT NULL DEFAULT '',
    source_table  TEXT NOT NULL DEFAULT '',
    source_row    INTEGER,
    recovery      TEXT NOT NULL DEFAULT 'allocated',
    blob_sha256   TEXT NOT NULL DEFAULT '',
    latitude      REAL,
    longitude     REAL,
    confidence    REAL NOT NULL DEFAULT 1.0,
    attributes    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_artifact_cat  ON artifact(category);
CREATE INDEX IF NOT EXISTS ix_artifact_ts   ON artifact(timestamp);
CREATE INDEX IF NOT EXISTS ix_artifact_app  ON artifact(app);
CREATE INDEX IF NOT EXISTS ix_artifact_rec  ON artifact(recovery);
CREATE INDEX IF NOT EXISTS ix_artifact_blob ON artifact(blob_sha256);
CREATE INDEX IF NOT EXISTS ix_artifact_cat_ts ON artifact(category, timestamp);
CREATE INDEX IF NOT EXISTS ix_artifact_app_cat ON artifact(app, category);
CREATE INDEX IF NOT EXISTS ix_artifact_dir ON artifact(direction);

CREATE TABLE IF NOT EXISTS participant (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id  TEXT NOT NULL REFERENCES artifact(artifact_id) ON DELETE CASCADE,
    identifier   TEXT NOT NULL DEFAULT '',
    normalised   TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'party',
    is_owner     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_part_artifact ON participant(artifact_id);
CREATE INDEX IF NOT EXISTS ix_part_norm     ON participant(normalised);

CREATE TABLE IF NOT EXISTS tag (
    artifact_id TEXT NOT NULL REFERENCES artifact(artifact_id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    colour      TEXT NOT NULL DEFAULT '#e2b33c',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (artifact_id, name)
);
CREATE INDEX IF NOT EXISTS ix_tag_name ON tag(name);

CREATE TABLE IF NOT EXISTS source (
    path        TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    parser      TEXT NOT NULL DEFAULT '',
    count       INTEGER NOT NULL DEFAULT 0,
    notes       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS blob (
    sha256      TEXT PRIMARY KEY,
    size        INTEGER NOT NULL DEFAULT 0,
    md5         TEXT NOT NULL DEFAULT '',
    sha1        TEXT NOT NULL DEFAULT '',
    mime        TEXT NOT NULL DEFAULT '',
    orig_path   TEXT NOT NULL DEFAULT '',
    stored_at   TEXT NOT NULL DEFAULT ''
);

CREATE VIRTUAL TABLE IF NOT EXISTS artifact_fts USING fts5(
    artifact_id UNINDEXED,
    body,
    parties,
    app,
    subtype,
    tokenize = 'unicode61 remove_diacritics 2'
);
"""


class ArtifactDB:
    """Read/write access to the artifact store."""

    def __init__(self, path: Path | str, read_only: bool = False):
        self.path = Path(path)
        self.read_only = read_only
        if read_only:
            uri = f"file:{self.path.as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.executescript(SCHEMA)
            self.set_meta("schema_version", str(SCHEMA_VERSION))
        self.conn.row_factory = sqlite3.Row
        if read_only:
            self.conn.execute("PRAGMA query_only=ON")
            self.conn.execute("PRAGMA mmap_size=268435456")
            self.conn.execute("PRAGMA cache_size=-131072")
        self._ensure_perf_indexes()

    # ------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value) if not isinstance(value, str) else value))
        self.conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def _ensure_perf_indexes(self) -> None:
        """Idempotent indexes for analytics-heavy queries (safe on sealed DBs)."""
        try:
            self.conn.executescript("""
                CREATE INDEX IF NOT EXISTS ix_artifact_cat_ts
                    ON artifact(category, timestamp);
                CREATE INDEX IF NOT EXISTS ix_artifact_app_cat
                    ON artifact(app, category);
                CREATE INDEX IF NOT EXISTS ix_artifact_dir
                    ON artifact(direction);
            """)
        except sqlite3.OperationalError:
            pass

    def _where_clause(self, where: str) -> tuple[str, str]:
        clause = f" WHERE {where}" if where else ""
        return clause, where

    # -------------------------------------------------------------- artifacts
    def add(self, art: Artifact) -> None:
        self.add_many([art])

    def add_many(self, artifacts: Iterable[Artifact]) -> int:
        rows, prows, frows = [], [], []
        n = 0
        for a in artifacts:
            n += 1
            rows.append((
                a.artifact_id, a.category.value, a.subtype, a.timestamp,
                a.timestamp_end, a.body, a.direction.value, a.app, a.source_path,
                a.source_table, a.source_row, a.recovery.value, a.blob_sha256,
                a.latitude, a.longitude, a.confidence,
                json.dumps(a.attributes, ensure_ascii=False, default=str),
            ))
            party_labels = []
            for p in a.participants:
                prows.append((a.artifact_id, p.identifier, p.normalised(),
                              p.display_name, p.role, 1 if p.is_owner else 0))
                party_labels.append(f"{p.display_name} {p.identifier}".strip())
            frows.append((a.artifact_id, a.body, " ".join(party_labels),
                          a.app, a.subtype))
        with self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO artifact VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows)
            self.conn.executemany(
                "INSERT INTO participant(artifact_id,identifier,normalised,"
                "display_name,role,is_owner) VALUES (?,?,?,?,?,?)", prows)
            self.conn.executemany(
                "INSERT INTO artifact_fts(artifact_id,body,parties,app,subtype) "
                "VALUES (?,?,?,?,?)", frows)
        return n

    def get(self, artifact_id: str) -> Optional[Artifact]:
        row = self.conn.execute(
            "SELECT * FROM artifact WHERE artifact_id=?", (artifact_id,)).fetchone()
        return self._hydrate(row) if row else None

    def iter_artifacts(self, where: str = "", params: Sequence[Any] = (),
                       order: str = "timestamp IS NULL, timestamp ASC",
                       limit: Optional[int] = None,
                       offset: int = 0) -> Iterator[Artifact]:
        sql = "SELECT * FROM artifact"
        if where:
            sql += f" WHERE {where}"
        if order:
            sql += f" ORDER BY {order}"
        if limit is not None:
            sql += f" LIMIT {int(limit)} OFFSET {int(offset)}"
        batch: List[sqlite3.Row] = []
        for row in self.conn.execute(sql, tuple(params)):
            batch.append(row)
            if len(batch) >= 500:
                yield from self._hydrate_many(batch)
                batch.clear()
        if batch:
            yield from self._hydrate_many(batch)

    def iter_artifact_rows(self, where: str = "", params: Sequence[Any] = (),
                           order: str = "timestamp IS NULL, timestamp ASC",
                           limit: Optional[int] = None,
                           offset: int = 0) -> Iterator[sqlite3.Row]:
        """Lightweight row iterator — no participant/tag hydration."""
        sql = "SELECT * FROM artifact"
        if where:
            sql += f" WHERE {where}"
        if order:
            sql += f" ORDER BY {order}"
        if limit is not None:
            sql += f" LIMIT {int(limit)} OFFSET {int(offset)}"
        yield from self.conn.execute(sql, tuple(params))

    def count(self, where: str = "", params: Sequence[Any] = ()) -> int:
        sql = "SELECT COUNT(*) AS c FROM artifact"
        if where:
            sql += f" WHERE {where}"
        return int(self.conn.execute(sql, tuple(params)).fetchone()["c"])

    def _hydrate(self, row: sqlite3.Row) -> Artifact:
        return next(self._hydrate_many([row]))

    def _hydrate_many(self, rows: List[sqlite3.Row]) -> Iterator[Artifact]:
        if not rows:
            return
        ids = [r["artifact_id"] for r in rows]
        parts_by_id: Dict[str, List[Participant]] = {i: [] for i in ids}
        tags_by_id: Dict[str, List[str]] = {i: [] for i in ids}
        chunk = 400
        for start in range(0, len(ids), chunk):
            batch_ids = ids[start:start + chunk]
            ph = ",".join("?" * len(batch_ids))
            for p in self.conn.execute(
                    f"SELECT * FROM participant WHERE artifact_id IN ({ph}) "
                    "ORDER BY artifact_id, id",
                    batch_ids):
                parts_by_id[p["artifact_id"]].append(
                    Participant(identifier=p["identifier"],
                                display_name=p["display_name"],
                                role=p["role"],
                                is_owner=bool(p["is_owner"])))
            for t in self.conn.execute(
                    f"SELECT artifact_id, name FROM tag WHERE artifact_id IN ({ph}) "
                    "ORDER BY artifact_id, name",
                    batch_ids):
                tags_by_id[t["artifact_id"]].append(t["name"])
        for row in rows:
            yield self._artifact_from_row(
                row, parts_by_id[row["artifact_id"]],
                tags_by_id[row["artifact_id"]])

    def _artifact_from_row(self, row: sqlite3.Row,
                           parts: List[Participant],
                           tags: List[str]) -> Artifact:
        try:
            attrs = json.loads(row["attributes"] or "{}")
        except json.JSONDecodeError:
            attrs = {}
        return Artifact(
            artifact_id=row["artifact_id"],
            category=Category.coerce(row["category"]),
            subtype=row["subtype"] or "",
            timestamp=row["timestamp"],
            timestamp_end=row["timestamp_end"],
            body=row["body"] or "",
            participants=parts,
            direction=Direction(row["direction"]) if row["direction"] in
                      {d.value for d in Direction} else Direction.UNKNOWN,
            app=row["app"] or "",
            source_path=row["source_path"] or "",
            source_table=row["source_table"] or "",
            source_row=row["source_row"],
            recovery=Recovery(row["recovery"]) if row["recovery"] in
                     {r.value for r in Recovery} else Recovery.ALLOCATED,
            blob_sha256=row["blob_sha256"] or "",
            latitude=row["latitude"], longitude=row["longitude"],
            confidence=row["confidence"] if row["confidence"] is not None else 1.0,
            attributes=attrs, tags=tags,
        )

    # ------------------------------------------------------------------- FTS
    def search_ids(self, query: str, limit: int = 5000) -> List[str]:
        sql = ("SELECT artifact_id FROM artifact_fts WHERE artifact_fts MATCH ? "
               "ORDER BY rank LIMIT ?")
        try:
            return [r["artifact_id"] for r in self.conn.execute(sql, (query, limit))]
        except sqlite3.OperationalError as exc:
            raise ValueError(f"invalid full-text query: {exc}") from exc

    # ------------------------------------------------------------------- tags
    def tag(self, artifact_id: str, name: str, colour: str = "#e2b33c",
            note: str = "", actor: str = "") -> None:
        from datetime import datetime, timezone
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO tag VALUES (?,?,?,?,?,?)",
                (artifact_id, name, colour, note,
                 datetime.now(timezone.utc).isoformat(timespec="seconds"), actor))

    def untag(self, artifact_id: str, name: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM tag WHERE artifact_id=? AND name=?",
                              (artifact_id, name))

    def tag_names(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT name, colour, COUNT(*) AS count FROM tag "
            "GROUP BY name, colour ORDER BY count DESC")]

    def tags_for_artifact(self, artifact_id: str) -> List[str]:
        return [r["name"] for r in self.conn.execute(
            "SELECT name FROM tag WHERE artifact_id=?", (artifact_id,))]

    def tag_rows(self, name: Optional[str] = None) -> List[Dict[str, Any]]:
        if name:
            rows = self.conn.execute(
                "SELECT artifact_id, name, colour, note, created_at, actor "
                "FROM tag WHERE name=? ORDER BY created_at DESC", (name,))
        else:
            rows = self.conn.execute(
                "SELECT artifact_id, name, colour, note, created_at, actor "
                "FROM tag ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    def artifact_ids_for_tag(self, name: Optional[str] = None) -> List[str]:
        if name is None:
            rows = self.conn.execute(
                "SELECT DISTINCT artifact_id FROM tag").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT artifact_id FROM tag WHERE name=?", (name,)).fetchall()
        return [r[0] for r in rows]

    # ---------------------------------------------------------------- sources
    def register_source(self, path: str, sha256: str, size: int, parser: str,
                        count: int, notes: str = "") -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO source(path,sha256,size,parser,count,notes) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,"
                "size=excluded.size,parser=excluded.parser,count=excluded.count,"
                "notes=excluded.notes",
                (path, sha256, size, parser, count, notes))

    def sources(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM source ORDER BY count DESC, path")]

    def register_blob(self, sha256: str, size: int, md5: str = "", sha1: str = "",
                      mime: str = "", orig_path: str = "") -> None:
        from datetime import datetime, timezone
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO blob VALUES (?,?,?,?,?,?,?)",
                (sha256, size, md5, sha1, mime, orig_path,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")))

    def blob_info(self, sha256: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM blob WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None

    def all_blob_hashes(self) -> List[str]:
        return [r["sha256"] for r in self.conn.execute("SELECT sha256 FROM blob")]

    # ------------------------------------------------------------- aggregates
    def category_counts(self) -> Dict[str, int]:
        return {r["category"]: r["c"] for r in self.conn.execute(
            "SELECT category, COUNT(*) AS c FROM artifact GROUP BY category "
            "ORDER BY c DESC")}

    def app_counts(self) -> Dict[str, int]:
        return {r["app"]: r["c"] for r in self.conn.execute(
            "SELECT app, COUNT(*) AS c FROM artifact WHERE app<>'' "
            "GROUP BY app ORDER BY c DESC")}

    def recovery_counts(self) -> Dict[str, int]:
        return {r["recovery"]: r["c"] for r in self.conn.execute(
            "SELECT recovery, COUNT(*) AS c FROM artifact GROUP BY recovery")}

    def time_bounds(self) -> tuple[Optional[int], Optional[int]]:
        row = self.conn.execute(
            "SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM artifact "
            "WHERE timestamp IS NOT NULL").fetchone()
        return (row["lo"], row["hi"]) if row else (None, None)

    def facet_counts(self, where: str = "", params: Sequence[Any] = ()
                     ) -> Dict[str, Dict[str, int]]:
        """SQL-side facet tallies — O(groups) not O(rows)."""
        clause = f" WHERE {where}" if where else ""
        p = tuple(params)
        out: Dict[str, Dict[str, int]] = {
            "category": {}, "app": {}, "recovery": {}, "direction": {},
        }
        for field, key in (("category", "category"), ("app", "app"),
                           ("recovery", "recovery"), ("direction", "direction")):
            sql = (f"SELECT {field} AS k, COUNT(*) AS c FROM artifact"
                   f"{clause} GROUP BY {field} ORDER BY c DESC")
            for r in self.conn.execute(sql, p):
                label = r["k"] or ("(none)" if field == "app" else "(n/a)")
                out[key][str(label)] = int(r["c"])
        return out

    def statistics_fast(self, where: str = "", params: Sequence[Any] = (),
                          tz_offset_minutes: int = 0) -> Dict[str, Any]:
        """Aggregate statistics without hydrating every artifact."""
        clause = f" WHERE {where}" if where else ""
        p = tuple(params)
        total = self.count(where, params)
        ts_clause = clause + (" AND" if where else " WHERE") + " timestamp IS NOT NULL"
        timestamped = int(self.conn.execute(
            f"SELECT COUNT(*) FROM artifact{ts_clause}", p).fetchone()[0])
        bounds = self.conn.execute(
            f"SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi "
            f"FROM artifact{ts_clause}", p).fetchone()
        lo, hi = bounds["lo"], bounds["hi"]

        tz_shift = f"{tz_offset_minutes} minutes"
        hour_sql = (
            "SELECT CAST(strftime('%H', datetime(timestamp/1000000, "
            f"'unixepoch', '{tz_shift}')) AS INTEGER) AS h, COUNT(*) AS c "
            f"FROM artifact{ts_clause} GROUP BY h ORDER BY h")
        hour_map = {int(r["h"]): int(r["c"])
                    for r in self.conn.execute(hour_sql, p)}
        by_hour = [{"hour": h, "count": hour_map.get(h, 0)} for h in range(24)]

        wd_sql = (
            "SELECT CAST(strftime('%w', datetime(timestamp/1000000, "
            f"'unixepoch', '{tz_shift}')) AS INTEGER) AS d, COUNT(*) AS c "
            f"FROM artifact{ts_clause} GROUP BY d ORDER BY d")
        wd_map = {int(r["d"]): int(r["c"]) for r in self.conn.execute(wd_sql, p)}
        day_names = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
                     "Friday", "Saturday"]
        by_weekday = [{"day": day_names[d], "count": wd_map.get(d, 0)}
                      for d in range(7)]

        day_sql = (
            "SELECT strftime('%Y-%m-%d', datetime(timestamp/1000000, "
            f"'unixepoch', '{tz_shift}')) AS d, COUNT(*) AS c "
            f"FROM artifact{ts_clause} GROUP BY d ORDER BY d")
        by_day = [{"date": r["d"], "count": int(r["c"])}
                  for r in self.conn.execute(day_sql, p)]

        night = sum(hour_map.get(h, 0) for h in range(0, 6))
        total_h = sum(hour_map.values()) or 1
        peak_hour = max(hour_map, key=hour_map.get) if hour_map else None
        peak_day = max(by_day, key=lambda x: x["count"])["date"] if by_day else None

        geo_clause = clause + (" AND" if where else " WHERE") + (
            " latitude IS NOT NULL AND longitude IS NOT NULL")
        geo = int(self.conn.execute(
            f"SELECT COUNT(*) FROM artifact{geo_clause}", p).fetchone()[0])

        def _group(field: str, limit: Optional[int] = None) -> Dict[str, int]:
            sql = (f"SELECT {field} AS k, COUNT(*) AS c FROM artifact{clause} "
                   f"GROUP BY {field} ORDER BY c DESC")
            if limit:
                sql += f" LIMIT {int(limit)}"
            return {str(r["k"] or ""): int(r["c"])
                    for r in self.conn.execute(sql, p)}

        recovery = _group("recovery")
        deleted = sum(v for k, v in recovery.items()
                      if k != Recovery.ALLOCATED.value)

        US = 1_000_000
        from ..parsers.timestamps import to_iso
        return {
            "total_artifacts": total,
            "timestamped": timestamped,
            "undated": total - timestamped,
            "first_activity": to_iso(lo, tz_offset_minutes) if lo else "",
            "last_activity": to_iso(hi, tz_offset_minutes) if hi else "",
            "span_days": round((hi - lo) / (86400 * US), 1) if lo and hi else 0,
            "categories": _group("category"),
            "applications": {k: v for k, v in _group("app", 25).items() if k},
            "recovery": recovery,
            "directions": {k: v for k, v in _group("direction").items()
                           if k and k != "unknown"},
            "deleted_recovered": deleted,
            "total_call_seconds": 0,
            "total_call_display": "0h 00m 00s",
            "geolocated_artifacts": geo,
            "histogram": {
                "by_hour": by_hour,
                "by_weekday": by_weekday,
                "by_day": by_day,
                "by_category_day": {},
                "peak_hour": peak_hour,
                "peak_day": peak_day,
                "night_activity_pct": round(100.0 * night / total_h, 1),
                "active_days": len(by_day),
                "timezone_offset_minutes": tz_offset_minutes,
            },
            "bursts": [],
            "gaps": [],
            "anomalies": [],
            "fast_path": True,
        }

    def dashboard_slices(self, tz_offset_minutes: int = 0) -> Dict[str, Any]:
        """SQL-side slices for the analysis dashboard — no full row hydrate."""
        tz = f"{int(tz_offset_minutes)} minutes"
        dt = f"datetime(timestamp/1000000, 'unixepoch', '{tz}')"

        def rows(sql: str) -> List[Dict[str, Any]]:
            try:
                return [dict(r) for r in self.conn.execute(sql)]
            except sqlite3.Error:
                return []

        def labelled(sql: str) -> List[Dict[str, Any]]:
            out = []
            for r in rows(sql):
                lab = r.get("k")
                if lab is None or str(lab).strip() == "":
                    continue
                out.append({"label": str(lab), "count": int(r["c"] or 0)})
            return out

        subtypes = labelled(
            "SELECT category || ' · ' || CASE WHEN subtype='' THEN '(none)' "
            "ELSE subtype END AS k, COUNT(*) AS c FROM artifact "
            "GROUP BY category, subtype ORDER BY c DESC LIMIT 24")
        media = labelled(
            "SELECT CASE WHEN subtype='' THEN 'File' ELSE subtype END AS k, "
            "COUNT(*) AS c FROM artifact WHERE category = 'Files & Media' "
            "GROUP BY subtype ORDER BY c DESC LIMIT 12")
        media_gps = rows(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN latitude IS NOT NULL AND longitude IS NOT NULL "
            "THEN 1 ELSE 0 END) AS geo FROM artifact "
            "WHERE category = 'Files & Media'")
        domains = labelled(
            "SELECT json_extract(attributes, '$.domain') AS k, COUNT(*) AS c "
            "FROM artifact WHERE category = 'Web' "
            "AND json_extract(attributes, '$.domain') IS NOT NULL "
            "AND json_extract(attributes, '$.domain') <> '' "
            "GROUP BY k ORDER BY c DESC LIMIT 14")
        ssids = labelled(
            "SELECT COALESCE(NULLIF(json_extract(attributes, '$.ssid'), ''), "
            "NULLIF(body, '')) AS k, COUNT(*) AS c FROM artifact "
            "WHERE category = 'Networks' GROUP BY k ORDER BY c DESC LIMIT 12")
        accounts = labelled(
            "SELECT COALESCE(NULLIF(json_extract(attributes, '$.account_name'), ''), "
            "NULLIF(app, ''), 'account') AS k, COUNT(*) AS c FROM artifact "
            "WHERE category = 'Accounts' GROUP BY k ORDER BY c DESC LIMIT 12")
        msg_apps = labelled(
            "SELECT CASE WHEN app='' THEN '(unknown app)' ELSE app END AS k, "
            "COUNT(*) AS c FROM artifact WHERE category IN ('Messages','Chats') "
            "GROUP BY app ORDER BY c DESC LIMIT 12")
        call_dirs = labelled(
            "SELECT direction AS k, COUNT(*) AS c FROM artifact "
            "WHERE category = 'Calls' GROUP BY direction ORDER BY c DESC")
        durations = labelled(
            "SELECT CASE "
            "WHEN CAST(json_extract(attributes,'$.duration_seconds') AS REAL) IS NULL "
            "  OR CAST(json_extract(attributes,'$.duration_seconds') AS REAL) <= 0 "
            "  THEN 'unknown' "
            "WHEN CAST(json_extract(attributes,'$.duration_seconds') AS REAL) < 10 "
            "  THEN '<10s' "
            "WHEN CAST(json_extract(attributes,'$.duration_seconds') AS REAL) < 60 "
            "  THEN '10–60s' "
            "WHEN CAST(json_extract(attributes,'$.duration_seconds') AS REAL) < 300 "
            "  THEN '1–5m' "
            "WHEN CAST(json_extract(attributes,'$.duration_seconds') AS REAL) < 900 "
            "  THEN '5–15m' "
            "ELSE '>15m' END AS k, COUNT(*) AS c FROM artifact "
            "WHERE category = 'Calls' GROUP BY 1")
        heat = rows(
            f"SELECT CAST(strftime('%w', {dt}) AS INTEGER) AS d, "
            f"CAST(strftime('%H', {dt}) AS INTEGER) AS h, COUNT(*) AS c "
            f"FROM artifact WHERE timestamp IS NOT NULL GROUP BY d, h")
        daily_cat = rows(
            f"SELECT strftime('%Y-%m-%d', {dt}) AS d, category AS k, "
            f"COUNT(*) AS c FROM artifact WHERE timestamp IS NOT NULL "
            f"GROUP BY d, k ORDER BY d")
        geo_grid = rows(
            "SELECT ROUND(latitude, 3) AS lat, ROUND(longitude, 3) AS lon, "
            "COUNT(*) AS c, MIN(artifact_id) AS sample FROM artifact "
            "WHERE latitude IS NOT NULL AND longitude IS NOT NULL "
            "GROUP BY lat, lon ORDER BY c DESC LIMIT 80")
        blobs = rows(
            "SELECT COUNT(*) AS c FROM artifact WHERE blob_sha256 <> ''")
        web_sub = labelled(
            "SELECT CASE WHEN subtype='' THEN 'Visit' ELSE subtype END AS k, "
            "COUNT(*) AS c FROM artifact WHERE category = 'Web' "
            "GROUP BY subtype ORDER BY c DESC LIMIT 8")
        mg = media_gps[0] if media_gps else {"total": 0, "geo": 0}
        return {
            "subtypes": subtypes,
            "media": media,
            "media_total": int(mg["total"] or 0),
            "media_geo": int(mg["geo"] or 0),
            "domains": domains,
            "ssids": ssids,
            "accounts": accounts,
            "message_apps": msg_apps,
            "call_directions": call_dirs,
            "call_durations": durations,
            "hour_weekday": [
                {"d": int(r["d"]), "h": int(r["h"]), "count": int(r["c"])}
                for r in heat if r["d"] is not None and r["h"] is not None
            ],
            "daily_category": [
                {"date": r["d"], "label": r["k"], "count": int(r["c"])}
                for r in daily_cat if r["d"]
            ],
            "geo_clusters": [
                {"latitude": float(r["lat"]), "longitude": float(r["lon"]),
                 "count": int(r["c"]), "artifact_ids": [r["sample"]]}
                for r in geo_grid if r["lat"] is not None
            ],
            "with_blob": int(blobs[0]["c"]) if blobs else 0,
            "web_subtypes": web_sub,
        }

    def places_light(self, where: str = "", params: Sequence[Any] = (),
                     limit: int = 50_000) -> List[Dict[str, Any]]:
        clause = f" WHERE {where}" if where else ""
        extra = " AND" if where else " WHERE"
        sql = (
            f"SELECT artifact_id, latitude, longitude, timestamp, category, "
            f"app, substr(body, 1, 120) AS summary FROM artifact"
            f"{clause}{extra} latitude IS NOT NULL AND longitude IS NOT NULL "
            f"ORDER BY timestamp ASC LIMIT {int(limit)}")
        return [dict(r) for r in self.conn.execute(sql, tuple(params))]

    def timeline_buckets_sql(self, where: str = "", params: Sequence[Any] = (),
                             resolution: str = "hour",
                             tz_offset_minutes: int = 0) -> List[Dict[str, Any]]:
        clause = f" WHERE {where}" if where else ""
        extra = " AND" if where else " WHERE"
        tz_shift = f"{tz_offset_minutes} minutes"
        if resolution == "day":
            fmt = "%Y-%m-%d"
            label = "date"
        elif resolution == "week":
            fmt = "%Y-W%W"
            label = "week"
        else:
            fmt = "%Y-%m-%d %H:00"
            label = "hour"
        sql = (
            f"SELECT strftime('{fmt}', datetime(timestamp/1000000, "
            f"'unixepoch', '{tz_shift}')) AS bucket, COUNT(*) AS c "
            f"FROM artifact{clause}{extra} timestamp IS NOT NULL "
            f"GROUP BY bucket ORDER BY bucket")
        return [{"bucket": r["bucket"], "count": int(r["c"]), "label": label}
                for r in self.conn.execute(sql, tuple(params))]

    # ------------------------------------------------------------------ close
    def optimise(self) -> None:
        """Compact the store and drop out of WAL mode.

        Switching to ``journal_mode=DELETE`` matters for sealing: a WAL-mode
        database mutates its main file when the last connection closes, which
        would invalidate any digest taken beforehand.
        """
        if self.read_only:
            return
        with self.conn:
            self.conn.execute(
                "INSERT INTO artifact_fts(artifact_fts) VALUES('optimize')")
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("VACUUM")
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:                                     # pragma: no cover
            pass

    def __enter__(self) -> "ArtifactDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
