"""Analysis session — the XAMN half of the suite (lab manual §6).

An :class:`AnalysisSession` opens one or more sealed containers read-only and
exposes every view the manual asks for:

===============================  =====================================
Manual step                      Method
===============================  =====================================
14  Case info + category counts  :meth:`overview`
15  Pictures & Videos gallery    :meth:`gallery`
16  Call records list            :meth:`list_view`
17  Connection view (calls)      :meth:`connections`
18  Per-application artifacts    :meth:`application`
19  Connection view (messages)   :meth:`connections`
20  Contacts column view         :meth:`column_view`
21  Report / export              :mod:`argus.report`
===============================  =====================================

Containers are opened **read-only and verified on open**.  If a container's
seal does not match, the session still opens — an examiner needs to be able to
look at damaged evidence — but every response carries the integrity failure so
it cannot be reported as sound.
"""

from __future__ import annotations

import heapq
import itertools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.container import EvidenceContainer, resolve_container_path
from ..core.db import ArtifactDB
from ..core.models import Artifact, Category, Recovery
from ..parsers.timestamps import to_iso
from . import search as aql
from .graph import ConnectionGraph, build_graph
from .timeline import build as build_timeline, summarise


@dataclass
class LoadedContainer:
    container: EvidenceContainer
    verification: Dict[str, Any] = field(default_factory=dict)

    @property
    def db(self) -> ArtifactDB:
        return self.container.db

    @property
    def name(self) -> str:
        return self.container.path.name


class AnalysisSession:
    """Read-only analysis over one or more evidence containers."""

    def __init__(self, paths: Iterable[Path | str], deep_verify: bool = False,
                 owner_label: str = "Device owner",
                 tz_offset_minutes: int = 0,
                 cache_root: Optional[Path] = None):
        self.owner_label = owner_label
        self.tz_offset = tz_offset_minutes
        self.loaded: List[LoadedContainer] = []
        self._sidecars: Dict[str, ArtifactDB] = {}
        for p in paths:
            resolved = resolve_container_path(p, cache_root=cache_root)
            container = EvidenceContainer(resolved, mode="r")
            self.loaded.append(LoadedContainer(
                container=container,
                verification=container.verify(deep=deep_verify)))
        if not self.loaded:
            raise ValueError("no containers supplied to the analysis session")
        self._graph_cache: Dict[str, ConnectionGraph] = {}
        self._analytics_cache: Dict[str, Any] = {}

    # ------------------------------------------------------------- plumbing
    @property
    def primary(self) -> LoadedContainer:
        return self.loaded[0]

    def _all_artifacts(self, where: str = "", params: tuple = ()
                       ) -> List[Artifact]:
        out: List[Artifact] = []
        for lc in self.loaded:
            out.extend(lc.db.iter_artifacts(where, params))
        return out

    def _merge_counts(self, method: str) -> Dict[str, int]:
        merged: Dict[str, int] = {}
        for lc in self.loaded:
            for k, v in getattr(lc.db, method)().items():
                merged[k] = merged.get(k, 0) + v
        return dict(sorted(merged.items(), key=lambda kv: -kv[1]))

    @property
    def integrity_ok(self) -> bool:
        return all(lc.verification.get("ok") for lc in self.loaded)

    def integrity_report(self) -> Dict[str, Any]:
        return {
            "ok": self.integrity_ok,
            "containers": [
                {"name": lc.name, **lc.verification} for lc in self.loaded
            ],
        }

    # ------------------------------------------------------- Step 14 overview
    def overview(self) -> Dict[str, Any]:
        """Case info, data sources and category-wise artifact counts."""
        extraction = self.primary.container.extraction
        total = sum(lc.db.count() for lc in self.loaded)
        lo_all, hi_all = [], []
        for lc in self.loaded:
            lo, hi = lc.db.time_bounds()
            if lo:
                lo_all.append(lo)
            if hi:
                hi_all.append(hi)

        recovery = self._merge_counts("recovery_counts")
        return {
            "case_id": extraction.get("case_id", ""),
            "exhibit_id": extraction.get("exhibit_id", ""),
            "operator": extraction.get("operator", ""),
            "method": extraction.get("method", ""),
            "time_span": extraction.get("time_span", ""),
            "created_at": self.primary.container.manifest.get("created_at", ""),
            "started_at": extraction.get("started_at", ""),
            "finished_at": extraction.get("finished_at", ""),
            "device": {
                "make": extraction.get("device_make", ""),
                "model": extraction.get("device_model", ""),
                "os": extraction.get("device_os", ""),
                "serial": extraction.get("device_serial", ""),
                "imei": extraction.get("imei", ""),
                "iccid": extraction.get("iccid", ""),
                "phone_number": extraction.get("phone_number", ""),
                "lock_state": extraction.get("lock_state", ""),
            },
            "encryption_level": (
                "Sealed (Merkle + hash-chained audit)"
                if self.primary.container.sealed else "Unsealed — in progress"),
            "containers": [
                {"name": lc.name, "artifacts": lc.db.count(),
                 "sealed": lc.container.sealed,
                 "integrity_ok": lc.verification.get("ok", False),
                 "problems": lc.verification.get("problems", [])}
                for lc in self.loaded
            ],
            "total_artifacts": total,
            "categories": self._merge_counts("category_counts"),
            "applications": self._merge_counts("app_counts"),
            "recovery": recovery,
            "deleted_recovered": sum(
                v for k, v in recovery.items() if k != Recovery.ALLOCATED.value),
            "first_activity": to_iso(min(lo_all), self.tz_offset) if lo_all else "",
            "last_activity": to_iso(max(hi_all), self.tz_offset) if hi_all else "",
            "data_sources": [s for lc in self.loaded for s in lc.db.sources()],
            "tags": self._merged_tags(),
            "integrity": self.integrity_report(),
        }

    def triage(self) -> Dict[str, Any]:
        """Fast examiner snapshot — counts, encrypted stores, integrity alerts."""
        ov = self.overview()
        encrypted = []
        for src in ov.get("data_sources") or []:
            blob = f"{src.get('parser','')} {src.get('notes','')} {src.get('path','')}".lower()
            if any(tok in blob for tok in (
                    "sqlcipher", "encrypted", "crypt12", "crypt14", "crypt15",
                    "not decoded", "key required")):
                encrypted.append({
                    "path": src.get("path", ""),
                    "parser": src.get("parser", ""),
                    "notes": src.get("notes", ""),
                })
        apps = sorted((ov.get("applications") or {}).items(),
                      key=lambda kv: -int(kv[1] or 0))[:12]
        alerts: List[Dict[str, str]] = []
        integ = ov.get("integrity") or {}
        if not integ.get("ok", True):
            alerts.append({
                "level": "critical",
                "title": "Container integrity verification failed",
                "detail": "Do not treat this extraction as sealed evidence "
                          "until the problems are resolved.",
            })
        deleted = int(ov.get("deleted_recovered") or 0)
        if deleted:
            alerts.append({
                "level": "high",
                "title": f"{deleted:,} recovered deleted record(s)",
                "detail": "These were not live on the handset. Each carries "
                          "a recovery method and confidence.",
            })
        if encrypted:
            alerts.append({
                "level": "warn",
                "title": f"{len(encrypted)} encrypted store(s) identified",
                "detail": "ARGUS names encrypted evidence; it does not decrypt it.",
            })
        cats = ov.get("categories") or {}
        if not cats and int(ov.get("total_artifacts") or 0) == 0:
            alerts.append({
                "level": "warn",
                "title": "No artifacts decoded yet",
                "detail": "MTP media copies often need analysis to finish. "
                          "Open Analyse if ingest is still running.",
            })
        return {
            "total_artifacts": ov.get("total_artifacts") or 0,
            "deleted_recovered": deleted,
            "categories": cats,
            "top_apps": [{"app": name, "count": n} for name, n in apps],
            "encrypted_stores": encrypted[:40],
            "alerts": alerts,
            "first_activity": ov.get("first_activity") or "",
            "last_activity": ov.get("last_activity") or "",
            "integrity": integ,
            "device": ov.get("device") or {},
            "method": ov.get("method") or "",
        }

    def _merged_tags(self) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for lc in self.loaded:
            for db in (lc.db, self._sidecar(lc)):
                for t in db.tag_names():
                    cur = merged.setdefault(t["name"], {"name": t["name"],
                                                        "colour": t["colour"],
                                                        "count": 0})
                    cur["count"] += t["count"]
        return sorted(merged.values(), key=lambda t: -t["count"])

    def _artifact_tags(self, lc: LoadedContainer, art: Artifact) -> List[str]:
        names = list(art.tags or [])
        seen = set(names)
        for name in self._sidecar(lc).tags_for_artifact(art.artifact_id):
            if name not in seen:
                names.append(name)
                seen.add(name)
        return names

    _TAG_ANY = "artifact_id IN (SELECT artifact_id FROM tag)"
    _TAG_NAMED = "artifact_id IN (SELECT artifact_id FROM tag WHERE name = ?)"

    def _tag_ids_clause(self, lc: LoadedContainer,
                        tag_name: Optional[str]) -> Tuple[str, tuple]:
        ids: set = set()
        for db in (lc.db, self._sidecar(lc)):
            ids.update(db.artifact_ids_for_tag(tag_name))
        if not ids:
            return "0=1", ()
        placeholders = ",".join("?" * len(ids))
        return f"artifact_id IN ({placeholders})", tuple(sorted(ids))

    def _container_where(self, lc: LoadedContainer,
                         compiled: aql.CompiledQuery) -> Tuple[str, tuple]:
        """Compile AQL for one container, merging sidecar analyst tags."""
        where, params = compiled.where, list(compiled.params)
        if "FROM tag" not in where:
            return where, tuple(params)
        if self._TAG_NAMED in where:
            prefix = where.split("WHERE name = ?")[0]
            n_q = prefix.count("?")
            tag_name = params[n_q]
            tag_where, tag_params = self._tag_ids_clause(lc, tag_name)
            new_where = where.replace(self._TAG_NAMED, tag_where)
            new_params = params[:n_q] + list(tag_params) + params[n_q + 1:]
            return new_where, tuple(new_params)
        if self._TAG_ANY in where:
            tag_where, tag_params = self._tag_ids_clause(lc, None)
            new_where = where.replace(self._TAG_ANY, tag_where)
            return new_where, tag_params
        return where, tuple(params)

    def _merge_facet_counts(self, where: str, params: tuple
                            ) -> Dict[str, Dict[str, int]]:
        merged: Dict[str, Dict[str, int]] = {
            "category": {}, "app": {}, "recovery": {}, "direction": {},
        }
        for lc in self.loaded:
            facets = lc.db.facet_counts(where, params)
            for dim, counts in facets.items():
                for k, v in counts.items():
                    merged[dim][k] = merged[dim].get(k, 0) + v
        return merged

    def facets(self, aql_text: str = "") -> Dict[str, Any]:
        compiled = aql.compile_query(aql_text)
        tallies: Dict[str, Dict[str, int]] = {
            "category": {}, "app": {}, "recovery": {}, "direction": {},
        }
        total = 0
        for lc in self.loaded:
            where, params = self._container_where(lc, compiled)
            total += lc.db.count(where, params)
            facets = lc.db.facet_counts(where, params)
            for dim, counts in facets.items():
                for k, v in counts.items():
                    tallies[dim][k] = tallies[dim].get(k, 0) + v
        return {
            "total": total,
            "counted": total,
            "category": tallies["category"],
            "app": tallies["app"],
            "recovery": tallies["recovery"],
            "direction": tallies["direction"],
            "note": "SQL aggregate counts (full matching set)",
        }

    def _fast_statistics(self, aql_text: str = "") -> Dict[str, Any]:
        cache_key = f"stats:{aql_text}"
        if cache_key in self._analytics_cache:
            return self._analytics_cache[cache_key]
        compiled = aql.compile_query(aql_text)
        merged: Dict[str, Any] = {
            "total_artifacts": 0, "timestamped": 0, "undated": 0,
            "categories": {}, "applications": {}, "recovery": {},
            "directions": {}, "deleted_recovered": 0,
            "geolocated_artifacts": 0, "histogram": {},
            "bursts": [], "gaps": [], "anomalies": [],
            "fast_path": True,
        }
        hist_merged: Dict[str, Any] = {}
        for lc in self.loaded:
            part = lc.db.statistics_fast(
                compiled.where, compiled.params, self.tz_offset)
            merged["total_artifacts"] += part["total_artifacts"]
            merged["timestamped"] += part["timestamped"]
            merged["undated"] += part["undated"]
            merged["deleted_recovered"] += part["deleted_recovered"]
            merged["geolocated_artifacts"] += part["geolocated_artifacts"]
            for k, v in (part.get("categories") or {}).items():
                merged["categories"][k] = merged["categories"].get(k, 0) + v
            for k, v in (part.get("applications") or {}).items():
                merged["applications"][k] = merged["applications"].get(k, 0) + v
            for k, v in (part.get("recovery") or {}).items():
                merged["recovery"][k] = merged["recovery"].get(k, 0) + v
            for k, v in (part.get("directions") or {}).items():
                merged["directions"][k] = merged["directions"].get(k, 0) + v
            h = part.get("histogram") or {}
            for bucket in h.get("by_hour") or []:
                hist_merged.setdefault("by_hour", {})
                hist_merged["by_hour"][bucket["hour"]] = (
                    hist_merged["by_hour"].get(bucket["hour"], 0) + bucket["count"])
            for bucket in h.get("by_weekday") or []:
                hist_merged.setdefault("by_weekday", {})
                hist_merged["by_weekday"][bucket["day"]] = (
                    hist_merged["by_weekday"].get(bucket["day"], 0) + bucket["count"])
            for bucket in h.get("by_day") or []:
                hist_merged.setdefault("by_day", {})
                hist_merged["by_day"][bucket["date"]] = (
                    hist_merged["by_day"].get(bucket["date"], 0) + bucket["count"])
        if hist_merged.get("by_hour"):
            by_hour = hist_merged["by_hour"]
            merged["histogram"] = {
                "by_hour": [{"hour": h, "count": by_hour.get(h, 0)}
                            for h in range(24)],
                "by_weekday": [{"day": d, "count": c}
                               for d, c in (hist_merged.get("by_weekday") or {}).items()],
                "by_day": [{"date": d, "count": c}
                           for d, c in sorted((hist_merged.get("by_day") or {}).items())],
                "by_category_day": {},
                "peak_hour": max(by_hour, key=by_hour.get) if by_hour else None,
                "peak_day": (max((hist_merged.get("by_day") or {}).items(),
                                 key=lambda x: x[1])[0]
                             if hist_merged.get("by_day") else None),
                "night_activity_pct": round(
                    100.0 * sum(by_hour.get(h, 0) for h in range(0, 6))
                    / max(1, sum(by_hour.values())), 1),
                "active_days": len(hist_merged.get("by_day") or {}),
                "timezone_offset_minutes": self.tz_offset,
            }
        merged["applications"] = dict(sorted(
            merged["applications"].items(), key=lambda kv: -kv[1])[:25])
        self._analytics_cache[cache_key] = merged
        return merged

    # --------------------------------------------------------------- queries
    def query(self, aql_text: str = "", limit: int = 500, offset: int = 0,
              order: str = "timestamp DESC") -> Dict[str, Any]:
        """Run an AQL query across every loaded container."""
        compiled = aql.compile_query(aql_text)
        reverse = "DESC" in order.upper()
        total = 0
        fetch = max(limit + offset, limit)
        batches: List[List[Tuple[LoadedContainer, Artifact]]] = []

        def _sort_key(pair: Tuple[LoadedContainer, Artifact]) -> int:
            art = pair[1]
            if art.timestamp is not None:
                return int(art.timestamp)
            return -1 if reverse else 2**62

        for lc in self.loaded:
            where, params = self._container_where(lc, compiled)
            total += lc.db.count(where, params)
            batches.append([(lc, art) for art in lc.db.iter_artifacts(
                where, params, order=order, limit=fetch)])

        if not batches:
            window: List[Tuple[LoadedContainer, Artifact]] = []
        elif len(batches) == 1:
            window = batches[0][offset:offset + limit]
        else:
            merged = heapq.merge(
                *batches,
                key=_sort_key,
                reverse=reverse,
            )
            window = list(itertools.islice(merged, offset, offset + limit))

        return {
            "query": aql_text,
            "sql_where": compiled.where,
            "total": total,
            "returned": len(window),
            "offset": offset,
            "artifacts": [self._render(art, lc=lc) for lc, art in window],
        }

    def get(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        for lc in self.loaded:
            art = lc.db.get(artifact_id)
            if art:
                rendered = self._render(art, full=True, lc=lc)
                rendered["container"] = lc.name
                return rendered
        return None

    def _render(self, art: Artifact, full: bool = False,
                lc: Optional[LoadedContainer] = None) -> Dict[str, Any]:
        d = {
            "artifact_id": art.artifact_id,
            "category": art.category.value,
            "subtype": art.subtype,
            "timestamp": art.timestamp,
            "timestamp_iso": to_iso(art.timestamp, self.tz_offset),
            "app": art.app,
            "direction": art.direction.value,
            "body": art.body if full else art.summary(400),
            "parties": [{"label": p.label(), "identifier": p.identifier,
                         "role": p.role, "is_owner": p.is_owner}
                        for p in art.participants],
            "recovery": art.recovery.value,
            "is_deleted": art.recovery != Recovery.ALLOCATED,
            "confidence": art.confidence,
            "source_path": art.source_path,
            "source_table": art.source_table,
            "source_row": art.source_row,
            "blob_sha256": art.blob_sha256,
            "latitude": art.latitude, "longitude": art.longitude,
            "tags": self._artifact_tags(lc, art) if lc else art.tags,
        }
        if full:
            d["attributes"] = art.attributes
            d["timestamp_end"] = art.timestamp_end
            if art.blob_sha256:
                for lc in self.loaded:
                    info = lc.db.blob_info(art.blob_sha256)
                    if info:
                        d["blob"] = info
                        break
        else:
            # These are the attributes an examiner needs to see *in the list*,
            # not only after opening an artifact — each one changes how the row
            # should be read.
            d["attributes"] = {
                k: v for k, v in art.attributes.items()
                if k in ("duration_display", "duration_seconds", "filename",
                         "size_display", "url", "domain", "media_kind",
                         "is_group", "chat_name", "display_name",
                         "phone_numbers", "attachment_count", "mime_type",
                         "extension_mismatch", "has_gps", "search_terms",
                         # provenance and reliability flags
                         "previews_encrypted_app", "encrypted", "concealed",
                         "partial_record", "columns_unrecoverable",
                         "content_recovered", "extraction_method",
                         "schema_variant", "amount", "counterparty",
                         "package", "event", "duration_seconds", "stream")
            }
        return d

    # ------------------------------------------- Step 15 gallery (§6.2)
    def gallery(self, only_images: bool = False, with_gps: bool = False,
                app: str = "", limit: int = 500,
                offset: int = 0) -> Dict[str, Any]:
        """Pictures & Videos quick view, filterable by time, location and app."""
        clauses = [f"category = '{Category.FILE.value}'"]
        params: List[Any] = []
        if only_images:
            clauses.append("subtype = 'Picture'")
        else:
            clauses.append("subtype IN ('Picture','Video')")
        if with_gps:
            clauses.append("latitude IS NOT NULL")
        if app:
            clauses.append("app = ?")
            params.append(app)
        where = " AND ".join(clauses)

        items, total = [], 0
        for lc in self.loaded:
            total += lc.db.count(where, tuple(params))
            for art in lc.db.iter_artifacts(where, tuple(params),
                                            order="timestamp DESC",
                                            limit=limit, offset=offset):
                items.append({
                    **self._render(art),
                    "container": lc.name,
                    "filename": art.attributes.get("filename", ""),
                    "size_display": art.attributes.get("size_display", ""),
                    "mime_type": art.attributes.get("mime_type", ""),
                    "dimensions": _dimensions(art),
                    "map_url": art.attributes.get("map_url", ""),
                })
        return {"total": total, "returned": len(items), "items": items,
                "apps": [a for a in self._merge_counts("app_counts")]}

    # ------------------------------------------- Step 16/20 list & column view
    def list_view(self, category: str, limit: int = 1000,
                  offset: int = 0) -> Dict[str, Any]:
        cat = Category.coerce(category).value
        return self.query(f'category:"{cat}"', limit=limit, offset=offset)

    def column_view(self, category: str, limit: int = 2000,
                    offset: int = 0) -> Dict[str, Any]:
        """Flat tabular projection — the manual's 'Column view' (Fig. 6.7)."""
        cat = Category.coerce(category)
        columns = _COLUMNS.get(cat, _COLUMNS[Category.OTHER])
        compiled = aql.compile_query(f'category:"{cat.value}"')
        reverse = True
        fetch = limit + offset
        batches: List[List[Artifact]] = []
        total = 0
        for lc in self.loaded:
            total += lc.db.count(compiled.where, compiled.params)
            batches.append(list(lc.db.iter_artifacts(
                compiled.where, compiled.params,
                order="timestamp DESC", limit=fetch)))
        if not batches:
            window: List[Artifact] = []
        elif len(batches) == 1:
            window = batches[0][offset:offset + limit]
        else:
            def _sort_key(art: Artifact) -> int:
                return int(art.timestamp) if art.timestamp is not None else -1
            merged = heapq.merge(*batches, key=_sort_key, reverse=reverse)
            window = list(itertools.islice(merged, offset, offset + limit))
        rows = [_project(art, columns, self.tz_offset) for art in window]
        return {"category": cat.value, "columns": [c[0] for c in columns],
                "rows": rows, "count": len(rows), "total": total,
                "offset": offset, "returned": len(rows)}

    # ----------------------------------- Steps 17/19 connection view (§6.4/6.6)
    def connections(self, scope: str = "all", min_weight: int = 1,
                    max_nodes: int = 300) -> Dict[str, Any]:
        """Communication graph. ``scope``: all | calls | messages."""
        key = f"{scope}:{min_weight}"
        graph = self._graph_cache.get(key)
        if graph is None:
            where, params = "", ()
            if scope == "calls":
                where, params = "category = ?", (Category.CALL.value,)
            elif scope == "messages":
                where, params = ("category IN (?,?)",
                                 (Category.MESSAGE.value, Category.CHAT.value))
            graph = ConnectionGraph(owner_label=self.owner_label)
            cap = max(max_nodes * 40, 5000)
            for lc in self.loaded:
                graph.learn_contacts(lc.db.iter_artifacts(
                    "category = ?", (Category.CONTACT.value,),
                    limit=cap))
            for lc in self.loaded:
                graph.add(lc.db.iter_artifacts(where, params, limit=cap))
            graph.finalise()
            self._graph_cache[key] = graph

        data = graph.to_dict(min_weight=min_weight, max_nodes=max_nodes)
        data["scope"] = scope
        data["top_contacts"] = graph.top_contacts(15)
        data["brokers"] = graph.brokers(8)
        data["one_way"] = graph.one_way_contacts()[:10]
        return data

    # ---------------------------------------- Step 18 per-application (§6.5)
    def applications(self) -> List[Dict[str, Any]]:
        counts = self._merge_counts("app_counts")
        cat_rows: Dict[str, Dict[str, int]] = {}
        for lc in self.loaded:
            for r in lc.db.conn.execute(
                    "SELECT app, category, COUNT(*) AS c FROM artifact "
                    "WHERE app<>'' GROUP BY app, category"):
                app = r["app"]
                cat_rows.setdefault(app, {})
                cat_rows[app][r["category"]] = (
                    cat_rows[app].get(r["category"], 0) + r["c"])
        return [{"app": app, "count": count, "categories": cat_rows.get(app, {})}
                for app, count in counts.items()]

    def application(self, app: str, limit: int = 500) -> Dict[str, Any]:
        result = self.query(f'app:"{app}"', limit=limit)
        media = [a for a in result["artifacts"]
                 if a["category"] == Category.FILE.value]
        result["app"] = app
        result["media_count"] = len(media)
        return result

    # ------------------------------------------------------------- analytics
    def timeline(self, aql_text: str = "", limit: int = 20000
                 ) -> Dict[str, Any]:
        compiled = aql.compile_query(aql_text)
        artifacts = []
        for lc in self.loaded:
            artifacts.extend(lc.db.iter_artifacts(
                compiled.where, compiled.params, limit=limit))
        entries = build_timeline(artifacts, self.tz_offset)
        return {"query": aql_text, "count": len(entries),
                "entries": [e.as_dict() for e in entries]}

    def statistics(self, aql_text: str = "") -> Dict[str, Any]:
        stats = self._fast_statistics(aql_text)
        if stats.get("total_artifacts", 0) <= 25_000:
            compiled = aql.compile_query(aql_text)
            artifacts = []
            for lc in self.loaded:
                artifacts.extend(lc.db.iter_artifacts(
                    compiled.where, compiled.params))
            deep = summarise(artifacts, self.tz_offset)
            stats["bursts"] = deep.get("bursts", [])
            stats["gaps"] = deep.get("gaps", [])
            stats["anomalies"] = deep.get("anomalies", [])
            stats["total_call_seconds"] = deep.get("total_call_seconds", 0)
            stats["total_call_display"] = deep.get("total_call_display", "")
        return stats

    def places(self) -> Dict[str, Any]:
        """Every geolocated artifact, for the map view."""
        points = []
        for lc in self.loaded:
            for row in lc.db.places_light():
                points.append({
                    "artifact_id": row["artifact_id"],
                    "latitude": row["latitude"],
                    "longitude": row["longitude"],
                    "timestamp": row["timestamp"],
                    "iso": to_iso(row["timestamp"], self.tz_offset),
                    "category": row["category"],
                    "app": row["app"],
                    "summary": (row.get("summary") or "")[:90],
                })
        lats = [p["latitude"] for p in points]
        lons = [p["longitude"] for p in points]
        return {
            "count": len(points), "points": points,
            "bounds": {"min_lat": min(lats), "max_lat": max(lats),
                       "min_lon": min(lons), "max_lon": max(lons)} if points else {},
        }

    def places_enriched(self, precision: int = 3) -> Dict[str, Any]:
        """Clustered places with movement tracks for the map view."""
        from .visualize import cluster_places

        base = self.places()
        enriched = cluster_places(base.get("points") or [], precision=precision)
        enriched["bounds"] = base.get("bounds") or enriched.get("bounds", {})
        return enriched

    def timeline_buckets(self, aql_text: str = "", resolution: str = "hour",
                         limit: int = 100_000) -> Dict[str, Any]:
        """Server-side timeline aggregation for interactive charts."""
        from .visualize import timeline_buckets as _buckets

        compiled = aql.compile_query(aql_text)
        buckets: List[Dict[str, Any]] = []
        for lc in self.loaded:
            buckets.extend(lc.db.timeline_buckets_sql(
                compiled.where, compiled.params, resolution, self.tz_offset))
        merged: Dict[str, int] = {}
        for b in buckets:
            merged[b["bucket"]] = merged.get(b["bucket"], 0) + b["count"]
        entries = [{"bucket": k, "count": v, "label": resolution}
                     for k, v in sorted(merged.items())]
        if entries:
            return {"resolution": resolution, "buckets": entries[:limit]}
        data = self.timeline(aql_text, limit=min(limit, 5000))
        return _buckets(data.get("entries") or [], resolution=resolution,
                        tz_offset_minutes=self.tz_offset)

    def analytics_dashboard(self, aql_text: str = "") -> Dict[str, Any]:
        """Combined statistics + chart series for the analytics view."""
        from .visualize import chart_series

        stats = self.statistics(aql_text)
        hist = stats.get("histogram") or {}
        return {
            "statistics": stats,
            "charts": chart_series(hist),
            "query": aql_text,
        }

    def _recent_activity(self, limit: int = 12) -> List[Dict[str, Any]]:
        """Latest timestamped artifacts across all loaded containers."""
        merged: List[Tuple[int, Dict[str, Any]]] = []
        for lc in self.loaded:
            for art in lc.db.iter_artifacts(
                    "timestamp IS NOT NULL", (),
                    order="timestamp DESC", limit=limit):
                merged.append((int(art.timestamp), self._render(art, lc=lc)))
        merged.sort(key=lambda x: -x[0])
        return [row for _, row in merged[:limit]]

    def _parser_summary(self, limit: int = 14) -> List[Dict[str, Any]]:
        tallies: Dict[str, Dict[str, Any]] = {}
        for lc in self.loaded:
            for src in lc.db.sources():
                key = src.get("parser") or "(unknown)"
                rec = tallies.setdefault(key, {
                    "parser": key,
                    "artifacts": 0,
                    "paths": 0,
                    "notes": set(),
                })
                rec["artifacts"] += int(src.get("count")
                                        or src.get("artifact_count") or 0)
                rec["paths"] += 1
                note = (src.get("notes") or "").strip()
                if note:
                    rec["notes"].add(note[:120])
        out = []
        for rec in tallies.values():
            out.append({
                "parser": rec["parser"],
                "artifacts": rec["artifacts"],
                "paths": rec["paths"],
                "notes": sorted(rec["notes"])[:3],
            })
        out.sort(key=lambda x: (-x["artifacts"], -x["paths"]))
        return out[:limit]

    def _extraction_provenance(self) -> Dict[str, Any]:
        """Acquisition quality signals for the command center."""
        lc = self.primary
        ext = dict(lc.container.extraction or {})
        sources = lc.db.sources()
        files_decoded = sum(int(s.get("count") or 0) for s in sources)
        log_alerts: List[Dict[str, str]] = []
        for entry in lc.container.log_entries():
            if entry.get("level") in ("warning", "error"):
                log_alerts.append({
                    "module": str(entry.get("module") or ""),
                    "message": str(entry.get("message") or "")[:240],
                    "level": str(entry.get("level") or "warning"),
                })
        log_alerts = log_alerts[-12:]
        audits = list(ext.get("decode_audit") or [])
        mtp_hint = ""
        mtp_manifest = lc.container.path / "raw" / "argus-mtp-manifest.json"
        mtp_missing: List[str] = []
        if mtp_manifest.is_file():
            try:
                mtp_data = json.loads(mtp_manifest.read_text(encoding="utf-8"))
                listed = int(mtp_data.get("files_listed") or 0)
                copied = int(mtp_data.get("files_copied") or 0)
                pct = mtp_data.get("completeness_pct")
                if pct is None and listed:
                    pct = round(100.0 * copied / listed, 1)
                if listed and copied < listed:
                    mtp_hint = (f"MTP {copied:,}/{listed:,} files on disk "
                                f"({pct}%)")
                top_missing = mtp_data.get("top_missing_folders") or []
                mtp_missing = [f"{name} ({count})" for name, count in top_missing[:6]]
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        seen = int(ext.get("decode_files_seen") or 0)
        parsed = int(ext.get("decode_files_parsed") or 0)
        coverage = float(ext.get("decode_coverage_pct") or 0)
        if not coverage and seen:
            coverage = round(100.0 * parsed / seen, 1)
        return {
            "method": ext.get("method", ""),
            "operator": ext.get("operator", ""),
            "started_at": ext.get("started_at", ""),
            "finished_at": ext.get("finished_at", ""),
            "decode_files_seen": seen,
            "decode_files_parsed": parsed,
            "decode_files_skipped": int(ext.get("decode_files_skipped") or 0),
            "decode_coverage_pct": coverage,
            "source_paths": len(sources),
            "artifacts_from_sources": files_decoded,
            "decode_by_parser": ext.get("decode_by_parser") or {},
            "audit_warnings": audits,
            "log_alerts": log_alerts,
            "mtp_completeness": mtp_hint,
            "mtp_missing_folders": mtp_missing,
            "sealed": bool(lc.container.sealed),
            "acquisition_summary": ext.get("acquisition_summary") or {},
            "preprocess_summary": ext.get("preprocess_summary") or {},
            "device_make": ext.get("device_make", ""),
            "device_model": ext.get("device_model", ""),
        }

    def _comms_quality(self) -> Dict[str, Any]:
        """SMS/contacts/calls acquisition vs decode quality — critical on Vivo."""
        lc = self.primary
        ext = dict(lc.container.extraction or {})
        acq = ext.get("acquisition_summary") or {}
        cats = self._fast_statistics("").get("categories") or {}
        providers = acq.get("comms_providers") or []
        make = (ext.get("device_make") or "").lower()
        model = (ext.get("device_model") or "").lower()
        decoded = {
            "messages": int(cats.get(Category.MESSAGE.value, 0))
                        + int(cats.get(Category.CHAT.value, 0)),
            "calls": int(cats.get(Category.CALL.value, 0)),
            "contacts": int(cats.get(Category.CONTACT.value, 0)),
        }
        gaps = [a for a in (ext.get("decode_audit") or [])
                if a.get("code") in ("comms_gap", "providers_empty")]
        provider_rows = sum(int(p.get("rows") or 0) for p in providers)
        empty_providers = [p.get("key") for p in providers
                           if int(p.get("rows") or 0) == 0 and not p.get("skipped")]
        return {
            "decoded": decoded,
            "providers": providers,
            "logical_dumps": acq.get("data_types") or {},
            "provider_row_total": int(acq.get("comms_row_total") or provider_rows),
            "empty_providers": empty_providers,
            "gaps": gaps,
            "is_vivo": "vivo" in make or "bbk" in make or "y02" in model,
            "method": ext.get("method", ""),
            "pattern": (
                "vivo_fallback" if decoded["messages"] > 0
                and decoded["contacts"] == 0 and decoded["calls"] == 0
                else ("complete" if all(decoded.values()) else "partial")
            ),
        }

    def suggest_owner_identifiers(self) -> List[str]:
        """Phone/IMEI/ICCID from extraction metadata for attribution rules."""
        ids: set[str] = set()
        ext = dict(self.primary.container.extraction or {})
        for key in ("phone_number", "imei", "iccid", "device_serial"):
            val = str(ext.get(key) or "").strip()
            if val and val not in ("unknown", "—"):
                ids.add(val)
        dev = self.overview().get("device") or {}
        for key in ("phone_number", "imei", "iccid", "serial"):
            val = str(dev.get(key) or "").strip()
            if val:
                ids.add(val)
        return sorted(ids)

    def dashboard_visuals(self) -> Dict[str, Any]:
        """One payload for the analysis command center: counts, charts, health."""
        from .visualize import (chart_series, examination_health,
                                temporal_insights)

        ov = self.overview()
        triage = self.triage()
        stats = self._fast_statistics("")
        cats = stats.get("categories") or {}
        conn: Dict[str, Any] = {
            "nodes": [], "edges": [], "top_contacts": [],
            "brokers": [], "one_way": [], "stats": {},
        }
        try:
            conn = self.connections("all", 1, 48)
        except Exception:
            pass
        st = conn.get("stats") or {}

        slices: Dict[str, Any] = {
            "subtypes": [], "media": [], "media_total": 0, "media_geo": 0,
            "domains": [], "ssids": [], "accounts": [], "message_apps": [],
            "call_directions": [], "call_durations": [], "hour_weekday": [],
            "daily_category": [], "geo_clusters": [], "with_blob": 0,
            "web_subtypes": [],
        }
        heat = [[0] * 24 for _ in range(7)]
        daily_cat: Dict[str, Dict[str, int]] = {}
        geo: List[Dict[str, Any]] = []
        for lc in self.loaded:
            part = lc.db.dashboard_slices(self.tz_offset)
            for key in ("subtypes", "media", "domains", "ssids", "accounts",
                        "message_apps", "call_directions", "call_durations",
                        "web_subtypes"):
                bag: Dict[str, int] = {x["label"]: x["count"]
                                       for x in (slices[key] or [])}
                for item in part.get(key) or []:
                    bag[item["label"]] = bag.get(item["label"], 0) + item["count"]
                slices[key] = [
                    {"label": k, "count": v}
                    for k, v in sorted(bag.items(), key=lambda kv: -kv[1])
                ]
            slices["media_total"] += int(part.get("media_total") or 0)
            slices["media_geo"] += int(part.get("media_geo") or 0)
            slices["with_blob"] += int(part.get("with_blob") or 0)
            for cell in part.get("hour_weekday") or []:
                d, h = int(cell["d"]), int(cell["h"])
                if 0 <= d <= 6 and 0 <= h <= 23:
                    heat[d][h] += int(cell["count"])
            for row in part.get("daily_category") or []:
                daily_cat.setdefault(row["date"], {})
                daily_cat[row["date"]][row["label"]] = (
                    daily_cat[row["date"]].get(row["label"], 0)
                    + int(row["count"]))
            geo.extend(part.get("geo_clusters") or [])

        dates = sorted(daily_cat)[-45:]
        top_cats = [c["label"] for c in sorted(
            [{"label": k, "count": v} for k, v in cats.items()],
            key=lambda x: -x["count"])[:6]]
        stacked = []
        for day in dates:
            rec = {"date": day, "total": sum(daily_cat[day].values())}
            for cat in top_cats:
                rec[cat] = daily_cat[day].get(cat, 0)
            stacked.append(rec)

        geo.sort(key=lambda p: -p["count"])
        lats = [p["latitude"] for p in geo]
        lons = [p["longitude"] for p in geo]

        hist = stats.get("histogram") or {}
        charts = {
            **chart_series(hist),
            "hour_weekday": heat,
            "stacked_daily": stacked,
            "stack_keys": top_cats,
        }
        total = int(stats.get("total_artifacts") or 0)
        timestamped = int(stats.get("timestamped") or 0)
        coverage = {
            "timestamped_pct": round(100 * timestamped / max(total, 1), 1),
            "geolocated_pct": round(
                100 * int(stats.get("geolocated_artifacts") or 0) / max(total, 1), 1),
            "deleted_pct": round(
                100 * int(stats.get("deleted_recovered") or 0) / max(total, 1), 1),
            "blob_pct": round(
                100 * int(slices.get("with_blob") or 0) / max(total, 1), 1),
            "category_count": len([k for k, v in cats.items() if v]),
            "app_count": len(stats.get("applications") or {}),
            "source_count": len(ov.get("data_sources") or []),
            "comms_per_day": round(
                (int(cats.get(Category.CALL.value, 0))
                 + int(cats.get(Category.MESSAGE.value, 0))
                 + int(cats.get(Category.CHAT.value, 0)))
                / max(float(stats.get("span_days") or 0) or 1.0, 1.0), 1),
        }
        temporal = temporal_insights(hist, stacked)
        health = examination_health(
            integrity_ok=bool(ov.get("integrity", {}).get("ok", True)),
            total=total,
            timestamped=timestamped,
            categories=coverage["category_count"],
            alerts=len(triage.get("alerts") or []),
            encrypted_stores=len(triage.get("encrypted_stores") or []),
        )
        deep_stats: Dict[str, Any] = {}
        if total and total <= 25_000:
            try:
                full = self.statistics("")
                deep_stats = {
                    k: full.get(k)
                    for k in ("bursts", "gaps", "anomalies",
                              "total_call_display", "total_call_seconds")
                    if full.get(k)
                }
                if deep_stats.get("bursts"):
                    temporal["bursts"] = deep_stats["bursts"][:6]
                if deep_stats.get("gaps"):
                    temporal["gaps"] = deep_stats["gaps"][:3]
            except Exception:
                deep_stats = {}

        return {
            "overview": {
                "case_id": ov.get("case_id", ""),
                "exhibit_id": ov.get("exhibit_id", ""),
                "operator": ov.get("operator", ""),
                "method": ov.get("method", ""),
                "time_span": ov.get("time_span", ""),
                "created_at": ov.get("created_at", ""),
                "started_at": ov.get("started_at", ""),
                "finished_at": ov.get("finished_at", ""),
                "device": ov.get("device") or {},
                "encryption_level": ov.get("encryption_level", ""),
                "integrity_ok": ov.get("integrity", {}).get("ok", True),
                "containers": ov.get("containers") or [],
            },
            "triage": triage,
            "health": health,
            "coverage": coverage,
            "temporal": temporal,
            "recent": self._recent_activity(14),
            "parsers": self._parser_summary(),
            "tags": self._merged_tags()[:12],
            "total_artifacts": stats.get("total_artifacts", 0),
            "deleted_recovered": stats.get("deleted_recovered", 0),
            "geolocated": stats.get("geolocated_artifacts", 0),
            "timestamped": stats.get("timestamped", 0),
            "span_days": stats.get("span_days", 0),
            "first_activity": stats.get("first_activity", ""),
            "last_activity": stats.get("last_activity", ""),
            "categories": [
                {"label": k, "count": v}
                for k, v in sorted(cats.items(), key=lambda kv: -kv[1])
            ],
            "applications": [
                {"label": k, "count": v}
                for k, v in sorted(
                    (stats.get("applications") or {}).items(),
                    key=lambda kv: -kv[1])[:14]
            ],
            "recovery": [
                {"label": k or "(n/a)", "count": v}
                for k, v in (stats.get("recovery") or {}).items()
            ],
            "directions": [
                {"label": k, "count": v}
                for k, v in (stats.get("directions") or {}).items()
            ],
            "charts": charts,
            "total_call_display": deep_stats.get("total_call_display", ""),
            "anomalies": deep_stats.get("anomalies", []),
            "calls": int(cats.get(Category.CALL.value, 0)),
            "messages": (int(cats.get(Category.MESSAGE.value, 0))
                         + int(cats.get(Category.CHAT.value, 0))),
            "web": int(cats.get(Category.WEB.value, 0)),
            "places": int(cats.get(Category.PLACE.value, 0)),
            "calendar": int(cats.get(Category.CALENDAR.value, 0)),
            "accounts_n": int(cats.get(Category.ACCOUNT.value, 0)),
            "networks_n": int(cats.get(Category.NETWORK.value, 0)),
            "security_n": int(cats.get(Category.SECURITY.value, 0)),
            "contacts": {
                "book": int(cats.get(Category.CONTACT.value, 0)),
                "active": int(st.get("total_nodes", 0)),
                "shown": int(st.get("shown_nodes", 0)),
                "edge_count": int(st.get("total_edges", 0)),
                "top": conn.get("top_contacts") or [],
                "nodes": conn.get("nodes") or [],
                "links": conn.get("edges") or [],
                "brokers": conn.get("brokers") or [],
                "one_way": conn.get("one_way") or [],
            },
            "media": {
                "by_type": slices["media"],
                "total": slices["media_total"],
                "geotagged": slices["media_geo"],
                "with_blob": slices["with_blob"],
            },
            "web_domains": slices["domains"],
            "web_subtypes": slices["web_subtypes"],
            "ssids": slices["ssids"],
            "accounts": slices["accounts"],
            "message_apps": slices["message_apps"],
            "call_directions": slices["call_directions"],
            "call_durations": slices["call_durations"],
            "subtypes": slices["subtypes"][:18],
            "geo_clusters": geo[:80],
            "geo_bounds": {
                "min_lat": min(lats), "max_lat": max(lats),
                "min_lon": min(lons), "max_lon": max(lons),
            } if geo else {},
            "extraction": self._extraction_provenance(),
            "comms_quality": self._comms_quality(),
            "owner_suggestions": self.suggest_owner_identifiers(),
            "recommendations": self._examination_recommendations(),
        }

    def _examination_recommendations(self) -> List[Dict[str, Any]]:
        from ..intel.recommendations import build_recommendations
        intel = None
        cache = getattr(self, "_intel_cache", None) or {}
        if cache:
            intel = next(iter(cache.values()))
        return build_recommendations(self, intel)

    def invalidate_intel_cache(self) -> None:
        """Clear cached intelligence after re-decode or tagging changes."""
        self._intel_cache = {}

    def source_tree(self, limit: int = 500) -> Dict[str, Any]:
        """Filesystem / source-path tree — XAMN file-system view analogue."""
        bags: Dict[str, Dict[str, Any]] = {}
        for lc in self.loaded:
            for r in lc.db.conn.execute(
                    "SELECT source_path AS p, category AS k, COUNT(*) AS c "
                    "FROM artifact WHERE source_path <> '' "
                    "GROUP BY source_path, category "
                    "ORDER BY c DESC LIMIT ?", (int(limit),)):
                path = r["p"] or ""
                rec = bags.setdefault(path, {"path": path, "count": 0,
                                             "categories": {}})
                rec["count"] += int(r["c"])
                rec["categories"][r["k"]] = (
                    rec["categories"].get(r["k"], 0) + int(r["c"]))
        nodes = sorted(bags.values(), key=lambda x: -x["count"])[:limit]
        return {"count": len(nodes), "nodes": nodes}

    def hex_preview(self, sha256: str, offset: int = 0,
                    length: int = 4096) -> Dict[str, Any]:
        """First-page hex dump of a stored blob (XAMN hex viewer analogue)."""
        sha256 = (sha256 or "").lower().strip()
        located = self.blob_path(sha256)
        if located is None:
            return {"error": "blob not present", "sha256": sha256}
        path, mime, size = located
        offset = max(0, int(offset))
        length = min(max(16, int(length)), 16384)
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append({
                "offset": offset + i,
                "hex": hexpart,
                "ascii": ascii_part,
            })
        return {
            "sha256": sha256, "mime": mime, "size": size,
            "offset": offset, "length": len(data), "lines": lines,
        }

    def deleted(self, limit: int = 1000) -> Dict[str, Any]:
        """Everything recovered from unallocated space, highest confidence first."""
        return self.query("deleted:true", limit=limit,
                          order="confidence DESC, timestamp DESC")

    # ------------------------------------------------------------------ tags
    def _sidecar(self, lc: LoadedContainer) -> ArtifactDB:
        key = str(lc.container.path)
        if key not in self._sidecars:
            path = lc.container.path.parent / f"{lc.name}.analysis.db"
            self._sidecars[key] = ArtifactDB(path, read_only=False)
        return self._sidecars[key]

    def tag(self, artifact_id: str, name: str, colour: str = "#e2b33c",
            note: str = "", actor: str = "") -> bool:
        """Tagging writes to a sidecar DB so sealed evidence stays untouched."""
        for lc in self.loaded:
            if lc.db.get(artifact_id):
                self._sidecar(lc).tag(artifact_id, name, colour, note, actor)
                return True
        return False

    def untag(self, artifact_id: str, name: str) -> bool:
        for lc in self.loaded:
            if lc.db.get(artifact_id):
                self._sidecar(lc).untag(artifact_id, name)
                return True
        return False

    def list_tags(self) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for lc in self.loaded:
            for row in self._sidecar(lc).tag_names():
                key = row["name"]
                if key in merged:
                    merged[key]["count"] = int(merged[key]["count"]) + int(row["count"])
                else:
                    merged[key] = dict(row)
        return sorted(merged.values(), key=lambda r: -int(r.get("count", 0)))

    def bookmarks(self, tag_name: Optional[str] = None,
                  limit: int = 500) -> Dict[str, Any]:
        """Artifacts flagged in sidecar analysis DBs (sealed evidence untouched)."""
        items: List[Dict[str, Any]] = []
        for lc in self.loaded:
            for rec in self._sidecar(lc).tag_rows(tag_name):
                art = lc.db.get(rec["artifact_id"])
                if not art:
                    continue
                rendered = self._render(art, lc=lc)
                rendered["bookmark"] = rec
                items.append(rendered)
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {
            "count": len(items),
            "tag": tag_name or "",
            "artifacts": items,
        }

    def scan_keywords(self, terms: Optional[List[str]] = None, *,
                      text: str = "", path: str = "",
                      per_term: int = 25) -> Dict[str, Any]:
        from .keywords import load_terms, scan_keywords
        loaded = load_terms(terms or (), text=text, path=path)
        if not loaded:
            return {"terms": 0, "matched": 0, "unmatched": 0, "hits": []}
        return scan_keywords(self, loaded, per_term=per_term)

    def export_rows(self, aql_text: str = "", limit: int = 5000,
                    fmt: str = "csv") -> Tuple[bytes, str, str]:
        """Return ``(body, mime, filename)`` for the current result set."""
        import csv
        import io
        result = self.query(aql_text, limit=limit, order="timestamp DESC")
        rows = result.get("artifacts") or []
        if fmt == "json":
            body = json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")
            return body, "application/json; charset=utf-8", "argus-export.json"
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "timestamp", "category", "subtype", "app", "direction",
            "recovery", "parties", "body", "source_path", "artifact_id",
        ])
        for art in rows:
            parties = "; ".join(
                p.get("label") or p.get("identifier") or ""
                for p in (art.get("parties") or [])
                if not p.get("is_owner"))
            writer.writerow([
                art.get("timestamp_iso") or "",
                art.get("category") or "",
                art.get("subtype") or "",
                art.get("app") or "",
                art.get("direction") or "",
                art.get("recovery") or "",
                parties,
                (art.get("body") or "").replace("\r\n", " ").replace("\n", " "),
                art.get("source_path") or "",
                art.get("artifact_id") or "",
            ])
        return (buf.getvalue().encode("utf-8-sig"),
                "text/csv; charset=utf-8", "argus-export.csv")

    def blob(self, sha256: str) -> Optional[Tuple[bytes, str]]:
        """Return ``(bytes, mime)`` for a stored blob."""
        located = self.blob_path(sha256)
        if located is None:
            return None
        path, mime, _size = located
        return path.read_bytes(), mime

    def blob_path(self, sha256: str) -> Optional[Tuple[Path, str, int]]:
        """Return ``(path, mime, size)`` for streaming blob content."""
        for lc in self.loaded:
            if lc.container.has_blob(sha256):
                path = lc.container.blob_file(sha256)
                info = lc.db.blob_info(sha256) or {}
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                return (path, info.get("mime", "application/octet-stream"), size)
        return None

    def intelligence(self, owner_identifiers: Optional[List[str]] = None,
                     hashset_registry: Any = None,
                     progress: Optional[Any] = None,
                     force_media: bool = False,
                     force_fusion: bool = False) -> Dict[str, Any]:
        """Findings, entities, correlation and community structure.

        Cached per session: the rules walk every artifact several times, and an
        examiner switching between views should not pay for that repeatedly.
        """
        key = (tuple(sorted(owner_identifiers or ())),
               id(hashset_registry) if hashset_registry is not None else 0,
               bool(force_media), bool(force_fusion))
        cached = getattr(self, "_intel_cache", {}).get(key)
        if cached is not None and progress is None:
            return cached
        from ..intel import analyse
        result = analyse(self, owner_name=self.owner_label,
                         owner_identifiers=owner_identifiers or [],
                         hashset_registry=hashset_registry,
                         progress=progress,
                         force_media=force_media,
                         force_fusion=force_fusion)
        if not hasattr(self, "_intel_cache"):
            self._intel_cache = {}
        self._intel_cache[key] = result
        return result

    def extraction_log(self) -> List[Dict[str, Any]]:
        out = []
        for lc in self.loaded:
            for e in lc.container.log_entries():
                out.append({**e, "container": lc.name})
        return sorted(out, key=lambda e: e.get("ts", ""))

    def audit_trail(self) -> List[Dict[str, Any]]:
        out = []
        for lc in self.loaded:
            for e in lc.container.audit.entries():
                out.append({**e, "container": lc.name})
        return out

    def close(self) -> None:
        for sc in self._sidecars.values():
            try:
                sc.close()
            except Exception:
                pass
        self._sidecars.clear()
        for lc in self.loaded:
            lc.container.close()

    def __enter__(self) -> "AnalysisSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------- projections
_COLUMNS: Dict[Category, List[Tuple[str, str]]] = {
    Category.CONTACT: [
        ("Name", "attr:display_name"), ("Phone numbers", "attr:phone_numbers"),
        ("Emails", "attr:emails"), ("Organisation", "attr:organisation"),
        ("Account", "attr:account_name"), ("Source", "app"),
        ("Recovery", "recovery"), ("Modified", "time"),
    ],
    Category.CALL: [
        ("Time", "time"), ("Type", "subtype"), ("Party", "parties"),
        ("Direction", "direction"), ("Duration", "attr:duration_display"),
        ("App", "app"), ("Recovery", "recovery"),
    ],
    Category.MESSAGE: [
        ("Time", "time"), ("Type", "subtype"), ("Direction", "direction"),
        ("Party", "parties"), ("Message", "body"), ("App", "app"),
        ("Recovery", "recovery"),
    ],
    Category.FILE: [
        ("Time", "time"), ("Filename", "attr:filename"),
        ("Type", "attr:mime_type"), ("Size", "attr:size_display"),
        ("Source app", "app"), ("Path", "source_path"), ("SHA-256", "sha"),
    ],
    Category.WEB: [
        ("Time", "time"), ("Type", "subtype"), ("Title", "body"),
        ("URL", "attr:url"), ("Domain", "attr:domain"), ("App", "app"),
        ("Recovery", "recovery"),
    ],
    Category.PLACE: [
        ("Time", "time"), ("Type", "subtype"), ("Latitude", "lat"),
        ("Longitude", "lon"), ("App", "app"),
    ],
    Category.OTHER: [
        ("Time", "time"), ("Category", "category"), ("Type", "subtype"),
        ("Summary", "body"), ("App", "app"), ("Recovery", "recovery"),
    ],
}


def _project(art: Artifact, columns: List[Tuple[str, str]],
             tz: int) -> Dict[str, Any]:
    row: Dict[str, Any] = {"artifact_id": art.artifact_id}
    for label, spec in columns:
        if spec == "time":
            row[label] = to_iso(art.timestamp, tz)
        elif spec == "parties":
            row[label] = ", ".join(p.label() for p in art.counterparties())
        elif spec == "body":
            row[label] = art.summary(200)
        elif spec == "sha":
            row[label] = art.blob_sha256[:16]
        elif spec == "lat":
            row[label] = art.latitude
        elif spec == "lon":
            row[label] = art.longitude
        elif spec.startswith("attr:"):
            v = art.attributes.get(spec[5:], "")
            row[label] = ", ".join(str(x) for x in v) if isinstance(v, list) else v
        else:
            v = getattr(art, spec, "")
            row[label] = v.value if hasattr(v, "value") else v
    return row


def _dimensions(art: Artifact) -> str:
    exif = art.attributes.get("exif") or {}
    w, h = exif.get("width"), exif.get("height")
    return f"{w}×{h}" if w and h else ""
