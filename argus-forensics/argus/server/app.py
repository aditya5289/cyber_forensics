"""Local analysis server — serves the XAMN-style UI and a JSON API.

Deliberately built on the standard library only.  A forensic workstation is
frequently air-gapped and locked down; requiring a pip install of a web
framework to look at evidence is a real operational failure, so ARGUS has none.

Security posture: binds to ``127.0.0.1`` by default, serves exactly one
directory of evidence chosen at start-up, and never accepts a path from the
client that is not a container it already loaded.  There is no upload, no
write endpoint that touches sealed evidence, and no shell surface.
"""

from __future__ import annotations

import json
import mimetypes
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from ..analyze.session import AnalysisSession

UI_DIR = Path(__file__).resolve().parent.parent / "ui"
# The analyst surface. `xamn.html` is kept and still served at /xamn.html so an
# examiner mid-case is not forced onto a new layout by upgrading.
UI_FILE = UI_DIR / "analyst.html"
LEGACY_UI = UI_DIR / "xamn.html"


class _Handler(BaseHTTPRequestHandler):
    session: AnalysisSession
    server_version = "ARGUS/1.0"

    # ------------------------------------------------------------- responses
    def _send(self, code: int, body: bytes, ctype: str,
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def _error(self, code: int, message: str) -> None:
        self._json({"error": message, "status": code}, code)

    def log_message(self, fmt: str, *args) -> None:      # quieter console
        return

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:                            # noqa: N802
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        try:
            if route in ("/xamn.html", "/legacy"):
                return self._serve_named(LEGACY_UI)
            if route in ("/", "/index.html"):
                return self._serve_ui()
            if route.startswith("/api/"):
                return self._api(route[5:], query)
            if route.startswith("/blob/"):
                return self._serve_blob(route[6:])
            return self._error(404, f"no such route: {route}")
        except Exception as exc:                          # pragma: no cover
            return self._error(500, f"{type(exc).__name__}: {exc}")

    do_HEAD = do_GET

    # ------------------------------------------------------------------ UI
    def _serve_named(self, target: Path) -> None:
        if not target.exists():
            return self._error(404, f"not found: {target.name}")
        self._send(200, target.read_bytes(), "text/html; charset=utf-8")

    def _serve_ui(self) -> None:
        if not UI_FILE.exists():
            return self._error(500, f"UI not found at {UI_FILE}")
        self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")

    def _serve_blob(self, sha: str) -> None:
        sha = sha.split("/")[0].split("?")[0]
        if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
            return self._error(400, "invalid blob identifier")
        got = self.session.blob(sha)
        if got is None:
            return self._error(404, "blob not present in any loaded container")
        data, mime = got
        self._send(200, data, mime or "application/octet-stream",
                   {"Content-Disposition": f'inline; filename="{sha[:16]}"'})

    # ----------------------------------------------------------------- API
    def _api(self, endpoint: str, q: Dict[str, str]) -> None:
        s = self.session
        i = lambda k, d: int(q.get(k, d))                  # noqa: E731

        routes: Dict[str, Callable[[], Any]] = {
            "overview":    lambda: s.overview(),
            "search":      lambda: s.query(q.get("q", ""), i("limit", 200),
                                           i("offset", 0),
                                           q.get("order", "timestamp DESC")),
            "artifact":    lambda: s.get(q.get("id", "")) or
                                   {"error": "not found"},
            "gallery":     lambda: s.gallery(
                                only_images=q.get("images") == "1",
                                with_gps=q.get("gps") == "1",
                                app=q.get("app", ""),
                                limit=i("limit", 300), offset=i("offset", 0)),
            "connections": lambda: s.connections(q.get("scope", "all"),
                                                 i("min_weight", 1),
                                                 i("max_nodes", 300)),
            "applications": lambda: s.applications(),
            "application": lambda: s.application(q.get("app", ""),
                                                 i("limit", 300)),
            "column":      lambda: s.column_view(q.get("category", "Contacts"),
                                                 i("limit", 2000)),
            "timeline":    lambda: s.timeline(q.get("q", ""), i("limit", 5000)),
            "statistics":  lambda: s.statistics(q.get("q", "")),
            "places":      lambda: s.places(),
            "places/clusters": lambda: s.places_enriched(i("precision", 3)),
            "timeline/buckets": lambda: s.timeline_buckets(
                q.get("q", ""), q.get("resolution", "hour"),
                i("limit", 100_000)),
            "analytics":   lambda: s.analytics_dashboard(q.get("q", "")),
            "deleted":     lambda: s.deleted(i("limit", 500)),
            "log":         lambda: s.extraction_log(),
            "audit":       lambda: s.audit_trail(),
            "integrity":   lambda: s.integrity_report(),
            "suggest":     lambda: _suggest(s),

            # The intelligence layer was reachable only from the CLI, so the
            # findings, entities, conversations and attribution work was
            # invisible to anyone using the application — which is most people.
            "intel":       lambda: _intel_summary(s, q),
            "findings":    lambda: _intel(s, q).get("findings", []),
            "entities":    lambda: _intel(s, q).get("entities", {}),
            "communities": lambda: _intel(s, q).get("communities", {}),
            "conversations": lambda: _intel(s, q).get("conversations", {}),
            "fusion":      lambda: _intel(s, q).get("fusion", {}),
            "media_matching": lambda: _intel(s, q).get("media_matching", {}),
            "hashsets":    lambda: _intel(s, q).get("hashsets", {}),
            "correlation": lambda: _intel(s, q).get("correlation", {}),
            "facets":      lambda: _facets(s, q.get("q", "")),
        }
        fn = routes.get(endpoint.strip("/"))
        if fn is None:
            return self._error(404, f"unknown endpoint '{endpoint}'. "
                                    f"Available: {sorted(routes)}")
        return self._json(fn())

    # ----------------------------------------------------------------- POST
    def do_POST(self) -> None:                           # noqa: N802
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._error(400, "request body is not valid JSON")

        if route == "/api/tag":
            ok = self.session.tag(
                payload.get("artifact_id", ""), payload.get("name", ""),
                payload.get("colour", "#e2b33c"), payload.get("note", ""),
                payload.get("actor", "analyst"))
            return self._json({"ok": ok})
        return self._error(404, f"no such route: {route}")


def _owner_ids(q: Dict[str, str]) -> List[str]:
    raw = q.get("owner", "")
    return [part.strip() for part in raw.split(",") if part.strip()]


def _intel(s: AnalysisSession, q: Dict[str, str]) -> Dict[str, Any]:
    return s.intelligence(_owner_ids(q))


def _intel_summary(s: AnalysisSession, q: Dict[str, str]) -> Dict[str, Any]:
    """Counts only, so the dashboard renders without shipping every record."""
    data = _intel(s, q)
    findings = data.get("findings", {}) or {}
    entities = data.get("entities", {}) or {}
    communities = data.get("communities", {}) or {}
    conversations = data.get("conversations", {}) or {}
    fusion = data.get("fusion", {}) or {}
    return {
        "findings": {
            "total": findings.get("count", 0),
            "by_severity": findings.get("by_severity", {}),
            "top": findings.get("top", [])[:8],
        },
        "entities": {
            "total": entities.get("total_entities", 0),
            "by_type": entities.get("by_kind", {}),
            "high_value": entities.get("high_value", [])[:10],
        },
        "communities": {
            "count": communities.get("count", 0),
            "modularity": communities.get("modularity"),
            "meaningful": communities.get("structure_is_meaningful", False),
            "note": communities.get("interpretation", ""),
        },
        "conversations": {
            "count": conversations.get("conversation_count", 0),
            "with_deleted": conversations.get("threads_with_deleted_content", 0),
        },
        "fusion": {
            "events": fusion.get("events", 0),
            "by_attribution": fusion.get("by_attribution", {}),
            "coverage": fusion.get("coverage"),
            "telemetry_available": fusion.get("telemetry_available", False),
        },
        "media_matching": data.get("media_matching", {}),
    }


def _tally(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for value in values:
        out[str(value)] = out.get(str(value), 0) + 1
    return out


def _facets(s: AnalysisSession, aql_text: str = "") -> Dict[str, Any]:
    """Counts per facet for the current result set.

    Computed server-side over the whole result set rather than over the page
    the browser happens to be holding. A facet count taken from one page of 200
    rows would tell an examiner "3 deleted" when the answer is 340, and they
    would have no way to notice the difference.
    """
    page = s.query(aql_text, limit=200000, offset=0)
    rows = page.get("artifacts", [])
    return {
        "total": page.get("total", len(rows)),
        "counted": len(rows),
        "category": _tally(r.get("category", "") for r in rows),
        "app": _tally(r.get("app") or "(none)" for r in rows),
        "recovery": _tally(r.get("recovery", "") for r in rows),
        "direction": _tally(r.get("direction") or "(n/a)" for r in rows),
        "note": ("Counts cover every record matching this query, not just the "
                 "page on screen."),
    }


def _suggest(s: AnalysisSession) -> Dict[str, Any]:
    from ..analyze import search as aql
    merged = aql.suggest(s.primary.db)
    merged["category"] = list(s.overview()["categories"])
    merged["app"] = list(s.overview()["applications"])[:40]
    return merged


def _free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]


def serve(containers: List[Path | str], host: str = "127.0.0.1",
          port: int = 8742, open_browser: bool = True,
          deep_verify: bool = False, owner_label: str = "Device owner",
          tz_offset_minutes: int = 0) -> None:
    """Start the analysis server (blocking)."""
    session = AnalysisSession(containers, deep_verify=deep_verify,
                              owner_label=owner_label,
                              tz_offset_minutes=tz_offset_minutes)
    _Handler.session = session
    port = _free_port(port)
    httpd = ThreadingHTTPServer((host, port), _Handler)

    url = f"http://{host}:{port}/"
    overview = session.overview()
    print(f"\n  ARGUS XAMN — analysis server")
    print(f"  {'─' * 58}")
    print(f"  Case         {overview['case_id'] or '(none)'}")
    print(f"  Exhibit      {overview['exhibit_id'] or '(none)'}")
    print(f"  Device       {overview['device']['make']} "
          f"{overview['device']['model']} {overview['device']['os']}".rstrip())
    print(f"  Artifacts    {overview['total_artifacts']:,} "
          f"({overview['deleted_recovered']:,} recovered from deleted space)")
    print(f"  Integrity    {'VERIFIED' if overview['integrity']['ok'] else 'FAILED — see UI'}")
    print(f"  {'─' * 58}")
    print(f"  Open {url}\n  Press Ctrl-C to stop.\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.")
    finally:
        httpd.server_close()
        session.close()
