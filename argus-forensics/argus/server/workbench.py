"""ARGUS Workbench — the single-click application server.

Serves one browser app that carries an examiner through the entire lab manual:
verify device support, create the case, register the exhibit, run the
extraction while watching the live log, then analyse the result and export the
report. No command line, no separate analysis step.

Still standard library only. A forensic workstation is frequently locked down
or air-gapped, and an application that cannot start without a package index is
an application that cannot be used when it matters.

Security posture
----------------
* Binds to ``127.0.0.1`` only, and mints a random session token at start-up.
  Every API call must carry it. Without this, any web page open in the same
  browser could drive an examiner's forensic tool through localhost.
* Directory browsing is read-only and returns names and sizes, never contents.
* Sealed evidence has no write path. Acquisition writes only into the case
  folder chosen by the operator.
* No upload endpoint, no shell surface, no eval.
"""

from __future__ import annotations

import gzip
import json
import mimetypes
import os
import platform
import secrets
import socket
import string
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from ..analyze.session import AnalysisSession
from ..core.case import Case, Exhibit, discover_cases, generate_case_id
from ..core.container import EvidenceContainer, is_argus_container_archive, resolve_container_path
from ..core.errors import ArgusError, AcquisitionError
from ..core.models import Category
from ..devices.detect import detect_all, toolchain_status
from ..devices.manual import DeviceManual, LOCK_STATES
from .jobs import Job, JobRunner

UI_DIR = Path(__file__).resolve().parent.parent / "ui"
WORKBENCH_HTML = UI_DIR / "workbench.html"
XAMN_HTML = UI_DIR / "xamn.html"
ANALYST_HTML = UI_DIR / "analyst.html"

ALL_CATEGORIES = [c.value for c in Category]


# ---------------------------------------------------------------- app state
class Workbench:
    """Shared state for the running application."""

    def __init__(self, workspace: Path, token: str):
        self.workspace = Path(workspace).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.manual = DeviceManual()
        self.jobs = JobRunner()
        self._sessions: Dict[str, AnalysisSession] = {}
        self._lock = threading.Lock()
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        from ..core.hashsets import HashSetRegistry
        self.hashset_registry = HashSetRegistry()
        from ..devices.watch import DeviceWatcher
        self.watcher = DeviceWatcher()

    def run_intelligence(self, containers: List[str],
                         owner_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Intelligence pass — reuses the per-session cache."""
        session = self.session_for(containers)
        return session.intelligence(owner_ids or [],
                                      hashset_registry=self.hashset_registry)

    # ------------------------------------------------------- analysis cache
    def session_for(self, containers: List[str],
                    deep_verify: bool = False,
                    tz_offset_minutes: int = 0) -> AnalysisSession:
        """Open (or reuse) a read-only analysis session for these containers."""
        containers = _as_container_list(containers)
        key = "|".join(sorted(str(Path(c).resolve()) for c in containers))
        key = f"{key}|tz:{tz_offset_minutes}|deep:{deep_verify}"
        with self._lock:
            existing = self._sessions.get(key)
            if existing is not None:
                return existing
        session = AnalysisSession(
            [Path(c) for c in containers],
            deep_verify=deep_verify,
            cache_root=self.workspace / ".cache" / "containers",
            tz_offset_minutes=tz_offset_minutes,
        )
        with self._lock:
            self._sessions[key] = session
        return session

    def drop_session(self, containers: List[str]) -> None:
        key = "|".join(sorted(str(Path(c).resolve()) for c in containers))
        with self._lock:
            session = self._sessions.pop(key, None)
        if session:
            session.close()

    def close(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


# ------------------------------------------------------------------ helpers
def _drives() -> List[str]:
    """Enumerate root locations to offer in the folder picker."""
    roots: List[str] = []
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            path = f"{letter}:\\"
            if os.path.exists(path):
                roots.append(path)
    else:
        roots.append("/")
    home = str(Path.home())
    for candidate in (home, str(Path(home) / "Desktop"),
                      str(Path(home) / "Documents"),
                      str(Path(home) / "Downloads")):
        if os.path.isdir(candidate) and candidate not in roots:
            roots.append(candidate)
    return roots


def _browse(path: str) -> Dict[str, Any]:
    """List a directory. Read-only: names, sizes and types, never contents."""
    if not path:
        return {"path": "", "parent": "", "roots": _drives(),
                "dirs": [], "files": [], "is_root_list": True}
    target = Path(path).expanduser()
    try:
        target = target.resolve()
    except OSError:
        pass
    if not target.exists():
        raise ArgusError(f"path does not exist: {target}")
    if not target.is_dir():
        target = target.parent

    dirs, files = [], []
    try:
        for entry in sorted(os.scandir(target), key=lambda e: e.name.lower()):
            try:
                if entry.is_dir(follow_symlinks=False):
                    marker = ""
                    if entry.name.endswith(".afc"):
                        marker = "container"
                    elif os.path.exists(os.path.join(entry.path, "case.json")):
                        marker = "case"
                    elif os.path.exists(os.path.join(entry.path, "Manifest.db")):
                        marker = "ios-backup"
                    dirs.append({"name": entry.name, "path": entry.path,
                                 "kind": marker})
                elif entry.is_file(follow_symlinks=False):
                    size = entry.stat().st_size
                    lower = entry.name.lower()
                    kind = "file"
                    if lower.endswith(".ab"):
                        kind = "backup"
                    elif lower.endswith((".xry", ".xrycase", ".xrydump")):
                        kind = "msab-xry"
                    elif lower.endswith((".ufdr", ".ufd")):
                        kind = "cellebrite"
                    elif lower.endswith((".zip", ".tar", ".tgz")):
                        kind = "archive"
                        if lower.endswith(".zip") and zip_contains_manifest(Path(entry.path)):
                            kind = "container"
                    files.append({"name": entry.name, "path": entry.path,
                                  "size": size, "kind": kind})
            except OSError:
                continue
    except PermissionError as exc:
        raise ArgusError(f"cannot read {target}: {exc}") from exc

    return {
        "path": str(target),
        "parent": str(target.parent) if target.parent != target else "",
        "roots": _drives(),
        "dirs": dirs,
        "files": files[:600],
        "is_root_list": False,
    }


def _is_evidence_container(path: Path) -> bool:
    return is_argus_container_archive(path)


def zip_contains_manifest(path: Path) -> bool:
    from ..core.container import zip_contains_manifest as _zip_manifest
    return _zip_manifest(path)


def _shell_open(path: Path) -> None:
    """Reveal a folder or file in the desktop shell."""
    target = path.expanduser()
    try:
        target = target.resolve()
    except OSError:
        pass
    if not target.exists():
        raise ArgusError(f"path does not exist: {target}")
    if sys.platform == "win32":
        os.startfile(str(target if target.is_dir() else target.parent))
    elif sys.platform == "darwin":
        import subprocess
        subprocess.Popen(["open", str(target)], close_fds=True)
    else:
        import subprocess
        subprocess.Popen(["xdg-open", str(target)], close_fds=True)


def _classify_source(path: str) -> Dict[str, Any]:
    """Tell the operator what they just pointed at, before they commit to it."""
    from ..acquire import adapters

    p = Path(path).expanduser()
    if not p.exists():
        return {"ok": False, "kind": "missing",
                "detail": "That path does not exist."}

    if is_argus_container_archive(p):
        return {
            "ok": True,
            "kind": "argus-container",
            "adapter": "argus.container",
            "detail": ("ARGUS sealed extraction — import to attach to this case "
                       "and analyse immediately (no re-decode needed)."),
            "import_note": ("This is a portable ARGUS extraction. Import will "
                            "attach it to the case; all artifacts are already "
                            "decoded and ready for analysis."),
            "path": str(p),
            "is_directory": p.is_dir(),
        }

    described = adapters.describe(p)
    if described.get("ok") and described.get("adapter") == "msab.xry":
        from ..acquire.msab import inspect_header, resolve_case
        from ..acquire.opaque import triage

        resolved = resolve_case(p)
        target = resolved.carve_target
        assessment = triage(target)
        header = inspect_header(target)
        out: Dict[str, Any] = {
            "ok": True,
            "kind": "msab-xry",
            "adapter": described["adapter"],
            "detail": described["description"],
            "carvable": assessment.carvable,
            "entropy": assessment.entropy,
            "wrapper": assessment.wrapper or header.get("wrapper", ""),
            "embedded": assessment.embedded,
            "recommendation": assessment.recommendation,
            "import_note": (
                "ARGUS imports native MSAB containers directly — companion "
                "case pairs are resolved, zip archives extracted, and "
                "embedded files carved automatically."),
        }
        if resolved.data_path and resolved.data_path != p:
            out["companion_file"] = str(resolved.data_path)
            out["detail"] = (
                f"MSAB case index → data file {resolved.data_path.name} "
                f"({_human(resolved.data_path.stat().st_size)})")
        if resolved.notes:
            out["notes"] = resolved.notes
        if assessment.entropy > 7.5:
            out["warning"] = (
                "High entropy — contents appear compressed or encrypted. "
                "Carving will not recover files. Export from XAMN: "
                "Report/Export → Files or Extended XML.")
        elif assessment.carvable:
            out["warning"] = ""
        return out

    if described.get("ok") and described.get("adapter") == "cellebrite.ufdr":
        return {
            "ok": True,
            "kind": "cellebrite-ufdr",
            "adapter": described["adapter"],
            "detail": described["description"],
            "import_note": "UFDR archives are unpacked; Cellebrite decoded "
                           "content is recorded as foreign provenance.",
        }

    if p.is_file():
        from ..acquire.e01 import is_ewf
        if is_ewf(p):
            from ..devices.detect import find_tool
            has_tool = bool(find_tool("ewfexport"))
            return {
                "ok": True,
                "kind": "ewf-e01",
                "adapter": "ewf.e01",
                "detail": f"EnCase EWF/E01 image ({_human(p.stat().st_size)})",
                "import_note": (
                    "Converted to raw with ewfexport, then carved by signature."
                    if has_tool else
                    "Install libewf and add ewfexport to PATH to import."),
                "warning": ("" if has_tool else
                            "ewfexport is not installed — E01 cannot be read yet"),
            }
        from ..acquire.aff import is_aff
        if is_aff(p):
            from ..devices.detect import find_tool
            has_tool = bool(find_tool("affconvert"))
            return {
                "ok": True,
                "kind": "aff-image",
                "adapter": "aff.image",
                "detail": f"AFF forensic image ({_human(p.stat().st_size)})",
                "import_note": (
                    "Converted to raw with affconvert, then carved by signature."
                    if has_tool else
                    "Install AFFLIB and add affconvert to PATH to import."),
                "warning": ("" if has_tool else
                            "affconvert is not installed — AFF cannot be read yet"),
            }
        if p.suffix.lower() == ".ab":
            return {"ok": True, "kind": "android-backup",
                    "detail": "Android adb backup archive (.ab). If it is "
                              "AES-encrypted you will need the backup password."}
        if described.get("ok"):
            return {"ok": True, "kind": described.get("adapter", "import"),
                    "adapter": described.get("adapter"),
                    "detail": described.get("description", described.get("label", ""))}
        return {"ok": True, "kind": "file",
                "detail": f"Single file ({p.suffix or 'no extension'}). It will "
                          f"be parsed if a parser recognises it."}
    if (p / "Manifest.db").exists():
        try:
            from ..acquire.ios_backup import IOSBackup
            backup = IOSBackup(p)
            info = backup.device_info()
            return {
                "ok": True, "kind": "ios-backup",
                "detail": (f"iOS backup — {info.get('device_name') or 'unnamed'} "
                           f"{info.get('product_type')} iOS "
                           f"{info.get('product_version')}"),
                "encrypted": backup.encrypted,
                "device": info,
                "warning": ("This backup is encrypted. Produce an unencrypted "
                            "backup, or supply the password."
                            if backup.encrypted else ""),
            }
        except Exception as exc:
            return {"ok": True, "kind": "ios-backup",
                    "detail": f"iOS backup folder (could not read header: {exc})"}

    markers = {"android": ["data/data", "sdcard", "system/build.prop",
                           "data/system/packages.list"],
               "ios": ["HomeDomain", "CameraRollDomain", "MediaDomain"]}
    hits = {k: sum(1 for m in v if (p / m).exists()) for k, v in markers.items()}
    files = sum(1 for _ in p.rglob("*") if _.is_file())
    if hits["android"] > hits["ios"] and hits["android"]:
        kind, detail = "android-tree", "Android file-system tree"
    elif hits["ios"]:
        kind, detail = "ios-tree", "iOS logical file tree"
    else:
        kind, detail = "folder", "Folder — platform not recognised from layout"
    return {"ok": True, "kind": kind,
            "detail": f"{detail} · {files:,} files", "files": files}


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _conversations_full(session: Any, query: Dict[str, str]) -> Dict[str, Any]:
    """Thread list with full turn transcripts for the analysis UI."""
    from ..analyze.conversations import build_conversations

    builder = build_conversations(session, owner_name=session.owner_label)
    min_turns = int(query.get("min_turns", 2))
    turn_limit = int(query.get("turn_limit", 500))
    threads = builder.build(min_turns=min_turns)
    summary = builder.summary(min_turns=min_turns)
    summary["conversations"] = [
        t.as_dict(include_turns=True, turn_limit=turn_limit) for t in threads]
    return summary


def _wb_suggest(session: AnalysisSession) -> Dict[str, Any]:
    from ..analyze import search as aql
    merged = aql.suggest(session.primary.db)
    overview = session.overview()
    merged["category"] = list(overview.get("categories", {}))
    merged["app"] = list(overview.get("applications", {}))[:40]
    merged["tag"] = [t["name"] for t in session.list_tags()]
    return merged


# ----------------------------------------------------------------- handler
class _Handler(BaseHTTPRequestHandler):
    wb: Workbench
    server_version = f"ARGUS-Workbench/{__version__}"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ responses
    def _send(self, code: int, body: bytes, ctype: str,
              extra: Optional[Dict[str, str]] = None) -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _json(self, payload: Any, code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        extra: Dict[str, str] = {}
        accept = self.headers.get("Accept-Encoding", "")
        if len(body) > 2048 and "gzip" in accept:
            body = gzip.compress(body, compresslevel=6)
            extra["Content-Encoding"] = "gzip"
        self._send(code, body, "application/json; charset=utf-8", extra)

    def _send_file(self, path: Path, mime: str, *,
                   filename: str = "") -> None:
        """Stream a file from disk, honouring Range requests for video seek."""
        size = path.stat().st_size
        range_hdr = self.headers.get("Range", "")
        start, end = 0, size - 1
        partial = False
        if range_hdr.startswith("bytes="):
            partial = True
            spec = range_hdr[6:].strip()
            if "-" in spec:
                a, b = spec.split("-", 1)
                if a.strip():
                    start = int(a)
                if b.strip():
                    end = int(b)
            else:
                start = int(spec)
        start = max(0, min(start, size - 1 if size else 0))
        end = max(start, min(end, size - 1 if size else 0))
        length = end - start + 1
        code = 206 if partial else 200
        self.send_response(code)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        disp = filename or path.name
        self.send_header("Content-Disposition", f'inline; filename="{disp}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "private, max-age=3600")
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            with path.open("rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = fh.read(min(65536, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, code: int, message: str, **extra: Any) -> None:
        self._json({"error": message, "status": code, **extra}, code)

    def log_message(self, fmt: str, *args) -> None:
        return

    # ------------------------------------------------------------------ auth
    def _authorised(self, query: Dict[str, str]) -> bool:
        token = (query.get("token")
                 or self.headers.get("X-ARGUS-Token", ""))
        return secrets.compare_digest(str(token), self.wb.token)

    # ------------------------------------------------------------------- GET
    def do_GET(self) -> None:                                # noqa: N802
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            if route in ("/", "/index.html"):
                return self._serve_file(WORKBENCH_HTML, "text/html")
            if route == "/xamn.html":
                return self._serve_file(XAMN_HTML, "text/html")
            if route in ("/analyst.html", "/analysis.html"):
                return self._serve_file(ANALYST_HTML, "text/html")
            if route == "/api/ping":
                return self._json({"ok": True, "version": __version__})

            if route.startswith("/api/") or route.startswith("/blob/"):
                if not self._authorised(query):
                    return self._error(401, "invalid or missing session token")
            if route.startswith("/blob/"):
                return self._serve_blob(route[6:], query)
            if route.startswith("/api/"):
                return self._api_get(route[5:].strip("/"), query)
            return self._error(404, f"no such route: {route}")
        except ArgusError as exc:
            return self._error(400, str(exc))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:
            return self._error(500, f"{type(exc).__name__}: {exc}")

    do_HEAD = do_GET

    def _serve_file(self, path: Path, ctype: str) -> None:
        if not path.exists():
            return self._error(500, f"UI asset missing: {path.name}")
        self._send(200, path.read_bytes(), f"{ctype}; charset=utf-8")

    def _serve_blob(self, sha: str, query: Dict[str, str]) -> None:
        sha = sha.split("/")[0].split("?")[0]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            return self._error(400, "invalid blob identifier")
        containers = _containers_arg(query)
        if not containers:
            return self._error(400, "no container specified")
        session = self.wb.session_for(containers, tz_offset_minutes=_tz_offset(query))
        located = session.blob_path(sha)
        if located is None:
            return self._error(404, "blob not present in the loaded containers")
        path, mime, _size = located
        return self._send_file(path, mime or "application/octet-stream",
                               filename=sha[:16])

    # ------------------------------------------------------------- GET API
    def _api_get(self, endpoint: str, q: Dict[str, str]) -> None:
        wb = self.wb
        i = lambda k, d: int(q.get(k, d))                     # noqa: E731

        # ---- environment ------------------------------------------------
        if endpoint == "env":
            from ..core.selfcheck import report as selfcheck_report
            sc = selfcheck_report()
            verification = sc.get("verification", {})
            return self._json({
                "version": __version__,
                # The build ID belongs in the UI, not just in `selfcheck`. An
                # examiner with several extracted copies on different drives
                # has no way to tell from the screen which one is running, and
                # will troubleshoot a fixed bug in a stale folder for as long
                # as it takes someone to ask which build it is.
                "build": _installation_id(),
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "workspace": str(wb.workspace),
                "started_at": wb.started_at,
                "toolchain": toolchain_status(),
                "categories": ALL_CATEGORIES,
                "lock_states": list(LOCK_STATES),
                "capabilities": _feature_report(),
                "suggested_case_id": generate_case_id(),
                "selfcheck": {
                    "ok": bool(verification.get("ok", True)),
                    "installation_id": sc.get("installation_id", ""),
                    "mismatch_count": len(verification.get("mismatches", [])),
                    "mismatches": (verification.get("mismatches") or [])[:8],
                },
            })

        if endpoint == "browse":
            return self._json(_browse(q.get("path", "")))

        if endpoint == "classify":
            return self._json(_classify_source(q.get("path", "")))

        # ---- device manual ----------------------------------------------
        if endpoint == "diagnose":
            from ..devices.diagnose import diagnose, vendor_guidance_for
            report = diagnose()
            data = report.as_dict()
            make = q.get("make", "")
            if make and not data["vendor_guidance"]:
                data["vendor_guidance"] = vendor_guidance_for(make)
            return self._json(data)

        if endpoint == "devices":
            deep = q.get("deep", "1") != "0"
            refresh = q.get("refresh_adb", "0") == "1"
            return self._json(detect_all(deep=deep, refresh_adb=refresh))

        if endpoint == "watch":
            reset = q.get("reset") == "1"
            if reset:
                wb.watcher.reset()
            return self._json(wb.watcher.poll())

        if endpoint == "hashsets":
            reg = wb.hashset_registry
            return self._json({
                "sets": [s.as_dict() for s in reg.sets],
                "count": len(reg.sets),
            })

        if endpoint == "manual/search":
            hits = wb.manual.search(q.get("q", ""), limit=i("limit", 12))
            return self._json({"results": [p.as_dict() for p in hits]})

        if endpoint == "manual/show":
            return self._json(wb.manual.overview(q.get("q", "")))

        # ---- cases -------------------------------------------------------
        if endpoint == "cases":
            base = q.get("dir") or str(wb.workspace / "cases")
            return self._json({"dir": base, "cases": discover_cases(base)})

        if endpoint == "case":
            case = Case.open(q.get("path", ""), password=q.get("password") or None)
            return self._json(case.overview())

        if endpoint == "case/summary":
            case = Case.open(q.get("path", ""), password=q.get("password") or None)
            return self._json(case.overview())

        if endpoint == "case/activity":
            case = Case.open(q.get("path", ""), password=q.get("password") or None)
            entries = list(case.audit.entries())
            limit = i("limit", 20)
            activity = [{
                "seq": e.get("seq"),
                "ts": e.get("ts", ""),
                "actor": e.get("actor", ""),
                "action": e.get("action", ""),
                "detail": e.get("detail", {}),
            } for e in entries[-limit:]]
            activity.reverse()
            return self._json({"activity": activity, "count": len(entries)})

        if endpoint == "case/incomplete":
            case_path = q.get("case_path") or q.get("path", "")
            case = Case.open(case_path, password=q.get("password") or None)
            exhibit = q.get("exhibit_id", "")
            method = q.get("method", "")
            hits = case.incomplete_extractions(exhibit or None, method)
            return self._json({"incomplete": hits, "count": len(hits)})

        if endpoint == "containers":
            case = Case.open(q.get("path", ""), password=q.get("password") or None)
            return self._json({"containers": [str(p) for p in case.containers()]})

        # ---- jobs --------------------------------------------------------
        if endpoint == "job":
            job = wb.jobs.get(q.get("id", ""))
            if job is None:
                return self._error(404, "no such job")
            return self._json(job.snapshot(since=i("since", 0)))

        if endpoint == "jobs":
            return self._json({"jobs": wb.jobs.recent(i("limit", 20))})

        # ---- verification -------------------------------------------------
        if endpoint == "verify":
            containers = _containers_arg(q)
            out = []
            for c in containers:
                resolved = resolve_container_path(
                    c, cache_root=wb.workspace / ".cache" / "containers")
                container = EvidenceContainer(resolved, mode="r")
                try:
                    out.append({"container": Path(c).name,
                                **container.verify(deep=q.get("deep") == "1")})
                finally:
                    container.close()
            return self._json({"results": out,
                               "ok": all(r["ok"] for r in out)})

        # ---- analysis (delegated to AnalysisSession) ----------------------
        containers = _containers_arg(q)
        if not containers:
            return self._error(400,
                               f"endpoint '{endpoint}' requires ?containers=")
        s = wb.session_for(containers, tz_offset_minutes=_tz_offset(q))
        if endpoint == "export":
            body, mime, name = s.export_rows(
                q.get("q", ""), i("limit", 5000), q.get("format", "csv"))
            return self._send(200, body, mime, {
                "Content-Disposition": f'attachment; filename="{name}"',
            })
        routes: Dict[str, Callable[[], Any]] = {
            "overview":     lambda: s.overview(),
            "search":       lambda: s.query(q.get("q", ""), i("limit", 500),
                                            i("offset", 0),
                                            q.get("order", "timestamp DESC")),
            "artifact":     lambda: s.get(q.get("id", "")) or {"error": "not found"},
            "gallery":      lambda: s.gallery(only_images=q.get("images") == "1",
                                              with_gps=q.get("gps") == "1",
                                              app=q.get("app", ""),
                                              limit=i("limit", 300),
                                              offset=i("offset", 0)),
            "connections":  lambda: s.connections(q.get("scope", "all"),
                                                  i("min_weight", 1),
                                                  i("max_nodes", 300)),
            "applications": lambda: s.applications(),
            "application":  lambda: s.application(q.get("app", ""), i("limit", 300)),
            "column":       lambda: s.column_view(q.get("category", "Contacts"),
                                                  i("limit", 2000),
                                                  i("offset", 0)),
            "timeline":     lambda: s.timeline(q.get("q", ""), i("limit", 5000)),
            "statistics":   lambda: s.statistics(q.get("q", "")),
            "places":       lambda: s.places(),
            "places/clusters": lambda: s.places_enriched(i("precision", 3)),
            "timeline/buckets": lambda: s.timeline_buckets(
                q.get("q", ""), q.get("resolution", "hour"),
                i("limit", 100_000)),
            "analytics":    lambda: s.analytics_dashboard(q.get("q", "")),
            "dashboard":    lambda: s.dashboard_visuals(),
            "sources":      lambda: s.source_tree(i("limit", 500)),
            "hex":          lambda: s.hex_preview(q.get("sha", ""),
                                                  i("offset", 0),
                                                  i("length", 4096)),
            "intel":        lambda: _wb_intel_summary(s, q),
            "findings":     lambda: wb.run_intelligence(
                containers, _owner_ids(q)).get("findings", {}),
            "entities":     lambda: wb.run_intelligence(
                containers, _owner_ids(q)).get("entities", {}),
            "communities":  lambda: wb.run_intelligence(
                containers, _owner_ids(q)).get("communities", {}),
            "facets":       lambda: _wb_facets(s, q.get("q", "")),
            "deleted":      lambda: s.deleted(i("limit", 500)),
            "log":          lambda: s.extraction_log(),
            "audit":        lambda: s.audit_trail(),
            "integrity":    lambda: s.integrity_report(),
            "suggest":      lambda: _wb_suggest(s),
            "tags":         lambda: {"tags": s.list_tags()},
            "intelligence": lambda: wb.run_intelligence(
                containers, _owner_ids(q)),
            "conversations": lambda: _conversations_full(s, q),
            "fusion": lambda: wb.run_intelligence(
                containers, _owner_ids(q)).get("fusion", {}),
            "media_matching": lambda: wb.run_intelligence(
                containers, _owner_ids(q)).get("media_matching", {}),
            "triage": lambda: s.triage(),
            "keywords": lambda: s.scan_keywords(
                [t for t in (q.get("terms") or "").replace("\n", ",").split(",")
                 if t.strip()],
                text=q.get("text", ""),
                path=q.get("path", ""),
                per_term=i("per_term", 25)),
            "bookmarks": lambda: s.bookmarks(q.get("tag") or None,
                                             i("limit", 500)),
        }
        fn = routes.get(endpoint)
        if fn is None:
            return self._error(404, f"unknown endpoint '{endpoint}'")
        return self._json(fn())

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:                               # noqa: N802
        parsed = urlparse(self.path)
        route = unquote(parsed.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._error(400, "request body is not valid JSON")
        if not self._authorised({**query, "token": payload.get("token", "")}):
            return self._error(401, "invalid or missing session token")

        try:
            return self._api_post(route[5:].strip("/"), payload)
        except ArgusError as exc:
            return self._error(400, str(exc))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:
            return self._error(500, f"{type(exc).__name__}: {exc}")

    def _api_post(self, endpoint: str, body: Dict[str, Any]) -> None:
        wb = self.wb

        # ---- Steps 3–5: create the case ---------------------------------
        if endpoint == "case/new":
            base = body.get("dir") or str(wb.workspace / "cases")
            case = Case.create(
                base, case_id=body.get("case_id") or None,
                investigator=body.get("investigator", ""),
                organisation=body.get("organisation", ""),
                description=body.get("description", ""),
                password=body.get("password") or None)
            return self._json({"ok": True, "case_id": case.case_id,
                               "path": str(case.root),
                               "overview": case.overview()})

        if endpoint == "case/close":
            case = Case.open(body["case_path"],
                             password=body.get("password") or None)
            case.close_case(body.get("conclusion", ""))
            return self._json({"ok": True, "overview": case.overview()})

        # ---- register the exhibit ---------------------------------------
        if endpoint == "exhibit/add":
            case = Case.open(body["case_path"],
                             password=body.get("password") or None)
            exhibit = case.add_exhibit(Exhibit(
                exhibit_id=body["exhibit_id"],
                description=body.get("description", ""),
                make=body.get("make", ""), model=body.get("model", ""),
                imei=body.get("imei", ""), serial=body.get("serial", ""),
                phone_number=body.get("phone_number", ""),
                seized_at=body.get("seized_at", ""),
                seized_by=body.get("seized_by", ""),
                seized_from=body.get("seized_from", ""),
                condition=body.get("condition", ""),
                isolation=body.get("isolation", "")))
            warnings = []
            if not exhibit.isolation:
                warnings.append(
                    "No isolation method recorded. Manual §7 precaution 2: "
                    "place the device in airplane mode or a Faraday pouch to "
                    "prevent a remote wipe.")
            return self._json({"ok": True, "exhibit": exhibit.as_dict(),
                               "warnings": warnings,
                               "overview": case.overview()})

        # ---- Steps 8–13: run the extraction ------------------------------
        if endpoint == "acquire":
            return self._json(self._start_acquisition(body))

        if endpoint == "acquire/preview":
            return self._json(self._preview_acquisition(body))

        if endpoint == "acquire/preflight":
            return self._json(self._preflight_acquisition(body))

        if endpoint == "acquire/batch":
            return self._json(self._start_batch_acquisition(body))

        if endpoint == "validate":
            return self._json(self._start_validation(body))

        if endpoint == "certificate":
            return self._json(self._start_certificate(body))

        if endpoint == "bundle":
            return self._json(self._start_bundle(body))

        if endpoint == "container/export":
            container_path = Path(body.get("container", "")).expanduser()
            if not container_path.exists():
                raise ArgusError("extraction container not found")
            if not _is_evidence_container(container_path):
                raise ArgusError("not a valid evidence container (.afc folder)")
            dest_raw = body.get("dest", "")
            if dest_raw:
                dest = Path(dest_raw).expanduser()
            else:
                dest = container_path.parent / f"{container_path.name}.zip"
            dest.parent.mkdir(parents=True, exist_ok=True)
            with EvidenceContainer(container_path, mode="r") as container:
                out = container.export_zip(dest)
            return self._json({
                "ok": True,
                "path": str(out),
                "size": out.stat().st_size,
            })

        if endpoint == "shell/open":
            path = body.get("path", "")
            if not path:
                raise ArgusError("path is required")
            target = Path(path).expanduser()
            _shell_open(target)
            return self._json({"ok": True, "path": str(target)})

        if endpoint == "hashset/load":
            path = body.get("path", "")
            kind = body.get("kind", "known-good")
            if not path:
                raise ArgusError("hash set path is required")
            hs = wb.hashset_registry.load(path, kind=kind,
                                          name=body.get("name") or None)
            return self._json({"ok": True, "set": hs.as_dict(),
                               "count": len(wb.hashset_registry.sets)})

        if endpoint == "job/cancel":
            job = wb.jobs.get(body.get("id", ""))
            if job is None:
                return self._error(404, "no such job")
            job.request_cancel()
            return self._json({"ok": True})

        # ---- Step 21: report ---------------------------------------------
        if endpoint == "report":
            return self._json(self._start_report(body))

        if endpoint == "intelligence/run":
            return self._json(self._start_intelligence(body))

        # ---- tagging -------------------------------------------------------
        if endpoint == "tag":
            session = wb.session_for(body.get("containers", []),
                                     tz_offset_minutes=int(body.get("tz", 0)))
            ok = session.tag(body.get("artifact_id", ""), body.get("name", ""),
                             body.get("colour", "#e2b33c"),
                             body.get("note", ""), body.get("actor", "analyst"))
            return self._json({"ok": ok})

        if endpoint == "untag":
            session = wb.session_for(body.get("containers", []),
                                     tz_offset_minutes=int(body.get("tz", 0)))
            ok = session.untag(body.get("artifact_id", ""), body.get("name", ""))
            return self._json({"ok": ok})

        if endpoint == "keywords":
            session = wb.session_for(body.get("containers", []),
                                     tz_offset_minutes=int(body.get("tz", 0)))
            return self._json(session.scan_keywords(
                body.get("terms") or [],
                text=body.get("text", ""),
                path=body.get("path", ""),
                per_term=int(body.get("per_term", 25))))

        if endpoint == "session/drop":
            wb.drop_session(body.get("containers", []))
            return self._json({"ok": True})

        return self._error(404, f"no such route: /api/{endpoint}")

    # ------------------------------------------------- acquisition plumbing
    def _build_acquire_plan(self, body: Dict[str, Any], *, for_preview: bool = False):
        from ..acquire.engine import AcquisitionPlan
        from ..devices.detect import resolve_device, _looks_like_mtp_serial

        case = Case.open(body["case_path"], password=body.get("password") or None)
        categories = body.get("categories") or ALL_CATEGORIES
        method = body.get("method", "import")
        transport = body.get("transport", "")
        serial = body.get("serial") or ""

        # A connected MTP handset must never be treated as a folder import.
        if method == "import" and (transport == "mtp" or _looks_like_mtp_serial(serial)):
            method = "mtp"

        source_path = Path(body["source_path"]) if body.get("source_path") else None
        if method == "import" and source_path:
            cases_root = (self.wb.workspace / "cases").resolve()
            try:
                if source_path.resolve() == cases_root:
                    raise ArgusError(
                        "That path is your cases folder, not evidence. "
                        "Connect the handset and use MTP extraction, or browse "
                        "to a specific backup or export folder to import.")
            except ArgusError:
                raise
            except OSError:
                pass

        plan = AcquisitionPlan(
            method=method,
            time_span=body.get("time_span", "all"),
            categories=list(categories),
            operator=body.get("operator", ""),
            exhibit_id=body.get("exhibit_id", ""),
            lock_state=body.get("lock_state", "unlocked"),
            device_name=body.get("device_name", ""),
            serial=body.get("serial") or None,
            source_path=source_path,
            backup_password=body.get("backup_password") or None,
            whatsapp_recovery_key=body.get("whatsapp_recovery_key") or None,
            whatsapp_passphrase=body.get("whatsapp_passphrase") or None,
            recover_deleted=bool(body.get("recover_deleted", True)),
            carve_confidence=float(body.get("carve_confidence", 0.45)),
            owner_identifiers=[s.strip() for s in
                               str(body.get("owner", "")).split(",") if s.strip()],
            owner_name=body.get("owner_name", "Device owner"),
            notes=body.get("notes", ""),
            resume=bool(body.get("resume")),
            resume_container=body.get("resume_container") or None,
            # Safe by default: turbo silently disables deleted-record carving
            # (see apply_turbo_settings). An omitted field must mean full
            # depth, matching AcquisitionPlan's own default and what the UI
            # actually sends — it only sets turbo=true when the operator
            # explicitly picks the Turbo method.
            turbo=bool(body.get("turbo", False)))
        if not for_preview:
            plan.validate()
            # Capability is a property of device_name + lock_state + method,
            # not of whether hardware answers right now. Gating here means an
            # unsupported combination is refused before a live device is even
            # required, instead of being masked by "no device detected".
            self._assert_acquire_supported(plan, method)

        device = None
        if method != "import":
            device = resolve_device(
                plan.serial,
                transport=body.get("transport", ""),
                mtp_name=body.get("mtp_name", ""),
                device_name=plan.device_name,
            )
        elif not plan.source_path or not plan.source_path.exists():
            raise ArgusError("choose an evidence folder or backup file to import")
        return case, plan, device, method

    def _assert_acquire_supported(self, plan, method: str) -> None:
        wb = self.wb
        if not (plan.device_name and method != "import"):
            return
        # backup/ios_backup and mtp are not modeled as per-device capability
        # rows - manual.assert_supported already remaps every iOS method name
        # (filesystem, logical, comprehensive, turbo, mtp) onto "backup"
        # internally, so an Apple device must NOT be exempted from the check
        # below; that used to skip gating entirely for any Apple device name,
        # which let a BFU iPhone be accepted for "filesystem" acquisition.
        if method in ("backup", "ios_backup", "mtp"):
            return
        if method in ("comprehensive", "turbo"):
            try:
                wb.manual.get(plan.device_name)
            except Exception:
                return
            for m in ("logical", "filesystem"):
                try:
                    wb.manual.assert_supported(
                        plan.device_name, plan.lock_state, m)
                    return
                except Exception:
                    continue
            from ..core.errors import ArgusError
            label = "Comprehensive" if method == "comprehensive" else "Turbo"
            raise ArgusError(
                f"{label} extraction requires logical or filesystem "
                "support for this device and lock state.")
        else:
            wb.manual.assert_supported(plan.device_name, plan.lock_state, method)

    def _preview_acquisition(self, body: Dict[str, Any]) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []
        recommended = ""
        try:
            case, plan, device, method = self._build_acquire_plan(
                body, for_preview=True)
            if not plan.operator.strip():
                errors.append("Operator is required for chain of custody.")
            if not plan.exhibit_id.strip():
                errors.append("Select an exhibit before starting extraction.")
            if not plan.categories:
                errors.append("Select at least one artifact category.")
            try:
                self._assert_acquire_supported(plan, method)
            except Exception as exc:
                errors.append(str(exc))
            if plan.device_name and method != "import":
                try:
                    overview = self.wb.manual.overview(plan.device_name)
                    row = next(
                        (r for r in overview.get("capability_overview", [])
                         if r.get("lock_state") == plan.lock_state),
                        None)
                    if row:
                        recommended = row.get("recommended", "")
                except Exception:
                    pass
            serial = body.get("serial", "")
            if serial and method != "import":
                try:
                    from ..acquire.android_adb import AdbSession, get_device_state
                    from ..acquire.android_adb import probe_capabilities
                    if get_device_state(serial) == "device":
                        probe = probe_capabilities(AdbSession(serial))
                        if probe.get("authorized"):
                            recommended = probe.get("recommended_method") or recommended
                except Exception:
                    pass
            if method == "mtp" and device and device.transport != "mtp":
                warnings.append(
                    "Selected device is not in MTP mode — use MTP method only "
                    "when USB debugging is unavailable.")
            if method == "mtp" and plan.device_name.strip():
                try:
                    self.wb.manual.get(plan.device_name)
                except Exception:
                    warnings.append(
                        f"'{plan.device_name}' is not in the device manual — "
                        "MTP will still copy shared storage; verify the handset "
                        "manually (manual §7).")
            if method == "turbo":
                warnings.append(
                    "Turbo mode skips carving and pull verification for speed.")
            return {
                "ok": not errors,
                "errors": errors,
                "warnings": warnings,
                "recommended_method": recommended,
                "method": method,
                "device": device.name if device else "",
            }
        except ArgusError as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        return {
            "ok": False,
            "errors": errors,
            "warnings": warnings,
            "recommended_method": recommended,
            "method": body.get("method", "import"),
            "device": "",
        }

    def _preflight_acquisition(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Device + workstation checks before starting extraction."""
        import shutil

        preview = self._preview_acquisition(body)
        checks: List[Dict[str, Any]] = []
        errors = list(preview.get("errors") or [])
        warnings = list(preview.get("warnings") or [])

        case_path = body.get("case_path", "")
        if case_path:
            try:
                usage = shutil.disk_usage(Path(case_path).expanduser())
                free_gb = usage.free / (1024 ** 3)
                ok = free_gb >= 5
                checks.append({
                    "id": "disk", "label": "Host disk space",
                    "ok": ok,
                    "detail": f"{free_gb:.1f} GB free on case volume",
                })
                if not ok:
                    warnings.append(
                        f"Low disk space ({free_gb:.1f} GB) — long extractions "
                        f"need at least 5 GB free.")
            except OSError:
                checks.append({
                    "id": "disk", "label": "Host disk space",
                    "ok": True, "detail": "Could not measure — case path unknown",
                })

        method = preview.get("method", body.get("method", ""))
        serial = body.get("serial", "")
        transport = body.get("transport", "")

        if method != "import":
            from ..devices.diagnose import diagnose
            diag = diagnose()
            adb_ok = bool(diag.adb_available)
            checks.append({
                "id": "adb", "label": "ADB available",
                "ok": adb_ok,
                "detail": diag.adb_version[:60] if diag.adb_version else "not found",
            })
            if not adb_ok:
                errors.append("adb not found — install platform-tools or use Import.")

            if method in ("logical", "filesystem", "comprehensive", "turbo", "backup"):
                authorized = [d for d in diag.devices if d.state == "device"]
                target = next((d for d in authorized
                               if not serial or d.serial == serial), None)
                if authorized and target:
                    checks.append({
                        "id": "adb_auth", "label": "USB debugging authorized",
                        "ok": True,
                        "detail": f"{target.model or target.serial} ready",
                    })
                elif diag.devices:
                    bad = diag.devices[0]
                    checks.append({
                        "id": "adb_auth", "label": "USB debugging authorized",
                        "ok": False,
                        "detail": f"{bad.serial} is {bad.state}",
                    })
                    if bad.state == "unauthorized":
                        errors.append(
                            "USB debugging not authorized — unlock phone and tap Allow.")
                    elif bad.state == "offline":
                        warnings.append(
                            "Device offline — set USB mode to File transfer and replug.")
                else:
                    checks.append({
                        "id": "adb_auth", "label": "USB debugging authorized",
                        "ok": False, "detail": "No handset on adb bus",
                    })
                    if transport != "mtp":
                        warnings.append(
                            "No ADB device detected — enable USB debugging or use MTP.")

            if method == "comprehensive" and transport == "mtp":
                warnings.append(
                    "Handset is in MTP mode — Comprehensive needs USB debugging. "
                    "Switch to File transfer + enable Developer options, or use MTP method.")

            if method == "mtp":
                from ..acquire import mtp as mtp_mod
                mtp_ok = mtp_mod.available()
                checks.append({
                    "id": "mtp_platform", "label": "MTP platform",
                    "ok": mtp_ok,
                    "detail": "Windows Shell MTP" if mtp_ok
                    else "MTP requires Windows — use Import or enable ADB",
                })
                if not mtp_ok:
                    errors.append(
                        "MTP acquisition requires Windows with Shell namespace.")
                if serial and adb_ok:
                    from ..acquire.android_adb import AdbSession, probe_capabilities
                    probe = probe_capabilities(AdbSession(serial))
                    if probe.get("authorized"):
                        checks.append({
                            "id": "adb_upgrade", "label": "ADB available for upgrade",
                            "ok": True,
                            "detail": (f"Comprehensive recommended — "
                                       f"{probe.get('discovered_dbs', 0)} app DB(s) "
                                       f"reachable"),
                        })
                        if preview.get("recommended_method") != "comprehensive":
                            preview["recommended_method"] = "comprehensive"
                        warnings.append(
                            "USB debugging is authorized — Comprehensive will "
                            "capture SMS, contacts, and calls that MTP cannot.")
                    else:
                        checks.append({
                            "id": "adb_upgrade", "label": "ADB upgrade path",
                            "ok": False,
                            "detail": "Enable USB debugging for live comms",
                        })
                        warnings.append(
                            "MTP copies shared storage only. For SMS/calls/contacts, "
                            "enable Developer options → USB debugging on the handset.")

            for prob in (diag.problems or [])[:2]:
                warnings.append(prob.get("issue", "")[:200])
            for note in (diag.vendor_guidance or [])[:2]:
                checks.append({
                    "id": "vendor", "label": "Vendor guidance",
                    "ok": True, "detail": note[:180],
                })

        battery = body.get("battery")
        if battery is not None:
            try:
                pct = int(battery)
                ok = pct >= 20
                checks.append({
                    "id": "battery", "label": "Device battery",
                    "ok": ok, "detail": f"{pct}%",
                })
                if not ok:
                    warnings.append(
                        f"Battery at {pct}% — connect charger before long extraction.")
            except (TypeError, ValueError):
                pass

        if preview.get("recommended_method"):
            checks.append({
                "id": "method", "label": "Recommended method",
                "ok": method == preview["recommended_method"]
                      or method in ("comprehensive", "import"),
                "detail": preview["recommended_method"],
            })

        return {
            "ok": not errors and preview.get("ok", False),
            "errors": errors,
            "warnings": warnings,
            "checks": checks,
            "preview": preview,
        }

    def _start_acquisition(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..acquire.engine import AcquisitionEngine

        # _build_acquire_plan already gates capability (device_name + lock_state
        # + method) before resolving a live device, so an unsupported request
        # never gets this far.
        case, plan, device, method = self._build_acquire_plan(body)

        label = f"{plan.exhibit_id} · {method}"

        def work(job: Job) -> Dict[str, Any]:
            engine = AcquisitionEngine(
                case, manual=self.wb.manual,
                progress=lambda entry: job.emit(
                    entry.get("module", ""), entry.get("status", ""),
                    entry.get("message", ""), entry.get("level", "info"),
                    **{k: v for k, v in entry.items()
                       if k not in ("module", "status", "message", "level", "ts")}),
                cancel_check=job.cancelled)
            job.emit("job", "start", f"Extraction queued — {label}")
            try:
                report = engine.run(plan, device=device)
                if report.container:
                    self.wb.drop_session([report.container])
                return report.as_dict()
            except AcquisitionError as exc:
                if "cancelled" in str(exc).lower():
                    return {"status": "Cancelled", "warnings": [str(exc)]}
                raise

        job = self.wb.jobs.submit("acquire", work, label=label)
        return {"ok": True, "job_id": job.id, "label": label}

    def _start_batch_acquisition(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..acquire.batch import (BatchAcquisitionEngine, BatchAcquisitionPlan,
                                     BatchDeviceSpec, build_specs_from_connected)

        wb = self.wb
        case = Case.open(body["case_path"], password=body.get("password") or None)
        method = body.get("method", "comprehensive")
        devices_in = body.get("devices") or []

        if body.get("all_connected"):
            devices_in = [s.as_dict() for s in build_specs_from_connected(
                method=method, prefix=body.get("exhibit_prefix", "EXH"))]
        if not devices_in:
            raise ArgusError(
                "no devices in batch queue — select handsets or set all_connected")

        specs = [BatchDeviceSpec(
            serial=d.get("serial", ""),
            exhibit_id=d.get("exhibit_id", ""),
            device_name=d.get("device_name", ""),
            lock_state=d.get("lock_state", "unlocked"),
            method=d.get("method", method),
            resume=bool(d.get("resume")),
            notes=d.get("notes", ""),
            make=d.get("make", ""),
            model=d.get("model", ""),
            imei=d.get("imei", ""),
            transport=d.get("transport", ""),
            mtp_name=d.get("mtp_name", ""),
        ) for d in devices_in]

        plan = BatchAcquisitionPlan(
            operator=body.get("operator", ""),
            devices=specs,
            time_span=body.get("time_span", "all"),
            categories=body.get("categories") or ALL_CATEGORIES,
            stop_on_error=bool(body.get("stop_on_error")),
            auto_register_exhibits=bool(body.get("auto_register_exhibits", True)),
            exhibit_prefix=body.get("exhibit_prefix", "EXH"),
            recover_deleted=bool(body.get("recover_deleted", True)),
            carve_confidence=float(body.get("carve_confidence", 0.45)),
            owner_identifiers=[s.strip() for s in
                               str(body.get("owner", "")).split(",") if s.strip()],
            owner_name=body.get("owner_name", "Device owner"),
            # See the matching comment in _build_acquire_plan: an omitted
            # field must not silently disable deleted-record recovery.
            turbo=bool(body.get("turbo", False)),
        )
        plan.validate()

        label = f"batch · {len(specs)} device(s)"

        def work(job: Job) -> Dict[str, Any]:
            engine = BatchAcquisitionEngine(
                case, manual=wb.manual,
                progress=lambda entry: job.emit(
                    entry.get("module", ""), entry.get("status", ""),
                    entry.get("message", ""), entry.get("level", "info"),
                    **{k: v for k, v in entry.items()
                       if k not in ("module", "status", "message", "level", "ts")}))
            job.emit("job", "start", f"Batch extraction — {len(specs)} device(s)")
            return engine.run(plan).as_dict()

        job = wb.jobs.submit("batch", work, label=label)
        return {"ok": True, "job_id": job.id, "label": label, "count": len(specs)}

    def _start_validation(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..validate.harness import run_validation
        wb = self.wb
        out_dir = Path(body.get("out_dir") or (wb.workspace / "validation"))

        def work(job: Job) -> Dict[str, Any]:
            job.emit("validate", "start",
                     "Building reference corpus with known ground truth")
            report = run_validation(
                progress=lambda m: job.emit("validate", "running", m))
            data = report.as_dict()
            out_dir.mkdir(parents=True, exist_ok=True)
            target = out_dir / "validation_report.json"
            target.write_text(json.dumps(data, indent=2, default=str),
                              encoding="utf-8")
            summary = data["summary"]
            job.emit("validate", "ok",
                     f"{summary['tests_passed']}/{summary['tests_run']} tests "
                     f"passed · recall {summary['overall_recall']} · precision "
                     f"{summary['overall_precision']}")
            for cap, m in data["by_capability"].items():
                job.emit("validate", "result",
                         f"{cap}: recall={m['recall']} precision={m['precision']}"
                         f" ({m['passed']}/{m['tests']} passed)")
            data["report_path"] = str(target)
            return data

        job = wb.jobs.submit("validate", work, label="tool validation")
        return {"ok": True, "job_id": job.id}

    def _start_certificate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..validate.certificate import (ExaminerNote, build_certificate,
                                            generate_key, write_certificate)
        wb = self.wb
        containers = body.get("containers") or []
        if not containers:
            raise ArgusError("no containers selected for the certificate")
        out_dir = Path(body.get("out_dir") or (wb.workspace / "certificates"))

        def work(job: Job) -> Dict[str, Any]:
            job.emit("certificate", "start",
                     f"Re-hashing every blob in {len(containers)} container(s)")
            validation = None
            vpath = body.get("validation_path")
            if vpath and Path(vpath).exists():
                validation = json.loads(Path(vpath).read_text())
                job.emit("certificate", "ok", "validation report attached")
            notes = [ExaminerNote(author=body.get("examiner") or "examiner",
                                  text=n)
                     for n in (body.get("notes") or []) if n]
            key = generate_key() if body.get("seal") else None
            cert = build_certificate(
                [Path(c) for c in containers],
                examiner=body.get("examiner", ""),
                organisation=body.get("organisation", ""),
                reference=body.get("reference", ""),
                notes=notes, validation=validation,
                peer_reviewer=body.get("peer_reviewer", ""), key=key)
            target = write_certificate(
                cert, out_dir / (body.get("basename") or "certificate.json"))
            result = {"path": str(target),
                      "digest": cert["certificate_sha256"],
                      "all_verified": cert["all_containers_verified"],
                      "containers": len(cert["containers"]),
                      "validation_attached": cert["validation"]["performed"]}
            if key:
                key_path = Path(str(target) + ".key")
                key_path.write_text(key.hex(), encoding="utf-8")
                result["key_path"] = str(key_path)
                job.emit("certificate", "warning",
                         "Seal key written alongside the certificate. Move it "
                         "to separate storage — anyone holding it can re-seal "
                         "an altered certificate.", level="warning")
            job.emit("certificate", "ok" if cert["all_containers_verified"]
                     else "error",
                     f"Certificate issued: {target.name}"
                     + ("" if cert["all_containers_verified"]
                        else " — WITH VERIFICATION FAILURES recorded"),
                     level="info" if cert["all_containers_verified"] else "error")
            return result

        job = wb.jobs.submit("certificate", work,
                             label=f"{len(containers)} container(s)")
        return {"ok": True, "job_id": job.id}

    def _start_intelligence(self, body: Dict[str, Any]) -> Dict[str, Any]:
        wb = self.wb
        containers = body.get("containers") or []
        if not containers:
            raise ArgusError("no containers selected for intelligence analysis")
        owner_ids = [x.strip() for x in
                     str(body.get("owner", "")).split(",") if x.strip()]

        def work(job: Job) -> Dict[str, Any]:
            session = wb.session_for(
                containers, tz_offset_minutes=int(body.get("tz", 0)))
            if body.get("force"):
                session.invalidate_intel_cache()
            job.emit("intel", "start",
                     f"Running intelligence rules over {len(containers)} "
                     f"container(s)…")
            result = session.intelligence(
                owner_ids,
                hashset_registry=wb.hashset_registry,
                progress=lambda msg: job.emit("intel", "progress", msg))
            count = int((result.get("findings") or {}).get("count", 0))
            job.emit("intel", "ok",
                     f"Intelligence complete — {count:,} finding(s)")
            return result

        job = wb.jobs.submit(
            "intelligence", work,
            label=f"intelligence · {len(containers)} container(s)")
        return {"ok": True, "job_id": job.id}

    def _start_report(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..report.builder import ReportBuilder, ReportOptions

        wb = self.wb
        containers = body.get("containers") or []
        if not containers:
            raise ArgusError("no containers selected for the report")
        out_dir = Path(body.get("out_dir") or (wb.workspace / "reports"))
        formats = body.get("formats") or ["html"]

        opts = ReportOptions(
            title=body.get("title") or "Mobile Device Forensic Examination Report",
            scope=body.get("scope", "all"),
            query=body.get("query", ""),
            selected_ids=body.get("selected_ids") or [],
            formats=list(formats),
            include_deleted=bool(body.get("include_deleted", True)),
            include_graph=bool(body.get("include_graph", True)),
            include_timeline=bool(body.get("include_timeline", True)),
            include_log=bool(body.get("include_log", False)),
            include_audit=bool(body.get("include_audit", False)),
            include_intelligence=bool(body.get("include_intelligence", True)),
            owner_identifiers=[x.strip() for x in
                               str(body.get("owner", "")).split(",") if x.strip()],
            examiner=body.get("examiner", ""),
            organisation=body.get("organisation", ""),
            reference=body.get("reference", ""),
            conclusion=body.get("conclusion", ""))

        def work(job: Job) -> Dict[str, Any]:
            job.emit("report", "start",
                     f"Verifying {len(containers)} container(s) before export")
            with AnalysisSession([Path(c) for c in containers],
                                 deep_verify=True) as session:
                if not session.integrity_ok:
                    job.emit("report", "warning",
                             "Integrity verification FAILED — the report will "
                             "carry a prominent warning on its first page.",
                             level="warning")
                else:
                    job.emit("report", "ok", "Integrity verified")
                builder = ReportBuilder(session, opts)
                job.emit("report", "building",
                         f"{builder.data['artifact_count']:,} artifacts "
                         f"({builder.data['deleted_count']:,} recovered from "
                         f"deleted space)")
                written = builder.write(out_dir, body.get("basename")
                                        or "forensic_report")
                for p in written:
                    job.emit("report", "ok",
                             f"{p.name} — {_human(p.stat().st_size)}")
                return {
                    "files": [{"path": str(p), "name": p.name,
                               "size": p.stat().st_size} for p in written],
                    "artifact_count": builder.data["artifact_count"],
                    "deleted_count": builder.data["deleted_count"],
                    "out_dir": str(out_dir),
                    "integrity_ok": session.integrity_ok,
                }

        job = wb.jobs.submit("report", work,
                             label=f"{len(containers)} container(s)")
        return {"ok": True, "job_id": job.id}

    def _start_bundle(self, body: Dict[str, Any]) -> Dict[str, Any]:
        from ..report.disclosure import write_disclosure_bundle

        wb = self.wb
        containers = body.get("containers") or []
        if not containers:
            raise ArgusError("no containers selected for the disclosure bundle")
        out_dir = Path(body.get("out_dir") or (wb.workspace / "disclosure"))

        def work(job: Job) -> Dict[str, Any]:
            return write_disclosure_bundle(
                [Path(c) for c in containers], out_dir,
                examiner=body.get("examiner", ""),
                organisation=body.get("organisation", ""),
                reference=body.get("reference", ""),
                conclusion=body.get("conclusion", ""),
                owner_identifiers=[x.strip() for x in
                                   str(body.get("owner", "")).split(",")
                                   if x.strip()],
                emit=lambda *a, **k: job.emit(*a, **k))

        job = wb.jobs.submit("bundle", work,
                             label=f"disclosure · {len(containers)} container(s)")
        return {"ok": True, "job_id": job.id}


def _as_container_list(raw: Any) -> List[str]:
    if isinstance(raw, (list, tuple)):
        out = []
        for item in raw:
            out.extend(_as_container_list(item))
        return out
    if not raw:
        return []
    text = str(raw)
    if "\n" in text:
        return [c.strip() for c in text.split("\n") if c.strip()]
    return [text]


def _containers_arg(q: Dict[str, str]) -> List[str]:
    return _as_container_list(q.get("containers") or q.get("container") or "")


def _tz_offset(q: Dict[str, str]) -> int:
    try:
        return int(q.get("tz", q.get("tz_offset", "0")))
    except (TypeError, ValueError):
        return 0


def _installation_id() -> str:
    """Short build identifier, or "" if it cannot be determined."""
    try:
        from ..core.selfcheck import installation_id
        return installation_id()[:12]
    except Exception:                                     # pragma: no cover
        return ""


def _feature_report() -> Dict[str, Any]:
    """What optional capabilities are actually available in this install."""
    def has(mod: str) -> bool:
        try:
            __import__(mod)
            return True
        except ImportError:
            return False
    return {
        "exif": {"available": has("PIL"), "provides": "EXIF and GPS from images",
                 "install": "pip install pillow"},
        "xlsx": {"available": has("openpyxl"), "provides": "Excel export",
                 "install": "pip install openpyxl"},
        "docx": {"available": has("docx"), "provides": "Word export",
                 "install": "pip install python-docx"},
        "pdf": {"available": has("reportlab"), "provides": "PDF export",
                "install": "pip install reportlab"},
        "encrypted_backup": {"available": has("Crypto"),
                             "provides": "encrypted Android .ab backups",
                             "install": "pip install pycryptodome"},
    }


def _owner_ids(q: Dict[str, str]) -> List[str]:
    return [p.strip() for p in q.get("owner", "").split(",") if p.strip()]


def _wb_facets(session: Any, aql_text: str = "") -> Dict[str, Any]:
    return session.facets(aql_text)


def _wb_intel_summary(session: Any, q: Dict[str, str]) -> Dict[str, Any]:
    data = session.intelligence(_owner_ids(q))
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
        "recommendations": session.dashboard_visuals().get("recommendations", []),
    }


# --------------------------------------------------------------------- serve
def _free_port(preferred: int) -> int:
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", candidate))
                return sock.getsockname()[1]
            except OSError:
                continue
    return preferred


def serve(workspace: Path | str = "~/ARGUS", port: int = 8742,
          open_browser: bool = True, quiet: bool = False,
          token: str | None = None, ready_json: bool = False) -> None:
    """Start the workbench application (blocking).

    When *ready_json* is True, emit a single JSON line on stdout once the
    server is listening (used by the Tauri desktop shell to discover port/token).
    An explicit *token* may be supplied by the host; otherwise one is generated.
    """
    token = token or secrets.token_urlsafe(24)
    wb = Workbench(Path(workspace), token)
    _Handler.wb = wb
    port = _free_port(port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}/#token={token}"

    if ready_json:
        import json as _json
        from argus.core.selfcheck import installation_id
        print(_json.dumps({
            "event": "ready",
            "port": port,
            "token": token,
            "url": url,
            "version": __version__,
            "build": installation_id(),
        }), flush=True)

    if not quiet:
        features = _feature_report()
        missing = [f"{k} ({v['install']})" for k, v in features.items()
                   if not v["available"]]
        print()
        print("   ARGUS Forensics — Workbench")
        rule = "-" * 60
        try:
            print("   " + "\u2500" * 60)
            rule = "\u2500" * 60
        except UnicodeEncodeError:
            pass
        print(f"   Version     {__version__}   Python {sys.version.split()[0]}")
        print(f"   Workspace   {wb.workspace}")
        tools = toolchain_status()
        print(f"   adb         {'found' if tools['adb']['available'] else 'not installed (Android live acquisition unavailable)'}")
        print(f"   iOS tools   {'found' if tools['libimobiledevice']['available'] else 'not installed (iOS live acquisition unavailable)'}")
        if missing:
            print(f"   Optional    missing: {', '.join(missing)}")
        try:
            print("   " + rule)
        except UnicodeEncodeError:
            print("   " + "-" * 60)
        print(f"   Open  {url}")
        print("   Close this window to stop the application.")
        print()

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not quiet:
            print("\n   Shutting down.")
    finally:
        httpd.server_close()
        wb.close()
