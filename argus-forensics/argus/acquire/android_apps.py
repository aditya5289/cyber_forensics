"""Discover application databases on a live Android handset.

Professional extractions do not rely on a fixed path list alone. Installed apps
change with every case, and the highest-value databases live under
``/data/data/<package>/databases/`` — unreachable without root unless the app
is debuggable and ``run-as`` succeeds.

This module enumerates packages and probes for database files the static
``FS_TARGETS`` list cannot know about in advance.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# Packages whose databases ARGUS parsers understand well.
KNOWN_APPS: dict[str, str] = {
    "com.whatsapp": "Messages",
    "com.whatsapp.w4b": "Messages",
    "org.telegram.messenger": "Messages",
    "com.facebook.orca": "Messages",
    "com.instagram.android": "Messages",
    "com.snapchat.android": "Messages",
    "com.discord": "Messages",
    "com.viber.voip": "Messages",
    "com.google.android.gm": "Email",
    "com.android.chrome": "Web",
    "com.sec.android.app.sbrowser": "Web",
    "com.android.providers.telephony": "Messages",
    "com.android.providers.contacts": "Contacts",
    "com.android.providers.calendar": "Calendar",
    "com.google.android.apps.messaging": "Messages",
    "com.samsung.android.messaging": "Messages",
    "com.vivo.im": "Messages",
    "com.android.bbksms": "Messages",
    "com.coloros.backuprestore": "Other",
    "com.miui.cloudbackup": "Other",
    "com.vivo.easyshare": "Other",
}

DB_NAME_HINTS = (
    "msgstore", "messages", "sms", "mmssms", "contacts", "calllog",
    "history", "chat", "threads", "wa.db", "backup", "db",
)


@dataclass
class AppDatabase:
    package: str
    remote_path: str
    category: str
    via: str = "run-as"          # run-as | root | known


def parse_package_list(text: str) -> List[str]:
    """Parse ``pm list packages`` output into package names."""
    packages: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("package:"):
            body = line.split(":", 1)[1].strip()
            if "=" in body:
                packages.append(body.rsplit("=", 1)[1].strip())
            else:
                packages.append(body)
        elif "=" in line:
            match = re.search(r"=([a-zA-Z][\w\.]+)\s*$", line)
            if match:
                packages.append(match.group(1))
    return sorted(set(packages))


def _looks_like_database(name: str) -> bool:
    lower = name.lower()
    if lower.endswith((".db", ".sqlite", ".sqlite3")):
        return True
    return any(hint in lower for hint in DB_NAME_HINTS)


def discover_app_databases(session, log: Optional[Callable[..., None]] = None,
                           limit: int = 180) -> List[AppDatabase]:
    """Find database paths via ``run-as`` (debuggable apps) and known packages."""
    found: List[AppDatabase] = []
    seen: set[str] = set()

    try:
        packages = parse_package_list(session.shell("pm list packages -f -3 -u"))
        if len(packages) < 20:
            packages = parse_package_list(session.shell("pm list packages -f -u"))
    except Exception as exc:
        if log:
            log("adb.discover", "warning",
                f"Could not list packages: {exc}", level="warning")
        packages = list(KNOWN_APPS.keys())

    # Known high-value packages first — even if pm list failed partially.
    ordered = []
    for pkg in KNOWN_APPS:
        if pkg in packages:
            ordered.append(pkg)
    for pkg in packages:
        if pkg not in ordered:
            ordered.append(pkg)

    def _probe_package(package: str) -> List[AppDatabase]:
        hits: List[AppDatabase] = []
        category = KNOWN_APPS.get(package, "Applications")
        base = f"/data/data/{package}/databases"
        candidates: List[str] = []
        local = session
        serial = getattr(session, "serial", None)
        if workers > 1 and isinstance(serial, str) and serial:
            from .android_adb import AdbSession
            local = AdbSession(serial)

        if local.has_root:
            listing = local.shell(
                f"su -c 'ls -1 {base} 2>/dev/null'").strip()
            if listing:
                for name in listing.splitlines():
                    name = name.strip()
                    if name and _looks_like_database(name):
                        candidates.append(f"{base}/{name}")
        else:
            listing = local.shell(
                f"run-as {package} ls databases 2>/dev/null").strip()
            if listing and "not debuggable" not in listing.lower():
                for name in listing.splitlines():
                    name = name.strip()
                    if name and _looks_like_database(name):
                        candidates.append(f"{base}/{name}")

        for remote in candidates:
            if not local.exists(remote):
                continue
            via = "root" if local.has_root else "run-as"
            hits.append(AppDatabase(package=package, remote_path=remote,
                                  category=category, via=via))
        return hits

    packages_slice = ordered[:limit]
    workers = min(8, max(1, len(packages_slice) // 8))
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe_package, pkg) for pkg in packages_slice]
            for fut in as_completed(futures):
                try:
                    for db in fut.result():
                        if db.remote_path in seen:
                            continue
                        seen.add(db.remote_path)
                        found.append(db)
                except Exception:
                    continue
    else:
        for package in packages_slice:
            for db in _probe_package(package):
                if db.remote_path in seen:
                    continue
                seen.add(db.remote_path)
                found.append(db)

    if log:
        log("adb.discover", "ok",
            f"Discovered {len(found)} application database(s) beyond the "
            f"fixed target list",
            progress_current=min(len(ordered), limit),
            progress_total=limit)
    return found


def pull_discovered_app_databases(session, dest: Path,
                                  databases: List[AppDatabase],
                                  log: Optional[Callable[..., None]] = None,
                                  *, skip_existing: bool = False,
                                  verify: bool = True):
    """Immediately pull databases found via run-as before bulk filesystem pass."""
    from .android_adb import PullResult

    result = PullResult()
    if not databases:
        return result
    dest.mkdir(parents=True, exist_ok=True)
    for db in databases[:80]:
        safe = db.remote_path.strip("/").replace("/", "__")
        local = dest / safe
        if skip_existing and local.is_file() and local.stat().st_size > 0:
            result.skipped.append(db.remote_path)
            continue
        ok, msg = session.pull(db.remote_path, local, verify=verify, log=log)
        if ok:
            result.pulled.append(db.remote_path)
            try:
                result.bytes_total += local.stat().st_size
            except OSError:
                pass
        else:
            result.failed.append(f"{db.remote_path}: {msg}")
    return result
