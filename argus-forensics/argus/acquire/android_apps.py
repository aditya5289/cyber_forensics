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
from pathlib import Path
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
    "com.google.android.gm": "Web",
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
    "com.tencent.mm": "Messages",
    "jp.naver.line.android": "Messages",
    "org.thoughtcrime.securesms": "Messages",
    "com.google.android.apps.maps": "Places",
    "com.transsion.smartmessage": "Messages",
    "com.transsion.phonemaster": "Other",
    "com.transsion.letswitch": "Other",
    "com.coloros.mms": "Messages",
    "com.oppo.mms": "Messages",
    "com.motorola.ccc.notification": "Messages",
    "com.truecaller": "Calls",
    "com.imo.android.imoim": "Messages",
    "com.botim.android": "Messages",
    "com.facebook.katana": "Chats",
    "com.twitter.android": "Chats",
    "com.skype.raider": "Calls",
    "kik.android": "Messages",
    "com.kakao.talk": "Messages",
    "com.google.android.apps.photos": "Files & Media",
    "com.sec.android.gallery3d": "Files & Media",
    "com.samsung.android.dialer": "Calls",
    "com.google.android.dialer": "Calls",
    "com.android.vending": "Applications",
}

# Shared-storage trees that survive without root. WhatsApp crypt backups,
# Telegram media, and OEM clone-phone folders live here — not under /data/data.
SHARED_APP_TREES: List[Tuple[str, str]] = [
    ("/sdcard/Android/media/com.whatsapp", "Chats"),
    ("/sdcard/Android/media/com.whatsapp.w4b", "Chats"),
    ("/sdcard/Android/media/org.telegram.messenger", "Chats"),
    ("/sdcard/Android/media/org.thoughtcrime.securesms", "Chats"),
    ("/sdcard/Android/data/com.whatsapp", "Chats"),
    ("/sdcard/Android/data/com.whatsapp.w4b", "Chats"),
    ("/sdcard/Android/data/org.telegram.messenger", "Chats"),
    ("/sdcard/Android/data/org.thoughtcrime.securesms", "Chats"),
    ("/sdcard/Android/data/com.tencent.mm", "Chats"),
    ("/sdcard/Android/data/jp.naver.line.android", "Chats"),
    ("/sdcard/Android/data/com.facebook.orca", "Chats"),
    ("/sdcard/WhatsApp/Databases", "Chats"),
    ("/sdcard/WhatsApp/Backups", "Chats"),
    ("/sdcard/Android/media/com.facebook.orca", "Chats"),
    ("/sdcard/Android/media/com.instagram.android", "Chats"),
    ("/sdcard/Android/media/com.snapchat.android", "Chats"),
    ("/sdcard/Android/data/com.instagram.android", "Chats"),
    ("/sdcard/Android/data/com.snapchat.android", "Chats"),
    ("/sdcard/Android/data/com.facebook.orca", "Chats"),
    ("/sdcard/Android/data/com.discord", "Chats"),
    ("/sdcard/Android/data/com.viber.voip", "Chats"),
    ("/sdcard/Android/data/com.imo.android.imoim", "Chats"),
    ("/sdcard/Telegram", "Chats"),
    ("/sdcard/Pictures/Telegram", "Chats"),
    ("/storage/emulated/0/Android/media/com.whatsapp", "Chats"),
    ("/storage/emulated/0/WhatsApp/Databases", "Chats"),
    ("/storage/emulated/0/Telegram", "Chats"),
    ("/sdcard/Bluetooth", "Files & Media"),
    ("/sdcard/Recordings/Call", "Calls"),
    ("/sdcard/Pictures/Screenshots", "Files & Media"),
    ("/sdcard/DCIM/Screenshots", "Files & Media"),
    ("/storage/emulated/0/Bluetooth", "Files & Media"),
    ("/storage/emulated/0/Recordings/Call", "Calls"),
]

ROOT_APP_SUBDIRS = ("databases", "files", "shared_prefs", "no_backup")

_CRYPT_FIND = (
    "find /sdcard /storage/emulated/0 -maxdepth 6 -type f "
    "\\( -name 'msgstore*.db.crypt*' -o -name '*.crypt12' "
    "-o -name '*.crypt14' -o -name '*.crypt15' -o -name 'wa.db' "
    "-o -name 'msgstore.db' -o -name 'key' -o -iname '*.vcf' "
    "-o -iname '*sms*.xml' -o -iname '*calls*.xml' \\) 2>/dev/null | head -n 120"
)

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
    for db in databases[:180]:
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


def pull_user_apks(session, dest: Path,
                   log: Optional[Callable[..., None]] = None,
                   *, skip_existing: bool = False, limit: int = 120):
    """Pull installed user APKs so the exhibit holds the binaries, not just data."""
    from .android_adb import PullResult

    result = PullResult()
    dest.mkdir(parents=True, exist_ok=True)
    listing = session.shell("pm list packages -3 -f") or session.shell("pm list packages -f")
    if not isinstance(listing, str):
        listing = ""
    pulled = 0
    for line in listing.splitlines():
        if pulled >= limit:
            break
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        if "=" not in body:
            continue
        apk_path, pkg = body.rsplit("=", 1)
        apk_path = apk_path.strip()
        pkg = pkg.strip()
        if not apk_path.endswith(".apk"):
            continue
        local = dest / f"{pkg}.apk"
        if skip_existing and local.is_file() and local.stat().st_size > 0:
            result.skipped.append(apk_path)
            continue
        ok, msg = session.pull(apk_path, local, verify=False, log=log)
        if ok:
            result.pulled.append(apk_path)
            pulled += 1
            try:
                result.bytes_total += local.stat().st_size
            except OSError:
                pass
        else:
            result.failed.append(f"{pkg}: {msg}")
    if log and result.pulled:
        log("adb.apk", "ok", f"Pulled {len(result.pulled)} user APK(s)")
    return result


def parse_find_paths(text: str) -> List[str]:
    """Parse ``find`` output into absolute remote paths."""
    found: List[str] = []
    if not isinstance(text, str):
        return found
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/") and " " not in line[:3]:
            found.append(line)
    return found[:120]


def discover_shared_crypt(session, log: Optional[Callable[..., None]] = None
                          ) -> List[str]:
    """Locate WhatsApp crypt backups and key files on shared storage."""
    try:
        text = session.shell(_CRYPT_FIND, timeout=90)
    except Exception:
        return []
    paths = parse_find_paths(text)
    if log and paths:
        log("adb.discover", "ok",
            f"Shared-storage crypt/key hunt — {len(paths)} file(s)")
    return paths


def pull_shared_app_trees(session, dest: Path,
                          log: Optional[Callable[..., None]] = None,
                          *, skip_existing: bool = False,
                          verify: bool = True,
                          extra_paths: Optional[List[str]] = None,
                          skip_shared_media: bool = False):
    """Pull messenger trees that live on shared storage (no root required)."""
    from .android_adb import PullResult, filter_shared_media_targets

    result = PullResult()
    dest.mkdir(parents=True, exist_ok=True)
    work: List[Tuple[str, str]] = list(SHARED_APP_TREES)
    for path in extra_paths or []:
        work.append((path, "Chats"))
    work = filter_shared_media_targets(work, skip=skip_shared_media)
    seen: set[str] = set()
    for remote, category in work:
        if remote in seen:
            continue
        seen.add(remote)
        try:
            present = session.exists(remote)
        except Exception:
            continue
        if present is not True and present is not False:
            # Unit-test mocks — do not treat a Mock as a live path.
            continue
        if not present:
            result.skipped.append(remote)
            continue
        local = dest / remote.lstrip("/")
        if skip_existing and local.exists():
            result.skipped.append(remote)
            continue
        try:
            ok, msg = session.pull(remote, local, verify=verify, log=log)
        except Exception as exc:
            ok, msg = False, str(exc)[:200]
        if ok:
            result.pulled.append(remote)
            try:
                result.bytes_total += sum(
                    p.stat().st_size for p in local.rglob("*") if p.is_file()
                ) if local.is_dir() else local.stat().st_size
            except OSError:
                pass
            if log:
                log("adb.shared", "ok",
                    f"{remote} ({category})", category=category)
        else:
            result.failed.append(f"{remote}: {msg}")
    return result


def pull_root_app_trees(session, dest: Path,
                        log: Optional[Callable[..., None]] = None,
                        *, skip_existing: bool = False,
                        verify: bool = True):
    """With a root shell, pull files/shared_prefs/databases for known apps."""
    from .android_adb import PullResult

    result = PullResult()
    if not getattr(session, "has_root", False):
        return result
    dest.mkdir(parents=True, exist_ok=True)
    try:
        installed = set(parse_package_list(
            session.shell("pm list packages -u")))
    except Exception:
        installed = set(KNOWN_APPS)
    targets = [pkg for pkg in KNOWN_APPS if pkg in installed] or list(KNOWN_APPS)
    for package in targets:
        for sub in ROOT_APP_SUBDIRS:
            remote = f"/data/data/{package}/{sub}"
            try:
                present = session.exists(remote)
            except Exception:
                continue
            if present is not True:
                continue
            local = dest / package / sub
            if skip_existing and local.exists():
                result.skipped.append(remote)
                continue
            try:
                ok, msg = session.pull(remote, local, verify=verify, log=log)
            except Exception as exc:
                ok, msg = False, str(exc)[:200]
            if ok:
                result.pulled.append(remote)
                try:
                    result.bytes_total += sum(
                        p.stat().st_size for p in local.rglob("*") if p.is_file()
                    ) if local.is_dir() else local.stat().st_size
                except OSError:
                    pass
            else:
                result.failed.append(f"{remote}: {msg}")
    if log and result.pulled:
        log("adb.root", "ok",
            f"Root app trees — {len(result.pulled)} path(s) from "
            f"{len(targets)} known package(s)")
    return result
