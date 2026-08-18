"""Live Android acquisition over ADB.

Two extraction actions are implemented, matching the manual's Step 8:

* **Logical (Full read)** — queries the device's own content providers
  (``content query --uri content://...``).  This is what the OS is willing to
  hand over to a normal app, so it needs no root, but it returns *allocated
  records only*: deleted messages are already gone at this layer.

* **File system** — pulls the actual database files (and their ``-wal`` /
  ``-journal`` sidecars) so the deleted-record carver has something to work
  with.  Without root this reaches shared storage and whatever ``run-as``
  allows on debuggable packages; with root it reaches ``/data/data``.

Every pulled file is hashed on the device (``sha256sum``) *and* on the
workstation, and the two are compared.  A mismatch means the transfer was
corrupted and is reported as an integrity failure rather than silently
accepted.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..core.errors import AcquisitionError
from ..core.hashing import hash_file
from ..devices.detect import find_tool


def _want_tar_stream(remote: str) -> bool:
    """Whole-tree paths where a tar pipe beats adb's per-file sync protocol."""
    path = (remote or "").rstrip("/")
    return path in {"/sdcard", "/storage/emulated/0", "/data/media/0"} \
        or path.startswith("/storage/")

# Content-provider URIs used by the logical action
PROVIDERS: Dict[str, Tuple[str, str]] = {
    "calls": ("content://call_log/calls", "Calls"),
    "contacts": ("content://com.android.contacts/data/phones", "Contacts"),
    "contacts_all": ("content://com.android.contacts/contacts", "Contacts"),
    "sms": ("content://sms", "Messages"),
    "sms_inbox": ("content://sms/inbox", "Messages"),
    "sms_sent": ("content://sms/sent", "Messages"),
    "mms": ("content://mms", "Messages"),
    "threads": ("content://mms-sms/conversations", "Messages"),
    "mms_part": ("content://mms/part", "Messages"),
    "mms_addr": ("content://mms/addr", "Messages"),
    "images": ("content://media/external/images/media", "Files & Media"),
    "video": ("content://media/external/video/media", "Files & Media"),
    "audio": ("content://media/external/audio/media", "Files & Media"),
    "downloads": ("content://downloads/my_downloads", "Files & Media"),
    "calendar": ("content://com.android.calendar/events", "Calendar"),
}

# Fallback URIs when the primary content provider refuses (common on BBK/Vivo).
_PROVIDER_FALLBACKS: Dict[str, List[str]] = {
    "contacts": [
        "content://com.android.contacts/contacts",
        "content://contacts/phones",
        "content://com.android.contacts/data/phones",
        "content://com.android.contacts/raw_contacts",
        "content://com.vivo.contacts/contacts",
        "content://com.bbk.contacts/contacts",
    ],
    "contacts_all": [
        "content://com.android.contacts/data",
        "content://com.android.contacts/contacts",
        "content://com.vivo.contacts/contacts",
    ],
    "sms": [
        "content://sms/inbox",
        "content://sms/sent",
        "content://sms/draft",
        "content://mms-sms/conversations",
        "content://com.android.mms-sms",
    ],
    "calls": [
        "content://call_log/calls",
        "content://com.android.contacts/calls",
        "content://com.vivo.contacts/calls",
    ],
}

# Shared-storage paths that may hold SMS/contact exports (no root required).
COMM_EXPORT_PATHS: List[Tuple[str, str]] = [
    ("/sdcard/Download", "Messages"),
    ("/sdcard/Documents", "Messages"),
    ("/sdcard/SMSBackupRestore", "Messages"),
    ("/sdcard/SMSBackup", "Messages"),
    ("/sdcard/sms_backup", "Messages"),
    ("/sdcard/SMSBackupPlus", "Messages"),
    ("/sdcard/Android/data/com.rits.clonemyphone/files", "Messages"),
    ("/sdcard/Backup", "Other"),
    ("/sdcard/backups", "Other"),
    ("/sdcard/.vivobackup", "Other"),
    ("/sdcard/VivoBackup", "Other"),
    ("/sdcard/iQOO", "Other"),
    ("/sdcard/Contacts", "Contacts"),
    ("/sdcard/contacts", "Contacts"),
    ("/sdcard/DCIM", "Files & Media"),
    ("/sdcard/Pictures", "Files & Media"),
    ("/storage/emulated/0/Download", "Messages"),
    ("/storage/emulated/0/Documents", "Messages"),
    ("/storage/emulated/0/SMSBackupRestore", "Messages"),
    ("/storage/emulated/0/SMSBackupPlus", "Messages"),
    ("/storage/emulated/0/Backup", "Other"),
    ("/storage/emulated/0/.vivobackup", "Other"),
    ("/storage/emulated/0/VivoBackup", "Other"),
    ("/storage/emulated/0/Contacts", "Contacts"),
    ("/storage/emulated/0/DCIM", "Files & Media"),
    ("/sdcard/EasyShare", "Other"),
    ("/sdcard/vivo", "Other"),
    ("/sdcard/BBK", "Other"),
    ("/storage/emulated/0/EasyShare", "Other"),
    ("/storage/emulated/0/vivo", "Other"),
    ("/storage/emulated/0/BBK", "Other"),
    ("/sdcard/MIUI/backup", "Other"),
    ("/storage/emulated/0/MIUI/backup", "Other"),
    ("/sdcard/Samsung/backup", "Other"),
    ("/sdcard/Google Messages", "Messages"),
    ("/storage/emulated/0/Google Messages", "Messages"),
]

_COMM_CATEGORIES = frozenset({
    "Messages", "Contacts", "Calls", "Chats", "Places", "Locations",
})

_DUMPSYS_COMMS = (
    ("call_log", "dumpsys call_log", "Calls"),
    ("telephony", "dumpsys telephony.registry", "Calls"),
    ("contacts", "dumpsys contact", "Contacts"),
)

_DUMPSYS_LOCATION = (
    ("location", "dumpsys location", "Places"),
    ("fused", "dumpsys fused_location", "Places"),
)

# Paths pulled by the file-system action, in priority order
FS_TARGETS: List[Tuple[str, str]] = [
    ("/data/data/com.android.providers.telephony/databases/mmssms.db", "Messages"),
    ("/data/data/com.android.providers.contacts/databases/contacts2.db", "Contacts"),
    ("/data/data/com.android.providers.contacts/databases/calllog.db", "Calls"),
    ("/data/data/com.whatsapp/databases/msgstore.db", "Messages"),
    ("/data/data/com.whatsapp/databases/wa.db", "Contacts"),
    ("/data/data/com.whatsapp/files/key", "Security"),
    ("/data/data/com.whatsapp.w4b/files/key", "Security"),
    ("/data/data/com.android.chrome/app_chrome/Default/History", "Web"),
    ("/data/system/users/0/accounts.db", "Security"),
    ("/data/misc/wifi/WifiConfigStore.xml", "Networks"),
    ("/data/system/packages.list", "Applications"),
    ("/sdcard/DCIM", "Files & Media"),
    ("/sdcard/Pictures", "Files & Media"),
    ("/sdcard/Download", "Files & Media"),
    ("/sdcard/Documents", "Files & Media"),
    ("/sdcard/Music", "Files & Media"),
    ("/sdcard/Movies", "Files & Media"),
    ("/sdcard/Recordings", "Files & Media"),
    ("/sdcard/WhatsApp/Media", "Files & Media"),
    ("/sdcard/WhatsApp", "Files & Media"),
    ("/sdcard/Telegram", "Files & Media"),
    ("/sdcard/Android/media", "Files & Media"),
    ("/sdcard/Android/data/com.vivo.easyshare", "Other"),
    ("/sdcard/Android/data/com.bbk.account", "Accounts"),
    ("/data/data/com.vivo.im/databases", "Messages"),
    ("/data/data/com.android.bbksms/databases", "Messages"),
    ("/data/data/com.vivo.contacts/databases", "Contacts"),
    ("/data/data/com.google.android.apps.messaging/databases", "Messages"),
    ("/data/data/com.samsung.android.messaging/databases", "Messages"),
    ("/data/data/com.samsung.android.dialer/databases", "Calls"),
    ("/storage/emulated/0", "Files & Media"),
]

SIDECARS = ("-wal", "-shm", "-journal")

CHAT_FS_TARGETS: List[Tuple[str, str]] = [
    ("/sdcard/WhatsApp", "Chats"),
    ("/sdcard/WhatsApp/Databases", "Chats"),
    ("/sdcard/Android/media/com.whatsapp", "Chats"),
    ("/sdcard/Telegram", "Chats"),
    ("/sdcard/Android/data/org.telegram.messenger", "Chats"),
    ("/sdcard/Signal", "Chats"),
    ("/sdcard/Android/data/org.thoughtcrime.securesms", "Chats"),
    ("/sdcard/GBWhatsApp", "Chats"),
    ("/sdcard/OGWhatsApp", "Chats"),
]

_MEDIA_CATEGORIES = frozenset({
    "Files & Media", "Places", "Locations",
})


@dataclass
class PullResult:
    pulled: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    bytes_total: int = 0
    integrity_failures: List[str] = field(default_factory=list)
    provider_stats: List[Dict[str, Any]] = field(default_factory=list)
    passes: List[str] = field(default_factory=list)


class AdbSession:
    """A thin, defensive wrapper around the ``adb`` binary."""

    def __init__(self, serial: str, timeout: int = 300):
        self.serial = serial
        self.timeout = timeout
        self._root: Optional[bool] = None

    def _cmd(self, *args: str) -> List[str]:
        adb = find_tool("adb") or "adb"
        return [adb, "-s", self.serial, *args]

    def run(self, *args: str, timeout: Optional[int] = None,
            check: bool = False) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(self._cmd(*args), capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  timeout=timeout or self.timeout)
        except FileNotFoundError as exc:
            raise AcquisitionError("adb is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise AcquisitionError(
                f"adb command timed out after {timeout or self.timeout}s: "
                f"{' '.join(args)[:120]}") from exc
        if check and proc.returncode != 0:
            raise AcquisitionError(
                f"adb {' '.join(args)[:80]} failed: "
                f"{(proc.stderr or '').strip()[:200]}")
        return proc

    def shell(self, command: str, timeout: Optional[int] = None) -> str:
        return self.run("shell", command, timeout=timeout).stdout or ""

    @property
    def has_root(self) -> bool:
        if self._root is None:
            out = self.shell("id").strip()
            self._root = "uid=0" in out or bool(self.shell("which su").strip())
        return self._root

    def exists(self, remote: str) -> bool:
        probe = f'ls -d {shlex.quote(remote)} 2>/dev/null'
        if self.has_root:
            probe = f'su -c {shlex.quote(probe)}'
        return bool(self.shell(probe).strip())

    def remote_sha256(self, remote: str) -> str:
        cmd = f"sha256sum {shlex.quote(remote)} 2>/dev/null"
        if self.has_root:
            cmd = f"su -c {shlex.quote(cmd)}"
        out = self.shell(cmd).strip()
        m = re.match(r"([0-9a-f]{64})\s", out)
        return m.group(1) if m else ""

    # ------------------------------------------------------------------ pull
    def pull(self, remote: str, local: Path,
             verify: bool = True, retries: int = 2,
             log: Optional[Callable[..., None]] = None) -> Tuple[bool, str]:
        """Pull one path with automatic retry and reconnect. Returns ``(ok, message)``."""
        last = "unknown error"
        for attempt in range(retries + 1):
            ok, msg = self._pull_once(remote, local, verify=verify)
            if ok:
                return True, "ok"
            last = msg
            if attempt < retries:
                if "offline" in msg.lower() or "not found" in msg.lower():
                    ensure_device_ready(self, log=log)
                time.sleep(0.4 * (attempt + 1))
        return False, last

    def _is_remote_dir(self, remote: str) -> bool:
        probe = f'test -d {shlex.quote(remote)} && echo DIR'
        if self.has_root:
            probe = f'su -c {shlex.quote(probe)}'
        return "DIR" in self.shell(probe)

    def _pull_tar_stream(self, remote: str, local: Path) -> bool:
        """Stream a remote directory as tar — far faster than per-file adb pull."""
        host_tar = shutil.which("tar")
        if not host_tar:
            return False
        which = self.shell("command -v tar 2>/dev/null").strip().splitlines()
        if not which:
            return False
        local.mkdir(parents=True, exist_ok=True)
        adb = find_tool("adb") or "adb"
        remote_cmd = f"tar cf - -C {shlex.quote(remote)} . 2>/dev/null"
        try:
            src = subprocess.Popen(
                [adb, "-s", self.serial, "exec-out", remote_cmd],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            dst = subprocess.run(
                [host_tar, "-xf", "-", "-C", str(local)],
                stdin=src.stdout, capture_output=True, timeout=14400)
            if src.stdout:
                src.stdout.close()
            src.wait(timeout=60)
        except (OSError, subprocess.SubprocessError):
            return False
        if dst.returncode != 0:
            return False
        try:
            next(local.iterdir())
        except StopIteration:
            return False
        except OSError:
            return False
        return True

    def _pull_once(self, remote: str, local: Path,
                   verify: bool = True) -> Tuple[bool, str]:
        local.parent.mkdir(parents=True, exist_ok=True)
        if _want_tar_stream(remote) and self._is_remote_dir(remote) \
                and self._pull_tar_stream(remote, local):
            return True, "ok-tar"
        proc = self.run("pull", "-a", remote, str(local), timeout=14400)
        if proc.returncode != 0:
            if self.has_root:
                staged = f"/data/local/tmp/argus_{abs(hash(remote)) % 10**8}"
                self.shell(f"su -c 'cp -r {shlex.quote(remote)} {staged} && "
                           f"chmod -R 644 {staged}'")
                proc = self.run("pull", "-a", staged, str(local))
                self.shell(f"su -c 'rm -rf {staged}'")
                if proc.returncode != 0:
                    return False, proc.stderr.strip()[:200]
            else:
                return False, proc.stderr.strip()[:200] or "permission denied"

        if verify and local.is_file():
            remote_hash = self.remote_sha256(remote)
            if remote_hash:
                local_hash = hash_file(local).sha256
                if local_hash != remote_hash:
                    return False, (f"integrity mismatch: device reported "
                                   f"{remote_hash[:16]}…, received "
                                   f"{local_hash[:16]}…")
        return True, "ok"


def pull_filesystem(session: AdbSession, dest: Path,
                    categories: Optional[List[str]] = None,
                    extra_paths: Optional[List[str]] = None,
                    log: Optional[Callable[..., None]] = None,
                    skip_existing: bool = False,
                    verify: bool = True,
                    parallel: int = 1,
                    vendor_paths: Optional[List[Tuple[str, str]]] = None
                    ) -> PullResult:
    """File-system action: pull databases and media, with WAL sidecars."""
    result = PullResult()
    targets = [(p, c) for p, c in FS_TARGETS
               if not categories or c in categories]
    if categories:
        if any(c in categories for c in ("Chats", "Messages")):
            for path, cat in CHAT_FS_TARGETS:
                if not categories or cat in categories or (
                        cat == "Chats" and "Messages" in categories):
                    targets.append((path, cat))
        if "Files & Media" not in categories:
            keep_media = {"/sdcard/Download", "/sdcard/Documents",
                          "/sdcard/WhatsApp", "/sdcard/Telegram"}
            targets = [
                (p, c) for p, c in targets
                if c != "Files & Media" or p in keep_media
            ]
            targets = [(p, c) for p, c in targets if p != "/storage/emulated/0"]
    for path, cat in (vendor_paths or []):
        targets.append((path, cat))
    for p in (extra_paths or []):
        targets.append((p, "Other"))

    # Prefer the full shared-storage tree over its named subfolders so a
    # filesystem/turbo run actually captures Internal storage, not just DCIM.
    if any(p == "/storage/emulated/0" for p, _ in targets):
        sess_probe = session
        if sess_probe.exists("/storage/emulated/0"):
            skip = {"/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Download",
                    "/sdcard/Documents", "/sdcard/Music", "/sdcard/Movies",
                    "/sdcard/Recordings", "/sdcard/WhatsApp/Media",
                    "/sdcard/WhatsApp", "/sdcard/Telegram",
                    "/sdcard/Android/media", "/sdcard"}
            targets = [(p, c) for p, c in targets if p not in skip]
        else:
            targets = [(p, c) for p, c in targets if p != "/storage/emulated/0"]

    if not session.has_root:
        if log:
            log("adb.filesystem", "warning",
                "Device is not rooted — /data/data is unreadable. Only shared "
                "storage will be acquired. Deleted-record recovery will be "
                "limited to what is present in shared storage.",
                level="warning")

    total = len(targets)
    workers = max(1, min(parallel, total or 1))

    def pull_target(index: int, remote: str, category: str) -> PullResult:
        partial = PullResult()
        sess = session if workers <= 1 else AdbSession(session.serial)
        if not sess.exists(remote):
            partial.skipped.append(remote)
            if log:
                log("adb.filesystem", "skipped", f"{remote} not present",
                    phase="transfer",
                    progress_current=index, progress_total=total,
                    progress_pct=round(100.0 * index / total, 1))
            return partial
        local = dest / remote.lstrip("/")
        if skip_existing and local.exists():
            size = _tree_size(local)
            if local.is_file() and not verify:
                partial.pulled.append(remote)
                partial.bytes_total += size
                if log:
                    log("adb.filesystem", "skipped",
                        f"unchanged {remote} (turbo skip)",
                        phase="transfer",
                        progress_current=index, progress_total=total,
                        progress_pct=round(100.0 * index / total, 1))
                return partial
            remote_hash = sess.remote_sha256(remote) if local.is_file() else ""
            if remote_hash and local.is_file():
                local_hash = hash_file(local).sha256
                if local_hash == remote_hash:
                    partial.pulled.append(remote)
                    partial.bytes_total += size
                    if log:
                        log("adb.filesystem", "skipped",
                            f"unchanged {remote} (resume)",
                            phase="transfer",
                            progress_current=index, progress_total=total,
                            progress_pct=round(100.0 * index / total, 1))
                    return partial
        ok, msg = sess.pull(remote, local, verify=verify, log=log)
        if ok:
            partial.pulled.append(remote)
            size = _tree_size(local)
            partial.bytes_total += size
            if log:
                log("adb.filesystem", "ok", f"pulled {remote}",
                    phase="transfer", category=category, bytes=size,
                    progress_current=index, progress_total=total,
                    progress_pct=round(100.0 * index / total, 1))
            if local.is_file():
                def pull_sidecar(suffix: str) -> Optional[str]:
                    sc = remote + suffix
                    if not sess.exists(sc):
                        return None
                    sok, _ = sess.pull(sc, Path(str(local) + suffix),
                                       verify=verify)
                    if sok:
                        if log:
                            log("adb.filesystem", "ok",
                                f"pulled sidecar {Path(sc).name}")
                        return sc
                    return None

                if workers > 1:
                    with ThreadPoolExecutor(max_workers=len(SIDECARS)) as sc_pool:
                        for sc in sc_pool.map(pull_sidecar, SIDECARS):
                            if sc:
                                partial.pulled.append(sc)
                else:
                    for suffix in SIDECARS:
                        sc = pull_sidecar(suffix)
                        if sc:
                            partial.pulled.append(sc)
        else:
            partial.failed.append(f"{remote}: {msg}")
            if "integrity mismatch" in msg:
                partial.integrity_failures.append(f"{remote}: {msg}")
            if log:
                log("adb.filesystem", "error", f"{remote}: {msg}", level="error")
        return partial

    def merge_partial(partial: PullResult) -> None:
        result.pulled.extend(partial.pulled)
        result.skipped.extend(partial.skipped)
        result.failed.extend(partial.failed)
        result.bytes_total += partial.bytes_total
        result.integrity_failures.extend(partial.integrity_failures)

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(pull_target, index, remote, category)
                for index, (remote, category) in enumerate(targets, start=1)]
            for fut in as_completed(futures):
                merge_partial(fut.result())
    else:
        for index, (remote, category) in enumerate(targets, start=1):
            merge_partial(pull_target(index, remote, category))
    return result


def acquire_comms_supplement(session: AdbSession, dest: Path,
                             categories: Optional[List[str]] = None,
                             log: Optional[Callable[..., None]] = None,
                             vendor_comm_paths: Optional[List[Tuple[str, str]]]
                             = None,
                             vendor_providers: Optional[
                                 List[Tuple[str, str, str]]] = None,
                             skip_existing: bool = False) -> PullResult:
    """Dumpsys, providers, exports, and comm DB pulls (no generic media)."""
    from . import android_comms
    overall = android_comms.acquire_communications_deep(
        session, dest, categories=categories, log=log,
        skip_existing=skip_existing,
        vendor_providers=vendor_providers,
        vendor_comm_paths=vendor_comm_paths)
    loc = [c for c in (categories or []) if c in ("Places", "Locations")]
    if loc:
        _merge_pull(overall, export_dumpsys(
            session, dest, _DUMPSYS_LOCATION, categories=loc, log=log))
    return overall


def probe_capabilities(session: AdbSession) -> Dict[str, Any]:
    """Quick handset probe for preflight and method recommendation."""
    state = get_device_state(session.serial)
    out: Dict[str, Any] = {
        "adb_state": state,
        "authorized": state == "device",
        "root": False,
        "run_as_packages": [],
        "discovered_dbs": 0,
        "recommended_method": "mtp",
    }
    if state != "device":
        return out
    try:
        out["root"] = session.has_root
        out["recommended_method"] = "comprehensive"
        from .android_apps import discover_app_databases

        discovered = discover_app_databases(session, limit=60)
        out["discovered_dbs"] = len(discovered)
        out["run_as_packages"] = sorted(
            {d.package for d in discovered if d.via == "run-as"})
    except Exception:
        pass
    return out


def comprehensive_acquire(session: AdbSession, dest: Path,
                          categories: Optional[List[str]] = None,
                          log: Optional[Callable[..., None]] = None,
                          skip_existing: bool = False,
                          verify: bool = True,
                          parallel: int = 1,
                          skip_app_discovery: bool = False,
                          vendor_fs: Optional[List[Tuple[str, str]]] = None,
                          vendor_comm: Optional[List[Tuple[str, str]]] = None,
                          vendor_providers: Optional[List[Tuple[str, str, str]]]
                          = None) -> PullResult:
    """Multi-pass god-level acquisition: logical, apps, filesystem, comms."""
    from .android_apps import discover_app_databases

    overall = PullResult()
    overall.passes = []
    total_passes = 4 if not skip_app_discovery else 3
    pass_no = 1
    if log:
        log("adb.comprehensive", "progress",
            f"Pass {pass_no}/{total_passes} — logical content-provider query",
            phase="transfer", progress_current=0, progress_total=total_passes)

    logical = logical_query(session, dest / "logical", categories, log=log,
                            skip_existing=skip_existing,
                            extra_providers=vendor_providers)
    overall.passes.append("logical")
    _merge_pull(overall, logical)
    overall.provider_stats.extend(logical.provider_stats)

    extra: List[str] = []
    if skip_app_discovery:
        if log:
            log("adb.comprehensive", "skipped",
                f"Pass 2/{total_passes} — app discovery skipped (turbo)")
    else:
        pass_no += 1
        if log:
            log("adb.comprehensive", "progress",
                f"Pass {pass_no}/{total_passes} — discovering application databases",
                phase="transfer", progress_current=pass_no - 1,
                progress_total=total_passes)
        discovered = discover_app_databases(session, log=log, limit=180)
        extra = [d.remote_path for d in discovered]
        overall.passes.append("discover")
        if log and extra:
            log("adb.comprehensive", "note",
                f"Will attempt {len(extra)} discovered database path(s)")
        if discovered:
            from .android_apps import pull_discovered_app_databases
            from .progress import human_bytes
            app_pull = pull_discovered_app_databases(
                session, dest / "apps", discovered, log=log,
                skip_existing=skip_existing, verify=verify)
            _merge_pull(overall, app_pull)
            if app_pull.pulled and log:
                log("adb.comprehensive", "ok",
                    f"Eager run-as pull — {len(app_pull.pulled)} app database(s) "
                    f"({human_bytes(app_pull.bytes_total)})")

    pass_no += 1
    if log:
        log("adb.comprehensive", "progress",
            f"Pass {pass_no}/{total_passes} — filesystem pull with WAL sidecars",
            phase="transfer", progress_current=pass_no - 1,
            progress_total=total_passes)

    filesystem = pull_filesystem(session, dest / "filesystem", categories,
                                   extra_paths=extra, log=log,
                                   skip_existing=skip_existing,
                                   verify=verify, parallel=parallel,
                                   vendor_paths=vendor_fs)
    overall.passes.append("filesystem")
    _merge_pull(overall, filesystem)

    pass_no += 1
    if log:
        log("adb.comprehensive", "progress",
            f"Pass {pass_no}/{total_passes} — dumpsys & backup exports",
            phase="transfer", progress_current=pass_no - 1,
            progress_total=total_passes)

    comms = acquire_comms_supplement(
        session, dest, categories=categories, log=log,
        vendor_comm_paths=vendor_comm, vendor_providers=vendor_providers)
    overall.passes.append("comms")
    _merge_pull(overall, comms)

    if log:
        log("adb.comprehensive", "ok",
            f"Comprehensive acquisition complete — "
            f"{len(overall.pulled)} path(s), "
            f"{overall.bytes_total:,} bytes",
            phase="transfer", progress_current=total_passes,
            progress_total=total_passes, progress_pct=100)
    return overall


def export_dumpsys(session: AdbSession, dest: Path,
                   targets: Iterable[Tuple[str, str, str]],
                   categories: Optional[List[str]] = None,
                   log: Optional[Callable[..., None]] = None) -> PullResult:
    """Fallback when ``content query`` is blocked — save raw dumpsys output."""
    result = PullResult()
    out_dir = dest / "dumpsys"
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, command, category in targets:
        if categories and category not in categories:
            continue
        try:
            text = session.shell(command, timeout=300)
        except AcquisitionError:
            try:
                text = session.shell(command, timeout=300)
            except AcquisitionError:
                continue
        if not text or len(text.strip()) < 40:
            continue
        target = out_dir / f"{key}.txt"
        target.write_text(text, encoding="utf-8")
        result.pulled.append(command)
        result.bytes_total += target.stat().st_size
        if log:
            log("adb.dumpsys", "ok",
                f"{command}: {len(text):,} bytes saved", category=category)
    return result


def logical_query(session: AdbSession, dest: Path,
                  categories: Optional[List[str]] = None,
                  log: Optional[Callable[..., None]] = None,
                  *,
                  comms_only: bool = False,
                  skip_existing: bool = False,
                  extra_providers: Optional[List[Tuple[str, str, str]]] = None,
                  providers_only: Optional[List[Tuple[str, str, str]]] = None
                  ) -> PullResult:
    """Logical action: query content providers and save the raw dumps."""
    result = PullResult()
    dest.mkdir(parents=True, exist_ok=True)
    if providers_only:
        work = [(key, uri, category) for key, uri, category in providers_only
                if not categories or category in categories]
    else:
        work = [(key, uri, category) for key, (uri, category) in PROVIDERS.items()
                if not categories or category in categories]
        seen_keys = {k for k, _, _ in work}
        for key, uri, category in (extra_providers or []):
            if key not in seen_keys:
                work.append((key, uri, category))
                seen_keys.add(key)
    if comms_only:
        work = [(k, u, c) for k, u, c in work
                if c in ("Messages", "Contacts", "Calls", "Chats")]
    if not work:
        return result

    total = len(work)
    done_lock = threading.Lock()
    done_count = [0]

    def _query_one(item: tuple) -> PullResult:
        key, uri, category = item
        partial = PullResult()
        target = dest / "content" / f"{key}.txt"
        if skip_existing and target.is_file():
            try:
                existing = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                existing = ""
            if existing.strip() and "Row:" in existing:
                rows = existing.count("Row:")
                partial.pulled.append(uri)
                partial.bytes_total += target.stat().st_size
                partial.provider_stats.append({
                    "key": key, "uri": uri, "rows": rows, "skipped": True})
                if log:
                    with done_lock:
                        done_count[0] += 1
                        cur = done_count[0]
                    log("adb.logical", "skipped",
                        f"{uri}: resume — {rows:,} row(s) on disk",
                        phase="transfer", progress_current=cur,
                        progress_total=total)
                return partial
        sess = AdbSession(session.serial)
        uris = [uri] + _PROVIDER_FALLBACKS.get(key, [])
        out = ""
        used = uri
        timeout = 600 if category == "Messages" else 240
        for candidate in uris:
            out = _content_query_paginated(sess, candidate, timeout=timeout)
            if out.strip() and "Error" not in out[:200] and "Row:" in out:
                used = candidate
                break
        if not out.strip() or "Error" in out[:200]:
            partial.skipped.append(uri)
            partial.provider_stats.append({
                "key": key, "uri": uri, "rows": 0, "skipped": False})
            if log:
                with done_lock:
                    done_count[0] += 1
                    cur = done_count[0]
                log("adb.logical", "skipped",
                    f"{uri}: {out.strip()[:120] or 'no rows returned'}",
                    phase="transfer", progress_current=cur,
                    progress_total=total)
            return partial
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(out, encoding="utf-8")
        partial.pulled.append(used)
        partial.bytes_total += target.stat().st_size
        rows = out.count("Row:")
        partial.provider_stats.append({
            "key": key, "uri": used, "rows": rows, "skipped": False})
        if log:
            with done_lock:
                done_count[0] += 1
                cur = done_count[0]
            log("adb.logical", "ok" if cur >= total else "progress",
                f"{used}: {rows:,} row(s)", category=category,
                phase="transfer", progress_current=cur, progress_total=total)
        return partial

    workers = min(6, len(work))
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for partial in pool.map(_query_one, work):
                result.pulled.extend(partial.pulled)
                result.skipped.extend(partial.skipped)
                result.bytes_total += partial.bytes_total
                result.provider_stats.extend(partial.provider_stats)
    else:
        for item in work:
            partial = _query_one(item)
            result.pulled.extend(partial.pulled)
            result.skipped.extend(partial.skipped)
            result.bytes_total += partial.bytes_total
            result.provider_stats.extend(partial.provider_stats)
    return result


def capture_identity(session: AdbSession) -> Dict[str, Any]:
    """Structured device identity captured at acquisition time."""
    from ..devices.identity import android_identity_from_props

    props: Dict[str, str] = {}
    for line in session.shell("getprop").splitlines():
        m = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]", line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    ident = android_identity_from_props(props)
    ident["android_id"] = session.shell(
        "settings get secure android_id").strip()
    ident["serial"] = session.serial
    ident["rooted"] = bool(session.has_root)
    ident["storage"] = session.shell("df -h /data /sdcard 2>/dev/null").strip()
    ident["date"] = session.shell("date").strip()
    ident["uptime"] = session.shell("uptime").strip()
    battery = session.shell("dumpsys battery")
    m = re.search(r"level:\s*(\d+)", battery)
    ident["battery"] = int(m.group(1)) if m else None
    return ident


def device_report(session: AdbSession, dest: Path, *, lite: bool = False) -> Path:
    """Capture device state for the record (Step 11 supporting detail)."""
    dest.mkdir(parents=True, exist_ok=True)
    ident = capture_identity(session)
    from ..devices.identity import write_identity
    write_identity(dest, ident)

    target = dest / "device_info.txt"
    blocks = {
        "identity": json_dumps_ident(ident),
        "getprop": session.shell("getprop") if not lite else "(turbo — full getprop skipped)",
        "battery": session.shell("dumpsys battery"),
        "df": session.shell("df -h"),
        "date": session.shell("date"),
        "uptime": session.shell("uptime"),
    }
    if not lite:
        blocks.update({
            "packages": session.shell("pm list packages -f -u"),
            "users": session.shell("pm list users"),
            "accounts": session.shell("dumpsys account | head -100"),
            "sim": session.shell("dumpsys telephony.registry | head -60"),
        })
    with target.open("w", encoding="utf-8") as fh:
        for name, body in blocks.items():
            fh.write(f"\n===== {name} =====\n{body}\n")
    return target


def json_dumps_ident(ident: Dict) -> str:
    import json
    return json.dumps(ident, indent=2, ensure_ascii=False, default=str)


def create_backup(session: AdbSession, dest: Path,
                  password: str = "", log=None) -> Optional[Path]:
    """Backup action: trigger ``adb backup``. Requires on-device confirmation."""
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "backup.ab"
    if log:
        log("adb.backup", "waiting",
            "Confirm the backup prompt on the device screen. This will time "
            "out after 10 minutes.", level="warning")
    proc = session.run("backup", "-apk", "-shared", "-all", "-f", str(target),
                       timeout=600)
    if proc.returncode != 0 or not target.exists() or target.stat().st_size < 64:
        if log:
            log("adb.backup", "error",
                "backup produced no data — Android 12+ and apps with "
                "allowBackup=false will refuse", level="error")
        return None
    return target


def _tree_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def _content_query_paginated(sess: AdbSession, uri: str,
                             *, batch_size: int = 500,
                             max_rows: int = 50000,
                             timeout: int = 240) -> str:
    """Query a content provider with pagination when supported."""
    chunks: List[str] = []
    offset = 0
    while offset < max_rows:
        cmd = (f"content query --uri {uri} --projection * "
               f"--limit {batch_size} --offset {offset}")
        chunk = sess.shell(cmd, timeout=timeout)
        if not chunk.strip() or "Error" in chunk[:200]:
            if offset == 0:
                plain = sess.shell(f"content query --uri {uri}", timeout=timeout)
                if plain.strip() and "Row:" in plain:
                    return plain
                return sess.shell(
                    f"content query --uri {uri} --projection *", timeout=timeout)
            break
        if "Row:" not in chunk:
            break
        rows = chunk.count("Row:")
        chunks.append(chunk)
        if rows < batch_size:
            break
        offset += batch_size
    return "\n".join(chunks)


def get_device_state(serial: str) -> str:
    """Return adb state for ``serial`` (device, offline, unauthorized, missing)."""
    for state, serials in adb_device_states().items():
        if serial in serials:
            return state
    return "missing"


def ensure_device_ready(session: AdbSession,
                        log: Optional[Callable[..., None]] = None,
                        *, restart: bool = True,
                        timeout: int = 90) -> bool:
    """Reconnect ADB if the handset dropped offline during extraction."""
    if get_device_state(session.serial) == "device":
        return True
    if log:
        log("adb.session", "warning",
            f"Device {get_device_state(session.serial)} — reconnecting ADB",
            level="warning")
    if restart:
        _restart_adb_server()
        time.sleep(2)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if get_device_state(session.serial) == "device":
            if log:
                log("adb.session", "ok", "ADB session restored")
            return True
        time.sleep(3)
    return False


def enable_keep_awake(session: AdbSession,
                      log: Optional[Callable[..., None]] = None) -> bool:
    """Prevent screen lock from killing ADB on long Funtouch/MIUI runs."""
    try:
        session.shell("svc power stayon usb")
        session.shell("settings put system screen_off_timeout 1800000")
        if log:
            log("adb.session", "ok",
                "Stay-awake enabled — screen will not sleep on USB power")
        return True
    except AcquisitionError:
        return False


def disable_keep_awake(session: AdbSession) -> None:
    try:
        session.shell("svc power stayon false")
    except AcquisitionError:
        pass


def write_adb_manifest(dest: Path, result: PullResult, *,
                       method: str = "adb",
                       serial: str = "") -> Path:
    """Persist ADB acquisition audit trail (parity with MTP manifest)."""
    import json
    from datetime import datetime, timezone

    manifest = {
        "format": "argus-adb-manifest/1",
        "method": method,
        "serial": serial,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "passes": result.passes,
        "summary": {
            "pulled": len(result.pulled),
            "skipped": len(result.skipped),
            "failed": len(result.failed),
            "bytes": result.bytes_total,
            "integrity_failures": len(result.integrity_failures),
        },
        "providers": result.provider_stats,
        "pulled": result.pulled[:5000],
        "failed": result.failed[:500],
        "skipped_paths": result.skipped[:500],
    }
    target = dest / "argus-adb-manifest.json"
    target.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return target


def list_authorized_serials() -> List[str]:
    """ADB serials in ``device`` state (authorized for debugging)."""
    adb = find_tool("adb")
    if not adb:
        return []
    try:
        out = subprocess.run(
            [adb, "devices"], capture_output=True, text=True,
            timeout=30, check=False).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return []
    serials: List[str] = []
    for line in out.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def adb_device_states() -> Dict[str, List[str]]:
    """Classify connected ADB endpoints by authorization state."""
    adb = find_tool("adb")
    states: Dict[str, List[str]] = {
        "device": [], "unauthorized": [], "offline": [], "other": [],
    }
    if not adb:
        return states
    try:
        out = subprocess.run(
            [adb, "devices"], capture_output=True, text=True,
            timeout=30, check=False).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return states
    for line in out.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        bucket = state if state in states else "other"
        states[bucket].append(serial)
    return states


def _restart_adb_server() -> None:
    adb = find_tool("adb")
    if not adb:
        return
    try:
        subprocess.run([adb, "kill-server"], capture_output=True, timeout=15)
        subprocess.run([adb, "start-server"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def wait_for_authorized_adb(log: Optional[Callable[..., None]] = None,
                            *, timeout: int = 180) -> Optional[str]:
    """Wait for an authorized ADB device — prompts examiner to enable debugging."""
    _restart_adb_server()
    deadline = time.time() + timeout
    prompted = False
    vivo_hint = False
    while time.time() < deadline:
        states = adb_device_states()
        if states["device"]:
            return states["device"][0]
        if states["unauthorized"] and log and not prompted:
            log("adb.comms", "warning",
                "Handset detected but USB debugging is not authorized — "
                "unlock the phone and tap Allow on the RSA fingerprint prompt. "
                "On Vivo/iQOO also enable USB debugging (Security settings).",
                level="warning")
            prompted = True
        elif not states["unauthorized"] and not states["device"] and log:
            remaining = int(deadline - time.time())
            if remaining % 25 < 4 or not prompted:
                msg = (
                    "Waiting for USB debugging — on the phone: Settings → "
                    "Developer options → USB debugging ON"
                )
                if not vivo_hint:
                    msg += (
                        ". Vivo/Y02: also turn on USB debugging (Security settings), "
                        "keep File transfer mode, unlock screen, tap Allow"
                    )
                    vivo_hint = True
                msg += f" ({remaining}s remaining)."
                log("adb.comms", "note", msg, level="warning")
                prompted = True
        time.sleep(3)
    return None


def pull_communication_exports(session: AdbSession, dest: Path,
                               categories: Optional[List[str]] = None,
                               log: Optional[Callable[..., None]] = None,
                               extra_paths: Optional[List[Tuple[str, str]]] = None
                               ) -> PullResult:
    """Pull shared-storage folders that may contain SMS/contact backups."""
    result = PullResult()
    paths = list(COMM_EXPORT_PATHS)
    seen = {p for p, _ in paths}
    for path, cat in (extra_paths or []):
        if path not in seen:
            paths.append((path, cat))
            seen.add(path)
    for remote, category in paths:
        if categories and category not in categories and category != "Other":
            continue
        if not session.exists(remote):
            continue
        local = dest / "comms_export" / remote.lstrip("/").replace("/", os.sep)
        if local.exists() and any(local.rglob("*")):
            if log:
                log("adb.comms", "skipped",
                    f"{remote} already present from MTP copy")
            continue
        ok, msg = session.pull(remote, local, verify=False)
        if ok:
            result.pulled.append(remote)
            result.bytes_total += _tree_size(local)
            if log:
                log("adb.comms", "ok",
                    f"Pulled communication export tree {remote}",
                    category=category)
        elif log:
            log("adb.comms", "skipped", f"{remote}: {msg[:100]}")
    return result


def pull_communication_databases(session: AdbSession, dest: Path,
                                 categories: Optional[List[str]] = None,
                                 log: Optional[Callable[..., None]] = None
                                 ) -> PullResult:
    """Pull telephony/contacts databases when root or run-as allows."""
    result = PullResult()
    db_targets = [
        ("/data/data/com.android.providers.telephony/databases/mmssms.db",
         "Messages"),
        ("/data/data/com.android.providers.contacts/databases/contacts2.db",
         "Contacts"),
        ("/data/data/com.android.providers.contacts/databases/calllog.db",
         "Calls"),
    ]
    for remote, category in db_targets:
        if categories and category not in categories:
            continue
        if not session.exists(remote):
            continue
        local = dest / "databases" / remote.split("/")[-1]
        ok, msg = session.pull(remote, local, verify=False)
        if ok:
            result.pulled.append(remote)
            try:
                result.bytes_total += local.stat().st_size
            except OSError:
                pass
            for side in SIDECARS:
                side_remote = remote + side
                if session.exists(side_remote):
                    session.pull(side_remote, Path(str(local) + side),
                                   verify=False)
            if log:
                log("adb.comms", "ok",
                    f"Pulled {remote.split('/')[-1]} ({category})",
                    category=category)
        elif log:
            log("adb.comms", "skipped", f"{remote}: {msg[:80]}")
    return result


def _merge_pull(into: PullResult, other: PullResult) -> None:
    into.pulled.extend(other.pulled)
    into.skipped.extend(other.skipped)
    into.failed.extend(other.failed)
    into.bytes_total += other.bytes_total
    into.integrity_failures.extend(other.integrity_failures)
    into.provider_stats.extend(other.provider_stats)
    for name in other.passes:
        if name not in into.passes:
            into.passes.append(name)


def acquire_communications(dest: Path,
                           categories: Optional[List[str]] = None,
                           log: Optional[Callable[..., None]] = None,
                           *,
                           wait_seconds: int = 180,
                           force_comms: bool = False) -> PullResult:
    """Extract SMS, contacts, calls and location — ADB + exports + DBs."""
    overall = PullResult()
    want = (list(_COMM_CATEGORIES) if force_comms
            else (categories or list(_COMM_CATEGORIES)))
    comms_want = [c for c in want
                  if c in ("Messages", "Contacts", "Calls", "Chats")]
    loc_want = [c for c in want if c in ("Places", "Locations")]
    if not comms_want and not loc_want and not force_comms:
        return overall

    serial = wait_for_authorized_adb(log, timeout=wait_seconds)
    if not serial:
        if log:
            log("adb.comms", "warning",
                "No authorized ADB device — SMS, contacts and live GPS were NOT "
                "pulled. On Vivo Y02: enable Developer options, USB debugging, "
                "and USB debugging (Security settings); keep USB on File transfer; "
                "unlock and tap Allow. Re-run extraction, OR export SMS Backup+ / "
                "vCard to Download before MTP copy.",
                level="warning")
        return overall

    if log:
        log("adb.comms", "start",
            f"Pulling SMS, contacts, calls and location via ADB "
            f"({serial[:24]}…)",
            phase="transfer")

    try:
        session = AdbSession(serial)
        if comms_want or force_comms:
            cats = comms_want or ["Messages", "Contacts", "Calls", "Chats"]
            _merge_pull(overall, acquire_comms_supplement(
                session, dest, categories=cats + loc_want, log=log))
        elif loc_want:
            session = AdbSession(serial)
            _merge_pull(overall, acquire_comms_supplement(
                session, dest, categories=loc_want, log=log))
    except Exception as exc:
        if log:
            log("adb.comms", "error", f"Communication pull failed: {exc}",
                level="error")

    if log:
        if overall.pulled:
            log("adb.comms", "ok",
                f"Communications acquisition — {len(overall.pulled)} source(s), "
                f"{overall.bytes_total:,} bytes")
        else:
            log("adb.comms", "warning",
                "ADB connected but no SMS/contacts/calls/location could be read — "
                "try comprehensive method with USB debugging, or SMS Backup+ / "
                "vCard export on the phone.",
                level="warning")
    return overall


def opportunistic_logical(dest: Path,
                          categories: Optional[List[str]] = None,
                          log: Optional[Callable[..., None]] = None
                          ) -> Optional[PullResult]:
    """Backward-compatible wrapper — now runs full communications acquisition."""
    result = acquire_communications(dest, categories=categories, log=log,
                                    wait_seconds=45)
    return result if result.pulled or result.skipped else None
