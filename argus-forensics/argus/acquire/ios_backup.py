"""iTunes / Finder iOS backup reader.

An iOS backup is *not* a directory tree — it is a flat store of files named by
SHA-1 of ``domain-relativePath``, scattered across 256 two-hex-character
subdirectories, with the real paths held in ``Manifest.db``.  Handing that raw
folder to a parser gets you nothing, which is why this module exists: it
rebuilds the logical tree (or a targeted subset of it) so ordinary parsers can
work on recognisable filenames.

``Manifest.db`` schema::

    Files(fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT,
          flags INTEGER, file BLOB)

``flags``: 1 = file, 2 = directory, 4 = symlink.
Encrypted backups (``Manifest.plist`` → ``IsEncrypted``) require the backup
password; this module detects and reports that condition explicitly rather
than producing a confusingly empty extraction.
"""

from __future__ import annotations

import plistlib
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ..core.errors import AcquisitionError

# Domains worth pulling first for a communications-focused examination
PRIORITY_DOMAINS = [
    "HomeDomain", "MediaDomain", "CameraRollDomain", "WirelessDomain",
    "AppDomain-net.whatsapp.WhatsApp", "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
    "AppDomain-com.burbn.instagram", "AppDomain-com.facebook.Facebook",
    "AppDomain-com.toyopagroup.picaboo", "AppDomain-ph.telegra.Telegraph",
    "SystemPreferencesDomain", "DatabaseDomain", "KeychainDomain",
]

KEY_FILES = [
    "Library/SMS/sms.db", "Library/CallHistoryDB/CallHistory.storedata",
    "Library/AddressBook/AddressBook.sqlitedb",
    "Library/Safari/History.db", "Library/Notes/notes.sqlite",
    "Library/Calendar/Calendar.sqlitedb",
    "Library/Caches/locationd/cache_encryptedA.db",
    "Library/Preferences/com.apple.commcenter.plist",
    "ChatStorage.sqlite", "Library/Preferences/com.apple.mobilephone.plist",
]


@dataclass
class BackupFile:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    size: int = 0

    @property
    def logical_path(self) -> str:
        return f"{self.domain}/{self.relative_path}" if self.relative_path \
            else self.domain

    def blob_path(self, root: Path) -> Path:
        return root / self.file_id[:2] / self.file_id


class IOSBackup:
    """Read an iTunes/Finder backup folder."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.manifest_db = self.root / "Manifest.db"
        self.manifest_plist = self.root / "Manifest.plist"
        self.info_plist = self.root / "Info.plist"
        if not self.manifest_db.exists():
            raise AcquisitionError(
                f"{self.root} is not an iOS backup (no Manifest.db). "
                f"For iOS 9 and earlier, Manifest.mbdb is used and is not "
                f"supported by this reader.")
        self.info = self._read_plist(self.info_plist)
        self.manifest = self._read_plist(self.manifest_plist)

    @staticmethod
    def _read_plist(path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            return plistlib.loads(path.read_bytes())
        except Exception:
            return {}

    # ---------------------------------------------------------------- header
    @property
    def encrypted(self) -> bool:
        return bool(self.manifest.get("IsEncrypted"))

    def device_info(self) -> Dict[str, str]:
        lockdown = self.manifest.get("Lockdown", {}) or {}
        return {
            "device_name": str(self.info.get("Device Name", "")),
            "display_name": str(self.info.get("Display Name", "")),
            "product_type": str(self.info.get("Product Type", "")),
            "product_version": str(self.info.get("Product Version", "")),
            "build_version": str(self.info.get("Build Version", "")),
            "serial_number": str(self.info.get("Serial Number", "")),
            "imei": str(self.info.get("IMEI", "")),
            "meid": str(self.info.get("MEID", "")),
            "iccid": str(self.info.get("ICCID", "")),
            "phone_number": str(self.info.get("Phone Number", "")),
            "unique_identifier": str(self.info.get("Unique Identifier", "")),
            "last_backup_date": str(self.info.get("Last Backup Date", "")),
            "itunes_version": str(self.info.get("iTunes Version", "")),
            "encrypted": str(self.encrypted),
            "target_identifier": str(lockdown.get("ProductType", "")),
        }

    def installed_apps(self) -> List[str]:
        apps = self.info.get("Applications", {}) or {}
        installed = self.info.get("Installed Applications", []) or []
        return sorted(set(list(apps.keys()) + [str(a) for a in installed]))

    # ----------------------------------------------------------------- files
    def files(self, domains: Optional[List[str]] = None) -> Iterator[BackupFile]:
        if self.encrypted:
            raise AcquisitionError(
                "backup is encrypted; the backup password is required to "
                "decrypt Manifest.db and the per-file keys")
        conn = sqlite3.connect(f"file:{self.manifest_db.as_posix()}?mode=ro",
                               uri=True)
        conn.row_factory = sqlite3.Row
        try:
            sql = "SELECT fileID, domain, relativePath, flags FROM Files"
            params: tuple = ()
            if domains:
                placeholders = ",".join("?" * len(domains))
                sql += f" WHERE domain IN ({placeholders})"
                params = tuple(domains)
            for r in conn.execute(sql, params):
                yield BackupFile(file_id=r["fileID"], domain=r["domain"] or "",
                                 relative_path=r["relativePath"] or "",
                                 flags=r["flags"] or 0)
        finally:
            conn.close()

    def rebuild(self, dest: Path, domains: Optional[List[str]] = None,
                only_key_files: bool = False,
                progress=None) -> Tuple[int, int, List[str]]:
        """Rebuild the logical file tree under ``dest``.

        Returns ``(files_written, bytes_written, warnings)``.
        """
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        warnings: List[str] = []
        written = total = 0

        for bf in self.files(domains):
            if bf.flags != 1:                       # 1 = regular file
                continue
            if only_key_files and not any(
                    bf.relative_path.endswith(k) for k in KEY_FILES):
                continue
            src = bf.blob_path(self.root)
            if not src.exists():
                src = self.root / bf.file_id       # flat layout (iOS 9 and older)
                if not src.exists():
                    continue
            target = dest / bf.domain / bf.relative_path
            try:
                resolved = target.resolve()
                if not str(resolved).startswith(str(dest.resolve())):
                    warnings.append(f"skipped traversal entry {bf.logical_path}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, target)
                size = target.stat().st_size
                written += 1
                total += size
                if progress and written % 250 == 0:
                    progress(written, total, bf.logical_path)
            except OSError as exc:
                warnings.append(f"{bf.logical_path}: {exc}")
        return written, total, warnings

    def find(self, needle: str) -> List[BackupFile]:
        n = needle.lower()
        return [f for f in self.files() if n in f.relative_path.lower()]

    def __repr__(self) -> str:                                # pragma: no cover
        d = self.device_info()
        return (f"<IOSBackup {d.get('device_name')} "
                f"{d.get('product_type')} iOS {d.get('product_version')} "
                f"encrypted={self.encrypted}>")
