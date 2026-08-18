"""Anti-forensics detection and deeper recovery.

The absence of evidence is itself evidence, and this module is about noticing
it. A handset that was factory reset last Tuesday, or has a vault app
installed, or whose WhatsApp database is encrypted, tells you something
important — but only if the tool says so instead of quietly reporting "no
messages found".

What it detects:

* **Encrypted stores** — SQLCipher databases, WhatsApp ``.crypt12/14/15``,
  Signal's encrypted store, iOS encrypted backups. These are reported as
  *encrypted*, never as empty.
* **Vault and hider applications** — a documented list of apps whose entire
  purpose is concealing photos and messages, plus their data directories.
* **Wipe and reset residue** — a device whose accounts, media and logs all
  begin on the same recent date has been reset, and the reset date is a fact
  worth knowing.
* **Uninstalled applications** — leftover directories, shared preferences and
  cache for apps that are no longer installed.
* **Thumbnail-cache recovery** — Android ``.thumbnails`` and iOS
  ``PhotoData/Thumbnails`` retain images long after the original photo is
  deleted, so a thumbnail is frequently the only surviving copy.
* **Secure-delete indicators** — a database with ``secure_delete`` on, or with
  zeroed freeblocks, will not yield carved records, and an examiner needs to
  know that the absence of recovered data has a technical cause.

Every detector reports what it saw and what it cannot conclude. "No deleted
records recovered" and "no deleted records recoverable because the app zeroes
freed pages" are different findings, and conflating them misleads.
"""

from __future__ import annotations

import os
import re
import sqlite3
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..core.models import Artifact, Category, Recovery
from .registry import ParseContext, ParseResult, register
from .timestamps import guess, to_iso

US = 1_000_000


# ═══════════════════════════════════════════════ vault / privacy app catalogue
@dataclass
class SuspectApp:
    package: str
    name: str
    kind: str                 # vault | secure-messenger | wiper | vpn | root
    note: str = ""


SUSPECT_APPS: List[SuspectApp] = [
    # Vaults and photo hiders
    SuspectApp("com.domobile.applock", "AppLock (DoMobile)", "vault",
               "Hides photos and videos in an encrypted vault"),
    SuspectApp("com.domobile.applockwatcher", "AppLock Watcher", "vault"),
    SuspectApp("com.gallery.vault", "Gallery Vault", "vault",
               "Photo/video hider with a decoy calculator interface"),
    SuspectApp("com.calculator.vault", "Calculator Vault", "vault",
               "Presents as a calculator; a PIN opens a hidden gallery"),
    SuspectApp("com.hideitpro", "Hide It Pro", "vault",
               "Presents as an audio manager"),
    SuspectApp("com.privacy.vault", "Privacy Vault", "vault"),
    SuspectApp("com.keepsafe.switchboard", "KeepSafe Photo Vault", "vault"),
    SuspectApp("com.enchantedcloud.photovault", "Photo Vault", "vault"),
    SuspectApp("com.smartapp.applock", "Smart AppLock", "vault"),
    SuspectApp("com.vaultapp.gallerylock", "Gallery Lock", "vault"),
    SuspectApp("com.appvault.hideapp", "Hide App", "vault"),
    SuspectApp("com.ruet.calculator", "Calculator+ Vault", "vault"),
    # Ephemeral / secure messengers
    SuspectApp("org.thoughtcrime.securesms", "Signal", "secure-messenger",
               "End-to-end encrypted; local store is encrypted at rest"),
    SuspectApp("com.wickr.me", "Wickr Me", "secure-messenger",
               "Ephemeral messaging with burn-on-read"),
    SuspectApp("ch.threema.app", "Threema", "secure-messenger"),
    SuspectApp("im.vector.app", "Element (Matrix)", "secure-messenger"),
    SuspectApp("org.telegram.messenger", "Telegram", "secure-messenger",
               "Secret chats are device-only and not in the main store"),
    SuspectApp("com.privatemessenger", "Private Messenger", "secure-messenger"),
    SuspectApp("com.silentcircle.silentphone", "Silent Phone", "secure-messenger"),
    SuspectApp("com.briarproject.briar.android", "Briar", "secure-messenger"),
    SuspectApp("com.sessionapp", "Session", "secure-messenger"),
    # Wipers and cleaners
    SuspectApp("com.iobit.mobilecare", "Advanced Mobile Care", "wiper"),
    SuspectApp("com.piriform.ccleaner", "CCleaner", "wiper",
               "Can securely erase files and clear traces"),
    SuspectApp("com.cleanmaster.mguard", "Clean Master", "wiper"),
    SuspectApp("com.shredder.filedelete", "File Shredder", "wiper",
               "Overwrites files so they cannot be carved"),
    SuspectApp("com.secure.eraser", "Secure Eraser", "wiper"),
    # Anonymity
    SuspectApp("org.torproject.torbrowser", "Tor Browser", "vpn",
               "Anonymised browsing; history is not retained"),
    SuspectApp("org.torproject.android", "Orbot (Tor)", "vpn"),
    SuspectApp("com.protonvpn.android", "ProtonVPN", "vpn"),
    SuspectApp("com.nordvpn.android", "NordVPN", "vpn"),
    SuspectApp("net.openvpn.openvpn", "OpenVPN", "vpn"),
    # Root / tamper
    SuspectApp("eu.chainfire.supersu", "SuperSU", "root",
               "Root management — indicates the device was rooted"),
    SuspectApp("com.topjohnwu.magisk", "Magisk", "root",
               "Root with systemless hiding"),
    SuspectApp("com.koushikdutta.superuser", "Superuser", "root"),
    SuspectApp("de.robv.android.xposed.installer", "Xposed", "root"),
]

SUSPECT_BY_PACKAGE = {a.package: a for a in SUSPECT_APPS}

# Directory names that betray a vault even when the package list is unavailable.
VAULT_DIR_MARKERS = [
    ".hidedata", ".vault", ".gallery_lock", ".hideitpro", ".calculator_vault",
    ".privacy", ".applock", ".keepsafe", ".secure_gallery", ".nomedia_vault",
]

# Extensions vault apps use to make media invisible to the media scanner.
VAULT_EXTENSIONS = {".hid", ".vault", ".lock", ".enc", ".sec", ".hdt", ".dat0"}


# ═══════════════════════════════════════════════════════ encrypted stores
ENCRYPTED_SIGNATURES: List[Tuple[str, bytes, str, str]] = [
    ("WhatsApp crypt14", b"\x00\x01", "msgstore.db.crypt14",
     "WhatsApp encrypted backup. Requires the 32-byte key from "
     "/data/data/com.whatsapp/files/key (root access needed)."),
    ("WhatsApp crypt15", b"\x00\x01", "msgstore.db.crypt15",
     "WhatsApp end-to-end encrypted backup. Requires the user's 64-digit "
     "recovery key or their backup password."),
]


def is_sqlcipher(path: Path) -> Tuple[bool, str]:
    """Distinguish an encrypted SQLite database from a corrupt one.

    A SQLCipher file has no readable header — the first 16 bytes are ciphertext
    rather than ``SQLite format 3``. High entropy across the whole first page,
    combined with a file size that is an exact multiple of a plausible page
    size, is the signature. Getting this wrong in either direction is bad: a
    corrupt file reported as encrypted sends an examiner hunting for a key that
    does not exist, and an encrypted file reported as corrupt loses the
    evidence entirely.
    """
    try:
        size = path.stat().st_size
        if size < 1024:
            return False, ""
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False, ""

    if head.startswith(b"SQLite format 3\x00"):
        return False, ""

    # Entropy of the first page.
    counts = Counter(head)
    total = len(head)
    import math
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())

    page_aligned = any(size % ps == 0 for ps in (1024, 2048, 4096, 8192))
    if entropy > 7.5 and page_aligned:
        return True, (f"High-entropy content ({entropy:.2f} bits/byte) with a "
                      f"page-aligned size ({size} bytes) and no SQLite header "
                      f"— consistent with SQLCipher or another encrypted store.")
    if entropy > 7.5:
        return True, (f"High-entropy content ({entropy:.2f} bits/byte) and no "
                      f"readable header — encrypted or compressed.")
    return False, ""


def secure_delete_state(path: Path) -> Dict[str, Any]:
    """Assess empirically whether a database can yield deleted records.

    A note on why this does not read ``PRAGMA secure_delete``: that pragma
    reports the setting of the *connection doing the reading*, not what was in
    force when rows were deleted, and its default is a compile-time option that
    differs between builds. Querying it tells you about your own SQLite library,
    not about the evidence. Reporting that as a property of the file would be
    straightforwardly wrong — and would wrongly excuse a carver that found
    nothing.

    What *is* observable from the file is whether its free space still contains
    data. So the file's own free regions are inspected directly:

    * freelist pages and page freeblocks that are entirely zero indicate the
      content was overwritten (secure delete, or a wipe utility);
    * an empty freelist with no freeblocks indicates a VACUUM, or that nothing
      was ever deleted;
    * non-zero bytes in free space mean deleted records are recoverable, and
      any failure to recover them is a limitation of the carver, not the file.
    """
    from .sqlite_reader import ForensicSQLite

    out: Dict[str, Any] = {"checked": False}
    try:
        db = ForensicSQLite(path, sidecars=False)
    except Exception:
        return out

    try:
        free_regions = 0
        free_bytes = 0
        nonzero_bytes = 0

        for page_no in db.freelist_pages():
            page = db.page(page_no)
            if len(page) > 8:
                body = page[8:]
                free_regions += 1
                free_bytes += len(body)
                nonzero_bytes += sum(1 for b in body if b)

        for name, schema in db.schemas().items():
            if name.startswith("sqlite_") or not schema.rootpage:
                continue
            for page_no in db.leaf_pages_for(schema.rootpage):
                for _offset, chunk in db._page_gaps(page_no):
                    free_regions += 1
                    free_bytes += len(chunk)
                    nonzero_bytes += sum(1 for b in chunk if b)

        out.update({
            "checked": True,
            "freelist_pages": db.freelist_count,
            "free_regions": free_regions,
            "free_bytes": free_bytes,
            "nonzero_free_bytes": nonzero_bytes,
            "residual_data_ratio": (round(nonzero_bytes / free_bytes, 4)
                                    if free_bytes else 0.0),
            "auto_vacuum": db.vacuum_mode != 0,
        })
    except Exception:
        return out
    finally:
        db.close()

    reasons: List[str] = []
    if out["free_bytes"] == 0:
        reasons.append(
            "the database has no free space at all — it has been VACUUMed, or "
            "no rows have ever been deleted from it. Either way there is "
            "nothing for a carver to recover, so an empty result here is not "
            "evidence that content was never deleted")
    elif out["nonzero_free_bytes"] == 0:
        reasons.append(
            f"all {out['free_bytes']} bytes of free space are zeroed across "
            f"{out['free_regions']} region(s) — freed content was overwritten, "
            f"consistent with secure deletion or a wipe utility. Deleted "
            f"records are unrecoverable from this file")
    elif out["residual_data_ratio"] < 0.02:
        reasons.append(
            f"only {out['residual_data_ratio']:.1%} of free space contains "
            f"non-zero bytes — freed content appears to have been largely "
            f"overwritten")

    if out.get("auto_vacuum"):
        reasons.append("auto_vacuum is enabled, so freed pages are returned to "
                       "the filesystem and recoverable content is reduced")

    out["recovery_limited"] = bool(reasons)
    out["explanation"] = "; ".join(reasons)
    return out


# ═══════════════════════════════════════════════════════════ parsers
@register(
    name="antiforensics.encrypted",
    patterns=["*.crypt12", "*.crypt14", "*.crypt15", "*.sqlcipher",
              "signal.db", "encrypted.db", "*.enc"],
    platform="", priority=95,
    description="Encrypted application stores — reported, never treated as empty",
)
def parse_encrypted(path: Path, ctx: ParseContext) -> ParseResult:
    """Encrypted store detection."""
    res = ParseResult(parser="antiforensics.encrypted", source=ctx.rel(path))
    try:
        size = path.stat().st_size
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    name = path.name.lower()
    detail = ""
    subtype = "Encrypted store"
    if ".crypt" in name:
        version = name.rsplit(".crypt", 1)[-1]
        subtype = f"WhatsApp encrypted backup (crypt{version})"
        detail = ("WhatsApp backup encrypted at rest. Decryption requires the "
                  "key file from /data/data/com.whatsapp/files/key for crypt12 "
                  "and crypt14, or the user's 64-digit recovery key for "
                  "crypt15. ARGUS does not attempt to break it.")
    else:
        encrypted, why = is_sqlcipher(path)
        if not encrypted:
            return res
        detail = why

    art = Artifact(
        category=Category.SECURITY, subtype=subtype,
        timestamp=int(path.stat().st_mtime * US),
        body=f"{path.name} — encrypted, not decoded",
        app=_app_from_path(path), source_path=ctx.rel(path),
        attributes={
            "filename": path.name, "size_bytes": size,
            "encrypted": True, "decoded": False,
            "explanation": detail,
            "impact": ("Any messages, contacts or media in this file are NOT "
                       "included in this extraction's artifact counts."),
        },
    )
    res.artifacts.append(art)
    res.notes.append(f"{ctx.rel(path)}: encrypted store, not decoded — {detail}")
    ctx.emit("antiforensics", "warning",
             f"{path.name}: encrypted store — content not included in this "
             f"extraction", level="warning")
    return res


@register(
    name="antiforensics.thumbnails",
    patterns=[".thumbdata*", "*.thumbdata3*", "thumbdata*"],
    platform="", priority=70,
    description="Android thumbnail cache — recovers images whose originals were deleted",
)
def parse_thumbnails(path: Path, ctx: ParseContext) -> ParseResult:
    """Android thumbnail cache carving.

    ``.thumbdata3--*`` is an append-only concatenation of JPEG thumbnails. The
    Android media scanner does not remove a thumbnail when its source photo is
    deleted, so this file routinely holds the only surviving copy of images the
    user believes are gone.
    """
    res = ParseResult(parser="antiforensics.thumbnails", source=ctx.rel(path))
    from .filecarver import FileCarver, SIGNATURES

    image_sigs = [s for s in SIGNATURES if s.extension in ("jpg", "png")]
    carver = FileCarver(signatures=image_sigs, max_files=4000, keep_data=True)
    try:
        data = path.read_bytes()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    carved = carver.carve_bytes(data)
    mtime = int(path.stat().st_mtime * US)
    for item in carved:
        sha = ""
        if ctx.store_blob:
            try:
                sha = _store_bytes(ctx, item.data,
                                   f"{ctx.rel(path)}#offset{item.offset}")
            except Exception as exc:
                res.warnings.append(f"thumbnail at {item.offset}: {exc}")
        art = Artifact(
            category=Category.FILE, subtype="Picture (thumbnail cache)",
            timestamp=mtime, body=f"thumbnail @ offset {item.offset}",
            app="Android media scanner", source_path=ctx.rel(path),
            blob_sha256=sha, recovery=Recovery.CARVED,
            confidence=item.confidence,
            attributes={
                "filename": f"thumb_{item.offset}.{item.extension}",
                "size_bytes": item.size, "mime_type": item.mime,
                "carved_offset": item.offset,
                "note": ("Recovered from the thumbnail cache. Android does not "
                         "purge thumbnails when the original photo is deleted, "
                         "so this may be the only surviving copy of an image "
                         "the user removed."),
            },
        )
        res.artifacts.append(art)
        res.deleted_recovered += 1

    if carved:
        res.notes.append(
            f"{ctx.rel(path)}: {len(carved)} thumbnail(s) carved — potential "
            f"survivors of deleted photographs")
        ctx.emit("antiforensics", "ok",
                 f"{path.name}: {len(carved)} thumbnails recovered")
    return res


@register(
    name="antiforensics.vault_media",
    patterns=["*.hid", "*.vault", "*.lock", "*.sec", "*.hdt"],
    platform="", priority=65,
    description="Media concealed by a vault application",
)
def parse_vault_media(path: Path, ctx: ParseContext) -> ParseResult:
    """Vault-hidden media.

    Most consumer "photo vault" apps do not really encrypt: they rename the
    file, change its extension and drop a ``.nomedia`` marker so the gallery
    ignores it. The bytes are intact, so the original image is recoverable.
    """
    res = ParseResult(parser="antiforensics.vault_media", source=ctx.rel(path))
    from .media.exif import sniff

    mime, desc = sniff(path)
    if not mime or not mime.startswith(("image/", "video/", "audio/")):
        return res

    try:
        stat = path.stat()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    sha = ""
    if ctx.store_blob:
        try:
            sha = ctx.store_blob(path, ctx.rel(path))
        except Exception as exc:
            res.warnings.append(f"{path.name}: {exc}")

    art = Artifact(
        category=Category.FILE,
        subtype=f"{'Picture' if mime.startswith('image/') else 'Media'} "
                f"(concealed)",
        timestamp=int(stat.st_mtime * US), body=path.name,
        app=_app_from_path(path), source_path=ctx.rel(path), blob_sha256=sha,
        attributes={
            "filename": path.name, "size_bytes": stat.st_size,
            "mime_type": mime, "file_type": desc,
            "extension_mismatch": True, "concealed": True,
            "mismatch_note": (
                f"Extension '{path.suffix}' conceals a {desc}. Vault "
                f"applications rename media so the gallery will not index it; "
                f"the file content is unmodified and fully recoverable."),
        },
    )
    res.artifacts.append(art)
    res.notes.append(f"{ctx.rel(path)}: concealed {desc} recovered from a vault")
    return res


# ═══════════════════════════════════════════════════ tree-level analysis
@dataclass
class AntiForensicsReport:
    suspect_apps: List[Dict[str, Any]] = field(default_factory=list)
    vault_directories: List[str] = field(default_factory=list)
    encrypted_stores: List[Dict[str, Any]] = field(default_factory=list)
    uninstalled_residue: List[Dict[str, Any]] = field(default_factory=list)
    limited_recovery: List[Dict[str, Any]] = field(default_factory=list)
    reset_estimate: Optional[Dict[str, Any]] = None
    thumbnail_caches: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def indicator_count(self) -> int:
        return (len(self.suspect_apps) + len(self.vault_directories)
                + len(self.encrypted_stores) + len(self.uninstalled_residue)
                + len(self.limited_recovery)
                + (1 if self.reset_estimate else 0))


def scan_tree(root: Path, installed_packages: Optional[Set[str]] = None
              ) -> AntiForensicsReport:
    """Sweep an acquired tree for anti-forensic indicators."""
    root = Path(root)
    report = AntiForensicsReport()
    seen_dirs: Set[str] = set()
    data_dirs: Set[str] = set()
    mtimes: List[float] = []

    for path in root.rglob("*"):
        try:
            is_dir = path.is_dir()
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        low = rel.lower()

        if is_dir:
            name = path.name
            if name in seen_dirs:
                continue
            seen_dirs.add(name)
            if any(marker in low for marker in VAULT_DIR_MARKERS):
                report.vault_directories.append(rel)
            # Application private-data directories
            if re.search(r"data/(data|user/\d+)/([a-z][\w.]+\.[\w.]+)$", low):
                data_dirs.add(name)
            continue

        try:
            stat = path.stat()
            mtimes.append(stat.st_mtime)
        except OSError:
            continue

        if path.name.lower().startswith((".thumbdata", "thumbdata")):
            report.thumbnail_caches.append(rel)

        if path.suffix.lower() in VAULT_EXTENSIONS:
            report.vault_directories.append(rel)

        if ".crypt" in path.name.lower():
            report.encrypted_stores.append({
                "path": rel, "kind": "WhatsApp encrypted backup",
                "size": stat.st_size})
        elif path.suffix.lower() in (".db", ".sqlite", ".sqlite3", ".storedata"):
            encrypted, why = is_sqlcipher(path)
            if encrypted:
                report.encrypted_stores.append({
                    "path": rel, "kind": "Encrypted database", "reason": why,
                    "size": stat.st_size})
            else:
                state = secure_delete_state(path)
                if state.get("recovery_limited"):
                    report.limited_recovery.append({
                        "path": rel, **state})

    # Suspect applications, from the package list where available and from
    # on-disk directories otherwise.
    candidates = set(installed_packages or ()) | data_dirs
    for package in sorted(candidates):
        app = SUSPECT_BY_PACKAGE.get(package)
        if app:
            report.suspect_apps.append({
                "package": app.package, "name": app.name, "kind": app.kind,
                "note": app.note,
                "installed": package in (installed_packages or set()),
                "data_directory_present": package in data_dirs,
            })

    # Residue: a data directory present for a package that is not installed.
    # System components are excluded — they legitimately hold data directories
    # without appearing in the user-installed package list, and reporting them
    # as "uninstalled apps" would bury the one entry that actually matters.
    if installed_packages:
        for package in sorted(data_dirs - set(installed_packages)):
            if _is_system_package(package):
                continue
            report.uninstalled_residue.append({
                "package": package,
                "known_app": SUSPECT_BY_PACKAGE.get(package).name
                             if package in SUSPECT_BY_PACKAGE else "",
                "note": ("Application data directory exists but the package is "
                         "not in the installed list — the app was removed and "
                         "its data was left behind."),
            })

    report.reset_estimate = _estimate_reset(mtimes)
    return report


def _estimate_reset(mtimes: List[float]) -> Optional[Dict[str, Any]]:
    """Infer a factory reset from a hard floor in file modification times.

    After a reset every file is recreated, so the oldest modification time in
    the tree becomes the reset date. If the bulk of files cluster tightly at
    that floor — and it is recent — the device was almost certainly wiped then.
    """
    if len(mtimes) < 20:
        return None
    ordered = sorted(mtimes)
    floor = ordered[0]
    span_days = (ordered[-1] - floor) / 86400
    if span_days > 400 or span_days <= 0:
        return None
    window = floor + 86400
    clustered = sum(1 for t in ordered if t <= window)
    ratio = clustered / len(ordered)
    if ratio < 0.30:
        return None
    return {
        "estimated_reset": to_iso(int(floor * US)),
        "files_at_floor": clustered,
        "total_files": len(ordered),
        "ratio_at_floor": round(ratio, 3),
        "activity_span_days": round(span_days, 1),
        "confidence": "medium" if ratio > 0.5 else "low",
        "explanation": (
            f"{ratio:.0%} of files share the earliest modification date in the "
            f"tree, and total activity spans only {span_days:.0f} days. This is "
            f"consistent with a factory reset or a fresh device setup at that "
            f"date. Note that an acquisition which copies files can itself "
            f"reset timestamps — confirm against the device's own build date "
            f"before relying on this."),
    }


def antiforensics_findings(report: AntiForensicsReport) -> List[Any]:
    """Convert indicators into findings."""
    from ..intel.findings import Finding

    out: List[Finding] = []

    vaults = [a for a in report.suspect_apps if a["kind"] == "vault"]
    if vaults or report.vault_directories:
        out.append(Finding(
            rule_id="antiforensics.vault",
            title=(f"{len(vaults)} vault/hider application(s) and "
                   f"{len(report.vault_directories)} concealment artifact(s)"),
            detail=("Applications whose purpose is concealing media were "
                    "present: " + ", ".join(a["name"] for a in vaults[:6])
                    if vaults else
                    "Directories or files matching known vault-app patterns "
                    "were found."),
            severity="high", confidence=0.8, category="antiforensics",
            evidence=([f"{a['name']} ({a['package']})" for a in vaults[:5]]
                      + report.vault_directories[:5]),
            metrics={"apps": vaults, "paths": report.vault_directories[:40]},
            why_it_matters=("A vault app means media was deliberately hidden. "
                            "Most consumer vaults only rename files rather "
                            "than encrypting them, so the content is usually "
                            "recoverable — look inside these directories."),
            caveat=("Vault and app-lock software is also used for ordinary "
                    "privacy. Presence alone is not evidence of wrongdoing."),
        ))

    if report.encrypted_stores:
        out.append(Finding(
            rule_id="antiforensics.encrypted_stores",
            title=f"{len(report.encrypted_stores)} encrypted store(s) not decoded",
            detail=("These files are encrypted and their contents are NOT "
                    "included in this extraction: "
                    + "; ".join(f"{e['path']} ({e['kind']})"
                                for e in report.encrypted_stores[:6])),
            severity="critical", confidence=0.85, category="antiforensics",
            evidence=[e["path"] for e in report.encrypted_stores[:8]],
            metrics={"stores": report.encrypted_stores[:20],
                       "remediation": ("Re-run Comprehensive with USB debugging "
                                       "to pull WhatsApp key, or document the "
                                       "limitation in your report.")},
            why_it_matters=("Artifact counts in this report exclude everything "
                            "in these files. Any conclusion about what is "
                            "*absent* from the handset must account for them."),
            caveat=("High entropy also describes compressed and already-deleted "
                    "data. Confirm the file type before pursuing a key."),
        ))

    if report.limited_recovery:
        out.append(Finding(
            rule_id="antiforensics.recovery_limited",
            title=(f"{len(report.limited_recovery)} database(s) cannot yield "
                   f"deleted records"),
            detail=("For these files, recovering no deleted records is the "
                    "expected technical outcome rather than a finding of "
                    "absence: "
                    + "; ".join(f"{e['path']} — {e['explanation']}"
                                for e in report.limited_recovery[:4])),
            severity="info", confidence=0.9, category="antiforensics",
            metrics={"databases": report.limited_recovery[:20]},
            why_it_matters=("Prevents a technical limitation being reported as "
                            "evidence that nothing was ever deleted."),
            caveat="",
        ))

    if report.uninstalled_residue:
        out.append(Finding(
            rule_id="antiforensics.uninstalled",
            title=f"{len(report.uninstalled_residue)} uninstalled application(s) left data behind",
            detail=("Data directories survive for applications no longer "
                    "installed: "
                    + ", ".join(e["package"]
                                for e in report.uninstalled_residue[:8])),
            severity="medium", confidence=0.75, category="antiforensics",
            metrics={"packages": report.uninstalled_residue[:30]},
            why_it_matters=("An app removed but not cleaned up may still hold "
                            "messages and media, and its removal date can be "
                            "significant in itself."),
            caveat=("Android leaves residue routinely after ordinary "
                    "uninstalls and updates."),
        ))

    wipers = [a for a in report.suspect_apps if a["kind"] == "wiper"]
    if wipers:
        out.append(Finding(
            rule_id="antiforensics.wiper",
            title=f"{len(wipers)} secure-deletion tool(s) installed",
            detail=("Applications capable of overwriting files so they cannot "
                    "be carved: " + ", ".join(a["name"] for a in wipers)),
            severity="high", confidence=0.7, category="antiforensics",
            metrics={"apps": wipers},
            why_it_matters=("If these were used, absence of recoverable "
                            "deleted data has a deliberate cause."),
            caveat=("Cleaner apps are hugely popular for freeing storage and "
                    "are usually installed for that reason alone."),
        ))

    if report.reset_estimate:
        est = report.reset_estimate
        out.append(Finding(
            rule_id="antiforensics.factory_reset",
            title=f"Possible factory reset around {est['estimated_reset'][:10]}",
            detail=est["explanation"],
            severity="high" if est["confidence"] == "medium" else "medium",
            confidence=0.5 if est["confidence"] == "low" else 0.7,
            category="antiforensics", metrics=est,
            why_it_matters=("A reset date bounds how far back any evidence on "
                            "this handset can reach, and a reset shortly "
                            "before seizure is significant."),
            caveat=("The acquisition process itself can normalise file "
                    "timestamps, producing exactly this pattern. Verify "
                    "against the device build date and the account creation "
                    "dates before relying on it."),
        ))

    if report.thumbnail_caches:
        out.append(Finding(
            rule_id="antiforensics.thumbnails_present",
            title=f"{len(report.thumbnail_caches)} thumbnail cache(s) available",
            detail=("Thumbnail caches were found and carved. Android retains "
                    "thumbnails after the source photograph is deleted, so "
                    "these may hold the only surviving copies: "
                    + ", ".join(report.thumbnail_caches[:5])),
            severity="medium", confidence=0.9, category="antiforensics",
            metrics={"paths": report.thumbnail_caches},
            why_it_matters=("Recovered thumbnails can establish that an image "
                            "existed even when the full-resolution original is "
                            "unrecoverable."),
            caveat=("A thumbnail is low resolution and carries no EXIF, so it "
                    "cannot establish where or when the photo was taken."),
        ))
    return out


# ────────────────────────────────────────────────────────────────── helpers
_SYSTEM_PREFIXES = (
    "android", "com.android.", "com.google.android.", "com.qualcomm.",
    "com.samsung.android.", "com.sec.android.", "com.mediatek.",
    "com.miui.", "com.xiaomi.", "com.huawei.", "com.oppo.", "com.vivo.",
    "com.oneplus.", "com.motorola.", "com.lge.", "com.sonyericsson.",
    "com.qti.", "vendor.qti.", "com.svox.", "org.chromium.",
)


def _is_system_package(package: str) -> bool:
    """System components hold data directories without being user-installed."""
    return package == "android" or package.startswith(_SYSTEM_PREFIXES)


def _store_bytes(ctx: ParseContext, data: bytes, label: str) -> str:
    """Store carved bytes via the container, using a temporary file."""
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(data)
        tmp = Path(fh.name)
    try:
        return ctx.store_blob(tmp, label) if ctx.store_blob else ""
    finally:
        tmp.unlink(missing_ok=True)


def _app_from_path(path: Path) -> str:
    text = path.as_posix().lower()
    for package, app in SUSPECT_BY_PACKAGE.items():
        if package in text:
            return app.name
    match = re.search(r"(?:data/data|data/user/\d+)/([a-z][\w.]+\.[\w.]+)", text)
    if match:
        return match.group(1)
    if "whatsapp" in text:
        return "WhatsApp"
    return "File system"
