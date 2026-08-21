"""Decrypt WhatsApp .crypt12/14/15 backups when keys are available.

ARGUS never attempts to break encryption — it decrypts only when the device
key, E2E recovery key (64 hex digits), or user-supplied passphrase was
provided during acquisition.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

_KEY_NAMES = ("key", "encrypted_backup.key", "wa_key", "whatsapp_key")
_CRYPT_GLOB = ("*.crypt12", "*.crypt14", "*.crypt15")
_SQLITE = b"SQLite format 3\x00"

# IV start, IV end, ciphertext start — common crypt12/14 layouts.
_OFFSETS: Tuple[Tuple[int, int, int], ...] = (
    (51, 67, 67),
    (67, 83, 83),
    (11, 27, 27),
    (15, 31, 31),
    (131, 147, 147),
)


@dataclass
class DecryptResult:
    source: str = ""
    output: str = ""
    version: str = ""
    ok: bool = False
    message: str = ""
    bytes_out: int = 0


@dataclass
class DecryptSummary:
    attempted: int = 0
    decrypted: int = 0
    results: List[DecryptResult] = field(default_factory=list)


def parse_key_file(blob: bytes) -> bytes:
    """Extract the 32-byte AES key from a WhatsApp key file or hex string."""
    if len(blob) == 32:
        return blob
    if len(blob) == 64:
        try:
            return bytes.fromhex(blob.decode("ascii").strip())
        except ValueError:
            pass
    text = blob.decode("utf-8", errors="ignore").strip()
    if len(text) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    if len(blob) >= 158:
        return blob[126:158]
    if len(blob) >= 32:
        return blob[-32:]
    raise ValueError("unrecognised WhatsApp key format")


def _derive_key(raw_key: bytes) -> bytes:
    return hmac.new(b"\x00" * 32, raw_key, hashlib.sha256).digest()


def _key_variants(blob: bytes) -> List[bytes]:
    raw = parse_key_file(blob)
    variants = [raw, _derive_key(raw)]
    if raw not in variants:
        variants.insert(0, raw)
    out: List[bytes] = []
    seen: set[bytes] = set()
    for key in variants:
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _finish_plaintext(plain: bytes) -> Optional[bytes]:
    if plain.startswith(_SQLITE):
        return plain
    try:
        decompressed = zlib.decompress(plain)
        if decompressed.startswith(_SQLITE):
            return decompressed
    except zlib.error:
        pass
    return None


def decrypt_crypt_payload(key_blob: bytes, encrypted: bytes,
                          *, version: str = "") -> Optional[bytes]:
    """Try AES-GCM decryption with known crypt12/14 offset patterns."""
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES                           # noqa: N811
        except ImportError:
            return None

    if len(encrypted) < 128:
        return None
    keys = _key_variants(key_blob)
    for key in keys:
        for iv_s, iv_e, db_s in _OFFSETS:
            if len(encrypted) < db_s + 32:
                continue
            iv = encrypted[iv_s:iv_e]
            tail = encrypted[db_s:]
            for tag_len in (16, 32):
                if len(tail) <= tag_len:
                    continue
                ct, tag = tail[:-tag_len], tail[-tag_len:]
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                    plain = cipher.decrypt_and_verify(ct, tag)
                    finished = _finish_plaintext(plain)
                    if finished:
                        return finished
                except (ValueError, KeyError):
                    continue
    return None


def _rel_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.name)


def _find_key_files(root: Path) -> List[Path]:
    found: List[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in _KEY_NAMES:
            found.append(path)
        elif name.endswith("/files/key") or path.as_posix().endswith("/files/key"):
            found.append(path)
        elif "whatsapp" in path.as_posix().lower() and name == "key":
            found.append(path)
    return found


def _find_crypt_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for pattern in _CRYPT_GLOB:
        out.extend(root.rglob(pattern))
    return sorted({p.resolve() for p in out if p.is_file()})


def parse_recovery_key(text: str) -> Optional[bytes]:
    """Parse WhatsApp E2E backup recovery key (64 hex digits)."""
    cleaned = re.sub(r"[\s\-]", "", (text or "").strip())
    if len(cleaned) == 64 and re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return bytes.fromhex(cleaned)
    return None


def _derive_crypt15_passphrase(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", password.encode("utf-8"), salt, 100_000)[:32]


def decrypt_crypt15(encrypted: bytes, *,
                    recovery_key: Optional[bytes] = None,
                    passphrase: str = "") -> Optional[bytes]:
    """Attempt crypt15 decryption with recovery key and/or passphrase."""
    candidates: List[bytes] = []
    if recovery_key and len(recovery_key) == 32:
        candidates.append(recovery_key)
    if passphrase:
        for start in (11, 67, 131, 15, 51):
            if len(encrypted) >= start + 32:
                candidates.append(
                    _derive_crypt15_passphrase(passphrase, encrypted[start:start + 32]))
    seen: set[bytes] = set()
    for key in candidates:
        if key in seen:
            continue
        seen.add(key)
        plain = decrypt_crypt_payload(key, encrypted, version="crypt15")
        if plain:
            return plain
    return None


def _write_decrypted(root: Path, crypt_path: Path, plain: bytes,
                     result: DecryptResult, summary: DecryptSummary,
                     log: Optional[Callable[..., None]],
                     output_root: Optional[Path] = None) -> None:
    out_name = crypt_path.name.rsplit(".crypt", 1)[0]
    if not out_name.endswith(".db"):
        out_name += ".db"
    if output_root:
        try:
            rel = crypt_path.parent.resolve().relative_to(root.resolve())
        except ValueError:
            rel = Path(".")
        dest_dir = Path(output_root) / rel
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_path = dest_dir / out_name
        rel_root = Path(output_root)
    else:
        out_path = crypt_path.with_name(out_name)
        rel_root = root
    if out_path.exists() and out_path.stat().st_size > 0:
        result.ok = True
        result.output = _rel_path(rel_root, out_path)
        result.message = "already decrypted"
        result.bytes_out = out_path.stat().st_size
        summary.decrypted += 1
        return
    try:
        out_path.write_bytes(plain)
        result.ok = True
        result.output = _rel_path(rel_root, out_path)
        result.bytes_out = len(plain)
        result.message = "decrypted"
        summary.decrypted += 1
        if log:
            log("decode.whatsapp", "ok",
                f"Decrypted {crypt_path.name} → {out_name} "
                f"({len(plain):,} bytes)")
    except OSError as exc:
        result.message = str(exc)


def decrypt_whatsapp_backups(raw_root: Path,
                             log: Optional[Callable[..., None]] = None,
                             *,
                             recovery_key: str = "",
                             passphrase: str = "",
                             output_root: Optional[Path] = None) -> DecryptSummary:
    """Locate key + crypt pairs and write decrypted SQLite databases."""
    root = Path(raw_root)
    summary = DecryptSummary()
    keys = _find_key_files(root)
    crypts = _find_crypt_files(root)
    rec_bytes = parse_recovery_key(recovery_key)
    if not crypts:
        return summary
    key_data: List[bytes] = []
    for key_path in keys:
        try:
            key_data.append(key_path.read_bytes())
        except OSError:
            continue
    if not key_data and not rec_bytes and not passphrase and log:
        log("decode.whatsapp", "note",
            f"Found {len(crypts)} encrypted WhatsApp backup(s) — "
            f"provide recovery key, passphrase, or pull device key via Comprehensive",
            level="warning")

    for crypt_path in crypts:
        summary.attempted += 1
        version = "crypt15" if crypt_path.name.endswith(".crypt15") else (
            "crypt14" if crypt_path.name.endswith(".crypt14") else "crypt12")
        result = DecryptResult(source=_rel_path(root, crypt_path),
                               version=version)
        try:
            encrypted = crypt_path.read_bytes()
        except OSError as exc:
            result.message = str(exc)
            summary.results.append(result)
            continue
        plain: Optional[bytes] = None
        if version == "crypt15":
            plain = decrypt_crypt15(
                encrypted, recovery_key=rec_bytes, passphrase=passphrase)
            if not plain:
                for blob in key_data:
                    plain = decrypt_crypt_payload(blob, encrypted, version=version)
                    if plain:
                        break
            if not plain and not rec_bytes and not passphrase:
                result.message = ("crypt15 — enter 64-digit recovery key or "
                                  "backup passphrase in extraction options")
        else:
            for blob in key_data:
                plain = decrypt_crypt_payload(blob, encrypted, version=version)
                if plain:
                    break
            if not plain and not key_data:
                result.message = ("no device key — pull key file with "
                                  "Comprehensive or use MTP + ADB upgrade")
            elif not plain:
                result.message = "decryption failed — key may not match backup"
        if not plain:
            summary.results.append(result)
            continue
        _write_decrypted(root, crypt_path, plain, result, summary, log,
                         output_root=output_root)
        summary.results.append(result)
    return summary


def as_dict(summary: DecryptSummary) -> Dict[str, Any]:
    return {
        "attempted": summary.attempted,
        "decrypted": summary.decrypted,
        "results": [r.__dict__ for r in summary.results],
    }
