"""Android ADB backup (``.ab``) reader.

An ``.ab`` file is a short text header followed by a (usually zlib-compressed,
optionally AES-encrypted) tar stream.  ``adb backup`` is deprecated from
Android 12 and most modern apps set ``android:allowBackup="false"``, so this
is a *fallback* acquisition path — but it is still the only path that works on
many older handsets in a real caseload.

Header::

    ANDROID BACKUP\\n
    <version>\\n
    <compressed 0|1>\\n
    <encryption none|AES-256>\\n
    [salt\\n user-salt\\n rounds\\n user-iv\\n master-key-blob\\n]

Encrypted backups are supported when a password is supplied: the master key is
unwrapped with PBKDF2-HMAC-SHA1 exactly as ``BackupManagerService`` does it.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Tuple

from ..core.errors import AcquisitionError

MAGIC = b"ANDROID BACKUP"
PBKDF2_KEY_SIZE = 32


@dataclass
class BackupHeader:
    version: int
    compressed: bool
    encryption: str
    offset: int


def read_header(data: bytes) -> BackupHeader:
    if not data.startswith(MAGIC):
        raise AcquisitionError("not an Android backup file (missing magic)")
    lines, pos = [], 0
    for _ in range(9):
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        lines.append(data[pos:nl])
        pos = nl + 1
        if len(lines) >= 4 and lines[3] == b"none":
            break
        if len(lines) >= 9:
            break
    if len(lines) < 4:
        raise AcquisitionError("truncated Android backup header")
    return BackupHeader(
        version=int(lines[1] or 1),
        compressed=lines[2] == b"1",
        encryption=lines[3].decode("ascii", "replace"),
        offset=pos,
    )


def _decrypt(data: bytes, lines: list[bytes], password: str) -> bytes:
    try:
        from Crypto.Cipher import AES                       # pycryptodome
    except ImportError as exc:                              # pragma: no cover
        raise AcquisitionError(
            "encrypted backup requires pycryptodome (pip install pycryptodome)"
        ) from exc

    user_salt = bytes.fromhex(lines[4].decode())
    ck_salt = bytes.fromhex(lines[5].decode())
    rounds = int(lines[6])
    user_iv = bytes.fromhex(lines[7].decode())
    master_blob = bytes.fromhex(lines[8].decode())

    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), user_salt,
                              rounds, PBKDF2_KEY_SIZE)
    blob = AES.new(key, AES.MODE_CBC, user_iv).decrypt(master_blob)
    pad = blob[-1]
    blob = blob[:-pad] if 0 < pad <= 16 else blob

    stream = io.BytesIO(blob)
    def _chunk() -> bytes:
        n = stream.read(1)
        if not n:
            raise AcquisitionError("malformed master key blob")
        return stream.read(n[0])

    master_iv = _chunk()
    master_key = _chunk()
    checksum = _chunk()

    calc = hashlib.pbkdf2_hmac(
        "sha1", "".join(chr(b) for b in master_key).encode("utf-8"),
        ck_salt, rounds, PBKDF2_KEY_SIZE)
    if calc != checksum:
        calc = hashlib.pbkdf2_hmac("sha1", bytes(master_key), ck_salt, rounds,
                                   PBKDF2_KEY_SIZE)
        if calc != checksum:
            raise AcquisitionError("backup password is incorrect")
    return AES.new(master_key, AES.MODE_CBC, master_iv).decrypt(data)


def to_tar_bytes(path: Path, password: Optional[str] = None) -> bytes:
    """Return the decompressed/decrypted tar payload of an ``.ab`` file."""
    data = Path(path).read_bytes()
    header = read_header(data)
    payload = data[header.offset:]

    if header.encryption.upper().startswith("AES"):
        lines, pos = [], 0
        for _ in range(9):
            nl = data.find(b"\n", pos)
            if nl < 0:
                break
            lines.append(data[pos:nl])
            pos = nl + 1
        if not password:
            raise AcquisitionError(
                "backup is AES-256 encrypted; supply the backup password")
        payload = _decrypt(data[pos:], lines, password)

    if header.compressed:
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            d = zlib.decompressobj()
            try:
                payload = d.decompress(payload)
            except zlib.error as exc:
                raise AcquisitionError(
                    f"backup payload could not be decompressed ({exc}); the "
                    f"file may be truncated") from exc
    return payload


def extract(path: Path, dest: Path, password: Optional[str] = None
            ) -> Tuple[int, list[str]]:
    """Extract an ``.ab`` backup into ``dest``. Returns ``(count, warnings)``."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    payload = to_tar_bytes(path, password)
    warnings: list[str] = []
    count = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r|") as tf:
        for member in tf:
            if not member.isfile():
                continue
            # Path traversal guard — a malicious backup must not escape dest.
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                warnings.append(f"skipped path-traversal entry: {member.name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with target.open("wb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
            count += 1
    return count, warnings


def list_apps(path: Path, password: Optional[str] = None) -> list[str]:
    """List the package names present in a backup without extracting it."""
    payload = to_tar_bytes(path, password)
    apps: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r|") as tf:
        for member in tf:
            parts = member.name.split("/")
            if len(parts) > 1 and parts[0] == "apps":
                apps.add(parts[1])
    return sorted(apps)
