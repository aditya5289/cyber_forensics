"""Host filesystem helpers — Windows long paths and adb pull destinations.

Windows still defaults to a 260-character MAX_PATH. ARGUS containers nest
``cases\\...\\exhibits\\...afc\\raw\\adb\\filesystem\\sdcard\\...``, so a
WhatsApp media tree routinely overruns that limit. ``adb pull`` also nests
the remote basename when the destination directory already exists, which
adds another ``\\com.whatsapp`` and makes the overflow worse.

These helpers:

* prefix local paths with ``\\\\?\\`` so CreateFileW accepts long names,
* create parent directories the same way,
* tell callers when an empty dest dir must be removed before ``adb pull``.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterator


_WIN_MAX = 240  # leave room for a filename under the dest folder


def win_long_path(path: Path | str) -> str:
    """Absolute path, with the Windows long-path prefix when needed."""
    raw = os.path.abspath(os.fspath(path))
    if os.name != "nt":
        return raw
    if raw.startswith("\\\\?\\"):
        return raw
    if raw.startswith("\\\\"):
        return "\\\\?\\UNC\\" + raw.lstrip("\\")
    return "\\\\?\\" + raw


def host_fs_path(path: Path | str) -> str:
    """Path string safe to pass to adb, tar, and os APIs on this host.

    Short Windows paths stay unprefixed so ``adb.exe`` (which does not
    always honour ``\\\\?\\``) keeps working. Long dests get the prefix.
    """
    raw = os.path.abspath(os.fspath(path))
    if os.name != "nt":
        return raw
    if raw.startswith("\\\\?\\") or len(raw) >= _WIN_MAX:
        return win_long_path(raw)
    return raw


def ensure_dir(path: Path | str) -> None:
    """``mkdir -p`` that works past MAX_PATH on Windows."""
    if os.name != "nt":
        Path(path).mkdir(parents=True, exist_ok=True)
        return
    os.makedirs(win_long_path(path), exist_ok=True)


def dir_nonempty(path: Path | str) -> bool:
    try:
        with os.scandir(host_fs_path(path) if os.name == "nt" else os.fspath(path)) as it:
            return next(it, None) is not None
    except OSError:
        return False


def rmdir_if_empty(path: Path | str) -> bool:
    """Remove *path* only when it is an empty directory. Returns True if removed."""
    try:
        target = host_fs_path(path) if os.name == "nt" else os.fspath(path)
        if not os.path.isdir(target):
            return False
        if dir_nonempty(path):
            return False
        os.rmdir(target)
        return True
    except OSError:
        return False


def path_too_long_for_win32(path: Path | str) -> bool:
    """True when a mirrored dest is likely to overflow MAX_PATH on Windows."""
    if os.name != "nt":
        return False
    return len(os.path.abspath(os.fspath(path))) >= _WIN_MAX


def is_win_path_error(message: str) -> bool:
    text = (message or "").lower()
    return any(token in text for token in (
        "cannot create",
        "filename or extension is too long",
        "the filename or extension is too long",
        "path too long",
        "error 206",
        "error 3",
        "system cannot find the path",
        "the directory name is invalid",
    ))


def safe_dest(parent: Path, name: str) -> Path:
    """Child path under *parent*, hashed short if Windows MAX_PATH would trip.

    Original names are recorded in ``argus-longpaths.json`` beside the files
    so the exhibit still names what the handset called them.
    """
    candidate = parent / name
    if not path_too_long_for_win32(candidate) and len(name) < 120:
        return candidate
    digest = hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:16]
    short_name = f"lp_{digest}"
    index = parent / "argus-longpaths.json"
    ensure_dir(parent)
    data: dict = {}
    if index.exists():
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    data[short_name] = name
    index.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                     encoding="utf-8")
    return parent / short_name


def make_short_stage(prefix: str = "argus-adb-") -> Path:
    """Short host folder for adb/tar when the real dest is too deep."""
    root = os.environ.get("ARGUS_STAGE") or tempfile.gettempdir()
    Path(root).mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=root))


def walk_files(root: Path | str) -> Iterator[Path]:
    start = host_fs_path(root) if os.name == "nt" else os.fspath(root)
    if os.path.isfile(start):
        yield Path(start)
        return
    if not os.path.isdir(start):
        return
    for dirpath, _dirnames, filenames in os.walk(start):
        for name in filenames:
            yield Path(dirpath) / name


def tree_bytes(root: Path | str) -> int:
    total = 0
    for path in walk_files(root):
        try:
            total += path.stat().st_size
        except OSError:
            pass
    return total


def relocate_tree(src: Path | str, dst: Path | str) -> None:
    """Copy *src* onto *dst*, creating long-path dest dirs as needed."""
    src_s = host_fs_path(src)
    dst_p = Path(dst)
    if os.path.isfile(src_s):
        ensure_dir(dst_p.parent)
        shutil.copy2(src_s, host_fs_path(dst_p))
        return
    if not os.path.isdir(src_s):
        return
    ensure_dir(dst_p)
    prefix = src_s.rstrip("\\/")
    for dirpath, dirnames, filenames in os.walk(src_s):
        rel = os.path.relpath(dirpath, prefix)
        target_dir = dst_p if rel in (".", "") else dst_p / rel
        ensure_dir(target_dir)
        for name in dirnames:
            ensure_dir(target_dir / name)
        for name in filenames:
            shutil.copy2(
                os.path.join(dirpath, name),
                host_fs_path(target_dir / name),
            )
