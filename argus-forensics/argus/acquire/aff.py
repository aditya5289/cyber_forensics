"""Advanced Forensic Format (AFF) images — convert when ``affconvert`` is available."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional, Tuple

from ..core.errors import AcquisitionError
from ..devices.detect import find_tool


def is_aff(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        head = path.read_bytes()[:8]
    except OSError:
        return False
    return head[:4] == b"AFF\x00" or head[:3] == b"AFD"


def convert_to_raw(source: Path, dest: Path,
                   log=None) -> Tuple[Path, int]:
    """Convert AFF to raw using ``affconvert``."""
    tool = find_tool("affconvert")
    if not tool:
        raise AcquisitionError(
            f"{source.name} is an AFF forensic image. Install AFFLIB and "
            f"ensure affconvert is on PATH, then retry — or convert manually:\n"
            f"  affconvert -e raw {source} {dest / (source.stem + '.dd')}")

    dest.mkdir(parents=True, exist_ok=True)
    target = dest / f"{source.stem}.dd"
    if log:
        log("aff", "start",
            f"Converting {source.name} to raw with affconvert")

    cmd = [tool, "-e", "raw", str(source), str(target)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError("affconvert timed out after 24 hours") from exc
    except FileNotFoundError as exc:
        raise AcquisitionError(f"affconvert not runnable: {tool}") from exc

    if proc.returncode != 0 or not target.exists():
        hint = (proc.stderr or proc.stdout or "").strip()[-400:]
        raise AcquisitionError(f"affconvert failed: {hint or proc.returncode}")

    size = target.stat().st_size
    if log:
        log("aff", "ok", f"Converted to {target.name} ({size:,} bytes)")
    return target, size
