"""EnCase EWF/E01 images — convert when ``ewfexport`` is available.

ARGUS does not implement EWF decompression internally. Reading an E01 as raw
bytes would return compressed data and produce silently wrong results. When
``ewfexport`` from libewf is on PATH, this module converts to a temporary raw
image and stages that instead.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from ..core.errors import AcquisitionError
from ..devices.detect import find_tool


def is_ewf(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        head = path.read_bytes()[:16]
    except OSError:
        return False
    return head[:3] == b"EVF" or head[:8] == b"EVF2\r\n\x81\x00"


def convert_to_raw(source: Path, dest: Path,
                   log=None) -> Tuple[Path, int]:
    """Convert ``source`` E01 to ``dest`` raw file. Returns ``(path, bytes)``."""
    tool = find_tool("ewfexport")
    if not tool:
        raise AcquisitionError(
            f"{source.name} is an EnCase EWF/E01 image. ARGUS cannot read "
            f"compressed E01 directly. Install libewf and ensure ewfexport is "
            f"on PATH, then retry — or convert manually:\n"
            f"  ewfexport -f raw -o {dest / (source.stem + '.dd')} {source}")

    dest.mkdir(parents=True, exist_ok=True)
    target = dest / f"{source.stem}.dd"
    if log:
        log("e01", "start",
            f"Converting {source.name} to raw with ewfexport — large images "
            f"may take hours")

    cmd = [tool, "-f", "raw", "-o", str(target), str(source)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(
            "ewfexport timed out after 24 hours") from exc
    except FileNotFoundError as exc:
        raise AcquisitionError(f"ewfexport not runnable: {tool}") from exc

    if proc.returncode != 0 or not target.exists():
        hint = (proc.stderr or proc.stdout or "").strip()[-400:]
        raise AcquisitionError(f"ewfexport failed: {hint or proc.returncode}")

    size = target.stat().st_size
    if log:
        log("e01", "ok", f"Converted to {target.name} ({size:,} bytes)")
    return target, size
