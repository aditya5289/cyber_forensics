#!/usr/bin/env python3
"""Generate src-tauri/icons/icon.ico for ARGUS Forensics (no external deps)."""

from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src-tauri" / "icons" / "icon.ico"


def _bmp_header(w: int, h: int, bpp: int = 32) -> bytes:
    row = ((w * bpp + 31) // 32) * 4
    img = row * h
    hdr = struct.pack("<IIIHHIIIIII", 40, w, h * 2, 1, bpp, 0, img, 0, 0, 0, 0)
    return hdr


def _pixel(x: int, y: int, size: int) -> tuple[int, int, int, int]:
    """Simple shield motif: dark panel + blue accent cross."""
    cx, cy = size // 2, size // 2
    dx, dy = abs(x - cx), abs(y - cy)
    # background
    r, g, b, a = 14, 17, 22, 255
    # outer ring
    dist = (dx * dx + dy * dy) ** 0.5
    if dist < size * 0.46:
        r, g, b = 21, 26, 33
    if dist < size * 0.40:
        r, g, b = 27, 34, 43
    # accent cross (forensic scope)
    if dx <= size * 0.06 and dy <= size * 0.28:
        r, g, b = 76, 154, 255
    if dy <= size * 0.06 and dx <= size * 0.28:
        r, g, b = 76, 154, 255
    # corner cut
    if x < size * 0.12 and y < size * 0.12:
        a = 0
    return b, g, r, a  # BGRA for ICO


def render(size: int) -> bytes:
    row_bytes = ((size * 32 + 31) // 32) * 4
    pixels = bytearray(row_bytes * size)
    for y in range(size):
        for x in range(size):
            b, g, r, a = _pixel(x, y, size)
            off = y * row_bytes + x * 4
            pixels[off:off + 4] = bytes((b, g, r, a))
    # AND mask (1 bpp, all transparent handled in alpha)
    mask_row = ((size + 31) // 32) * 4
    mask = bytes(mask_row * size)
    return _bmp_header(size, size) + bytes(pixels) + mask


def write_ico(path: Path, sizes: list[int]) -> None:
    images = [render(s) for s in sizes]
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = []
    blobs = []
    for size, data in zip(sizes, images):
        w = h = size if size < 256 else 0
        entries.append(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset))
        blobs.append(data)
        offset += len(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + b"".join(entries) + b"".join(blobs))


if __name__ == "__main__":
    write_ico(OUT, [16, 32, 48, 64, 128, 256])
    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
