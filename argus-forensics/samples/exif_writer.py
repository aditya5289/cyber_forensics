"""Minimal EXIF APP1 writer — no third-party dependency.

Written by hand because a forensic workstation cannot be assumed to have
network access to install ``piexif``, and because a sample generator that
silently produces images *without* GPS would make the tool look like it cannot
read GPS.

Emits a little-endian TIFF header containing IFD0 (Make, Model, DateTime, plus
pointers), the Exif sub-IFD (DateTimeOriginal, DateTimeDigitized, pixel
dimensions) and the GPS sub-IFD (lat/lon as three RATIONALs each with a
hemisphere reference). That is exactly the structure
``argus.parsers.media.exif`` reads back, so the round trip is a genuine test.

Reference: Exif 2.32 §4.6, TIFF 6.0 §2.
"""

from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# TIFF field types
BYTE, ASCII, SHORT, LONG, RATIONAL = 1, 2, 3, 4, 5
TYPE_SIZE = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8}

# IFD0
TAG_MAKE, TAG_MODEL, TAG_DATETIME = 0x010F, 0x0110, 0x0132
TAG_EXIF_IFD, TAG_GPS_IFD = 0x8769, 0x8825
# Exif sub-IFD
TAG_DT_ORIGINAL, TAG_DT_DIGITIZED = 0x9003, 0x9004
TAG_PIXEL_X, TAG_PIXEL_Y = 0xA002, 0xA003
# GPS sub-IFD
TAG_GPS_LAT_REF, TAG_GPS_LAT = 0x0001, 0x0002
TAG_GPS_LON_REF, TAG_GPS_LON = 0x0003, 0x0004
TAG_GPS_ALT_REF, TAG_GPS_ALT = 0x0005, 0x0006
TAG_GPS_DATESTAMP = 0x001D


def _to_dms(value: float) -> List[Tuple[int, int]]:
    """Decimal degrees → three RATIONALs (deg, min, sec)."""
    v = abs(value)
    deg = int(v)
    minutes_full = (v - deg) * 60
    minutes = int(minutes_full)
    seconds = round((minutes_full - minutes) * 60 * 10000)
    return [(deg, 1), (minutes, 1), (seconds, 10000)]


class _IFDBuilder:
    """Serialise one IFD, spilling oversized values into a data area."""

    def __init__(self, base_offset: int):
        self.base = base_offset          # offset of this IFD from TIFF start
        self.entries: List[Tuple[int, int, int, Any]] = []

    def add(self, tag: int, ftype: int, value: Any) -> None:
        if ftype == ASCII:
            data = value.encode("ascii", "replace") + b"\x00"
            count = len(data)
        elif ftype == RATIONAL:
            pairs = value if isinstance(value, list) else [value]
            count = len(pairs)
            data = b"".join(struct.pack("<II", n, d) for n, d in pairs)
        elif ftype == SHORT:
            vals = value if isinstance(value, list) else [value]
            count = len(vals)
            data = b"".join(struct.pack("<H", v) for v in vals)
        elif ftype == LONG:
            vals = value if isinstance(value, list) else [value]
            count = len(vals)
            data = b"".join(struct.pack("<I", v) for v in vals)
        elif ftype == BYTE:
            data = bytes(value if isinstance(value, (list, bytes)) else [value])
            count = len(data)
        else:
            raise ValueError(f"unsupported field type {ftype}")
        self.entries.append((tag, ftype, count, data))

    def serialise(self, next_ifd: int = 0) -> Tuple[bytes, int]:
        """Return ``(bytes, total_length)`` for this IFD plus its data area."""
        self.entries.sort(key=lambda e: e[0])         # TIFF requires tag order
        n = len(self.entries)
        directory_size = 2 + n * 12 + 4
        data_area_offset = self.base + directory_size

        directory = struct.pack("<H", n)
        data_area = b""
        for tag, ftype, count, data in self.entries:
            if len(data) <= 4:
                payload = data.ljust(4, b"\x00")
            else:
                payload = struct.pack("<I", data_area_offset + len(data_area))
                data_area += data
                if len(data_area) % 2:               # keep word alignment
                    data_area += b"\x00"
            directory += struct.pack("<HHI", tag, ftype, count) + payload
        directory += struct.pack("<I", next_ifd)
        return directory + data_area, directory_size + len(data_area)


def build_exif(make: str = "Synthetic", model: str = "ARGUS Test Camera",
               taken: Optional[datetime] = None,
               width: int = 0, height: int = 0,
               latitude: Optional[float] = None,
               longitude: Optional[float] = None,
               altitude: Optional[float] = None) -> bytes:
    """Build a complete APP1 payload (``Exif\\0\\0`` + TIFF structure)."""
    taken = taken or datetime.now()
    stamp = taken.strftime("%Y:%m:%d %H:%M:%S")

    # Two passes: the first measures the sub-IFDs so IFD0 can point at them.
    def assemble(exif_off: int, gps_off: int) -> Tuple[bytes, bytes, bytes]:
        ifd0 = _IFDBuilder(8)
        ifd0.add(TAG_MAKE, ASCII, make)
        ifd0.add(TAG_MODEL, ASCII, model)
        ifd0.add(TAG_DATETIME, ASCII, stamp)
        ifd0.add(TAG_EXIF_IFD, LONG, exif_off)
        if latitude is not None and longitude is not None:
            ifd0.add(TAG_GPS_IFD, LONG, gps_off)

        exif = _IFDBuilder(exif_off)
        exif.add(TAG_DT_ORIGINAL, ASCII, stamp)
        exif.add(TAG_DT_DIGITIZED, ASCII, stamp)
        if width:
            exif.add(TAG_PIXEL_X, LONG, width)
        if height:
            exif.add(TAG_PIXEL_Y, LONG, height)

        gps = _IFDBuilder(gps_off)
        if latitude is not None and longitude is not None:
            gps.add(TAG_GPS_LAT_REF, ASCII, "N" if latitude >= 0 else "S")
            gps.add(TAG_GPS_LAT, RATIONAL, _to_dms(latitude))
            gps.add(TAG_GPS_LON_REF, ASCII, "E" if longitude >= 0 else "W")
            gps.add(TAG_GPS_LON, RATIONAL, _to_dms(longitude))
            gps.add(TAG_GPS_DATESTAMP, ASCII, taken.strftime("%Y:%m:%d"))
            if altitude is not None:
                gps.add(TAG_GPS_ALT_REF, BYTE, 0 if altitude >= 0 else 1)
                gps.add(TAG_GPS_ALT, RATIONAL, [(int(abs(altitude) * 100), 100)])

        b0, len0 = ifd0.serialise()
        be, lene = exif.serialise()
        bg, leng = gps.serialise() if gps.entries else (b"", 0)
        return b0, be, bg

    # Pass 1 with placeholder offsets to learn the lengths.
    b0, be, bg = assemble(0, 0)
    exif_off = 8 + len(b0)
    gps_off = exif_off + len(be)
    # Pass 2 with real offsets. Lengths are stable because the offset fields are
    # fixed-width LONGs, so one re-run is sufficient.
    b0, be, bg = assemble(exif_off, gps_off)

    tiff = b"II" + struct.pack("<HI", 42, 8) + b0 + be + bg
    return b"Exif\x00\x00" + tiff


def insert_exif(jpeg_bytes: bytes, exif_payload: bytes) -> bytes:
    """Insert (or replace) the APP1 EXIF segment of a JPEG."""
    if jpeg_bytes[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    out = bytearray(b"\xff\xd8")
    pos = 2
    inserted = False

    # Preserve a leading JFIF APP0 if present, then place APP1 immediately after.
    while pos < len(jpeg_bytes) - 1:
        if jpeg_bytes[pos] != 0xFF:
            break
        marker = jpeg_bytes[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:                       # start of scan — copy the rest
            break
        seg_len = struct.unpack(">H", jpeg_bytes[pos + 2:pos + 4])[0]
        segment = jpeg_bytes[pos:pos + 2 + seg_len]
        if marker == 0xE1 and jpeg_bytes[pos + 4:pos + 8] == b"Exif":
            pos += 2 + seg_len                   # drop any existing EXIF
            continue
        out += segment
        pos += 2 + seg_len
        if marker == 0xE0 and not inserted:
            out += b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) \
                   + exif_payload
            inserted = True

    if not inserted:
        out = bytearray(b"\xff\xd8")
        out += b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
        out += jpeg_bytes[2:]
        return bytes(out)

    out += jpeg_bytes[pos:]
    return bytes(out)


def write_jpeg_with_exif(path: Path, image, taken: datetime,
                         latitude: Optional[float] = None,
                         longitude: Optional[float] = None,
                         altitude: Optional[float] = None,
                         make: str = "Synthetic",
                         model: str = "ARGUS Test Camera",
                         quality: int = 82) -> None:
    """Save a PIL image as a JPEG carrying real EXIF and optional GPS."""
    import io
    buf = io.BytesIO()
    image.save(buf, "JPEG", quality=quality)
    payload = build_exif(make=make, model=model, taken=taken,
                         width=image.width, height=image.height,
                         latitude=latitude, longitude=longitude,
                         altitude=altitude)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(insert_exif(buf.getvalue(), payload))
