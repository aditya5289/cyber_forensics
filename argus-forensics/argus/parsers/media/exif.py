"""Pictures, videos and documents — metadata, EXIF, GPS and thumbnails.

Lab manual Step 15 / §6.2 (gallery view, filterable by time, location and
source application) and Step 18 / §6.5 (per-application cached media with file
path, dimensions and hash values).

Two forensic points worth stating plainly:

* **File extensions lie.** Type is determined by magic bytes, so a JPEG
  renamed ``notes.txt`` still appears in the gallery, and an executable
  renamed ``photo.jpg`` is flagged rather than silently treated as an image.
* **EXIF GPS is high-value and easy to get wrong.** Coordinates are stored as
  three rationals plus a hemisphere reference; ignoring the S/W reference puts
  half the world's photos in the wrong hemisphere.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ...core.models import Artifact, Category
from ..registry import ParseContext, ParseResult, register
from ..timestamps import from_iso, guess

try:
    from PIL import Image, ExifTags
    _PIL = True
except ImportError:                                          # pragma: no cover
    _PIL = False

MAGIC: list[tuple[bytes, str, str]] = [
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image"),
    (b"GIF87a", "image/gif", "GIF image"),
    (b"GIF89a", "image/gif", "GIF image"),
    (b"BM", "image/bmp", "Bitmap image"),
    (b"RIFF", "image/webp", "WebP image"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4", "MP4 video"),
    (b"\x00\x00\x00\x20ftyp", "video/mp4", "MP4 video"),
    (b"\x1aE\xdf\xa3", "video/x-matroska", "Matroska video"),
    (b"OggS", "audio/ogg", "Ogg audio"),
    (b"ID3", "audio/mpeg", "MP3 audio"),
    (b"%PDF", "application/pdf", "PDF document"),
    (b"PK\x03\x04", "application/zip", "ZIP archive / Office document"),
    (b"\x7fELF", "application/x-elf", "ELF executable"),
    (b"MZ", "application/x-dosexec", "Windows executable"),
    (b"dex\n", "application/x-dex", "Android DEX"),
    (b"SQLite format 3\x00", "application/x-sqlite3", "SQLite database"),
]

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif",
             ".tiff", ".tif"}
VIDEO_EXT = {".mp4", ".mov", ".3gp", ".mkv", ".avi", ".webm", ".m4v"}
AUDIO_EXT = {".mp3", ".m4a", ".aac", ".opus", ".ogg", ".wav", ".amr"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
           ".rtf", ".csv"}


def sniff(path: Path) -> Tuple[str, str]:
    """Return ``(mime, description)`` from magic bytes."""
    try:
        with path.open("rb") as fh:
            head = fh.read(32)
    except OSError:
        return "", ""
    for sig, mime, desc in MAGIC:
        if head.startswith(sig):
            if sig == b"RIFF" and head[8:12] != b"WEBP":
                return "application/octet-stream", "RIFF container"
            return mime, desc
    if b"ftyp" in head[:16]:
        brand = head[8:12].decode("ascii", "ignore")
        if brand.startswith(("heic", "heix", "mif1", "hevc")):
            return "image/heic", "HEIC image"
        return "video/mp4", "MP4/QuickTime video"
    return "", ""


@register(
    name="media.files",
    patterns=["*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.webp", "*.heic",
              "*.mp4", "*.mov", "*.3gp", "*.mkv", "*.avi", "*.m4v",
              "*.mp3", "*.m4a", "*.aac", "*.opus", "*.amr", "*.wav",
              "*.pdf", "*.docx", "*.xlsx", "*.pptx"],
    platform="", priority=40,
    description="Media and document files with EXIF/GPS metadata",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """Media file."""
    res = ParseResult(parser="media.files", source=ctx.rel(path))
    try:
        stat = path.stat()
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    mime, desc = sniff(path)
    ext = path.suffix.lower()
    declared = _kind_from_ext(ext)
    actual = _kind_from_mime(mime)
    mismatch = bool(mime and declared and actual and declared != actual)

    subtype = {"image": "Picture", "video": "Video", "audio": "Audio",
               "document": "Document"}.get(actual or declared, "File")

    exif = _read_exif(path) if (actual or declared) == "image" else {}
    lat = exif.pop("_latitude", None)
    lon = exif.pop("_longitude", None)

    ts = (exif.get("DateTimeOriginal_us") or exif.get("DateTime_us")
          or int(stat.st_mtime * 1_000_000))
    if not ctx.in_span(ts):
        return res

    # Perceptual hashes are computed at ingest so visual matching later costs
    # nothing — and so they are sealed into the container alongside the image
    # rather than recomputed from a copy years afterwards.
    perceptual: Dict[str, Any] = {}
    if (actual or declared) == "image" and not ctx.skip_perceptual_hash:
        from .perceptual import hash_image
        perceptual = hash_image(path).as_dict()

    sha = ""
    if ctx.store_blob:
        try:
            sha = ctx.store_blob(path, ctx.rel(path))
        except Exception as exc:
            res.warnings.append(f"{path.name}: could not store blob ({exc})")

    art = Artifact(
        category=Category.FILE, subtype=subtype, timestamp=ts,
        body=path.name, app=_app_from_path(path),
        source_path=ctx.rel(path), blob_sha256=sha,
        latitude=lat, longitude=lon,
        attributes={
            "filename": path.name,
            "extension": ext,
            "size_bytes": stat.st_size,
            "size_display": _human(stat.st_size),
            "mime_type": mime or "unknown",
            "file_type": desc or "unrecognised",
            "modified": int(stat.st_mtime * 1_000_000),
            "accessed": int(stat.st_atime * 1_000_000),
            "created": int(getattr(stat, "st_ctime", stat.st_mtime) * 1_000_000),
            "extension_mismatch": mismatch,
            "mismatch_note": (
                f"Extension '{ext}' claims {declared} but content is {actual} "
                f"({mime}) — possible deliberate concealment." if mismatch else ""),
            "exif": exif,
            "perceptual": perceptual,
            "has_gps": lat is not None,
            "map_url": (f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
                        f"#map=17/{lat}/{lon}") if lat is not None else "",
        },
    )
    res.artifacts.append(art)
    if mismatch:
        res.notes.append(
            f"{ctx.rel(path)}: extension/content mismatch ({ext} vs {mime})")
    return res


def _kind_from_ext(ext: str) -> str:
    if ext in IMAGE_EXT:
        return "image"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    if ext in DOC_EXT:
        return "document"
    return ""


def _kind_from_mime(mime: str) -> str:
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("audio/"):
        return "audio"
    if mime in ("application/pdf",) or "officedocument" in mime:
        return "document"
    return ""


def _app_from_path(path: Path) -> str:
    p = path.as_posix().lower()
    markers = [
        ("com.whatsapp", "WhatsApp"), ("whatsapp", "WhatsApp"),
        ("com.instagram", "Instagram"), ("instagram", "Instagram"),
        ("com.facebook.katana", "Facebook"), ("com.facebook.orca", "Messenger"),
        ("com.snapchat", "Snapchat"), ("snapchat", "Snapchat"),
        ("telegram", "Telegram"), ("signal", "Signal"),
        ("dcim/camera", "Camera"), ("/dcim/", "Camera"),
        ("screenshots", "Screenshots"), ("download", "Downloads"),
        ("photodata", "Apple Photos"), ("/media/", "Media store"),
    ]
    for marker, name in markers:
        if marker in p:
            return name
    return "File system"


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _rational_to_float(value: Any) -> Optional[float]:
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return value[0] / value[1] if value[1] else None
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _dms_to_decimal(dms, ref: str) -> Optional[float]:
    try:
        parts = [_rational_to_float(v) for v in dms]
        if len(parts) < 3 or any(p is None for p in parts):
            return None
        deg = parts[0] + parts[1] / 60.0 + parts[2] / 3600.0
        if str(ref).upper() in ("S", "W"):
            deg = -deg
        return round(deg, 7)
    except (TypeError, ValueError):
        return None


def _read_exif(path: Path) -> Dict[str, Any]:
    """Extract EXIF including GPS. Returns ``{}`` when unavailable."""
    if not _PIL:
        return {}
    out: Dict[str, Any] = {}
    try:
        with Image.open(path) as img:
            out["width"], out["height"] = img.size
            out["format"] = img.format or ""
            out["mode"] = img.mode
            raw = img.getexif()
            if not raw:
                return out

            def absorb(mapping, table):
                for tag_id, value in mapping.items():
                    name = table.get(tag_id, str(tag_id))
                    if name in ("GPSInfo", "ExifOffset", "MakerNote",
                                "UserComment"):
                        continue
                    if isinstance(value, bytes):
                        value = value[:64].hex()
                    if isinstance(value, (str, int, float)):
                        out[name] = value

            absorb(raw, ExifTags.TAGS)
            # DateTimeOriginal, pixel dimensions and lens data live in the Exif
            # sub-IFD, not IFD0. Reading only IFD0 loses the capture time —
            # which is usually the timestamp that actually matters.
            if hasattr(raw, "get_ifd"):
                try:
                    absorb(raw.get_ifd(0x8769) or {}, ExifTags.TAGS)
                except Exception:
                    pass

            for field in ("DateTimeOriginal", "DateTime", "DateTimeDigitized"):
                if field in out:
                    txt = str(out[field]).replace(":", "-", 2)
                    us = from_iso(txt) or guess(out[field], field)
                    if us:
                        out[f"{field}_us"] = us

            gps_ifd = raw.get_ifd(0x8825) if hasattr(raw, "get_ifd") else None
            if gps_ifd:
                g = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
                lat = _dms_to_decimal(g.get("GPSLatitude", ()),
                                      g.get("GPSLatitudeRef", "N"))
                lon = _dms_to_decimal(g.get("GPSLongitude", ()),
                                      g.get("GPSLongitudeRef", "E"))
                if lat is not None and lon is not None:
                    out["_latitude"] = lat
                    out["_longitude"] = lon
                    out["GPSAltitude"] = _rational_to_float(g.get("GPSAltitude"))
                    out["GPSDateStamp"] = str(g.get("GPSDateStamp", ""))
    except Exception:
        return out
    return out
