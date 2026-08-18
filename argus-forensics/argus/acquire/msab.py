"""MSAB XRY extraction — every lawful route into an ARGUS case.

MSAB's native ``.xry`` container is proprietary and undocumented. ARGUS does not
decode it, and will not guess at a structure nobody published — half-understood
containers produce records that look authoritative and are wrong.

What ARGUS *does* do, exhaustively:

* **Resolve case pairs.** A small ``.xrycase`` is an index; the device data
  lives in a companion ``.xry``. Importing the index alone is the single most
  common reason an examiner concludes an extraction is empty.

* **Recognise disguised archives.** XRY exports are sometimes zip archives with
  a vendor extension. Magic bytes beat the filename.

* **Carve embedded files.** SQLite databases, images, property lists and other
  signature-bearing files inside an undecodable wrapper are recovered by
  structural carving and handed to the normal parser pipeline — including
  carving their own unallocated space.

* **Handle split extractions.** Multi-segment ``.xry`` files are concatenated
  and carved as one image, the same way split ``dd`` images are.

* **Parse XRY XML exports.** Extended XML from XAMN carries device metadata
  and decoded-model counts, recorded as **foreign provenance** attributed to
  MSAB rather than silently adopted as ARGUS findings.

Every recovered file names the byte offset it came from. Every limitation is
stated plainly. Absence here is not evidence that the device lacked the data.
"""

from __future__ import annotations

import re
import shutil
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.errors import AcquisitionError
from ..core.streaming import ImageReader, discover_segments, human_bytes
from .opaque import carve_container, triage

# Companion .xrycase files below ~20 MB are almost certainly indexes.
INDEX_SIZE_HINT = 20 * 1024 * 1024  # used in triage guidance / docs

# Extensions MSAB uses for native containers.
NATIVE_EXTENSIONS = frozenset({".xry", ".xrycase", ".xrydump"})

XRY_MAGIC = b"XRY\x00"
SFS_MAGIC = b"SFS\x00"


@dataclass
class ResolvedCase:
    """Which file(s) in an MSAB case actually hold device data."""

    requested: Path
    data_path: Optional[Path] = None
    index_path: Optional[Path] = None
    segments: List[Path] = field(default_factory=list)
    is_index_only: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def carve_target(self) -> Path:
        """The file to read when carving or triaging."""
        if self.segments:
            return self.segments[0]
        if self.data_path:
            return self.data_path
        return self.requested


def resolve_case(path: Path) -> ResolvedCase:
    """Find the data-bearing file(s) behind an MSAB case path.

  A ``.xrycase`` under ~20 MB is almost always metadata. The companion ``.xry``
  in the same folder is where the extraction lives. Examiners who import only
  the index conclude the case is empty — this function exists to stop that.
    """
    path = Path(path)
    result = ResolvedCase(requested=path)
    if not path.exists():
        return result

    parent = path.parent
    stem = path.stem
    suffix = path.suffix.lower()

    if path.is_file() and suffix in NATIVE_EXTENSIONS:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        if suffix == ".xrycase":
            result.is_index_only = True
            result.index_path = path
            # Same stem: Case123.xrycase → Case123.xry
            for candidate in (
                parent / f"{stem}.xry",
                parent / f"{stem}.XRY",
                parent / stem.replace(".xrycase", ".xry"),
            ):
                if candidate.is_file() and candidate != path:
                    if candidate.stat().st_size > size:
                        result.data_path = candidate
                        result.is_index_only = False
                        result.notes.append(
                            f"Resolved companion data file: {candidate.name} "
                            f"({human_bytes(candidate.stat().st_size)})")
                        break
            if result.is_index_only:
                # Any .xry in the folder larger than the index is probably it.
                siblings = sorted(
                    (p for p in parent.glob("*.xry")
                     if p.is_file() and p != path
                     and p.stat().st_size > size),
                    key=lambda p: -p.stat().st_size)
                if siblings:
                    result.data_path = siblings[0]
                    result.is_index_only = False
                    result.notes.append(
                        f"Resolved largest companion .xry: "
                        f"{siblings[0].name} "
                        f"({human_bytes(siblings[0].stat().st_size)})")
                else:
                    result.notes.append(
                        f"{path.name} looks like a case index "
                        f"({human_bytes(size)}). No companion .xry was found "
                        f"in {parent}.")
        else:
            # .xry / .xrydump are data containers — even when small.
            result.data_path = path
            # Record the index if present.
            for candidate in (parent / f"{stem}.xrycase",
                              parent / f"{stem}.XRYCASE"):
                if candidate.is_file():
                    result.index_path = candidate
                    break

        target = result.data_path or path
        result.segments = discover_segments(target)
        if len(result.segments) > 1:
            total = sum(p.stat().st_size for p in result.segments)
            result.notes.append(
                f"Split extraction: {len(result.segments)} segment(s), "
                f"{human_bytes(total)} total")

    return result


def inspect_header(path: Path) -> Dict[str, Any]:
    """Read what the XRY header actually says — without decoding the body."""
    info: Dict[str, Any] = {"magic": "", "wrapper": "", "size": 0}
    try:
        info["size"] = path.stat().st_size
    except OSError:
        return info
    try:
        with path.open("rb") as handle:
            head = handle.read(64)
    except OSError:
        return info
    if head.startswith(XRY_MAGIC):
        info["magic"] = "XRY"
        info["wrapper"] = "msab.xry"
        if len(head) >= 8:
            # MSAB containers often carry a version dword after the magic.
            info["header_dword"] = struct.unpack_from("<I", head, 4)[0]
    elif head.startswith(b"PK\x03\x04"):
        info["magic"] = "ZIP"
        info["wrapper"] = "zip"
    elif head.startswith(SFS_MAGIC):
        info["magic"] = "SFS"
        info["wrapper"] = "sfs"
    return info


def read_xry_report(report: Path) -> Tuple[Dict[str, Any],
                                           List[Dict[str, Any]],
                                           List[str]]:
    """Read device metadata and decoded-model counts from an XRY XML export.

    Deliberately shallow, like the UFDR reader: enough to record what MSAB
    found and which device it came from, without re-implementing XAMN's decoder.
    """
    device: Dict[str, Any] = {}
    decoded: List[Dict[str, Any]] = []
    notes: List[str] = []
    try:
        import xml.etree.ElementTree as ET

        counts: Dict[str, int] = {}
        for _event, elem in ET.iterparse(report, events=("end",)):
            tag = elem.tag.rsplit("}", 1)[-1].lower()
            if tag in ("device", "deviceinfo", "handset"):
                for child in elem.iter():
                    ctag = child.tag.rsplit("}", 1)[-1]
                    name = (child.get("name") or child.get("key")
                            or child.get("type") or ctag or "").strip()
                    value = (child.text or child.get("value")
                             or child.get("id") or "").strip()
                    if name and value and len(value) < 300:
                        device[name] = value
                elem.clear()
            elif tag in ("property", "field", "attribute"):
                name = (elem.get("name") or elem.get("key") or "").strip()
                value = (elem.text or elem.get("value") or "").strip()
                if name and value and len(value) < 300:
                    device[name] = value
                elem.clear()
            elif tag in ("model", "artifacttype", "category", "datatype"):
                model_type = (elem.get("type") or elem.get("name")
                              or elem.text or "unknown").strip()
                if model_type:
                    counts[model_type] = counts.get(model_type, 0) + 1
                elem.clear()
            elif tag in ("item", "record", "artifact"):
                model_type = (elem.get("type") or elem.get("category")
                              or elem.get("datatype") or "").strip()
                if model_type:
                    counts[model_type] = counts.get(model_type, 0) + 1
                elem.clear()
            elif tag in ("file", "files"):
                elem.clear()

        # Regex fallback for exports that flatten metadata into one big document.
        if not device:
            try:
                head = report.read_text(encoding="utf-8",
                                        errors="replace")[:250_000]
            except OSError:
                head = ""
            for key, pattern in (
                ("device", r"<Device[^>]*(?:name|model)=\"([^\"]+)\""),
                ("imei", r"IMEI[^0-9]{0,16}(\d{14,17})"),
                ("operator", r"[Oo]perator[^>]*>([^<]{2,80})<"),
                ("serial", r"[Ss]erial[^>]*>([^<]{4,40})<"),
                ("phone_number", r"[Pp]hone[^>]*>(\+?\d{6,20})<"),
            ):
                match = re.search(pattern, head)
                if match:
                    device[key] = match.group(1).strip()

        decoded = [{"model": k, "count": v, "decoded_by": "MSAB XRY"}
                   for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
        if decoded:
            notes.append(
                "MSAB's own decoded model counts recorded as foreign "
                "provenance: " + ", ".join(f"{d['model']} {d['count']}"
                                           for d in decoded[:10]))
    except Exception as exc:
        notes.append(f"XRY XML present but not fully readable ({exc}); "
                     f"exported files were still staged and parsed")
    return device, decoded, notes


def _extract_zip(path: Path, dest: Path) -> Tuple[int, int]:
    """Extract a zip archive (including one wearing an XRY extension)."""
    count = total = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir() or member.file_size <= 0:
                continue
            name = member.filename.replace("\\", "/").lstrip("/")
            if ".." in name.split("/"):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
            total += target.stat().st_size
    return count, total


def _carve_streaming(path: Path, dest: Path,
                     max_files: int = 25_000) -> Dict[str, Any]:
    """Carve a (possibly split) native container with streaming I/O."""
    from ..parsers.filecarver import FileCarver

    carved_root = dest / "_carved"
    carved_root.mkdir(parents=True, exist_ok=True)
    by_type: Dict[str, int] = {}
    written = 0
    bytes_out = 0

    with ImageReader(path) as reader:
        carver = FileCarver(max_files=max_files, keep_data=True,
                            require_validation=True)
        report = carver.carve_image(reader)

    for item in report.files:
        folder = carved_root / item.extension.lstrip(".")
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{item.offset:012d}.{item.extension.lstrip('.')}"
        try:
            target.write_bytes(item.data)
            written += 1
            bytes_out += item.size
            by_type[item.signature] = by_type.get(item.signature, 0) + 1
        except OSError:
            continue

    return {
        "files": written,
        "bytes": bytes_out,
        "by_type": by_type,
        "truncated": report.truncated,
        "scan": report.summary(),
    }


def _scan_sfs_regions(path: Path, dest: Path,
                      max_files: int = 5000) -> Dict[str, Any]:
    """Recover files from MSAB SFS-structured regions by signature carving.

    SFS layout is not published. What is safe: locate ``SFS\\x00`` markers and
    carve recognisable file types from the bytes that follow, the same approach
    used for any other opaque wrapper.
    """
    from ..parsers.filecarver import FileCarver

    carved_root = dest / "_sfs_carved"
    carved_root.mkdir(parents=True, exist_ok=True)
    try:
        data = path.read_bytes()
    except OSError:
        return {"files": 0, "regions": 0}

    regions: List[Tuple[int, int]] = []
    start = 0
    while True:
        idx = data.find(SFS_MAGIC, start)
        if idx < 0:
            break
        # Carve from each SFS marker through the next one (or EOF).
        start = idx + 4
        regions.append((idx, len(data) - idx))

    if not regions:
        return {"files": 0, "regions": 0}

    carver = FileCarver(max_files=max_files, keep_data=True,
                        require_validation=True)
    written = 0
    for region_offset, _length in regions[:200]:
        window = data[region_offset:region_offset + 32 * 1024 * 1024]
        carver.carve_bytes(window, base_offset=region_offset)

    for item in carver.report.files:
        target = carved_root / f"{item.offset:012d}_{item.sha256[:10]}{item.extension}"
        try:
            target.write_bytes(item.data)
            written += 1
        except OSError:
            continue

    return {"files": written, "regions": len(regions)}


def stage_native(path: Path, dest: Path, staged: Any) -> None:
    """Stage a native MSAB container using every route that can work.

    Raises :class:`AcquisitionError` only when nothing recoverable was found
    and the examiner needs a conversion path instead.
    """
    resolved = resolve_case(path)
    staged.notes.extend(resolved.notes)
    target = resolved.carve_target

    if resolved.is_index_only and not resolved.data_path:
        raise AcquisitionError(
            f"{path.name} is an MSAB case index ({human_bytes(path.stat().st_size)}), "
            f"not the extraction. The device data lives in a companion .xry file "
            f"in the same folder — none was found next to it. Point ARGUS at "
            f"the .xry file, or export from XAMN: Report/Export → Files.")

    dest.mkdir(parents=True, exist_ok=True)
    header = inspect_header(target)

    # Route 1: zip in disguise (magic beats extension).
    if zipfile.is_zipfile(target):
        staged.source_format = "MSAB XRY export (zip container)"
        count, total = _extract_zip(target, dest)
        staged.files += count
        staged.bytes_staged += total
        staged.notes.append(
            f"{target.name} is a zip archive despite its extension. "
            f"{count} member(s) extracted ({human_bytes(total)}).")
        return

    assessment = triage(target)

    # Route 2: signature carving (streaming for large / split files).
    if assessment.carvable:
        staged.source_format = "MSAB XRY container (carved)"
        if len(resolved.segments) > 1 or target.stat().st_size > 64 * 1024 * 1024:
            result = _carve_streaming(target, dest)
            mode = "streaming carve"
        else:
            carved_dest = dest / "_carved"
            result = carve_container(target, carved_dest)
            mode = result.get("mode", "carve")
            staged.files += result.get("files", 0)
            staged.bytes_staged += sum(
                p.stat().st_size for p in carved_dest.rglob("*") if p.is_file())
            staged.notes.append(result.get("note", ""))
            if mode != "zip":
                by_type = {}
                for entry in result.get("carved", []):
                    by_type[entry.get("type", "?")] = \
                        by_type.get(entry.get("type", "?"), 0) + 1
                staged.notes.append(
                    f"{result.get('files', 0)} file(s) carved by signature "
                    f"({mode}): "
                    + ", ".join(f"{k} {v}" for k, v in
                                sorted(by_type.items(), key=lambda kv: -kv[1])[:8]))
            return

        staged.files += result["files"]
        staged.bytes_staged += result["bytes"]
        staged.notes.append(
            f"{result['files']} file(s) recovered by {mode} from "
            f"{target.name} ({human_bytes(result['bytes'])}). "
            + ", ".join(f"{k} {v}" for k, v in
                        sorted(result["by_type"].items(),
                               key=lambda kv: -kv[1])[:8]))
        staged.notes.append(
            "Carved files have no original path — each name encodes the byte "
            "offset in the container so the recovery can be repeated and "
            "checked. MSAB's proprietary record layout was not interpreted.")
        if result.get("truncated"):
            staged.warnings.append(
                "carving stopped at the file limit; raise max_files to recover more")
        return

    # Route 3: SFS regions — only when routine carving found nothing but SFS
    # markers are present in the sample.
    if header.get("wrapper") == "sfs" or assessment.embedded:
        sfs = _scan_sfs_regions(target, dest)
        if sfs["files"] > 0:
            staged.source_format = "MSAB XRY container (SFS carve)"
            staged.files += sfs["files"]
            staged.notes.append(
                f"{sfs['files']} file(s) carved from {sfs['regions']} SFS "
                f"region(s). SFS layout is not published; only signature-bearing "
                f"embedded files were recovered.")
            return

    # Nothing worked — say exactly why and what to do instead.
    extra = ""
    if assessment.wrapper_note:
        extra = f" {assessment.wrapper_note}"
    if assessment.entropy > 7.5:
        raise AcquisitionError(
            f"{target.name} is a native MSAB container with high entropy "
            f"({assessment.entropy:.2f} bits/byte) — the contents are "
            f"compressed or encrypted and no file signatures survive inside "
            f"them.{extra} Export from XAMN: Report/Export → Files (the "
            f"extracted file system) or Extended XML, then import that folder.")
    raise AcquisitionError(
        f"{target.name} is a native MSAB container ARGUS cannot decode.{extra} "
        f"No recoverable embedded files were found. Export from XAMN: "
        f"Report/Export → Files or Extended XML, then import that folder.")


def stage_xml_export(path: Path, dest: Path, staged: Any,
                     copy_tree: Any) -> None:
    """Stage an XRY XML export folder and record MSAB's decoded metadata."""
    dest.mkdir(parents=True, exist_ok=True)
    copy_tree(path, dest, staged)

    reports = sorted(dest.rglob("*.xml"),
                     key=lambda p: -p.stat().st_size)[:6]
    for xml in reports:
        try:
            head = xml.read_text(encoding="utf-8", errors="replace")[:8000]
        except OSError:
            continue
        if "xry" not in head.lower() and "msab" not in head.lower():
            continue
        device, decoded, notes = read_xry_report(xml)
        for key, value in device.items():
            staged.device.setdefault(key, value)
        if decoded:
            staged.foreign_decoded.extend(decoded)
        staged.notes.extend(notes)
        break

    staged.notes.append(
        "XRY XML export staged. ARGUS parses the exported files itself; any "
        "content XRY decoded is attributed to MSAB, not adopted as an ARGUS "
        "finding.")
