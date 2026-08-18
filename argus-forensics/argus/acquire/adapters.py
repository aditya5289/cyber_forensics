"""Import adapters — ingesting other tools' extractions.

Most evidence an examiner receives was not acquired by the tool they are using.
It arrives as a Cellebrite `.ufdr`, an XRY export, a GrayKey folder, a tarball
from someone's `adb pull`, or a raw `dd` image. A tool that only reads its own
output is a tool that cannot be used on a real caseload.

Each adapter does two things: **detect** whether it can handle a source, and
**stage** that source into a plain file tree the normal parser pipeline can walk.
Nothing is re-implemented per format — the value is in normalisation.

Two principles worth stating.

**Adapters preserve, they do not interpret.** Where a source already contains
another tool's *decoded* output (UFDR's `report.xml`, an AXIOM CSV), ARGUS stages
the original files *and* records that decoded content as provenance. It does not
silently adopt another tool's conclusions as its own findings, because the
examiner needs to know which tool decoded what.

**Refuse rather than half-read.** A format we cannot correctly decode is reported
as unsupported with a specific reason and a conversion suggestion. Reading an E01
as raw bytes, or a `.ufd` without its payload, would produce silently wrong
results — worse than a clear refusal.
"""

from __future__ import annotations

import csv
import io
import json
import re
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..core.errors import AcquisitionError

# Archive members above this are copied streamed; below, read in one go.
STREAM_THRESHOLD = 8 << 20
MAX_MEMBERS = 400_000


@dataclass
class StagedSource:
    """The result of staging an external source into a walkable tree."""

    root: Path
    adapter: str
    source_format: str
    files: int = 0
    bytes_staged: int = 0
    platform: str = ""
    # How strongly the tree matched that platform. A low score on a populated
    # tree means the layout was not recognised, which is worth showing rather
    # than hiding behind a confident-looking label.
    platform_confidence: float = 0.0
    platform_label: str = ""
    device: Dict[str, Any] = field(default_factory=dict)
    foreign_decoded: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["root"] = str(self.root)
        d["foreign_decoded"] = self.foreign_decoded[:200]
        return d


@dataclass
class Adapter:
    """One import format."""

    name: str
    label: str
    detect: Callable[[Path], bool]
    stage: Callable[[Path, Path, Any], StagedSource]
    priority: int = 50
    description: str = ""


_ADAPTERS: List[Adapter] = []


def register_adapter(name: str, label: str, priority: int = 50,
                    description: str = ""):
    def deco(pair):
        detect, stage = pair
        _ADAPTERS.append(Adapter(name=name, label=label, detect=detect,
                                 stage=stage, priority=priority,
                                 description=description))
        _ADAPTERS.sort(key=lambda a: -a.priority)
        return pair
    return deco


def adapters() -> List[Adapter]:
    return list(_ADAPTERS)


# ═══════════════════════════════════════════════════════════════ helpers
def _safe_target(dest: Path, member_name: str) -> Optional[Path]:
    """Resolve an archive member inside ``dest``, refusing path traversal."""
    cleaned = member_name.replace("\\", "/").lstrip("/")
    cleaned = re.sub(r"(^|/)\.\.(/|$)", "/", cleaned).strip("/")
    if not cleaned:
        return None
    target = (dest / cleaned)
    try:
        resolved = target.resolve()
        if not str(resolved).startswith(str(dest.resolve())):
            return None
    except OSError:
        return None
    return target


def _extract_zip(archive: Path, dest: Path, staged: StagedSource,
                 skip: Callable[[str], bool] = lambda n: False) -> None:
    with zipfile.ZipFile(archive) as zf:
        for index, info in enumerate(zf.infolist()):
            if index >= MAX_MEMBERS:
                staged.warnings.append(
                    f"archive has more than {MAX_MEMBERS} members; truncated")
                break
            if info.is_dir() or skip(info.filename):
                continue
            target = _safe_target(dest, info.filename)
            if target is None:
                staged.warnings.append(
                    f"refused path-traversal member: {info.filename}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(info) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, length=1 << 20)
                staged.files += 1
                staged.bytes_staged += target.stat().st_size
            except (OSError, zipfile.BadZipFile) as exc:
                staged.warnings.append(f"{info.filename}: {exc}")


def _extract_tar(archive: Path, dest: Path, staged: StagedSource) -> None:
    mode = "r:*"
    with tarfile.open(archive, mode) as tf:
        for index, member in enumerate(tf):
            if index >= MAX_MEMBERS:
                staged.warnings.append(
                    f"archive has more than {MAX_MEMBERS} members; truncated")
                break
            if not member.isfile():
                continue
            target = _safe_target(dest, member.name)
            if target is None:
                staged.warnings.append(
                    f"refused path-traversal member: {member.name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            try:
                with target.open("wb") as out:
                    shutil.copyfileobj(src, out, length=1 << 20)
                staged.files += 1
                staged.bytes_staged += target.stat().st_size
            except OSError as exc:
                staged.warnings.append(f"{member.name}: {exc}")


def _copy_tree(src: Path, dest: Path, staged: StagedSource) -> None:
    for path in src.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            rel = path.relative_to(src)
        except ValueError:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(path, target)
            staged.files += 1
            staged.bytes_staged += target.stat().st_size
        except OSError as exc:
            staged.warnings.append(f"{rel}: {exc}")


def _zip_names(path: Path, limit: int = 4000) -> List[str]:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()[:limit]
    except Exception:
        return []


def _detect_platform(root: Path) -> str:
    """Classify a staged tree by platform.

    This delegates to the platform registry rather than keeping its own marker
    table. It previously kept a second copy, and that copy had already drifted:
    it knew nothing about feature phones, SD cards or wearables, so a card dump
    imported here was classified as "" while `argus identify` on the same tree
    named it correctly. Two tables describing the same thing will always end up
    disagreeing, and the examiner has no way to know which one they are seeing.
    """
    from ..parsers.platforms import detect_platform

    name, _confidence = detect_platform(root)
    return name


def _detect_platform_scored(root: Path) -> Tuple[str, float]:
    """As above, but keeping the confidence so it can be surfaced."""
    from ..parsers.platforms import detect_platform

    return detect_platform(root)


def _record_platform(staged: "StagedSource", root: Path) -> None:
    """Attach the platform label and how confident the classification is."""
    from ..parsers.platforms import PLATFORM_BY_NAME

    name, confidence = _detect_platform_scored(root)
    if staged.platform and not name:
        # The adapter asserted a platform from the container format itself
        # (an iOS backup is an iOS backup even if the tree looks unusual).
        name, confidence = staged.platform, 1.0
    staged.platform_confidence = round(confidence, 3)
    profile = PLATFORM_BY_NAME.get(staged.platform or name)
    staged.platform_label = profile.label if profile else ""
    if staged.platform and confidence and confidence < 0.5:
        staged.warnings.append(
            f"Platform classified as '{staged.platform}' with low confidence "
            f"({confidence:.0%}). The staged tree did not match the expected "
            f"layout closely. Confirm the source is what it claims to be "
            f"before relying on parser selection.")


# ═══════════════════════════════════════════════════ Cellebrite UFDR / UFD
def _detect_ufdr(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() in (".ufdr", ".ufd"):
        return True
    if path.is_file() and path.suffix.lower() == ".zip":
        names = [n.lower() for n in _zip_names(path, 200)]
        return any("report.xml" in n for n in names) and \
               any(n.startswith("files/") for n in names)
    return False


def _stage_ufdr(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage a Cellebrite UFDR.

    A `.ufdr` is a ZIP holding `report.xml` (Cellebrite's *decoded* output) plus
    a `files/` tree of the original artefacts. ARGUS stages the original files and
    parses them itself, while recording what Cellebrite decoded as **foreign
    provenance** — clearly attributed to Cellebrite rather than presented as an
    ARGUS finding. Two tools agreeing is corroboration; silently adopting another
    tool's output as your own is not.

    A bare `.ufd` is only a metadata pointer file — its payload lives in sibling
    `.bin` files — so it is refused with an explanation rather than half-read.
    """
    staged = StagedSource(root=dest, adapter="cellebrite.ufdr",
                          source_format="Cellebrite UFDR")

    if path.suffix.lower() == ".ufd" and not zipfile.is_zipfile(path):
        raise AcquisitionError(
            f"{path.name} is a Cellebrite .ufd metadata file, not a container. "
            f"Its payload lives in sibling .bin files. Point ARGUS at the "
            f"folder holding the .ufd and its .bin files, or export a .ufdr "
            f"from Physical Analyzer.")

    if not zipfile.is_zipfile(path):
        raise AcquisitionError(f"{path.name} is not a readable UFDR archive")

    dest.mkdir(parents=True, exist_ok=True)
    _extract_zip(path, dest, staged)

    report = next((p for p in dest.rglob("report.xml")), None)
    if report is not None:
        staged.device, decoded, notes = _read_ufdr_report(report)
        staged.foreign_decoded = decoded
        staged.notes.extend(notes)
    staged.platform = (_detect_platform(dest)
                       or staged.device.get("platform", ""))
    _record_platform(staged, dest)
    staged.notes.append(
        "Original files staged from the UFDR and parsed by ARGUS. Any content "
        "Cellebrite decoded is recorded separately as foreign provenance, "
        "attributed to Cellebrite.")
    return staged


def _read_ufdr_report(report: Path) -> Tuple[Dict[str, Any],
                                             List[Dict[str, Any]],
                                             List[str]]:
    """Read device metadata and decoded-model counts from a UFDR report.xml.

    Deliberately shallow: enough to record what the other tool found and what
    device it came from, without re-implementing Cellebrite's decoding.
    """
    device: Dict[str, Any] = {}
    decoded: List[Dict[str, Any]] = []
    notes: List[str] = []
    try:
        import xml.etree.ElementTree as ET
        # Stream it: a report.xml for a full extraction can be very large.
        counts: Dict[str, int] = {}
        for event, elem in ET.iterparse(report, events=("end",)):
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag == "metadata" or tag == "deviceInfo":
                for child in elem:
                    ctag = child.tag.rsplit("}", 1)[-1]
                    name = (child.get("name") or child.get("key")
                            or ctag or "").strip()
                    value = (child.text or child.get("value") or "").strip()
                    if name and value and len(value) < 200:
                        device[name] = value
                elem.clear()
            elif tag == "model":
                model_type = elem.get("type") or "unknown"
                counts[model_type] = counts.get(model_type, 0) + 1
                elem.clear()
            elif tag in ("file",):
                elem.clear()
        decoded = [{"model": k, "count": v, "decoded_by": "Cellebrite"}
                   for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
        if decoded:
            notes.append(
                "Cellebrite's own decoded model counts recorded as foreign "
                "provenance: " + ", ".join(f"{d['model']} {d['count']}"
                                           for d in decoded[:8]))
    except Exception as exc:
        notes.append(f"report.xml present but not fully readable ({exc}); "
                     f"original files were still staged and parsed")
    return device, decoded, notes


# ═══════════════════════════════════════════════════════════ MSAB XRY export
def _detect_xry(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() in (".xry", ".xrydump", ".xrycase"):
        return True
    if path.is_dir():
        if any(path.glob("*.xry")) or any(path.glob("*.xrycase")):
            return True
        # An XRY XML export: a report XML plus a files folder.
        xml = list(path.glob("*.xml"))[:6]
        for candidate in xml:
            try:
                head = candidate.read_text(encoding="utf-8",
                                           errors="replace")[:4000]
            except OSError:
                continue
            if "XRY" in head or "msab" in head.lower():
                return True
    return False


def _stage_xry(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage an MSAB XRY export or native container.

    Native ``.xry`` / ``.xrycase`` files are handled by :mod:`argus.acquire.msab`,
    which resolves companion case pairs, extracts zip-in-disguise archives,
    and carves embedded signature-bearing files. Proprietary MSAB record layouts
    are never guessed at — only files the container demonstrably holds are
    recovered.

    An XRY *XML* export (report XML plus an extracted files tree) is fully
    usable and MSAB's decoded metadata is recorded as foreign provenance.
    """
    from . import msab

    staged = StagedSource(root=dest, adapter="msab.xry",
                          source_format="MSAB XRY export")

    if path.is_file() and path.suffix.lower() in msab.NATIVE_EXTENSIONS:
        msab.stage_native(path, dest, staged)
        staged.platform = _detect_platform(dest)
        _record_platform(staged, dest)
        if not staged.platform:
            staged.warnings.append(
                "Platform could not be inferred from carved content. "
                "Parsers that are not platform-specific will still run.")
        return staged

    if path.is_dir() and any(path.glob("*.xry")):
        # A folder holding native .xry files — stage the largest data file.
        data_files = sorted(path.glob("*.xry"), key=lambda p: -p.stat().st_size)
        msab.stage_native(data_files[0], dest, staged)
        staged.platform = _detect_platform(dest)
        _record_platform(staged, dest)
        return staged

    msab.stage_xml_export(path, dest, staged, _copy_tree)
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    return staged


# ═══════════════════════════════════════════════════════════ Magnet AXIOM
def _detect_axiom(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() == ".csv":
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            return False
        lowered = head.lower()
        return ("artifact" in lowered and "source" in lowered) or \
               "magnet axiom" in lowered
    if path.is_dir():
        return bool(list(path.glob("*.mfdb"))) or \
               bool(list(path.glob("AXIOM*.csv")))
    return False


def _stage_axiom(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage a Magnet AXIOM export.

    AXIOM's `.mfdb` case file is proprietary and refused. A CSV export is
    recorded as **foreign decoded content** — it is another tool's conclusions,
    not raw evidence, and ARGUS keeps that distinction explicit.
    """
    staged = StagedSource(root=dest, adapter="magnet.axiom",
                          source_format="Magnet AXIOM export")
    dest.mkdir(parents=True, exist_ok=True)

    if path.is_dir() and list(path.glob("*.mfdb")):
        raise AcquisitionError(
            "This folder contains a Magnet AXIOM .mfdb case file, which is a "
            "proprietary database ARGUS does not decode. In AXIOM Examine, "
            "export the artifacts to CSV and the files to a folder, then import "
            "that.")

    if path.is_file():
        shutil.copy2(path, dest / path.name)
        staged.files += 1
        staged.bytes_staged += path.stat().st_size
        rows, columns = _read_axiom_csv(path)
        staged.foreign_decoded = [{
            "model": "AXIOM CSV export", "count": rows,
            "decoded_by": "Magnet AXIOM", "columns": columns[:25],
        }]
        staged.notes.append(
            f"AXIOM CSV recorded as foreign decoded content ({rows} rows). "
            f"These are Magnet AXIOM's conclusions, attributed to AXIOM. To "
            f"have ARGUS decode the evidence independently, import the original "
            f"files rather than the CSV.")
    else:
        _copy_tree(path, dest, staged)
        staged.platform = _detect_platform(dest)
        _record_platform(staged, dest)
    return staged


def _read_axiom_csv(path: Path) -> Tuple[int, List[str]]:
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader, [])
            return sum(1 for _ in reader), [h.strip() for h in header]
    except Exception:
        return 0, []


# ═══════════════════════════════════════════════════════════════ GrayKey
def _detect_graykey(path: Path) -> bool:
    if not path.is_dir():
        return False
    names = {p.name.lower() for p in path.iterdir()} if path.exists() else set()
    if {"filesystem1", "filesystem2"} & names:
        return True
    return any(n.startswith("graykey") for n in names) or \
        (path / "device_info.txt").exists() and (path / "files").is_dir()


def _stage_graykey(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage a GrayKey extraction — a plain filesystem tree plus metadata."""
    staged = StagedSource(root=dest, adapter="graykey",
                          source_format="GrayKey filesystem extraction")
    dest.mkdir(parents=True, exist_ok=True)
    _copy_tree(path, dest, staged)
    for name in ("device_info.txt", "info.txt", "metadata.txt"):
        info = dest / name
        if info.exists():
            try:
                for line in info.read_text(encoding="utf-8",
                                           errors="replace").splitlines():
                    if ":" in line:
                        key, _, value = line.partition(":")
                        key, value = key.strip(), value.strip()
                        if key and value and len(value) < 200:
                            staged.device[key] = value
            except OSError:
                pass
    staged.platform = _detect_platform(dest) or "ios"
    _record_platform(staged, dest)
    staged.notes.append(
        "GrayKey produces a full filesystem tree, so ARGUS parses it exactly as "
        "it would a file-system extraction it performed itself.")
    return staged


# ═══════════════════════════════════════════════════ vendor phone backups
_VENDOR_MARKERS = {
    "samsung.smartswitch": (
        "Samsung Smart Switch backup",
        ("smartswitch", "sswitch", "bnr", "samsungdata")),
    "huawei.hisuite": ("Huawei HiSuite backup", ("hisuite", "huawei_backup")),
    "xiaomi.miui": ("Xiaomi MIUI backup", ("miui", "descript.xml", ".bak")),
    "oppo.clone": ("OPPO/OnePlus Clone Phone backup", ("clonephone", "oppo")),
    "lg.backup": ("LG Backup", ("lgbackup", "lgb")),
}


def _detect_vendor_backup(path: Path) -> bool:
    blob = path.name.lower()
    if path.is_dir():
        blob += " " + " ".join(p.name.lower()
                               for p in list(path.iterdir())[:200])
    return any(any(m in blob for m in markers)
               for _label, markers in _VENDOR_MARKERS.values())


def _stage_vendor_backup(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage an OEM phone-transfer backup.

    Samsung Smart Switch, Huawei HiSuite, Xiaomi MIUI and similar produce
    application-scoped archives. ARGUS unpacks the containers it can read and
    lists the ones it cannot, so an examiner knows exactly which applications
    were *not* covered rather than assuming the extraction was complete.
    """
    blob = path.name.lower()
    if path.is_dir():
        blob += " " + " ".join(p.name.lower() for p in list(path.iterdir())[:200])
    label = "OEM phone backup"
    adapter = "vendor.backup"
    for key, (name, markers) in _VENDOR_MARKERS.items():
        if any(m in blob for m in markers):
            label, adapter = name, key
            break

    staged = StagedSource(root=dest, adapter=adapter, source_format=label)
    dest.mkdir(parents=True, exist_ok=True)

    unpacked = 0
    unreadable: List[str] = []
    sources = [path] if path.is_file() else [
        p for p in path.rglob("*") if p.is_file()]
    for item in sources:
        suffix = item.suffix.lower()
        try:
            if zipfile.is_zipfile(item):
                sub = dest / (item.stem or "archive")
                sub.mkdir(parents=True, exist_ok=True)
                _extract_zip(item, sub, staged)
                unpacked += 1
                continue
            if tarfile.is_tarfile(item):
                sub = dest / (item.stem or "archive")
                sub.mkdir(parents=True, exist_ok=True)
                _extract_tar(item, sub, staged)
                unpacked += 1
                continue
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
            unreadable.append(f"{item.name}: {exc}")
            continue
        # Not an archive: stage verbatim so parsers still see it.
        target = dest / item.name if path.is_file() else \
            dest / item.relative_to(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(item, target)
            staged.files += 1
            staged.bytes_staged += target.stat().st_size
        except OSError as exc:
            unreadable.append(f"{item.name}: {exc}")

    if unreadable:
        staged.warnings.extend(unreadable[:40])
        staged.notes.append(
            f"{len(unreadable)} container(s) in this backup could not be "
            f"unpacked. Their contents are NOT included, so any conclusion "
            f"about what is absent must account for them.")
    staged.platform = _detect_platform(dest) or "android"
    _record_platform(staged, dest)
    staged.notes.append(
        f"{label}: {unpacked} archive(s) unpacked. OEM backups are "
        f"application-scoped — apps that opt out of backup are absent by "
        f"design, not because nothing was found.")
    return staged


# ═══════════════════════════════════════════════════════════ generic archive
def _detect_archive(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in (".tar", ".tgz", ".tar.gz", ".gz", ".tar.bz2",
                               ".tbz", ".tar.xz", ".txz", ".zip"):
        return True
    return zipfile.is_zipfile(path) or tarfile.is_tarfile(path)


def _stage_archive(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage a plain TAR/ZIP of a filesystem — an `adb pull` tarball, say."""
    staged = StagedSource(root=dest, adapter="archive",
                          source_format="filesystem archive")
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(path):
        staged.source_format = "ZIP filesystem archive"
        _extract_zip(path, dest, staged)
    elif tarfile.is_tarfile(path):
        staged.source_format = "TAR filesystem archive"
        _extract_tar(path, dest, staged)
    else:
        raise AcquisitionError(f"{path.name} is not a readable TAR or ZIP")
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    return staged


# ═══════════════════════════════════════════════════════════════ raw image
def _carve_image_file(path: Path, dest: Path,
                      staged: StagedSource) -> None:
    """Carve a raw dd image into ``dest/_carved``."""
    from ..core.streaming import ImageReader, human_bytes
    from ..parsers.filecarver import FileCarver

    carved_dir = dest / "_carved"
    carved_dir.mkdir(parents=True, exist_ok=True)
    with ImageReader(path) as reader:
        staged.notes.append(
            f"Image: {human_bytes(reader.size)} across "
            f"{len(reader.segments)} segment(s).")
        carver = FileCarver(max_files=20000, keep_data=True)
        report = carver.carve_image(reader)

    by_type: Dict[str, int] = {}
    for item in report.files:
        folder = carved_dir / item.extension
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{item.offset:012d}.{item.extension}"
        try:
            target.write_bytes(item.data)
            staged.files += 1
            staged.bytes_staged += item.size
            by_type[item.signature] = by_type.get(item.signature, 0) + 1
        except OSError as exc:
            staged.warnings.append(f"offset {item.offset}: {exc}")

    staged.notes.append(
        f"{len(report.files)} file(s) carved by signature: "
        + ", ".join(f"{k} {v}" for k, v in
                    sorted(by_type.items(), key=lambda kv: -kv[1])[:8]))
    staged.notes.append(
        "Carved files have no original path or filename — ARGUS carves rather "
        "than walking a filesystem. Each artifact records the byte offset it "
        "came from so it can be re-derived from the image.")
    if report.truncated:
        staged.warnings.append(
            "carving stopped at the file limit; raise it to recover more")


def _detect_aff(path: Path) -> bool:
    from .aff import is_aff
    return is_aff(path)


def _stage_aff(path: Path, dest: Path, ctx: Any) -> StagedSource:
    from .aff import convert_to_raw

    staged = StagedSource(root=dest, adapter="aff.image",
                          source_format="AFF (converted)")
    dest.mkdir(parents=True, exist_ok=True)
    raw_dir = dest / "_aff"
    raw_path, size = convert_to_raw(path, raw_dir)
    staged.notes.append(
        f"Converted {path.name} to raw ({size:,} bytes) via affconvert.")
    _carve_image_file(raw_path, dest, staged)
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    return staged


def _detect_ewf(path: Path) -> bool:
    from .e01 import is_ewf
    return is_ewf(path)


def _stage_ewf(path: Path, dest: Path, ctx: Any) -> StagedSource:
    from .e01 import convert_to_raw

    staged = StagedSource(root=dest, adapter="ewf.e01",
                          source_format="EnCase EWF/E01 (converted)")
    dest.mkdir(parents=True, exist_ok=True)
    raw_dir = dest / "_e01"
    raw_path, size = convert_to_raw(path, raw_dir)
    staged.notes.append(
        f"Converted {path.name} to raw ({size:,} bytes) via ewfexport.")
    _carve_image_file(raw_path, dest, staged)
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    return staged


def _detect_image(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in (".dd", ".raw", ".img", ".bin", ".e01", ".ex01",
                               ".aff", ".qcow2"):
        return True
    return bool(re.match(r"^\.\d{2,4}$", path.suffix))


def _stage_image(path: Path, dest: Path, ctx: Any) -> StagedSource:
    """Stage a raw disk image by carving it.

    ARGUS does not implement a filesystem driver, so an image is processed by
    signature carving rather than by walking directories. That recovers files
    and application databases but loses paths and filenames — stated plainly,
    because a carved artifact with no path is weaker evidence than the same
    artifact found at a known location.
    """
    from ..core.streaming import ImageReader

    staged = StagedSource(root=dest, adapter="raw.image",
                          source_format="raw disk image")
    dest.mkdir(parents=True, exist_ok=True)
    _carve_image_file(path, dest, staged)
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    return staged


# ═══════════════════════════════════════════════════════════ existing formats
def _detect_ios_backup(path: Path) -> bool:
    return path.is_dir() and (path / "Manifest.db").exists()


def _stage_ios_backup(path: Path, dest: Path, ctx: Any) -> StagedSource:
    from .ios_backup import IOSBackup
    staged = StagedSource(root=dest, adapter="apple.backup",
                          source_format="iTunes/Finder iOS backup",
                          platform="ios")
    backup = IOSBackup(path)
    staged.device = backup.device_info()
    if backup.encrypted:
        raise AcquisitionError(
            "This iOS backup is encrypted. Supply the backup password, or "
            "produce an unencrypted backup with "
            "`idevicebackup2 encryption off <password>`.")
    written, total, warnings = backup.rebuild(dest)
    staged.files, staged.bytes_staged = written, total
    staged.warnings.extend(warnings[:40])
    staged.notes.append(
        "iOS backups store files by SHA-1 of domain+path; ARGUS rebuilt the "
        "logical tree from Manifest.db so parsers see recognisable filenames.")
    return staged


def _detect_adb_backup(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() == ".ab":
        return True
    try:
        with path.open("rb") as fh:
            return fh.read(14) == b"ANDROID BACKUP"
    except OSError:
        return False


def _stage_adb_backup(path: Path, dest: Path, ctx: Any) -> StagedSource:
    from .android_backup import extract, read_header
    staged = StagedSource(root=dest, adapter="android.backup",
                          source_format="Android adb backup",
                          platform="android")
    header = read_header(path.read_bytes()[:512])
    staged.device = {"backup_version": header.version,
                     "compressed": header.compressed,
                     "encryption": header.encryption}
    password = getattr(ctx, "backup_password", None)
    count, warnings = extract(path, dest, password)
    staged.files = count
    staged.bytes_staged = sum(p.stat().st_size for p in dest.rglob("*")
                              if p.is_file())
    staged.warnings.extend(warnings[:40])
    staged.notes.append(
        "adb backup is application-scoped: apps setting allowBackup=false are "
        "absent by design, and the mechanism is deprecated from Android 12.")
    return staged


def _detect_folder(path: Path) -> bool:
    return path.is_dir()


def _stage_folder(path: Path, dest: Path, ctx: Any) -> StagedSource:
    from ..core.custody import import_field_log

    staged = StagedSource(root=dest, adapter="folder",
                          source_format="file tree")
    dest.mkdir(parents=True, exist_ok=True)
    _copy_tree(path, dest, staged)
    _, custody = import_field_log(path, dest)
    if custody.get("imported"):
        staged.notes.append(
            f"Imported PS1 field custody log: {custody.get('entries', 0)} "
            f"entr{'y' if custody.get('entries') == 1 else 'ies'}")
        if not custody.get("ok"):
            staged.warnings.append(
                "Field custody chain verification failed — treat provenance "
                "with caution")
    staged.platform = _detect_platform(dest)
    _record_platform(staged, dest)
    if not staged.platform:
        staged.notes.append(
            "Platform could not be inferred from the directory layout. Parsers "
            "that are not platform-specific will still run, and content-based "
            "identification still applies.")
    return staged


def _detect_file(path: Path) -> bool:
    return path.is_file()


def _stage_file(path: Path, dest: Path, ctx: Any) -> StagedSource:
    staged = StagedSource(root=dest, adapter="single-file",
                          source_format="single file")
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest / path.name)
    staged.files = 1
    staged.bytes_staged = path.stat().st_size
    return staged


# ═══════════════════════════════════════════════════════════ registration
register_adapter("cellebrite.ufdr", "Cellebrite UFDR", priority=95,
                 description="Cellebrite UFED report container (.ufdr)")(
    (_detect_ufdr, _stage_ufdr))
register_adapter("msab.xry", "MSAB XRY export", priority=92,
                 description="MSAB XRY / XAMN export")(
    (_detect_xry, _stage_xry))
register_adapter("graykey", "GrayKey extraction", priority=90,
                 description="GrayKey full filesystem extraction")(
    (_detect_graykey, _stage_graykey))
register_adapter("apple.backup", "iOS backup", priority=88,
                 description="iTunes / Finder iOS backup folder")(
    (_detect_ios_backup, _stage_ios_backup))
register_adapter("android.backup", "Android adb backup", priority=86,
                 description="Android adb backup archive (.ab)")(
    (_detect_adb_backup, _stage_adb_backup))
register_adapter("vendor.backup", "OEM phone backup", priority=84,
                 description="Samsung / Huawei / Xiaomi / OPPO / LG backup")(
    (_detect_vendor_backup, _stage_vendor_backup))
register_adapter("magnet.axiom", "Magnet AXIOM export", priority=82,
                 description="Magnet AXIOM CSV or export folder")(
    (_detect_axiom, _stage_axiom))
register_adapter("aff.image", "AFF forensic image", priority=73,
                 description="Advanced Forensic Format — converted via affconvert")(
    (_detect_aff, _stage_aff))
register_adapter("ewf.e01", "EnCase E01/EWF", priority=72,
                 description="EnCase evidence file — converted via ewfexport")(
    (_detect_ewf, _stage_ewf))
register_adapter("raw.image", "Raw disk image", priority=70,
                 description="dd / raw / split image, carved by signature")(
    (_detect_image, _stage_image))
register_adapter("archive", "Filesystem archive", priority=60,
                 description="TAR / TAR.GZ / ZIP of a file tree")(
    (_detect_archive, _stage_archive))
register_adapter("folder", "File tree", priority=20,
                 description="Any folder of files")(
    (_detect_folder, _stage_folder))
register_adapter("single-file", "Single file", priority=10,
                 description="One file to parse")(
    (_detect_file, _stage_file))


# ═══════════════════════════════════════════════════════════════ public API
def identify(path: Path | str) -> Optional[Adapter]:
    """Return the highest-priority adapter that claims this source."""
    path = Path(path)
    if not path.exists():
        return None
    for adapter in _ADAPTERS:
        try:
            if adapter.detect(path):
                return adapter
        except Exception:
            continue
    return None


def describe(path: Path | str) -> Dict[str, Any]:
    """What is this source? Reported before anything is copied."""
    path = Path(path)
    if not path.exists():
        return {"ok": False, "reason": f"path does not exist: {path}"}
    adapter = identify(path)
    if adapter is None:
        return {"ok": False, "reason": "no import adapter recognised this source"}
    return {
        "ok": True,
        "adapter": adapter.name,
        "label": adapter.label,
        "description": adapter.description,
        "path": str(path),
        "is_directory": path.is_dir(),
    }


def stage(path: Path | str, dest: Path | str, ctx: Any = None) -> StagedSource:
    """Detect the format and stage it into ``dest`` for the parser pipeline."""
    path, dest = Path(path), Path(dest)
    adapter = identify(path)
    if adapter is None:
        raise AcquisitionError(
            f"No import adapter recognised {path.name}. Supported: "
            + ", ".join(a.label for a in _ADAPTERS))
    staged = adapter.stage(path, dest, ctx)
    if not staged.files:
        staged.warnings.append(
            "the adapter staged no files — the source may be empty, or its "
            "contents may be in a container ARGUS could not open")
    return staged
