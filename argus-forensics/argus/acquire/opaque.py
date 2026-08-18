"""Reading what can be read from a container nobody documented.

Vendor tools ship proprietary containers — MSAB `.xry`, Cellebrite `.ufd` — whose
internal structure is not published. ARGUS cannot decode them, and guessing at a
container layout is precisely the mistake this project exists to avoid: a
half-understood structure yields records that look authoritative and are wrong.

Refusing outright, though, throws away something real. These containers hold the
device's actual files, and those files have signatures. A SQLite database inside
an undocumented wrapper is still a SQLite database. So:

**Triage** reports what the bytes actually are — a zip in disguise, a compressed
stream, something with SQLite headers scattered through it — so an examiner knows
before spending an afternoon whether an independent read is even possible.

**Carving** then extracts the recognisable files and hands them to the normal
parsers, which decode them properly and carve their unallocated space in turn.

The distinction that must never blur: this recovers *files the container holds*.
It does not decode the container, and it cannot see anything the vendor stored in
a format of their own devising. What comes out is real; what does not come out is
not evidence of absence. Every artifact says so.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Container signatures worth naming. A vendor extension tells you the tool that
# wrote the file; the magic bytes tell you what it actually is, and the two
# disagree more often than you would expect.
WRAPPERS: List[Tuple[bytes, str, str]] = [
    (b"PK\x03\x04", "zip", "A zip archive. Its members can be listed and "
                           "extracted directly."),
    (b"PK\x05\x06", "zip (empty)", "An empty zip archive."),
    (b"\x1f\x8b", "gzip", "A gzip stream. Decompress before examining."),
    (b"BZh", "bzip2", "A bzip2 stream."),
    (b"\xfd7zXZ\x00", "xz", "An xz stream."),
    (b"7z\xbc\xaf\x27\x1c", "7-zip", "A 7-zip archive."),
    (b"Rar!\x1a\x07", "rar", "A RAR archive."),
    (b"SQLite format 3\x00", "sqlite", "A SQLite database — readable directly."),
    (b"\x53\x46\x53\x00", "sfs", "Possibly an MSAB structured file store."),
    (b"AFF", "aff", "An Advanced Forensic Format image."),
    (b"EVF\x09", "ewf/e01", "An EnCase evidence file. Convert with ewfexport."),
    (b"\x00\x00\x00\x0cjP", "jp2", "A JPEG 2000 stream."),
    (b"XRY\x00", "msab.xry",
     "An MSAB XRY container. The structure is proprietary and ARGUS does not "
     "decode it. A small file (tens of KB) is a case index holding metadata "
     "and pointers, not the extraction itself — look for the companion .xry "
     "file, which is where the device data lives."),
    (b"<?xml", "xml", "An XML document — readable directly."),
    (b"bplist00", "bplist", "An Apple binary property list — readable directly."),
    (b"<!DOCTYPE plist", "plist", "An Apple XML property list — readable directly."),
]

# How much of the file to sample when estimating what is inside. Reading the
# whole of a 60 GB full-file-system extraction to answer "is this worth trying"
# would defeat the purpose of triage.
SAMPLE_BYTES = 32 * 1024 * 1024

# Formats that are not containers at all — ARGUS parses these directly, and
# telling an examiner to "carve" one would send them the long way round to a
# file they can simply open.
DIRECTLY_READABLE = {"xml", "plist", "bplist", "sqlite"}


@dataclass
class Triage:
    """What a container turned out to be."""

    path: Path
    size: int = 0
    extension: str = ""
    wrapper: str = ""
    wrapper_note: str = ""
    zip_members: int = 0
    zip_sample: List[str] = field(default_factory=list)
    embedded: Dict[str, int] = field(default_factory=dict)
    sampled_bytes: int = 0
    entropy: float = 0.0
    carvable: bool = False
    recommendation: str = ""
    caveat: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path), "size": self.size,
            "extension": self.extension, "wrapper": self.wrapper,
            "wrapper_note": self.wrapper_note,
            "zip_members": self.zip_members, "zip_sample": self.zip_sample,
            "embedded_signatures": self.embedded,
            "sampled_bytes": self.sampled_bytes,
            "entropy": round(self.entropy, 3),
            "carvable": self.carvable,
            "recommendation": self.recommendation,
            "caveat": self.caveat,
        }


def _shannon(data: bytes) -> float:
    """Entropy in bits per byte.

    Near 8.0 means compressed or encrypted, and carving will find nothing
    because there are no plaintext signatures left to find. Saying so upfront
    saves an examiner from concluding the evidence was empty.
    """
    if not data:
        return 0.0
    import math

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _count_embedded(data: bytes) -> Dict[str, int]:
    """Count recognisable file headers, discounting chance occurrences.

    A three-byte marker appears in random data roughly once every 16 MB, so in a
    compressed or encrypted container a handful of "JPEG headers" turn up by
    coincidence. Reporting those as recoverable files would promise an examiner
    a recovery that cannot happen — and worse, an empty carve would then read as
    "the device held nothing" rather than "this route cannot reach it".

    So a hit only counts when it appreciably exceeds what chance alone would
    produce for a marker of that length.
    """
    markers = {
        "sqlite": b"SQLite format 3\x00",
        "jpeg": b"\xff\xd8\xff",
        "png": b"\x89PNG\r\n\x1a\n",
        "gif": b"GIF8",
        "pdf": b"%PDF-",
        "zip": b"PK\x03\x04",
        "gzip": b"\x1f\x8b\x08",
        "bplist": b"bplist00",
        "xml": b"<?xml",
        "sqlite_wal": b"\x37\x7f\x06\x82",
    }
    found: Dict[str, int] = {}
    for name, marker in markers.items():
        count = data.count(marker)
        if not count:
            continue
        expected_by_chance = len(data) / (256.0 ** len(marker))
        threshold = expected_by_chance * 4
        if len(marker) <= 3:
            # Three bytes match by accident often enough that a couple of hits
            # mean nothing. Demand a real cluster.
            threshold = max(threshold, 3.0)
        else:
            # A long, distinctive marker is meaningful even once. Requiring two
            # discarded a 1.4 MB XML plist whose single `<?xml` sits at offset
            # zero — reporting a perfectly readable file as unrecognisable.
            threshold = max(threshold, 0.5)
        if count <= threshold:
            continue
        found[name] = count
    return found


def triage(path: Path | str, sample_bytes: int = SAMPLE_BYTES) -> Triage:
    """Report what a container actually is, without decoding it."""
    path = Path(path)
    result = Triage(path=path, extension=path.suffix.lower())

    # MSAB case-index resolution: triage the data file, not the index.
    triage_path = path
    companion_note = ""
    if path.is_file() and path.suffix.lower() == ".xrycase":
        try:
            from .msab import resolve_case

            resolved = resolve_case(path)
            if resolved.data_path and resolved.data_path != path:
                triage_path = resolved.data_path
                companion_note = (
                    f"Triage target resolved from {path.name} to "
                    f"{resolved.data_path.name} "
                    f"({resolved.data_path.stat().st_size:,} bytes).")
            elif resolved.is_index_only:
                companion_note = (
                    f"{path.name} appears to be a case index, not the "
                    f"extraction. No companion .xry was found alongside it.")
        except Exception:                                 # pragma: no cover
            pass
    try:
        result.size = triage_path.stat().st_size
    except OSError as exc:
        result.recommendation = f"Cannot read: {exc}"
        return result

    if result.size == 0:
        result.recommendation = "The file is empty."
        return result

    with open(triage_path, "rb") as handle:
        head = handle.read(4096)
        sample = head + handle.read(max(0, sample_bytes - len(head)))
    result.sampled_bytes = len(sample)

    for magic, name, note in WRAPPERS:
        if head.startswith(magic):
            result.wrapper = name
            result.wrapper_note = note
            break

    if zipfile.is_zipfile(triage_path):
        result.wrapper = result.wrapper or "zip"
        try:
            with zipfile.ZipFile(triage_path) as archive:
                names = archive.namelist()
                result.zip_members = len(names)
                result.zip_sample = names[:25]
        except Exception:                                 # pragma: no cover
            pass

    result.entropy = _shannon(sample[: 4 * 1024 * 1024])
    result.embedded = _count_embedded(sample)
    # Entropy overrides the signature count. Above ~7.5 bits/byte the contents
    # are compressed or encrypted, and any surviving "signature" is noise that
    # happens to match — carving it would recover nothing and imply the device
    # was empty.
    high_entropy = result.entropy > 7.5
    result.carvable = (result.zip_members > 0
                       or (bool(result.embedded) and not high_entropy))

    # ---------------------------------------------------------- verdict
    if result.wrapper in DIRECTLY_READABLE:
        result.recommendation = (
            f"This is not an opaque container — it is {result.wrapper}, which "
            f"ARGUS parses directly. Import it as evidence; no conversion or "
            f"carving is needed.")
        result.carvable = False
    elif result.zip_members:
        result.recommendation = (
            f"This is a zip archive containing {result.zip_members} members "
            f"despite its '{result.extension}' extension. ARGUS can extract "
            f"and parse the members directly.")
    elif result.embedded and not high_entropy:
        summary = ", ".join(f"{n}×{k}" for k, n in
                            sorted(result.embedded.items(),
                                   key=lambda kv: -kv[1])[:5])
        result.recommendation = (
            f"The container structure is not decodable, but recognisable files "
            f"are embedded in it ({summary} in the first "
            f"{result.sampled_bytes // (1024 * 1024)} MB). Carving will recover "
            f"those files, and ARGUS will parse them normally — including "
            f"carving their own unallocated space.")
    elif high_entropy:
        result.recommendation = (
            f"Entropy is {result.entropy:.2f} bits/byte, so the contents are "
            f"compressed or encrypted. No plaintext file signatures survive "
            f"— any that appear to match are chance byte sequences — so "
            f"carving will recover nothing. Export from the originating tool "
            f"instead. An empty carve here would mean this route cannot reach "
            f"the data, not that the device held none.")
    else:
        result.recommendation = (
            "No recognisable file signatures were found in the sampled region. "
            "Carving is unlikely to help. Export from the originating tool.")

    if companion_note:
        result.recommendation = companion_note + " " + result.recommendation

    result.caveat = (
        "Carving recovers files the container happens to hold in a recognisable "
        "format. It does not decode the container's own structure, so anything "
        "the vendor stored in a proprietary layout — their decoded records, "
        "their tags, their analyst notes — will not appear. Absence here is not "
        "evidence that the device lacked the data; it means this route could "
        "not reach it. For a complete read, export from the tool that made the "
        "container.")
    return result


def carve_container(path: Path | str, dest: Path | str,
                    max_files: int = 5000,
                    progress: Optional[Any] = None) -> Dict[str, Any]:
    """Extract recognisable files from an undecodable container.

    Recovered files are written into ``dest`` named by offset, so every one
    traces back to a byte position in the original container and the extraction
    can be repeated and checked.
    """
    from ..parsers.filecarver import FileCarver

    path, dest = Path(path), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    # Zip first: if it really is an archive, member names and paths are far more
    # useful than carved offsets, and the structure is not a guess.
    if zipfile.is_zipfile(path):
        extracted = 0
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.file_size <= 0:
                    continue
                # Refuse absolute paths and traversal — a hostile or merely
                # sloppy archive must not write outside the staging directory.
                name = member.filename.replace("\\", "/").lstrip("/")
                target = (dest / name).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, open(target, "wb") as out:
                    out.write(src.read())
                extracted += 1
                if extracted >= max_files:
                    break
        return {
            "mode": "zip",
            "files": extracted,
            "note": (f"{extracted} member(s) extracted from what is, despite "
                     f"its extension, a zip archive. Paths and names are the "
                     f"archive's own, not inferred."),
        }

    carver = FileCarver(max_files=max_files, require_validation=True,
                        keep_data=True)
    report = carver.carve_file(path)
    written: List[Dict[str, Any]] = []
    for item in report.files:
        name = f"{item.offset:012d}_{item.sha256[:12]}{item.extension}"
        target = dest / name
        try:
            target.write_bytes(item.data)
        except OSError:
            continue
        written.append({"file": name, "offset": item.offset, "size": item.size,
                        "sha256": item.sha256, "type": item.signature,
                        "validated": item.validated})

    return {
        "mode": "carve",
        "files": len(written),
        "carved": written[:2000],
        "scan": report.summary(),
        "note": ("Files were recovered by signature from an undecodable "
                 "container. Each name encodes the byte offset it came from, so "
                 "the recovery can be repeated and checked. The container's own "
                 "structure was not interpreted, and records the vendor stored "
                 "in a proprietary layout are not present."),
    }
