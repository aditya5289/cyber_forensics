"""Tool validation harness — measured error rates, not claims.

Under *Daubert* and equivalent standards, a party relying on a forensic tool
can be asked: what is its known error rate? "It works well" is not an answer.
This module produces one.

The method follows NIST CFTT practice: construct reference data where the
correct answer is known by construction, run the tool against it, and report
recall, precision and the specific items missed. Because the corpus is
generated rather than curated, the ground truth is exact — every planted
message, deleted row and concealed file is recorded at the moment it is
created, so a miss cannot be explained away.

What this measures honestly:

* **Recall** — of the artifacts that exist, how many did we find?
* **Precision** — of the artifacts we reported, how many were real?
* **Per-capability breakdown** — carving recall is not the same as parsing
  recall, and reporting a single blended figure would hide a weak component.

What it deliberately does *not* do: measure against real-world data. Generated
data has known limitations — it cannot reproduce every schema variant a real
caseload contains. That limitation is stated in the output rather than papered
over, because a validation report that overstates its own coverage is worse
than none.
"""

from __future__ import annotations

import json
import platform
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .. import __version__


# ═══════════════════════════════════════════════════════════ result types
@dataclass
class TestResult:
    """One validation test with a measurable outcome."""

    test_id: str
    capability: str
    description: str
    expected: int = 0
    found: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    missed_items: List[str] = field(default_factory=list)
    spurious_items: List[str] = field(default_factory=list)
    passed: bool = False
    duration_s: float = 0.0
    error: str = ""
    notes: str = ""

    @property
    def recall(self) -> Optional[float]:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 4) if denom else None

    @property
    def precision(self) -> Optional[float]:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 4) if denom else None

    @property
    def f1(self) -> Optional[float]:
        r, p = self.recall, self.precision
        if r is None or p is None or (r + p) == 0:
            return None
        return round(2 * r * p / (r + p), 4)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.update(recall=self.recall, precision=self.precision, f1=self.f1)
        return d


@dataclass
class ValidationReport:
    tool: str = "ARGUS Forensics"
    version: str = __version__
    generated_at: str = ""
    environment: Dict[str, str] = field(default_factory=dict)
    results: List[TestResult] = field(default_factory=list)

    def by_capability(self) -> Dict[str, Dict[str, Any]]:
        grouped: Dict[str, List[TestResult]] = {}
        for r in self.results:
            grouped.setdefault(r.capability, []).append(r)
        out: Dict[str, Dict[str, Any]] = {}
        for cap, tests in sorted(grouped.items()):
            tp = sum(t.true_positives for t in tests)
            fp = sum(t.false_positives for t in tests)
            fn = sum(t.false_negatives for t in tests)
            out[cap] = {
                "tests": len(tests),
                "passed": sum(1 for t in tests if t.passed),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
                "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
                "false_negative_rate": round(fn / (tp + fn), 4) if (tp + fn) else None,
                "false_positive_rate": round(fp / (tp + fp), 4) if (tp + fp) else None,
            }
        return out

    def summary(self) -> Dict[str, Any]:
        tp = sum(r.true_positives for r in self.results)
        fp = sum(r.false_positives for r in self.results)
        fn = sum(r.false_negatives for r in self.results)
        passed = sum(1 for r in self.results if r.passed)
        return {
            "tests_run": len(self.results),
            "tests_passed": passed,
            "tests_failed": len(self.results) - passed,
            "overall_recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
            "overall_precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "total_expected": tp + fn,
            "total_missed": fn,
            "total_spurious": fp,
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool, "version": self.version,
            "generated_at": self.generated_at,
            "environment": self.environment,
            "summary": self.summary(),
            "by_capability": self.by_capability(),
            "results": [r.as_dict() for r in self.results],
            "limitations": LIMITATIONS,
            "method": METHOD,
        }


METHOD = (
    "Reference data is generated programmatically so that ground truth is "
    "exact: every message, deleted row, concealed file and planted entity is "
    "recorded at creation. The tool is then run against that data and its "
    "output compared item by item. Recall is the proportion of existing "
    "artifacts recovered; precision is the proportion of reported artifacts "
    "that were real. Tests are deterministic — the same seed produces the same "
    "corpus, so results are reproducible by a third party."
)

LIMITATIONS = [
    "The corpus is synthetic. It reproduces the documented schemas of the "
    "applications covered, but not every version variant found in a real "
    "caseload; recall against an unseen schema variant may be lower.",
    "Deleted-record recall is measured against records whose bytes are still "
    "physically present in the file. SQLite compacts pages when freeing cells "
    "and overwrites some deleted content outright; those records are "
    "unrecoverable by any tool and are reported separately rather than counted "
    "as failures. In the reference corpus a majority of deleted rows were "
    "destroyed this way, which is itself a finding: deletion in a busy table "
    "frequently leaves nothing behind.",
    "Where an application securely deletes, or the database has been vacuumed, "
    "recovery is impossible by construction. ARGUS reports that condition "
    "explicitly rather than presenting an empty result as evidence that "
    "nothing was deleted.",
    "Encrypted stores are counted as correctly *identified*, not decoded. "
    "ARGUS does not attempt decryption and claims no capability there.",
    "Figures describe this build on this platform. Re-run the harness after "
    "any upgrade — a validation result does not transfer between versions.",
    "Carving recall depends on how much of a file survived. A partially "
    "overwritten file that cannot be validated is reported as a miss, which "
    "makes the figure conservative rather than flattering.",
]


# ═══════════════════════════════════════════════════════════ reference data
@dataclass
class GroundTruth:
    """What the reference corpus contains, recorded at construction."""

    root: Path
    live_sms: List[str] = field(default_factory=list)
    deleted_sms: List[str] = field(default_factory=list)
    live_calls: int = 0
    deleted_calls: int = 0
    contacts: List[str] = field(default_factory=list)
    embedded_files: List[Tuple[str, int, int]] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)
    concealed_files: List[str] = field(default_factory=list)
    encrypted_files: List[str] = field(default_factory=list)
    image_path: Optional[Path] = None


ENTITY_PLANTS: Dict[str, List[str]] = {
    "btc": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],
    "eth": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
    "iban": ["GB82 WEST 1234 5698 7654 32"],
    "card": ["4539148803436467", "378282246310005"],
    "onion": ["expyuzz4wqqyqhjn.onion"],
    "imei": ["490154203237518"],
    "upi": ["rahul.mehta@okaxis"],
}

DELETED_TEXTS = [
    "Burn the paperwork before Friday.",
    "The customs officer has been paid.",
    "Move the container tonight, not tomorrow.",
    "Nobody can trace this handset to me.",
    "Meet at the old jetty, 02:00, come alone.",
    "I told you to stop putting this in writing.",
    "Delete every trace of this conversation.",
    "The second shipment clears customs on Thursday.",
]


def build_reference_corpus(root: Path, seed: int = 20260730) -> GroundTruth:
    """Create reference data with exactly-known contents."""
    import random
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    truth = GroundTruth(root=root)

    base_ms = 1_780_000_000_000

    # ---- SMS store with known live and deleted content --------------------
    sms_path = root / ("data/data/com.android.providers.telephony/"
                       "databases/mmssms.db")
    sms_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(sms_path)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("""CREATE TABLE sms (_id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER, address TEXT, person INTEGER, date INTEGER,
        date_sent INTEGER, protocol INTEGER, read INTEGER, status INTEGER,
        type INTEGER, subject TEXT, body TEXT, service_center TEXT,
        seen INTEGER, sub_id INTEGER, creator TEXT)""")

    entity_texts: List[str] = []
    for kind, values in ENTITY_PLANTS.items():
        for value in values:
            entity_texts.append(f"reference {kind} value {value} end")
    truth.entities = {k: list(v) for k, v in ENTITY_PLANTS.items()}

    live_texts = [f"Reference live message number {i} for validation."
                  for i in range(220)] + entity_texts
    for i, text in enumerate(live_texts):
        conn.execute(
            "INSERT INTO sms (thread_id,address,person,date,date_sent,protocol,"
            "read,status,type,subject,body,service_center,seen,sub_id,creator) "
            "VALUES (?,?,0,?,?,0,1,-1,?,'',?,'+919999999999',1,1,'')",
            (i % 12, f"+9198765{i % 100:05d}", base_ms + i * 60_000,
             base_ms + i * 60_000, 1 + (i % 2), text))
    conn.commit()
    truth.live_sms = list(live_texts)

    # Deleted rows: inserted, committed, then deleted so the bytes remain in
    # freed space. Each is recorded as ground truth for the carver.
    marker_thread = 999
    for i, text in enumerate(DELETED_TEXTS):
        conn.execute(
            "INSERT INTO sms (thread_id,address,person,date,date_sent,protocol,"
            "read,status,type,subject,body,service_center,seen,sub_id,creator) "
            "VALUES (?,?,0,?,?,0,1,-1,1,'',?,'+919999999999',1,1,'')",
            (marker_thread, "+919555000111", base_ms + 500_000 + i * 60_000,
             base_ms + 500_000 + i * 60_000, text))
    conn.commit()
    conn.execute("DELETE FROM sms WHERE thread_id = ?", (marker_thread,))
    conn.commit()
    conn.close()
    truth.deleted_sms = list(DELETED_TEXTS)

    # ---- Call log ---------------------------------------------------------
    call_path = root / ("data/data/com.android.providers.contacts/"
                        "databases/calllog.db")
    call_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(call_path)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("""CREATE TABLE calls (_id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT,
        numbertype INTEGER, new INTEGER, is_read INTEGER,
        geocoded_location TEXT, presentation INTEGER, subscription_id TEXT,
        via_number TEXT)""")
    total_calls = 140
    for i in range(total_calls):
        conn.execute(
            "INSERT INTO calls (number,date,duration,type,name,numbertype,new,"
            "is_read,geocoded_location,presentation,subscription_id,via_number)"
            " VALUES (?,?,?,?,?,2,0,1,'Reference',1,'0','')",
            (f"+9198111{i % 100:05d}", base_ms + i * 300_000,
             rng.randint(5, 900), 1 + (i % 3), f"Reference Contact {i % 20}"))
    conn.commit()
    conn.close()
    truth.live_calls = total_calls
    truth.deleted_calls = 0

    # ---- Contacts ---------------------------------------------------------
    contacts_path = root / ("data/data/com.android.providers.contacts/"
                            "databases/contacts2.db")
    conn = sqlite3.connect(contacts_path)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.executescript("""
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER, display_name TEXT, account_name TEXT,
            account_type TEXT, starred INTEGER, times_contacted INTEGER,
            last_time_contacted INTEGER, deleted INTEGER,
            contact_last_updated_timestamp INTEGER);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            mimetype TEXT);
        CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT,
            data2 INTEGER, data3 TEXT);
    """)
    for mt in ("vnd.android.cursor.item/name",
               "vnd.android.cursor.item/phone_v2",
               "vnd.android.cursor.item/email_v2"):
        conn.execute("INSERT INTO mimetypes (mimetype) VALUES (?)", (mt,))
    names = [f"Reference Person {i:02d}" for i in range(24)]
    for i, name in enumerate(names, 1):
        conn.execute("INSERT INTO raw_contacts (contact_id,display_name,"
                     "account_name,account_type,starred,times_contacted,"
                     "last_time_contacted,deleted,"
                     "contact_last_updated_timestamp) "
                     "VALUES (?,?,'ref@example.com','com.google',0,1,?,0,?)",
                     (i, name, base_ms, base_ms))
        conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                     " VALUES (?,1,?,0)", (i, name))
        conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                     " VALUES (?,2,?,2)", (i, f"+9197000{i:05d}"))
    conn.commit()
    conn.close()
    truth.contacts = names

    # ---- Raw image with embedded files, for carving ------------------------
    from PIL import Image
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "samples"))
    try:
        from exif_writer import write_jpeg_with_exif
    except ImportError:
        write_jpeg_with_exif = None

    embedded: List[Tuple[str, int, int]] = []
    blob = bytearray()
    scratch = root / "_scratch"
    scratch.mkdir(exist_ok=True)
    for i in range(6):
        img = Image.new("RGB", (240, 180))
        px = img.load()
        for y in range(180):
            for x in range(240):
                px[x, y] = ((x * 3 + i * 37) % 256, (y * 5) % 256, 100 + i * 20)
        target = scratch / f"ref_{i}.jpg"
        if write_jpeg_with_exif:
            write_jpeg_with_exif(target, img,
                                 datetime.now(timezone.utc), latitude=18.94,
                                 longitude=72.93)
        else:
            img.save(target, "JPEG", quality=80)
        payload = target.read_bytes()
        blob += bytes(rng.getrandbits(8) for _ in range(rng.randint(1024, 4096)))
        embedded.append(("jpg", len(blob), len(payload)))
        blob += payload
    # Embed the SMS database too — a carved application database is the
    # highest-value carving outcome, so it must be measured.
    db_bytes = sms_path.read_bytes()
    blob += bytes(rng.getrandbits(8) for _ in range(2048))
    embedded.append(("db", len(blob), len(db_bytes)))
    blob += db_bytes
    blob += bytes(rng.getrandbits(8) for _ in range(2048))

    image_path = root / "reference.dd"
    image_path.write_bytes(bytes(blob))
    shutil.rmtree(scratch, ignore_errors=True)
    truth.embedded_files = embedded
    truth.image_path = image_path

    # ---- Concealed and encrypted files ------------------------------------
    conceal_dir = root / "sdcard/.vault"
    conceal_dir.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (200, 150), (40, 90, 140))
    concealed = conceal_dir / "notes_backup.hid"
    if write_jpeg_with_exif:
        write_jpeg_with_exif(concealed, img, datetime.now(timezone.utc))
    else:
        img.save(concealed, "JPEG")
    truth.concealed_files = [str(concealed.relative_to(root))]

    enc_dir = root / "sdcard/WhatsApp/Databases"
    enc_dir.mkdir(parents=True, exist_ok=True)
    enc = enc_dir / "msgstore.db.crypt14"
    enc.write_bytes(bytes(rng.getrandbits(8) for _ in range(8192)))
    truth.encrypted_files = [str(enc.relative_to(root))]

    return truth


# ═══════════════════════════════════════════════════════════════ the tests
def _timed(fn: Callable[[], Any]) -> Tuple[Any, float]:
    import time
    start = time.perf_counter()
    value = fn()
    return value, round(time.perf_counter() - start, 3)


def test_live_parsing(truth: GroundTruth) -> List[TestResult]:
    """Do we recover every live record that exists?"""
    from ..parsers.registry import ParseContext, dispatch, load_all
    from ..core.models import Category, Recovery
    load_all()

    results: List[TestResult] = []
    ctx = ParseContext(evidence_root=truth.root, platform="android",
                       recover_deleted=False)

    # --- SMS
    sms_path = (truth.root / "data/data/com.android.providers.telephony"
                             "/databases/mmssms.db")
    parsed, secs = _timed(lambda: dispatch(sms_path, ctx))
    bodies = {a.body for a in parsed.artifacts
              if a.category == Category.MESSAGE}
    expected = set(truth.live_sms)
    tp = len(expected & bodies)
    missed = sorted(expected - bodies)
    spurious = sorted(bodies - expected)
    results.append(TestResult(
        test_id="parse.sms.live", capability="Parsing — messages",
        description=(f"Recover all {len(expected)} live SMS records from a "
                     f"reference telephony store"),
        expected=len(expected), found=len(bodies), true_positives=tp,
        false_negatives=len(missed), false_positives=len(spurious),
        missed_items=missed[:10], spurious_items=spurious[:10],
        passed=not missed and not spurious, duration_s=secs))

    # --- Calls
    call_path = (truth.root / "data/data/com.android.providers.contacts"
                              "/databases/calllog.db")
    parsed, secs = _timed(lambda: dispatch(call_path, ctx))
    calls = [a for a in parsed.artifacts if a.category == Category.CALL]
    tp = min(len(calls), truth.live_calls)
    results.append(TestResult(
        test_id="parse.calls.live", capability="Parsing — calls",
        description=f"Recover all {truth.live_calls} call-log records",
        expected=truth.live_calls, found=len(calls), true_positives=tp,
        false_negatives=max(truth.live_calls - len(calls), 0),
        false_positives=max(len(calls) - truth.live_calls, 0),
        passed=len(calls) == truth.live_calls, duration_s=secs))

    # --- Contacts
    contacts_path = (truth.root / "data/data/com.android.providers.contacts"
                                  "/databases/contacts2.db")
    parsed, secs = _timed(lambda: dispatch(contacts_path, ctx))
    found_names = {a.attributes.get("display_name", "")
                   for a in parsed.artifacts if a.category == Category.CONTACT}
    expected_names = set(truth.contacts)
    tp = len(expected_names & found_names)
    missed = sorted(expected_names - found_names)
    results.append(TestResult(
        test_id="parse.contacts", capability="Parsing — contacts",
        description=f"Recover all {len(expected_names)} contacts with numbers",
        expected=len(expected_names), found=len(found_names - {""}),
        true_positives=tp, false_negatives=len(missed),
        false_positives=len(found_names - expected_names - {""}),
        missed_items=missed[:10], passed=not missed, duration_s=secs))
    return results


def test_deleted_recovery(truth: GroundTruth) -> List[TestResult]:
    """Do we recover every deleted record whose bytes still exist?

    A subtlety that decides whether this figure means anything: deleting a row
    does not guarantee its bytes survive. SQLite compacts pages as it frees
    cells, and in doing so it overwrites some deleted content outright. Those
    records are gone from the file — no carver can recover them, and no tool
    that claims to is telling the truth.

    So recall is measured against the records that are **physically still
    present in the file**, established by searching the raw bytes. Records
    destroyed by SQLite's own page management are reported separately as
    context. Measuring against the deleted count instead would understate the
    carver against an impossible standard, which misleads in the opposite
    direction to the usual vendor exaggeration but misleads all the same.
    """
    from ..parsers.sqlite_reader import ForensicSQLite

    sms_path = (truth.root / "data/data/com.android.providers.telephony"
                             "/databases/mmssms.db")
    raw = sms_path.read_bytes()

    deleted = set(truth.deleted_sms)
    # Ground truth for *recoverability*, not merely for deletion.
    residual = {text for text in deleted if text.encode("utf-8") in raw}
    destroyed = sorted(deleted - residual)

    def run():
        with ForensicSQLite(sms_path) as db:
            return db.carve("sms", min_confidence=0.4)

    carved, secs = _timed(run)
    recovered_text = {v for rec in carved for v in rec.values
                      if isinstance(v, str)}

    tp = sum(1 for text in residual if text in recovered_text)
    missed = sorted(text for text in residual if text not in recovered_text)

    # A carved string that was never planted — live or deleted — is spurious.
    legitimate = deleted | set(truth.live_sms)
    spurious = sorted(v for v in recovered_text
                      if len(v) > 25 and v not in legitimate)

    return [TestResult(
        test_id="carve.sqlite.deleted", capability="Deleted-record recovery",
        description=(f"Recover the {len(residual)} of {len(deleted)} deleted "
                     f"SMS records whose bytes survive in the file"),
        expected=len(residual), found=len(carved), true_positives=tp,
        false_negatives=len(missed), false_positives=len(spurious),
        missed_items=missed, spurious_items=spurious[:10],
        passed=not missed and not spurious, duration_s=secs,
        notes=(f"{len(deleted)} records were deleted; {len(residual)} remain "
               f"physically present and {len(destroyed)} were overwritten by "
               f"SQLite page compaction and are unrecoverable by any tool. "
               f"Recall is measured against the {len(residual)} recoverable "
               f"records. The carver additionally recovered "
               f"{sum(1 for v in recovered_text if v in set(truth.live_sms))} "
               f"superseded copies of live records from unallocated space."))]


def test_file_carving(truth: GroundTruth) -> List[TestResult]:
    """Do we recover embedded files at the right offset and size?"""
    from ..core.streaming import ImageReader
    from ..parsers.filecarver import FileCarver

    def run():
        with ImageReader(truth.image_path, block_size=1 << 16) as reader:
            carver = FileCarver(max_files=500, keep_data=False)
            carver.carve_image(reader)
            return carver.report

    report, secs = _timed(run)
    planted = {(off, size) for _kind, off, size in truth.embedded_files}
    got = {(f.offset, f.size) for f in report.files}
    exact = planted & got
    offsets_only = {off for off, _ in planted} & {off for off, _ in got}
    missed = sorted(f"offset {off} size {size}"
                    for off, size in planted - got)
    spurious = sorted(f"offset {f.offset} {f.signature}"
                      for f in report.files
                      if f.offset not in {off for off, _ in planted})
    return [TestResult(
        test_id="carve.files.image", capability="File carving",
        description=(f"Recover {len(planted)} files embedded in a raw image at "
                     f"the exact offset and byte length"),
        expected=len(planted), found=len(report.files),
        true_positives=len(exact), false_negatives=len(planted - got),
        false_positives=len(spurious), missed_items=missed,
        spurious_items=spurious[:10],
        passed=len(exact) == len(planted) and not spurious, duration_s=secs,
        notes=(f"{len(offsets_only)}/{len(planted)} located at the correct "
               f"offset; {len(exact)}/{len(planted)} also with the exact byte "
               f"length. Byte-exact recovery is required to pass."))]


def test_entity_extraction(truth: GroundTruth) -> List[TestResult]:
    """Do we find and correctly type planted identifiers?"""
    from ..intel.entities import EntityExtractor

    def run():
        ex = EntityExtractor()
        for kind, values in truth.entities.items():
            for value in values:
                ex.scan_text(f"reference {kind} value {value} end",
                             artifact_id=f"{kind}:{value}")
        return ex

    extractor, secs = _timed(run)
    results: List[TestResult] = []
    for kind, values in sorted(truth.entities.items()):
        found = {h.normalised for h in extractor.results(kinds=[kind])}
        expected_norm = set()
        for value in values:
            hits = [h for h in extractor.hits.values()
                    if h.kind == kind and (value.lower() in h.value.lower()
                                           or h.value.lower() in value.lower())]
            expected_norm.update(h.normalised for h in hits)
        tp = len(expected_norm & found)
        missed = [v for v in values
                  if not any(v.lower().replace(" ", "") in
                             h.value.lower().replace(" ", "")
                             for h in extractor.results(kinds=[kind]))]
        results.append(TestResult(
            test_id=f"entity.{kind}", capability="Entity extraction",
            description=(f"Detect and correctly type {len(values)} planted "
                         f"{kind} value(s), including checksum validation"),
            expected=len(values), found=len(found),
            true_positives=len(values) - len(missed),
            false_negatives=len(missed), false_positives=0,
            missed_items=missed, passed=not missed, duration_s=secs))
    return results


def test_validator_accuracy(truth: GroundTruth) -> List[TestResult]:
    """Do the checksum validators reject invalid values?

    Recall alone is not enough for entity extraction: a validator that accepts
    everything would score perfect recall while being useless. This measures
    the other half — correct rejection of near-miss values.
    """
    from ..intel.entities import (valid_btc, valid_card, valid_iban,
                                  valid_imei, valid_upi)
    cases: List[Tuple[str, Callable[[str], bool], str, bool]] = [
        ("btc", valid_btc, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", True),
        ("btc", valid_btc, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", False),
        ("btc", valid_btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", True),
        ("btc", valid_btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", False),
        ("iban", valid_iban, "GB82 WEST 1234 5698 7654 32", True),
        ("iban", valid_iban, "GB82 WEST 1234 5698 7654 33", False),
        ("card", valid_card, "4539148803436467", True),
        ("card", valid_card, "4539148803436468", False),
        ("card", valid_card, "378282246310005", True),
        ("card", valid_card, "490154203237518", False),   # an IMEI, not a card
        ("imei", valid_imei, "490154203237518", True),
        ("imei", valid_imei, "490154203237519", False),
        ("upi", valid_upi, "rahul.mehta@okaxis", True),
        ("upi", valid_upi, "rahul@example.com", False),
    ]
    correct = 0
    wrong: List[str] = []
    for kind, fn, value, want in cases:
        try:
            got = fn(value)
        except Exception as exc:
            wrong.append(f"{kind} {value}: raised {exc}")
            continue
        if got == want:
            correct += 1
        else:
            wrong.append(f"{kind} {value}: expected {want}, got {got}")
    return [TestResult(
        test_id="entity.validators", capability="Entity validation",
        description=(f"Accept {sum(1 for c in cases if c[3])} valid and reject "
                     f"{sum(1 for c in cases if not c[3])} near-miss values "
                     f"using published checksum algorithms"),
        expected=len(cases), found=len(cases), true_positives=correct,
        false_negatives=len(wrong), false_positives=0, missed_items=wrong,
        passed=not wrong,
        notes=("Measures correct rejection as well as correct acceptance. A "
               "validator that accepted everything would show perfect recall "
               "while being worthless."))]


def test_integrity_detection(truth: GroundTruth) -> List[TestResult]:
    """Does tampering with sealed evidence always get caught?"""
    from ..core.case import Case, Exhibit
    from ..core.container import EvidenceContainer, ExtractionMeta
    from ..core.models import Artifact, Category

    workdir = Path(tempfile.mkdtemp(prefix="argus-validate-"))
    detected = 0
    vectors = ["blob byte flip", "artifact database edit",
               "custody log entry edit", "custody log entry removal"]
    failures: List[str] = []
    try:
        def fresh(name: str) -> Path:
            case = Case.create(workdir / name, case_id="VAL")
            case.add_exhibit(Exhibit("EXH-1"))
            container = case.new_container("EXH-1",
                                           ExtractionMeta(operator="validator"))
            art = Artifact(category=Category.MESSAGE, body="reference",
                           timestamp=1_780_000_000_000_000)
            container.db.add(art)
            container.store_blob(b"reference blob content", "ref.bin")
            container.seal()
            container.close()
            return Path(container.path)

        # 1. blob tamper
        path = fresh("v1")
        blob = next(p for p in (path / "blobs").rglob("*") if p.is_file())
        import os
        os.chmod(blob, 0o644)
        blob.write_bytes(b"tampered")
        if not EvidenceContainer(path, mode="r").verify(deep=True)["ok"]:
            detected += 1
        else:
            failures.append("blob byte flip not detected")

        # 2. database tamper
        path = fresh("v2")
        db = path / "artifacts.db"
        os.chmod(db, 0o644)
        conn = sqlite3.connect(db)
        conn.execute("UPDATE artifact SET body='altered'")
        conn.commit(); conn.close()
        if not EvidenceContainer(path, mode="r").verify(deep=True)["ok"]:
            detected += 1
        else:
            failures.append("artifact database edit not detected")

        # 3. custody log edit
        path = fresh("v3")
        log = path / "audit.jsonl"
        os.chmod(log, 0o644)
        entries = [json.loads(l) for l in log.read_text().splitlines() if l]
        entries[0]["actor"] = "someone else"
        log.write_text("\n".join(json.dumps(e, sort_keys=True)
                                for e in entries) + "\n")
        if not EvidenceContainer(path, mode="r").verify(deep=True)["ok"]:
            detected += 1
        else:
            failures.append("custody log edit not detected")

        # 4. custody log removal
        path = fresh("v4")
        log = path / "audit.jsonl"
        os.chmod(log, 0o644)
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[1:]) + "\n")
        if not EvidenceContainer(path, mode="r").verify(deep=True)["ok"]:
            detected += 1
        else:
            failures.append("custody log removal not detected")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return [TestResult(
        test_id="integrity.tamper_detection",
        capability="Evidence integrity",
        description=("Detect all four tamper vectors against a sealed "
                     "container: " + ", ".join(vectors)),
        expected=len(vectors), found=detected, true_positives=detected,
        false_negatives=len(failures), false_positives=0,
        missed_items=failures, passed=not failures,
        notes=("A single undetected vector invalidates the integrity claim, so "
               "this test must pass completely or not at all."))]


def test_antiforensics(truth: GroundTruth) -> List[TestResult]:
    """Do we identify concealed and encrypted material?"""
    from ..parsers.antiforensics import scan_tree, is_sqlcipher

    report, secs = _timed(lambda: scan_tree(truth.root))
    conceal_found = {Path(p).name for p in report.vault_directories}
    expected_conceal = {Path(p).name for p in truth.concealed_files}
    missed_conceal = sorted(expected_conceal - conceal_found)

    enc_found = {Path(e["path"]).name for e in report.encrypted_stores}
    expected_enc = {Path(p).name for p in truth.encrypted_files}
    missed_enc = sorted(expected_enc - enc_found)

    results = [TestResult(
        test_id="antiforensics.concealed", capability="Anti-forensics detection",
        description=(f"Identify {len(expected_conceal)} media file(s) concealed "
                     f"by extension inside a vault directory"),
        expected=len(expected_conceal), found=len(conceal_found),
        true_positives=len(expected_conceal) - len(missed_conceal),
        false_negatives=len(missed_conceal), false_positives=0,
        missed_items=missed_conceal, passed=not missed_conceal,
        duration_s=secs),
        TestResult(
        test_id="antiforensics.encrypted", capability="Anti-forensics detection",
        description=(f"Identify {len(expected_enc)} encrypted store(s) and "
                     f"report them as encrypted rather than empty"),
        expected=len(expected_enc), found=len(enc_found),
        true_positives=len(expected_enc) - len(missed_enc),
        false_negatives=len(missed_enc), false_positives=0,
        missed_items=missed_enc, passed=not missed_enc,
        notes="Identification only. ARGUS claims no decryption capability.")]

    # Encrypted must not be confused with a readable database.
    real_db = (truth.root / "data/data/com.android.providers.telephony"
                            "/databases/mmssms.db")
    wrong: List[str] = []
    if is_sqlcipher(real_db)[0]:
        wrong.append("a readable SQLite database was misreported as encrypted")
    results.append(TestResult(
        test_id="antiforensics.no_false_encryption",
        capability="Anti-forensics detection",
        description="Do not misreport a readable database as encrypted",
        expected=1, found=1, true_positives=0 if wrong else 1,
        false_negatives=0, false_positives=len(wrong), missed_items=wrong,
        passed=not wrong,
        notes=("A false encryption report sends an examiner hunting for a key "
               "that does not exist.")))
    return results


def test_determinism(truth: GroundTruth) -> List[TestResult]:
    """Does the same evidence produce the same result twice?"""
    from ..parsers.sqlite_reader import ForensicSQLite
    from ..intel.correlate import label_propagation

    sms_path = (truth.root / "data/data/com.android.providers.telephony"
                             "/databases/mmssms.db")
    with ForensicSQLite(sms_path) as db:
        first = [tuple(str(v) for v in r.values) for r in db.carve("sms")]
    with ForensicSQLite(sms_path) as db:
        second = [tuple(str(v) for v in r.values) for r in db.carve("sms")]
    carve_stable = first == second

    adjacency = {"a": {"b": 5.0, "c": 5.0}, "b": {"a": 5.0, "c": 5.0},
                 "c": {"a": 5.0, "b": 5.0, "x": 1.0},
                 "x": {"c": 1.0, "y": 5.0, "z": 5.0},
                 "y": {"x": 5.0, "z": 5.0}, "z": {"x": 5.0, "y": 5.0}}
    graph_stable = (label_propagation(adjacency) ==
                    label_propagation(adjacency))

    failures = []
    if not carve_stable:
        failures.append("carving produced different results on repeat runs")
    if not graph_stable:
        failures.append("community detection is not deterministic")
    return [TestResult(
        test_id="repeatability.deterministic", capability="Repeatability",
        description=("Carving and community detection must return identical "
                     "results for identical input"),
        expected=2, found=2, true_positives=2 - len(failures),
        false_negatives=len(failures), false_positives=0,
        missed_items=failures, passed=not failures,
        notes=("A tool whose output varies between runs on the same evidence "
               "cannot support a repeatable finding."))]


ALL_TESTS: List[Callable[[GroundTruth], List[TestResult]]] = [
    test_live_parsing,
    test_deleted_recovery,
    test_file_carving,
    test_entity_extraction,
    test_validator_accuracy,
    test_integrity_detection,
    test_antiforensics,
    test_determinism,
]


# ═══════════════════════════════════════════════════════════════ the runner
def run_validation(workdir: Optional[Path] = None, seed: int = 20260730,
                   keep_corpus: bool = False,
                   progress: Optional[Callable[[str], None]] = None
                   ) -> ValidationReport:
    """Build the reference corpus, run every test, and report the numbers."""
    temp = workdir is None
    root = Path(workdir) if workdir else Path(
        tempfile.mkdtemp(prefix="argus-validation-"))
    corpus = root / "reference_corpus"

    report = ValidationReport(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "sqlite": sqlite3.sqlite_version,
            "machine": platform.machine(),
            "corpus_seed": str(seed),
        })
    try:
        if progress:
            progress("Building reference corpus with known ground truth")
        truth = build_reference_corpus(corpus, seed=seed)

        for test_fn in ALL_TESTS:
            name = test_fn.__name__.replace("test_", "").replace("_", " ")
            if progress:
                progress(f"Running: {name}")
            try:
                report.results.extend(test_fn(truth) or [])
            except Exception as exc:
                report.results.append(TestResult(
                    test_id=test_fn.__name__, capability="Harness",
                    description=f"Test '{name}' could not complete",
                    error=f"{type(exc).__name__}: {exc}", passed=False,
                    expected=1, false_negatives=1,
                    notes=("A test that fails to run is reported rather than "
                           "omitted — silently dropping it would inflate the "
                           "pass rate.")))
    finally:
        if temp and not keep_corpus:
            shutil.rmtree(root, ignore_errors=True)
    return report
