"""Triage and carving of containers nobody documented.

The temptation with a proprietary container is to guess at its structure. That
produces records which look authoritative and are wrong, which is the one
outcome this project treats as unacceptable. So the rule here is narrow: report
what the bytes demonstrably are, recover files that carry their own signatures,
and never claim to have understood the container.

The second rule is subtler and cost a bug during development. Telling an
examiner "carvable" about an encrypted container promises a recovery that cannot
happen — and when the carve returns nothing, that reads as "the device held
nothing" rather than "this route cannot reach it".
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from argus.acquire.opaque import carve_container, triage


def _sqlite_bytes(path: Path, rows: int = 40) -> bytes:
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, "
                "date INTEGER, body TEXT)")
    con.executemany("INSERT INTO sms (address,date,body) VALUES (?,?,?)",
                    [(f"+4477{i:06d}", 1700000000000 + i,
                      f"Message {i} about the berth") for i in range(rows)])
    con.commit()
    con.close()
    return path.read_bytes()


class Identification(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-opaque-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, name: str, payload: bytes) -> Path:
        target = self.dir / name
        target.write_bytes(payload)
        return target

    def test_magic_bytes_beat_the_extension(self) -> None:
        """A vendor extension names the tool that wrote the file.

        The magic bytes say what it actually is, and the two disagree more often
        than expected.
        """
        target = self._write("evidence.xry", b"PK\x03\x04" + b"\x00" * 200)
        self.assertEqual(triage(target).wrapper, "zip")

    def test_xry_container_is_named(self) -> None:
        target = self._write("case.xrycase", b"XRY\x00" + os.urandom(4096))
        report = triage(target)
        self.assertEqual(report.wrapper, "msab.xry")
        self.assertIn("proprietary", report.wrapper_note)

    def test_xry_note_points_at_the_companion_file(self) -> None:
        """A small .xrycase is an index, not the extraction.

        An examiner who does not know that will conclude the extraction is
        empty.
        """
        target = self._write("case.xrycase", b"XRY\x00" + os.urandom(12000))
        self.assertIn("case index", triage(target).wrapper_note)

    def test_directly_readable_formats_are_not_called_containers(self) -> None:
        for name, payload in [
            ("keychain.plist", b'<?xml version="1.0"?><plist></plist>'),
            ("data.bplist", b"bplist00" + os.urandom(500)),
        ]:
            report = triage(self._write(name, payload))
            self.assertIn("parses directly", report.recommendation, name)
            self.assertFalse(report.carvable, name)

    def test_a_single_long_marker_at_offset_zero_counts(self) -> None:
        """Requiring two occurrences discarded a real 1.4 MB XML plist.

        Its single `<?xml` sits at offset zero, and demanding a second one
        reported a perfectly readable file as unrecognisable.
        """
        target = self._write("big.plist",
                             b'<?xml version="1.0"?>' + b"a" * 1_000_000)
        self.assertEqual(triage(target).wrapper, "xml")


class DoesNotPromiseWhatItCannotDeliver(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-entropy-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_encrypted_container_is_not_reported_as_carvable(self) -> None:
        """Random bytes contain 3-byte JPEG markers by chance.

        Counting those as recoverable files promises a recovery that cannot
        happen.
        """
        target = self.dir / "encrypted.xry"
        target.write_bytes(b"XRY\x00" + os.urandom(3_000_000))
        report = triage(target)
        self.assertGreater(report.entropy, 7.5)
        self.assertFalse(report.carvable)
        self.assertIn("chance byte sequences", report.recommendation)

    def test_the_verdict_says_absence_is_not_proof_of_absence(self) -> None:
        target = self.dir / "encrypted.xry"
        target.write_bytes(b"XRY\x00" + os.urandom(2_000_000))
        self.assertIn("not that the device held none",
                      triage(target).recommendation)

    def test_every_triage_carries_the_scope_caveat(self) -> None:
        target = self.dir / "thing.xry"
        target.write_bytes(b"XRY\x00" + os.urandom(50_000))
        caveat = triage(target).caveat
        self.assertIn("does not decode the container", caveat)
        self.assertIn("not evidence", caveat)


class Recovery(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-carve-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_files_are_carved_out_of_an_opaque_wrapper(self) -> None:
        inner = _sqlite_bytes(self.dir / "inner.db")
        jpeg = (b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00"
                + os.urandom(3000) + b"\xff\xd9")
        container = self.dir / "opaque.xry"
        container.write_bytes(b"XRY\x00VENDOR" + os.urandom(512) + inner
                              + os.urandom(2048) + jpeg)

        out = self.dir / "carved"
        result = carve_container(container, out)
        self.assertEqual(result["mode"], "carve")
        self.assertGreaterEqual(result["files"], 2)
        kinds = {c["type"] for c in result["carved"]}
        self.assertTrue(any("SQLite" in k for k in kinds), kinds)

    def test_carved_names_record_the_source_offset(self) -> None:
        """The recovery has to be repeatable and checkable."""
        inner = _sqlite_bytes(self.dir / "inner.db")
        container = self.dir / "opaque.xry"
        container.write_bytes(b"XRY\x00" + os.urandom(300) + inner)
        result = carve_container(container, self.dir / "carved")
        for entry in result["carved"]:
            self.assertIn(str(entry["offset"]).zfill(12), entry["file"])

    def test_a_zip_in_disguise_uses_its_real_member_names(self) -> None:
        """Member names are the archive's own, not inferred from offsets."""
        container = self.dir / "export.xry"
        with zipfile.ZipFile(container, "w") as archive:
            archive.writestr("data/data/com.app/databases/msgstore.db", "x" * 40)
            archive.writestr("info.xml", "<x/>")
        result = carve_container(container, self.dir / "out")
        self.assertEqual(result["mode"], "zip")
        self.assertEqual(result["files"], 2)
        self.assertTrue((self.dir / "out" / "info.xml").exists())

    def test_archive_traversal_is_refused(self) -> None:
        """A hostile or merely sloppy archive must not escape the staging dir."""
        container = self.dir / "evil.xry"
        with zipfile.ZipFile(container, "w") as archive:
            archive.writestr("../../escaped.txt", "no")
            archive.writestr("fine.txt", "yes")
        out = self.dir / "out"
        carve_container(container, out)
        self.assertFalse((self.dir / "escaped.txt").exists())
        self.assertFalse((self.dir.parent / "escaped.txt").exists())

    def test_carving_reports_the_scan_it_performed(self) -> None:
        container = self.dir / "opaque.xry"
        container.write_bytes(b"XRY\x00" + os.urandom(80_000))
        result = carve_container(container, self.dir / "out")
        self.assertIn("scan", result)
        self.assertIn("bytes_scanned", result["scan"])

    def test_the_note_disclaims_decoding_the_container(self) -> None:
        container = self.dir / "opaque.xry"
        container.write_bytes(b"XRY\x00" + os.urandom(40_000))
        note = carve_container(container, self.dir / "out")["note"]
        self.assertIn("was not interpreted", note)


class EmptyAndBroken(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-edge-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_empty_file(self) -> None:
        target = self.dir / "empty.xry"
        target.write_bytes(b"")
        self.assertIn("empty", triage(target).recommendation.lower())

    def test_missing_file_does_not_raise(self) -> None:
        report = triage(self.dir / "absent.xry")
        self.assertIn("Cannot read", report.recommendation)

    def test_tiny_file(self) -> None:
        target = self.dir / "tiny.xry"
        target.write_bytes(b"XR")
        self.assertIsNotNone(triage(target).recommendation)


if __name__ == "__main__":
    unittest.main()


class GeneratorIsRerunnable(unittest.TestCase):
    """Regenerating into an existing folder must just work.

    The second run used to open the first run's databases and fail on
    "table calls already exists". The traceback pointed at a CREATE TABLE, which
    reads like a broken generator rather than "this folder already holds a
    device" — and the obvious response is to run the identical command again.
    """

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-regen-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _build(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "samples"))
        import make_device
        return make_device.build_android(self.dir / "android")

    def test_second_run_into_the_same_folder_succeeds(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(first, second,
                         "regenerating produced different planted evidence")

    def test_planted_counts_are_stable_across_runs(self) -> None:
        counts = [self._build() for _ in range(3)]
        self.assertEqual(counts[0], counts[1])
        self.assertEqual(counts[1], counts[2])
        self.assertGreater(counts[0].get("deleted_sms", 0), 0,
                           "the fixture must still plant deleted records")
