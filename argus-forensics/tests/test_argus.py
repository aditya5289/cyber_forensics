"""ARGUS test suite.

Run with::

    python -m pytest tests/ -v          # if pytest is available
    python tests/test_argus.py          # standalone, no dependencies

The suite is deliberately weighted toward the two properties that matter most
in a forensic tool and that are easiest to get quietly wrong:

* **Integrity detection** — tampering with a blob, the artifact database or
  the custody log must be caught. A tool that silently accepts altered
  evidence is worse than no tool.
* **Deleted-record recovery** — the carver must recover records that were
  genuinely deleted, and must *not* invent records that never existed.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "samples"))

from argus.analyze.graph import ConnectionGraph
from argus.analyze.search import compile_query
from argus.analyze.session import AnalysisSession
from argus.core.audit import AuditLog
from argus.core.case import Case, Exhibit
from argus.core.container import EvidenceContainer, ExtractionMeta
from argus.core.errors import CaseError, DeviceNotSupportedError, QueryError
from argus.core.hashing import hash_bytes, merkle_root
from argus.core.models import Artifact, Category, Direction, Recovery
from argus.devices.manual import DeviceManual
from argus.parsers import timestamps as ts
from argus.parsers.sqlite_reader import (ForensicSQLite, read_varint,
                                         serial_type_size)


# ===========================================================================
class TestVarintAndSerialTypes(unittest.TestCase):
    """SQLite record primitives. Everything else depends on these."""

    def test_single_byte_varint(self):
        self.assertEqual(read_varint(b"\x01", 0), (1, 1))
        self.assertEqual(read_varint(b"\x7f", 0), (127, 1))

    def test_multi_byte_varint(self):
        self.assertEqual(read_varint(b"\x81\x00", 0), (128, 2))
        self.assertEqual(read_varint(b"\x82\x2c", 0), (300, 2))

    def test_nine_byte_varint(self):
        data = b"\xff" * 8 + b"\xff"
        value, consumed = read_varint(data, 0)
        self.assertEqual(consumed, 9)
        self.assertGreater(value, 1 << 55)

    def test_varint_past_end_raises(self):
        with self.assertRaises(IndexError):
            read_varint(b"\x81", 0)

    def test_serial_type_sizes(self):
        cases = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0,
                 12: 0, 14: 1, 13: 0, 15: 1, 25: 6}
        for stype, expected in cases.items():
            self.assertEqual(serial_type_size(stype), expected,
                             f"serial type {stype}")


# ===========================================================================
class TestTimestamps(unittest.TestCase):
    """Epoch handling — the single most common source of silent wrong answers."""

    def test_unix_seconds(self):
        self.assertEqual(ts.from_epoch(1_700_000_000, "unix_s"),
                         1_700_000_000_000_000)

    def test_apple_absolute(self):
        # 2001-01-01T00:00:00Z in Apple time is 0; in Unix time 978307200.
        self.assertEqual(ts.from_epoch(760_000_000, "apple"),
                         (760_000_000 + 978_307_200) * 1_000_000)

    def test_webkit(self):
        webkit = (1_700_000_000 + 11_644_473_600) * 1_000_000
        self.assertEqual(ts.from_epoch(webkit, "webkit"), 1_700_000_000_000_000)

    def test_implausible_rejected(self):
        # A raw Unix-seconds value read as microseconds lands in 1970 and must
        # be refused rather than silently producing a 1970 timeline entry.
        self.assertIsNone(ts.from_epoch(1_700_000_000, "unix_us"))
        self.assertIsNone(ts.from_epoch(0, "unix_s"))
        self.assertIsNone(ts.from_epoch(-5, "unix_s"))

    def test_guess_discriminates_magnitudes(self):
        secs = ts.guess(1_700_000_000)
        millis = ts.guess(1_700_000_000_000)
        self.assertEqual(secs, millis)

    def test_guess_apple_hint(self):
        got = ts.guess(760_000_000, hint="ZDATE")
        self.assertEqual(got, (760_000_000 + 978_307_200) * 1_000_000)

    def test_iso_round_trip(self):
        us = ts.from_iso("2026-03-15T10:30:00Z")
        self.assertTrue(ts.to_iso(us).startswith("2026-03-15T10:30:00"))

    def test_span_presets(self):
        lo, hi = ts.span_to_range("7d")
        self.assertIsNotNone(lo)
        self.assertAlmostEqual((hi - lo) / 1_000_000, 7 * 86400, delta=2)
        self.assertEqual(ts.span_to_range("all"), (None, None))

    def test_span_custom_range(self):
        lo, hi = ts.span_to_range("2026-01-01..2026-01-31")
        self.assertLess(lo, hi)

    def test_span_invalid_raises(self):
        with self.assertRaises(ValueError):
            ts.span_to_range("last tuesday")


# ===========================================================================
class TestHashingAndAudit(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_digest_stable(self):
        a, b = hash_bytes(b"evidence"), hash_bytes(b"evidence")
        self.assertTrue(a.matches(b))
        self.assertFalse(a.matches(hash_bytes(b"evidencf")))

    def test_merkle_root_order_independent(self):
        h = [hash_bytes(bytes([i])).sha256 for i in range(5)]
        self.assertEqual(merkle_root(h), merkle_root(list(reversed(h))))

    def test_merkle_root_changes_on_edit(self):
        h = [hash_bytes(bytes([i])).sha256 for i in range(5)]
        altered = h[:-1] + [hash_bytes(b"different").sha256]
        self.assertNotEqual(merkle_root(h), merkle_root(altered))

    def test_audit_chain_valid(self):
        log = AuditLog(self.tmp / "audit.jsonl", actor="tester")
        for i in range(6):
            log.record("test.action", {"i": i})
        ok, problems = log.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(len(log), 6)

    def test_audit_detects_edited_entry(self):
        path = self.tmp / "audit.jsonl"
        log = AuditLog(path, actor="tester")
        log.record("a", {"v": 1})
        log.record("b", {"v": 2})
        entries = [json.loads(l) for l in path.read_text().splitlines() if l]
        entries[0]["detail"]["v"] = 99
        path.write_text("\n".join(json.dumps(e, sort_keys=True)
                                  for e in entries) + "\n")
        ok, problems = AuditLog(path).verify()
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p for p in problems), problems)

    def test_audit_detects_removed_entry(self):
        path = self.tmp / "audit.jsonl"
        log = AuditLog(path, actor="tester")
        for i in range(4):
            log.record("x", {"i": i})
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        ok, problems = AuditLog(path).verify()
        self.assertFalse(ok)
        self.assertTrue(any("chain" in p or "gap" in p for p in problems),
                        problems)


# ===========================================================================
class TestDeviceManual(unittest.TestCase):

    def setUp(self):
        self.manual = DeviceManual()

    def test_search_finds_reference_device(self):
        hits = self.manual.search("iPhone 12 mini")
        self.assertTrue(hits)
        self.assertEqual(hits[0].name, "Apple iPhone 12 mini")

    def test_search_by_internal_identifier(self):
        hits = self.manual.search("iPhone13,1")
        self.assertTrue(hits)
        self.assertIn("iPhone 12 mini", hits[0].name)

    def test_bfu_yields_less_than_unlocked(self):
        profile = self.manual.get("iPhone 12 mini")
        unlocked = {c.method for c in profile.methods_for("unlocked")}
        bfu = {c.method for c in profile.methods_for("bfu")}
        self.assertTrue(bfu < unlocked,
                        "BFU must not offer more than unlocked")
        self.assertNotIn("filesystem", bfu)

    def test_unsupported_combination_refused(self):
        with self.assertRaises(DeviceNotSupportedError):
            self.manual.assert_supported("iPhone 12 mini", "bfu", "filesystem")

    def test_unknown_device_refused(self):
        with self.assertRaises(DeviceNotSupportedError):
            self.manual.get("Nonexistent Phone 9000")

    def test_supported_combination_allowed(self):
        cap = self.manual.assert_supported("Galaxy S21 5G", "unlocked",
                                           "filesystem")
        self.assertEqual(cap.method, "filesystem")


# ===========================================================================
class TestCarver(unittest.TestCase):
    """The deleted-record recovery engine."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = self.tmp / "test.db"
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA secure_delete=OFF")
        conn.execute("""CREATE TABLE sms (_id INTEGER PRIMARY KEY,
            address TEXT, date INTEGER, body TEXT, type INTEGER)""")
        self.kept = []
        self.removed = []
        for i in range(400):
            body = f"Message {i} concerning the shipment and the meeting point"
            conn.execute("INSERT INTO sms(address,date,body,type) "
                         "VALUES (?,?,?,?)",
                         (f"+91987654{i:04d}", 1_700_000_000_000 + i * 60_000,
                          body, 1 + i % 2))
            (self.removed if 100 <= i < 260 else self.kept).append(body)
        conn.commit()
        conn.execute("DELETE FROM sms WHERE _id BETWEEN 101 AND 260")
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reads_live_rows(self):
        with ForensicSQLite(self.db_path) as db:
            live = list(db.rows("sms"))
        self.assertEqual(len(live), 240)

    def test_recovers_deleted_records(self):
        with ForensicSQLite(self.db_path) as db:
            carved = db.carve("sms")
        self.assertGreater(len(carved), 0,
                           "carver recovered nothing from deleted space")
        bodies = {v for rec in carved for v in rec.values
                  if isinstance(v, str) and v.startswith("Message ")}
        self.assertTrue(bodies & set(self.removed),
                        "no recovered record matches a deleted message")

    def test_does_not_invent_records(self):
        """Every carved value must be a string that really existed."""
        with ForensicSQLite(self.db_path) as db:
            carved = db.carve("sms")
        real = set(self.kept) | set(self.removed)
        for rec in carved:
            for v in rec.values:
                if isinstance(v, str) and v.startswith("Message "):
                    self.assertIn(v, real,
                                  f"carver fabricated a record body: {v!r}")

    def test_carved_rows_substitute_rowid_alias(self):
        with ForensicSQLite(self.db_path) as db:
            rows = list(db.carved_rows("sms"))
        self.assertTrue(rows)
        with_id = [r for r, _ in rows if r.get("_id") is not None]
        self.assertTrue(with_id or all(r.get("_rowid") is None
                                       for r, _ in rows))

    def test_clean_database_yields_nothing(self):
        clean = self.tmp / "clean.db"
        conn = sqlite3.connect(clean)
        conn.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, "
                     "address TEXT, date INTEGER, body TEXT, type INTEGER)")
        for i in range(50):
            conn.execute("INSERT INTO sms(address,date,body,type) "
                         "VALUES ('+1',1700000000000,?,1)", (f"live {i}",))
        conn.commit(); conn.close()
        with ForensicSQLite(clean) as db:
            carved = db.carve("sms")
        self.assertEqual(len(carved), 0,
                         "carver produced records from a database with no "
                         "deletions — these would be false positives")

    def test_rejects_non_sqlite(self):
        bogus = self.tmp / "not.db"
        bogus.write_bytes(b"this is not a database" * 20)
        from argus.core.errors import ParserError
        with self.assertRaises(ParserError):
            ForensicSQLite(bogus)

    def test_source_file_unmodified(self):
        before = self.db_path.read_bytes()
        with ForensicSQLite(self.db_path) as db:
            list(db.rows("sms"))
            db.carve("sms")
            db.integrity()
        self.assertEqual(before, self.db_path.read_bytes(),
                         "reading the database modified the source evidence")


# ===========================================================================
class TestQueryLanguage(unittest.TestCase):

    def test_bare_term(self):
        q = compile_query("meeting")
        self.assertIn("artifact_fts", q.where)
        self.assertEqual(q.params, ["meeting"])

    def test_category_field(self):
        q = compile_query("category:Messages")
        self.assertEqual(q.where, "category = ?")
        self.assertEqual(q.params, ["Messages"])

    def test_boolean_and(self):
        q = compile_query("category:Calls AND app:WhatsApp")
        self.assertIn("AND", q.where)
        self.assertEqual(len(q.params), 2)

    def test_implicit_and(self):
        explicit = compile_query("category:Calls AND app:WhatsApp")
        implicit = compile_query("category:Calls app:WhatsApp")
        self.assertEqual(explicit.where, implicit.where)

    def test_or_and_parentheses(self):
        q = compile_query("(category:Calls OR category:Messages) AND deleted:true")
        self.assertIn("OR", q.where)
        self.assertIn("AND", q.where)

    def test_negation(self):
        q = compile_query("NOT app:Instagram")
        self.assertTrue(q.where.startswith("NOT"))

    def test_deleted_filter(self):
        self.assertEqual(compile_query("deleted:true").where, "recovery <> ?")
        self.assertEqual(compile_query("deleted:false").where, "recovery = ?")

    def test_date_filters(self):
        q = compile_query("after:2026-01-01")
        self.assertEqual(q.where, "timestamp >= ?")
        self.assertIsInstance(q.params[0], int)

    def test_has_gps(self):
        self.assertIn("latitude", compile_query("has:gps").where)

    def test_phrase_is_parameterised_not_interpolated(self):
        """A quote in a search term must never reach SQL as syntax."""
        q = compile_query("\"O'Brien'; DROP TABLE artifact;--\"")
        self.assertNotIn("DROP TABLE", q.where)
        self.assertTrue(any("DROP TABLE" in str(p) for p in q.params))

    def test_unknown_field_raises(self):
        with self.assertRaises(QueryError):
            compile_query("nonsense:value")

    def test_unbalanced_parenthesis_raises(self):
        with self.assertRaises(QueryError):
            compile_query("(category:Calls")

    def test_empty_query_matches_all(self):
        self.assertEqual(compile_query("").where, "1=1")


# ===========================================================================
class TestConnectionGraph(unittest.TestCase):

    @staticmethod
    def _message(sender: str, receiver: str, from_me: bool, ts_us: int):
        art = Artifact(category=Category.MESSAGE, timestamp=ts_us,
                       direction=(Direction.OUTGOING if from_me
                                  else Direction.INCOMING), app="TestApp")
        if from_me:
            art.add_participant("", "Owner", role="from", is_owner=True)
            art.add_participant(receiver, "", role="to")
        else:
            art.add_participant(sender, "", role="from")
            art.add_participant("", "Owner", role="to", is_owner=True)
        return art

    def test_identity_normalisation(self):
        """The same person written three ways must be one node."""
        arts = [
            self._message("", "+91 98765 43210", True, 1_700_000_000_000_000),
            self._message("09876543210", "", False, 1_700_000_100_000_000),
            self._message("919876543210@s.whatsapp.net", "", False,
                          1_700_000_200_000_000),
        ]
        g = ConnectionGraph().add(arts).finalise()
        non_owner = [n for n in g.nodes.values() if not n.is_owner]
        self.assertEqual(len(non_owner), 1,
                         f"identity resolution split one party into "
                         f"{len(non_owner)} nodes")
        self.assertEqual(non_owner[0].artifact_count, 3)

    def test_does_not_over_merge(self):
        arts = [
            self._message("", "+919876543210", True, 1_700_000_000_000_000),
            self._message("", "+919876543211", True, 1_700_000_100_000_000),
        ]
        g = ConnectionGraph().add(arts).finalise()
        self.assertEqual(len([n for n in g.nodes.values() if not n.is_owner]), 2)

    def test_edge_weights_and_reciprocity(self):
        arts = [self._message("", "+919876543210", True, 1_700_000_000_000_000 + i)
                for i in range(5)]
        arts += [self._message("+919876543210", "", False,
                               1_700_000_500_000_000 + i) for i in range(3)]
        g = ConnectionGraph().add(arts).finalise()
        edge = next(iter(g.edges.values()))
        self.assertEqual(edge.artifact_count, 8)
        self.assertGreater(edge.reciprocity, 0)

    def test_one_way_contact_detected(self):
        arts = [self._message("+919555000111", "", False,
                              1_700_000_000_000_000 + i * 1000)
                for i in range(6)]
        g = ConnectionGraph().add(arts).finalise()
        self.assertTrue(g.one_way_contacts(min_artifacts=3))

    def test_contact_names_applied(self):
        contact = Artifact(category=Category.CONTACT, body="Priya Nair",
                           attributes={"display_name": "Priya Nair"})
        contact.add_participant("+919876543210", "Priya Nair")
        g = ConnectionGraph()
        g.learn_contacts([contact])
        g.add([self._message("", "+919876543210", True, 1_700_000_000_000_000)])
        g.finalise()
        labels = {n.label for n in g.nodes.values() if not n.is_owner}
        self.assertIn("Priya Nair", labels)

    def test_graphml_exports(self):
        g = ConnectionGraph().add(
            [self._message("", "+919876543210", True, 1_700_000_000_000_000)]
        ).finalise()
        xml = g.to_graphml()
        self.assertIn("<graphml", xml)
        self.assertIn("</graphml>", xml)


# ===========================================================================
class TestCaseAndContainer(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sealed_container(self):
        case = Case.create(self.tmp, case_id="CASE-T1", investigator="Tester")
        case.add_exhibit(Exhibit("EXH-1", make="Apple", model="iPhone 12 mini"))
        container = case.new_container(
            "EXH-1", ExtractionMeta(operator="Tester", method="import"))
        art = Artifact(category=Category.MESSAGE, body="hello",
                       timestamp=1_700_000_000_000_000)
        art.add_participant("+919876543210", "Priya")
        container.db.add(art)
        container.store_blob(b"pretend photo bytes", "photo.jpg")
        container.seal()
        container.close()
        return case, Path(container.path)

    def test_duplicate_case_refused(self):
        Case.create(self.tmp, case_id="DUP")
        with self.assertRaises(CaseError):
            Case.create(self.tmp, case_id="DUP")

    def test_password_protection(self):
        Case.create(self.tmp, case_id="LOCKED", password="hunter2")
        with self.assertRaises(CaseError):
            Case.open(self.tmp / "LOCKED")
        with self.assertRaises(CaseError):
            Case.open(self.tmp / "LOCKED", password="wrong")
        case = Case.open(self.tmp / "LOCKED", password="hunter2")
        self.assertEqual(case.case_id, "LOCKED")

    def test_password_not_stored(self):
        Case.create(self.tmp, case_id="SECRET", password="hunter2")
        raw = (self.tmp / "SECRET" / "case.json").read_text()
        self.assertNotIn("hunter2", raw)

    def test_exhibit_must_exist_before_extraction(self):
        case = Case.create(self.tmp, case_id="NOEX")
        with self.assertRaises(CaseError):
            case.new_container("MISSING", ExtractionMeta(operator="t"))

    def test_sealed_container_verifies(self):
        _, path = self._sealed_container()
        container = EvidenceContainer(path, mode="r")
        result = container.verify(deep=True)
        container.close()
        self.assertTrue(result["ok"], result["problems"])

    def test_container_export_zip(self):
        _, path = self._sealed_container()
        dest = self.tmp / "portable.zip"
        with EvidenceContainer(path, mode="r") as container:
            out = container.export_zip(dest)
        self.assertEqual(out, dest)
        self.assertTrue(dest.is_file())
        self.assertGreater(dest.stat().st_size, 0)

    def test_zip_roundtrip_resolve_and_analyze(self):
        from argus.core.container import (
            resolve_container_path, is_argus_container_archive,
        )
        _, path = self._sealed_container()
        zip_path = self.tmp / "portable.afc.zip"
        with EvidenceContainer(path, mode="r") as container:
            container.export_zip(zip_path)
        self.assertTrue(is_argus_container_archive(zip_path))
        cache = self.tmp / "cache"
        resolved = resolve_container_path(zip_path, cache_root=cache)
        self.assertTrue((resolved / "manifest.json").is_file())
        with EvidenceContainer(resolved, mode="r") as container:
            result = container.verify(deep=False)
        self.assertTrue(result["ok"], result.get("problems"))

    def test_tampered_blob_detected(self):
        _, path = self._sealed_container()
        blob = next(p for p in (path / "blobs").rglob("*") if p.is_file())
        os.chmod(blob, 0o644)
        blob.write_bytes(b"tampered content")
        container = EvidenceContainer(path, mode="r")
        result = container.verify(deep=True)
        container.close()
        self.assertFalse(result["ok"])
        self.assertTrue(any("blob" in p for p in result["problems"]))

    def test_tampered_database_detected(self):
        _, path = self._sealed_container()
        db = path / "artifacts.db"
        os.chmod(db, 0o644)
        conn = sqlite3.connect(db)
        conn.execute("UPDATE artifact SET body='altered'")
        conn.commit(); conn.close()
        container = EvidenceContainer(path, mode="r")
        result = container.verify(deep=True)
        container.close()
        self.assertFalse(result["ok"])
        self.assertTrue(any("artifacts.db" in p for p in result["problems"]))

    def test_sealed_container_rejects_writes(self):
        from argus.core.errors import WriteBlockViolation
        _, path = self._sealed_container()
        container = EvidenceContainer(path, mode="r")
        with self.assertRaises(WriteBlockViolation):
            container.store_blob(b"new data", "x.bin")
        container.close()

    def test_blob_deduplication(self):
        case = Case.create(self.tmp, case_id="DEDUP")
        case.add_exhibit(Exhibit("E1"))
        c = case.new_container("E1", ExtractionMeta(operator="t"))
        d1 = c.store_blob(b"identical", "a.jpg")
        d2 = c.store_blob(b"identical", "b.jpg")
        self.assertEqual(d1.sha256, d2.sha256)
        self.assertEqual(len(list(c.iter_blobs())), 1)
        c.close()


# ===========================================================================
class TestEndToEnd(unittest.TestCase):
    """Full pipeline against a generated device tree."""

    @classmethod
    def setUpClass(cls):
        import make_device
        cls.tmp = Path(tempfile.mkdtemp())
        cls.evidence = cls.tmp / "evidence"
        make_device.build_android(cls.evidence)

        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        case = Case.create(cls.tmp / "cases", case_id="E2E",
                           investigator="Tester")
        case.add_exhibit(Exhibit("EXH-1", make="Samsung",
                                 model="Galaxy S21 5G"))
        plan = AcquisitionPlan(method="import", source_path=cls.evidence,
                               operator="Tester", exhibit_id="EXH-1",
                               device_name="Samsung Galaxy S21 5G")
        cls.report = AcquisitionEngine(case).run(plan)
        cls.container = Path(cls.report.container)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_extraction_completed(self):
        self.assertTrue(self.report.status.startswith("Completed"),
                        self.report.warnings)

    def test_artifacts_decoded(self):
        self.assertGreater(self.report.artifacts, 300)

    def test_deleted_records_recovered(self):
        self.assertGreater(self.report.deleted_recovered, 0,
                           "no deleted records recovered from a tree that "
                           "contains deletions")

    def test_expected_categories_present(self):
        for category in ("Messages", "Calls", "Contacts", "Files & Media",
                         "Web"):
            self.assertIn(category, self.report.categories, category)

    def test_container_sealed_and_verified(self):
        self.assertTrue(self.report.seal.get("container_seal"))
        with AnalysisSession([self.container]) as s:
            self.assertTrue(s.integrity_ok, s.integrity_report())

    def test_planted_deleted_message_recovered(self):
        """A specific message that was deleted must come back."""
        import make_device
        with AnalysisSession([self.container]) as s:
            result = s.query("deleted:true", limit=500)
        bodies = " ".join(a["body"] for a in result["artifacts"])
        hits = [m for m in make_device.DELETED_MESSAGES if m in bodies]
        self.assertTrue(hits,
                        "none of the planted deleted messages were recovered")

    def test_disguised_file_identified_by_content(self):
        with AnalysisSession([self.container]) as s:
            result = s.query('category:"Files & Media"', limit=100)
        mismatched = [a for a in result["artifacts"]
                      if a.get("attributes", {}).get("extension_mismatch")]
        self.assertTrue(mismatched,
                        "the JPEG renamed .txt was not detected")

    def test_gps_extracted_from_exif(self):
        with AnalysisSession([self.container]) as s:
            places = s.places()
        self.assertGreater(places["count"], 0, "no EXIF GPS recovered")

    def test_connection_graph_built(self):
        with AnalysisSession([self.container]) as s:
            graph = s.connections("all")
        self.assertGreater(graph["stats"]["total_nodes"], 1)
        self.assertTrue(graph["top_contacts"])

    def test_timeline_ordered(self):
        with AnalysisSession([self.container]) as s:
            entries = s.timeline()["entries"]
        stamps = [e["timestamp"] for e in entries]
        self.assertEqual(stamps, sorted(stamps), "timeline is not ordered")

    def test_reports_generate(self):
        from argus.report.builder import ReportBuilder, ReportOptions
        out = self.tmp / "reports"
        with AnalysisSession([self.container]) as s:
            opts = ReportOptions(formats=["html", "xml", "json", "csv"],
                                 examiner="Tester")
            written = ReportBuilder(s, opts).write(out)
        self.assertEqual(len(written), 4)
        for path in written:
            self.assertGreater(path.stat().st_size, 500, path.name)

    def test_html_report_flags_integrity(self):
        from argus.report.builder import ReportBuilder, ReportOptions
        with AnalysisSession([self.container]) as s:
            html = ReportBuilder(s, ReportOptions())._html_document()
        self.assertIn("INTEGRITY VERIFIED", html)

    def test_source_evidence_untouched(self):
        """Acquisition must not modify the source tree."""
        digests = {}
        for p in sorted(self.evidence.rglob("*")):
            if p.is_file():
                digests[p] = hash_bytes(p.read_bytes()).sha256
        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        case = Case.open(self.tmp / "cases" / "E2E")
        plan = AcquisitionPlan(method="import", source_path=self.evidence,
                               operator="Tester", exhibit_id="EXH-1")
        AcquisitionEngine(case).run(plan)
        for p, before in digests.items():
            self.assertEqual(hash_bytes(p.read_bytes()).sha256, before,
                             f"acquisition modified source evidence: {p}")


# ===========================================================================
class TestWorkbenchApp(unittest.TestCase):
    """The one-click application, driven exactly as the browser drives it.

    These run against a real HTTP server on a loopback port, so they cover the
    routing, the auth gate and the JSON contract the UI depends on — not just
    the Python functions underneath.
    """

    PORT = 8791

    @classmethod
    def setUpClass(cls):
        import json as _json
        import threading
        import time
        import urllib.error
        import urllib.parse
        import urllib.request

        import make_device
        from argus.server import workbench as W

        cls.urllib = urllib
        cls.json = _json
        cls.tmp = Path(tempfile.mkdtemp())
        cls.evidence = cls.tmp / "evidence"
        make_device.build_android(cls.evidence)

        cls.token = "unit-test-token"
        W.secrets.token_urlsafe = lambda n=24: cls.token
        threading.Thread(target=W.serve, kwargs=dict(
            workspace=cls.tmp / "workspace", port=cls.PORT,
            open_browser=False, quiet=True), daemon=True).start()

        cls.base = f"http://127.0.0.1:{cls.PORT}"
        for _ in range(60):                     # wait for the port to answer
            try:
                urllib.request.urlopen(f"{cls.base}/api/ping", timeout=2).read()
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("workbench server did not start")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------- helpers
    def get(self, endpoint, **params):
        # 'endpoint' rather than 'path' so a ?path= query parameter can be
        # passed through without colliding with the positional argument.
        params["token"] = self.token
        url = f"{self.base}/api/{endpoint}?" + self.urllib.parse.urlencode(params)
        with self.urllib.request.urlopen(url, timeout=90) as r:
            return json.loads(r.read())

    def post(self, endpoint, body):
        req = self.urllib.request.Request(
            f"{self.base}/api/{endpoint}",
            data=json.dumps({**body, "token": self.token}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with self.urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())

    def wait_for_job(self, job_id, timeout=180):
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            snap = self.get("job", id=job_id, since=0)
            if snap["status"] in ("done", "failed", "cancelled"):
                return snap
            time.sleep(0.25)
        self.fail(f"job {job_id} did not finish within {timeout}s")

    # --------------------------------------------------------------- tests
    def test_01_ui_assets_served(self):
        for path in ("/", "/xamn.html", "/analyst.html"):
            with self.urllib.request.urlopen(self.base + path, timeout=30) as r:
                body = r.read()
            self.assertEqual(r.status, 200, path)
            self.assertGreater(len(body), 10_000, path)

    def test_02_token_required(self):
        with self.assertRaises(self.urllib.error.HTTPError) as ctx:
            self.urllib.request.urlopen(f"{self.base}/api/env", timeout=15)
        self.assertEqual(ctx.exception.code, 401)

    def test_03_bad_token_rejected(self):
        url = f"{self.base}/api/env?token=not-the-real-token"
        with self.assertRaises(self.urllib.error.HTTPError) as ctx:
            self.urllib.request.urlopen(url, timeout=15)
        self.assertEqual(ctx.exception.code, 401)

    def test_04_environment_report(self):
        env = self.get("env")
        self.assertEqual(len(env["categories"]), 16)
        self.assertIn("pdf", env["capabilities"])
        self.assertIn("adb", env["toolchain"])
        self.assertIn("selfcheck", env)
        self.assertIn("ok", env["selfcheck"])

    def test_04b_case_activity_and_preview(self):
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-ACT", "investigator": "Tester"})
        case_path = created["path"]
        self.post("exhibit/add", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "make": "Samsung", "model": "Galaxy S21 5G"})
        activity = self.get("case/activity", path=case_path, limit=5)
        self.assertGreaterEqual(activity["count"], 2)
        self.assertTrue(any(a["action"] in ("exhibit.register", "exhibit.add")
                            for a in activity["activity"]))
        preview = self.post("acquire/preview", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "operator": "Tester", "method": "import",
            "source_path": str(self.evidence),
            "device_name": "Samsung Galaxy S21 5G"})
        self.assertTrue(preview["ok"], preview.get("errors"))
        bad = self.post("acquire/preview", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "operator": "", "method": "import",
            "source_path": str(self.evidence)})
        self.assertFalse(bad["ok"])
        self.assertTrue(bad["errors"])

    def test_04c_failed_job_includes_traceback(self):
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-TB", "investigator": "Tester"})
        case_path = created["path"]
        self.post("exhibit/add", {"case_path": case_path, "exhibit_id": "EXH-001"})
        with self.assertRaises(self.urllib.error.HTTPError):
            self.post("acquire", {
                "case_path": case_path, "exhibit_id": "EXH-001",
                "operator": "Tester", "method": "filesystem",
                "device_name": "iPhone 12 mini", "lock_state": "bfu",
                "serial": "missing-device"})
        # Preview should fail fast without spawning a job
        preview = self.post("acquire/preview", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "operator": "Tester", "method": "filesystem",
            "device_name": "iPhone 12 mini", "lock_state": "bfu"})
        self.assertFalse(preview["ok"])

    def test_04d_mtp_preview_uncatalogued_device(self):
        from unittest import mock

        from argus.devices.detect import DetectedDevice

        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-MTP", "investigator": "Tester"})
        case_path = created["path"]
        self.post("exhibit/add", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "make": "OnePlus", "model": "Nord"})
        fake = DetectedDevice(
            transport="mtp",
            serial="::usb#vid_2d95&pid_6002",
            model="OnePlus Nord",
            marketing_name="OnePlus Nord",
            os_family="Android",
            lock_state="unlocked",
            raw={"mtp_path": "::usb#vid_2d95&pid_6002", "mtp_name": "OnePlus Nord",
                 "ready": True},
        )
        with mock.patch("argus.devices.detect.resolve_device", return_value=fake):
            preview = self.post("acquire/preview", {
                "case_path": case_path, "exhibit_id": "EXH-001",
                "operator": "Tester", "method": "mtp",
                "device_name": "ZZZ Uncatalogued MTP Handset 9999",
                "serial": fake.serial, "transport": "mtp",
                "mtp_name": "OnePlus Nord",
            })
        self.assertTrue(preview["ok"], preview.get("errors"))
        self.assertTrue(
            any("not in the device manual" in w.lower()
                for w in preview.get("warnings", [])),
            preview.get("warnings"))

    def test_05_browse_and_classify(self):
        listing = self.get("browse", path=str(self.evidence))
        self.assertTrue(listing["dirs"])
        info = self.get("classify", path=str(self.evidence))
        self.assertEqual(info["kind"], "android-tree")

    def test_06_classify_missing_path(self):
        info = self.get("classify", path=str(self.tmp / "nope"))
        self.assertFalse(info["ok"])

    def test_07_device_manual(self):
        found = self.get("manual/search", q="Galaxy S21")
        self.assertTrue(found["results"])
        matrix = self.get("manual/show", q="iPhone 12 mini")
        bfu = next(r for r in matrix["capability_overview"]
                   if r["lock_state"] == "bfu")
        self.assertEqual({m["method"] for m in bfu["methods"]},
                         {"sim", "screenshot"})

    def test_08_full_workflow(self):
        """Case → exhibit → extraction → analysis → report, over HTTP."""
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-TEST", "investigator": "Tester"})
        self.assertTrue(created["ok"])
        case_path = created["path"]

        added = self.post("exhibit/add", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "make": "Samsung", "model": "Galaxy S21 5G",
            "isolation": "Faraday pouch"})
        self.assertTrue(added["ok"])

        # An exhibit with no isolation recorded must produce a warning.
        warned = self.post("exhibit/add", {
            "case_path": case_path, "exhibit_id": "EXH-002", "isolation": ""})
        self.assertTrue(warned["warnings"])

        started = self.post("acquire", {
            "case_path": case_path, "exhibit_id": "EXH-001",
            "operator": "Tester", "method": "import",
            "source_path": str(self.evidence),
            "device_name": "Samsung Galaxy S21 5G", "time_span": "all"})
        job = self.wait_for_job(started["job_id"])
        self.assertEqual(job["status"], "done", job.get("error"))

        result = job["result"]
        self.assertGreater(result["artifacts"], 300)
        self.assertGreater(result["deleted_recovered"], 0)
        self.assertTrue(result["seal"]["container_seal"])
        self.assertGreater(len(job["log"]), 10, "live log was not populated")

        container = result["container"]
        overview = self.get("overview", containers=container)
        self.assertTrue(overview["integrity"]["ok"])

        verified = self.get("verify", containers=container, deep="1")
        self.assertTrue(verified["ok"], verified)

        found = self.get("search", containers=container,
                         q="category:Messages AND deleted:true", limit=5)
        self.assertGreater(found["total"], 0)

        report_job = self.post("report", {
            "containers": [container],
            "out_dir": str(self.tmp / "workspace" / "reports"),
            "formats": ["html", "xml", "json", "csv"], "examiner": "Tester"})
        done = self.wait_for_job(report_job["job_id"])
        self.assertEqual(done["status"], "done", done.get("error"))
        self.assertEqual(len(done["result"]["files"]), 4)
        for f in done["result"]["files"]:
            self.assertTrue(Path(f["path"]).exists())

    def test_09_capability_gate_over_http(self):
        """An unsupported method must be refused before a job is created."""
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-GATE", "investigator": "Tester"})
        self.post("exhibit/add", {"case_path": created["path"],
                                  "exhibit_id": "EXH-A"})
        with self.assertRaises(self.urllib.error.HTTPError) as ctx:
            self.post("acquire", {
                "case_path": created["path"], "exhibit_id": "EXH-A",
                "operator": "Tester", "method": "filesystem",
                "device_name": "iPhone 12 mini", "lock_state": "bfu"})
        body = json.loads(ctx.exception.read())
        self.assertIn("does not support", body["error"])

    def test_10_acquire_requires_operator(self):
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-OP", "investigator": "Tester"})
        self.post("exhibit/add", {"case_path": created["path"],
                                  "exhibit_id": "EXH-A"})
        with self.assertRaises(self.urllib.error.HTTPError) as ctx:
            self.post("acquire", {
                "case_path": created["path"], "exhibit_id": "EXH-A",
                "operator": "", "method": "import",
                "source_path": str(self.evidence)})
        self.assertIn("Operator", json.loads(ctx.exception.read())["error"])

    def test_11_job_log_is_resumable(self):
        """Polling from an arbitrary sequence must not lose or repeat lines."""
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-LOG", "investigator": "Tester"})
        self.post("exhibit/add", {"case_path": created["path"],
                                  "exhibit_id": "EXH-A"})
        started = self.post("acquire", {
            "case_path": created["path"], "exhibit_id": "EXH-A",
            "operator": "Tester", "method": "import",
            "source_path": str(self.evidence)})
        job = self.wait_for_job(started["job_id"])
        full = self.get("job", id=started["job_id"], since=0)["log"]
        self.assertGreater(len(full), 5)
        tail = self.get("job", id=started["job_id"], since=3)["log"]
        self.assertEqual(tail[0]["seq"], 4)
        self.assertEqual([e["seq"] for e in full],
                         list(range(1, len(full) + 1)),
                         "log sequence numbers are not contiguous")

    def test_12_batch_requires_devices(self):
        created = self.post("case/new", {
            "dir": str(self.tmp / "workspace" / "cases"),
            "case_id": "WB-BATCH", "investigator": "Tester"})
        with self.assertRaises(self.urllib.error.HTTPError) as ctx:
            self.post("acquire/batch", {
                "case_path": created["path"],
                "operator": "Tester",
                "devices": []})
        self.assertIn("no devices", json.loads(ctx.exception.read())["error"])



# ===========================================================================
class TestProtobufDecoder(unittest.TestCase):
    """Schema-less protobuf decoding."""

    @staticmethod
    def _varint(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    def _field(self, num, wire):
        return self._varint((num << 3) | wire)

    def _string(self, num, text):
        raw = text.encode()
        return self._field(num, 2) + self._varint(len(raw)) + raw

    def _int(self, num, value):
        return self._field(num, 0) + self._varint(value)

    def setUp(self):
        from argus.parsers import protobuf
        self.pb = protobuf
        inner = self._string(1, "+919555000111")
        self.blob = (self._string(1, "Move the container tonight")
                     + self._int(2, 1783200000000)
                     + self._field(5, 2) + self._varint(len(inner)) + inner)

    def test_decodes_completely(self):
        msg = self.pb.decode(self.blob)
        self.assertEqual(len(msg), 3)
        self.assertEqual(msg.trailing, b"")

    def test_strings_not_shredded_into_fake_messages(self):
        """A plain string must not be mis-parsed as a nested message."""
        msg = self.pb.decode(self.blob)
        field = msg.first(1)
        self.assertEqual(field.as_text, "Move the container tonight")
        self.assertIsNone(field.as_message)

    def test_nested_message_recognised(self):
        msg = self.pb.decode(self.blob)
        nested = msg.first(5)
        self.assertIsNotNone(nested.as_message)
        self.assertEqual(nested.as_message.first(1).as_text, "+919555000111")

    def test_extract_text_finds_all_strings(self):
        found = self.pb.extract_text(self.blob)
        self.assertIn("Move the container tonight", found)
        self.assertIn("+919555000111", found)

    def test_extract_timestamps_plausible_only(self):
        stamps = self.pb.extract_timestamps(self.blob)
        self.assertIn(1783200000000 * 1000, stamps)

    def test_probe_rejects_non_protobuf(self):
        self.assertTrue(self.pb.probe(self.blob))
        self.assertFalse(self.pb.probe(b"\xff\xd8\xff\xe0" + b"j" * 40))
        self.assertFalse(self.pb.probe(
            b"this is ordinary english text, not protobuf at all"))


# ===========================================================================
class TestFileCarver(unittest.TestCase):
    """Signature carving with structural validation."""

    @classmethod
    def setUpClass(cls):
        import random
        from PIL import Image
        cls.tmp = Path(tempfile.mkdtemp())
        rng = random.Random(4242)
        blob = bytearray()
        cls.planted = []
        for i in range(5):
            img = Image.new("RGB", (160, 120))
            px = img.load()
            for y in range(120):
                for x in range(160):
                    px[x, y] = ((x * 3 + i * 30) % 256, (y * 5) % 256, 90)
            target = cls.tmp / f"p{i}.jpg"
            img.save(target, "JPEG", quality=80)
            payload = target.read_bytes()
            blob += bytes(rng.getrandbits(8) for _ in range(rng.randint(700, 3000)))
            cls.planted.append((len(blob), len(payload)))
            blob += payload
        blob += bytes(rng.getrandbits(8) for _ in range(1500))
        cls.image = cls.tmp / "test.dd"
        cls.image.write_bytes(bytes(blob))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _carve(self, block_size=1 << 16):
        from argus.core.streaming import ImageReader
        from argus.parsers.filecarver import FileCarver
        with ImageReader(self.image, block_size=block_size) as reader:
            carver = FileCarver(max_files=200, keep_data=False)
            return carver.carve_image(reader)

    def test_recovers_every_planted_file(self):
        report = self._carve()
        got = {(f.offset, f.size) for f in report.files}
        self.assertEqual(set(self.planted) - got, set(),
                         "some planted files were not recovered byte-exactly")

    def test_no_false_positives(self):
        report = self._carve()
        offsets = {off for off, _ in self.planted}
        spurious = [f for f in report.files if f.offset not in offsets]
        self.assertEqual(spurious, [], f"carver invented {len(spurious)} files")

    def test_survives_block_boundaries(self):
        """A file spanning a block boundary must still be recovered in full."""
        small = self._carve(block_size=4096)
        got = {(f.offset, f.size) for f in small.files}
        self.assertEqual(set(self.planted) - got, set(),
                         "files spanning block boundaries were truncated")

    def test_validators_reject_garbage(self):
        from argus.parsers.filecarver import (validate_jpeg, validate_png,
                                              validate_sqlite)
        self.assertIsNone(validate_jpeg(b"\xff\xd8\xff" + b"\x00" * 100))
        self.assertIsNone(validate_png(b"not a png at all"))
        self.assertIsNone(validate_sqlite(b"SQLite format 3\x00" + b"\x00" * 20))

    def test_refuses_ewf_container(self):
        from argus.core.streaming import ImageReader
        from argus.core.errors import ArgusError
        bad = self.tmp / "x.E01"
        bad.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 200)
        with self.assertRaises(ArgusError):
            ImageReader(bad)


# ===========================================================================
class TestStreaming(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data = bytes(range(256)) * 400

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_split_image_reassembled(self):
        from argus.core.streaming import ImageReader
        half = len(self.data) // 2
        (self.tmp / "img.001").write_bytes(self.data[:half])
        (self.tmp / "img.002").write_bytes(self.data[half:])
        with ImageReader(self.tmp / "img.001") as reader:
            self.assertEqual(reader.size, len(self.data))
            self.assertEqual(len(reader.segments), 2)
            # A read spanning the segment boundary must be contiguous.
            self.assertEqual(reader.read(half - 40, 80),
                             self.data[half - 40:half + 40])

    def test_single_pass_hash_matches_hashlib(self):
        import hashlib
        from argus.core.streaming import ImageReader, hash_and_scan
        path = self.tmp / "one.dd"
        path.write_bytes(self.data)
        seen = []
        with ImageReader(path, block_size=1024) as reader:
            result = hash_and_scan(reader,
                                   scanners=[lambda o, b: seen.append(len(b))],
                                   overlap=16)
        self.assertEqual(result["sha256"],
                         hashlib.sha256(self.data).hexdigest())
        self.assertTrue(result["complete"])
        self.assertTrue(seen)


# ===========================================================================
class TestIntelligence(unittest.TestCase):
    """Entities, findings and correlation."""

    def test_entity_validators_known_answers(self):
        from argus.intel.entities import (valid_btc, valid_card, valid_iban,
                                          valid_imei, valid_upi)
        cases = [
            (valid_btc, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", True),
            (valid_btc, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", False),
            (valid_btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", True),
            (valid_btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", False),
            (valid_iban, "GB82 WEST 1234 5698 7654 32", True),
            (valid_iban, "GB82 WEST 1234 5698 7654 33", False),
            (valid_card, "4539148803436467", True),
            (valid_card, "4539148803436468", False),
            (valid_card, "378282246310005", True),
            (valid_card, "490154203237518", False),
            (valid_imei, "490154203237518", True),
            (valid_imei, "490154203237519", False),
            (valid_upi, "rahul.mehta@okaxis", True),
            (valid_upi, "rahul@example.com", False),
        ]
        for fn, value, want in cases:
            self.assertEqual(fn(value), want, f"{fn.__name__}({value!r})")

    def test_overlapping_entities_resolved(self):
        """An IMEI must not also be reported as a payment card."""
        from argus.intel.entities import EntityExtractor
        ex = EntityExtractor()
        ex.scan_text("his imei is 490154203237518 if you need it")
        kinds = {h.kind for h in ex.results()}
        self.assertIn("imei", kinds)
        self.assertNotIn("card", kinds)

    def test_owner_number_not_reported(self):
        from argus.intel.entities import EntityExtractor
        ex = EntityExtractor()
        ex.set_owner_identifiers(["+919111222333"])
        ex.scan_text("call me on +91 91112 22333 later")
        self.assertEqual([h for h in ex.results(kinds=["phone"])], [])

    def test_label_propagation_deterministic(self):
        from argus.intel.correlate import label_propagation, modularity
        adjacency = {"a": {"b": 5.0, "c": 5.0}, "b": {"a": 5.0, "c": 5.0},
                     "c": {"a": 5.0, "b": 5.0, "x": 1.0},
                     "x": {"c": 1.0, "y": 5.0, "z": 5.0},
                     "y": {"x": 5.0, "z": 5.0}, "z": {"x": 5.0, "y": 5.0}}
        first = label_propagation(adjacency)
        self.assertEqual(first, label_propagation(adjacency))
        self.assertEqual(len(set(first.values())), 2,
                         "two obvious clusters were not separated")
        self.assertGreater(modularity(adjacency, first), 0.3)

    def test_identical_people_not_flagged_as_similar_names(self):
        from argus.core.models import Artifact, Category
        from argus.intel.correlate import CrossExhibitCorrelator
        corr = CrossExhibitCorrelator()
        for exhibit in ("A", "B"):
            art = Artifact(category=Category.CONTACT, body="Vikram Desai",
                           attributes={"display_name": "Vikram Desai"})
            art.add_participant("+919900112233", "Vikram Desai")
            art.add_participant("vikram@example.com", "Vikram Desai")
            corr.add_exhibit(exhibit, [art])
        self.assertTrue(corr.shared_parties())
        self.assertEqual(corr.name_similarities(), [],
                         "a party matched by identifier was also reported as a "
                         "weak name guess")

    def test_shared_media_requires_identical_digest(self):
        from argus.core.models import Artifact, Category
        from argus.intel.correlate import CrossExhibitCorrelator
        corr = CrossExhibitCorrelator()
        for exhibit, sha in (("A", "a" * 64), ("B", "a" * 64), ("B", "b" * 64)):
            art = Artifact(category=Category.FILE, body="photo.jpg",
                           blob_sha256=sha)
            corr.add_exhibit(exhibit, [art])
        shared = corr.shared_media()
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["sha256"], "a" * 64)


# ===========================================================================
class TestAntiForensics(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_encrypted_distinguished_from_readable(self):
        import random
        from argus.parsers.antiforensics import is_sqlcipher
        rng = random.Random(9)
        enc = self.tmp / "signal.db"
        enc.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096 * 4)))
        self.assertTrue(is_sqlcipher(enc)[0])

        plain = self.tmp / "plain.db"
        conn = sqlite3.connect(plain)
        conn.execute("CREATE TABLE t (a TEXT)")
        conn.execute("INSERT INTO t VALUES ('hello')")
        conn.commit(); conn.close()
        self.assertFalse(is_sqlcipher(plain)[0],
                         "a readable database was misreported as encrypted")

    def test_recovery_assessment_is_empirical(self):
        """The verdict must come from the file, not from a local pragma."""
        from argus.parsers.antiforensics import secure_delete_state
        path = self.tmp / "vacuumed.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (a TEXT)")
        for i in range(200):
            conn.execute("INSERT INTO t VALUES (?)", (f"row {i}" * 8,))
        conn.commit()
        conn.execute("DELETE FROM t WHERE rowid < 150")
        conn.commit()
        conn.execute("VACUUM")
        conn.close()
        state = secure_delete_state(path)
        self.assertTrue(state["checked"])
        self.assertTrue(state["recovery_limited"])
        self.assertIn("free space", state["explanation"])

    def test_system_packages_not_called_uninstalled(self):
        from argus.parsers.antiforensics import _is_system_package
        self.assertTrue(_is_system_package("com.android.providers.telephony"))
        self.assertTrue(_is_system_package("com.google.android.gms"))
        self.assertFalse(_is_system_package("com.gallery.vault"))


# ===========================================================================
class TestValidationHarness(unittest.TestCase):
    """The harness that measures the tool's own error rates."""

    @classmethod
    def setUpClass(cls):
        from argus.validate.harness import run_validation
        cls.report = run_validation()
        cls.data = cls.report.as_dict()

    def test_all_tests_pass(self):
        failed = [r["test_id"] for r in self.data["results"] if not r["passed"]]
        self.assertEqual(failed, [], f"validation failures: {failed}")

    def test_reports_recall_and_precision(self):
        summary = self.data["summary"]
        self.assertIsNotNone(summary["overall_recall"])
        self.assertIsNotNone(summary["overall_precision"])

    def test_per_capability_error_rates(self):
        caps = self.data["by_capability"]
        self.assertGreaterEqual(len(caps), 8)
        for name, metrics in caps.items():
            self.assertIn("false_negative_rate", metrics, name)

    def test_limitations_are_stated(self):
        self.assertGreaterEqual(len(self.data["limitations"]), 4)

    def test_deleted_recall_measured_against_recoverable(self):
        """Recall must not be measured against records SQLite destroyed."""
        entry = next(r for r in self.data["results"]
                     if r["test_id"] == "carve.sqlite.deleted")
        self.assertIn("unrecoverable by any tool", entry["notes"])


# ===========================================================================
class TestCertificate(unittest.TestCase):

    def setUp(self):
        from argus.core.case import Case, Exhibit
        from argus.core.container import ExtractionMeta
        from argus.core.models import Artifact, Category
        self.tmp = Path(tempfile.mkdtemp())
        case = Case.create(self.tmp, case_id="CERT")
        case.add_exhibit(Exhibit("EXH-1"))
        container = case.new_container("EXH-1",
                                      ExtractionMeta(operator="tester"))
        art = Artifact(category=Category.MESSAGE, body="reference",
                       timestamp=1_780_000_000_000_000)
        container.db.add(art)
        container.store_blob(b"reference blob", "ref.bin")
        container.seal()
        container.close()
        self.container = Path(container.path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_issue_and_verify(self):
        from argus.validate.certificate import (build_certificate,
                                                verify_certificate,
                                                write_certificate)
        cert = build_certificate([self.container], examiner="tester")
        path = write_certificate(cert, self.tmp / "cert.json")
        result = verify_certificate(path)
        self.assertTrue(result["ok"], result["problems"])

    def test_hmac_seal_round_trip(self):
        from argus.validate.certificate import (build_certificate, generate_key,
                                                verify_certificate,
                                                write_certificate)
        key = generate_key()
        cert = build_certificate([self.container], key=key)
        path = write_certificate(cert, self.tmp / "sealed.json")
        self.assertTrue(verify_certificate(path, key=key)["ok"])
        self.assertFalse(verify_certificate(path, key=generate_key())["ok"])

    def test_detects_altered_certificate(self):
        from argus.validate.certificate import (build_certificate,
                                                verify_certificate,
                                                write_certificate)
        cert = build_certificate([self.container], examiner="tester")
        path = write_certificate(cert, self.tmp / "cert.json")
        data = json.loads(path.read_text())
        data["examination"]["examiner"] = "someone else"
        path.write_text(json.dumps(data))
        result = verify_certificate(path, recheck_evidence=False)
        self.assertFalse(result["ok"])
        self.assertTrue(any("altered" in p or "mismatch" in p
                            for p in result["problems"]))

    def test_detects_tampered_evidence(self):
        from argus.validate.certificate import (build_certificate,
                                                verify_certificate,
                                                write_certificate)
        cert = build_certificate([self.container], examiner="tester")
        path = write_certificate(cert, self.tmp / "cert.json")
        blob = next(p for p in (self.container / "blobs").rglob("*")
                    if p.is_file())
        os.chmod(blob, 0o644)
        blob.write_bytes(b"tampered")
        result = verify_certificate(path)
        self.assertFalse(result["ok"])

    def test_states_what_the_seal_does_not_prove(self):
        from argus.validate.certificate import (build_certificate,
                                                generate_key)
        cert = build_certificate([self.container], key=generate_key())
        self.assertIn("NOT a digital signature", cert["seal"]["meaning"])



# ===========================================================================
class TestExpandedParsers(unittest.TestCase):
    """The social, system and telemetry parsers, against ground truth."""

    @classmethod
    def setUpClass(cls):
        import make_device
        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        cls.tmp = Path(tempfile.mkdtemp())
        cls.evidence = cls.tmp / "evidence"
        cls.android_stats = make_device.build_android(cls.evidence / "android")
        cls.ios_stats = make_device.build_ios(cls.evidence / "ios")

        case = Case.create(cls.tmp / "cases", case_id="PARSERS",
                           investigator="tester")
        case.add_exhibit(Exhibit("EXH-A", make="Samsung"))
        case.add_exhibit(Exhibit("EXH-I", make="Apple"))
        engine = AcquisitionEngine(case)
        cls.report_a = engine.run(AcquisitionPlan(
            method="import", source_path=cls.evidence / "android",
            operator="tester", exhibit_id="EXH-A"))
        cls.report_i = engine.run(AcquisitionPlan(
            method="import", source_path=cls.evidence / "ios",
            operator="tester", exhibit_id="EXH-I"))
        cls.containers = [Path(cls.report_a.container),
                          Path(cls.report_i.container)]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _count(self, aql: str) -> int:
        with AnalysisSession(self.containers) as session:
            return session.query(aql, limit=1)["total"]

    def test_telegram_messages_decoded_from_blobs(self):
        """Telegram keeps message text in a serialised blob, not a column."""
        self.assertGreaterEqual(self._count("app:Telegram AND category:Messages"),
                                self.android_stats["telegram"])

    def test_telegram_deleted_partially_recovered(self):
        """A deleted row whose leading column was destroyed is still recovered."""
        self.assertGreaterEqual(self._count("app:Telegram AND deleted:true"), 1)

    def test_instagram_json_payload_fallback(self):
        self.assertGreaterEqual(self._count("app:Instagram"),
                                self.android_stats["instagram"])

    def test_snapchat_metadata_recorded_without_content(self):
        """Snapchat content is ephemeral; the metadata must still be reported."""
        with AnalysisSession(self.containers) as session:
            result = session.query("app:Snapchat", limit=50)
        metadata_only = [a for a in result["artifacts"]
                         if "metadata only" in (a["subtype"] or "")]
        self.assertTrue(metadata_only,
                        "Snapchat records with no surviving content were not "
                        "reported as metadata-only")

    def test_messenger_and_instagram_not_double_counted(self):
        """threads_db2 must be claimed by exactly one parser."""
        from argus.parsers.registry import load_all, parsers_for
        load_all()
        target = (self.evidence / "android/data/data/com.facebook.orca"
                                  "/databases/threads_db2")
        claimants = [s.name for s in parsers_for(target, "android")]
        self.assertEqual(claimants, ["android.messenger"],
                         f"threads_db2 claimed by {claimants}")

    def test_viber_and_discord(self):
        self.assertGreaterEqual(self._count("app:Viber"),
                                self.android_stats["viber"])

    def test_gmail_and_payments(self):
        self.assertGreaterEqual(self._count("app:Gmail"),
                                self.android_stats["gmail"])
        self.assertGreaterEqual(self._count("app:Paytm"),
                                self.android_stats["payments"])

    def test_maps_history_geolocated(self):
        with AnalysisSession(self.containers) as session:
            result = session.query('app:"Google Maps"', limit=20)
        located = [a for a in result["artifacts"] if a["latitude"] is not None]
        self.assertTrue(located, "Maps destinations lost their coordinates")

    def test_notifications_preview_encrypted_apps(self):
        """The highest-value cross-source result must be present."""
        with AnalysisSession(self.containers) as session:
            result = session.query("app:Signal", limit=50)
        previews = [a for a in result["artifacts"]
                    if a.get("attributes", {}).get("previews_encrypted_app")]
        self.assertGreaterEqual(
            len(previews), 2,
            "notification previews of encrypted-app content were not recovered")

    def test_knowledgec_usage_timeline(self):
        self.assertGreaterEqual(self._count("type:KnowledgeC"),
                                self.ios_stats["knowledgec_events"])

    def test_powerlog_corroborates(self):
        self.assertGreaterEqual(self._count("type:PowerLog"),
                                self.ios_stats["powerlog_events"])

    def test_usage_events_recorded(self):
        self.assertGreaterEqual(
            self._count('category:"User activity log"'),
            self.android_stats["usage_events"])

    def test_cross_source_findings_generated(self):
        from argus.intel import analyse
        with AnalysisSession(self.containers) as session:
            result = analyse(session, owner_identifiers=["+919111222333"])
        rules = {f["rule_id"] for f in result["findings"]["findings"]}
        self.assertIn("crosssource.notification_leak", rules,
                      "the notification-leak inference did not fire")
        self.assertIn("activity.device_in_use", rules)

    def test_every_finding_still_cites_evidence(self):
        from argus.intel import analyse
        with AnalysisSession(self.containers) as session:
            result = analyse(session, owner_identifiers=["+919111222333"])
        uncited = [f["title"] for f in result["findings"]["findings"]
                   if not f["artifact_ids"]]
        self.assertEqual(uncited, [], f"findings with no citations: {uncited}")

    def test_every_finding_states_a_caveat(self):
        from argus.intel import analyse
        with AnalysisSession(self.containers) as session:
            result = analyse(session, owner_identifiers=["+919111222333"])
        missing = [f["title"] for f in result["findings"]["findings"]
                   if not f["caveat"] and f["category"] != "engine"]
        self.assertLessEqual(len(missing), 1,
                             f"findings with no caveat: {missing}")



# ===========================================================================
class TestPerceptualHashing(unittest.TestCase):
    """Matching the same picture across re-encoded files."""

    @classmethod
    def setUpClass(cls):
        from PIL import Image
        cls.tmp = Path(tempfile.mkdtemp())

        def render(seed, size=(320, 240)):
            img = Image.new("RGB", size)
            px = img.load()
            for y in range(size[1]):
                for x in range(size[0]):
                    px[x, y] = ((x * 3 + seed * 17) % 256,
                                (y * 5 + seed * 7) % 256,
                                (x + y + seed) % 256)
            return img

        base = render(1)
        base.save(cls.tmp / "original.jpg", "JPEG", quality=95)
        base.save(cls.tmp / "recompressed.jpg", "JPEG", quality=30)
        base.resize((160, 120), Image.Resampling.LANCZOS).save(
            cls.tmp / "resized.jpg", "JPEG", quality=85)
        render(99).save(cls.tmp / "different.jpg", "JPEG", quality=95)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_files_are_cryptographically_distinct(self):
        """The premise: SHA-256 cannot link these."""
        digests = {p.name: hash_bytes(p.read_bytes()).sha256
                   for p in self.tmp.glob("*.jpg")}
        self.assertEqual(len(set(digests.values())), len(digests),
                         "test images are not cryptographically distinct")

    def test_recompression_survives(self):
        from argus.parsers.media.perceptual import compare, hash_image
        a = hash_image(self.tmp / "original.jpg")
        b = hash_image(self.tmp / "recompressed.jpg")
        verdict, agreement, _ = compare(a, b)
        self.assertIn(verdict, ("identical", "near-duplicate"))
        self.assertGreaterEqual(agreement, 2)

    def test_resize_survives(self):
        from argus.parsers.media.perceptual import compare, hash_image
        verdict, _, _ = compare(hash_image(self.tmp / "original.jpg"),
                                hash_image(self.tmp / "resized.jpg"))
        self.assertIn(verdict, ("identical", "near-duplicate"))

    def test_different_image_not_matched(self):
        from argus.parsers.media.perceptual import compare, hash_image
        verdict, _, distances = compare(hash_image(self.tmp / "original.jpg"),
                                        hash_image(self.tmp / "different.jpg"))
        self.assertEqual(verdict, "",
                         f"unrelated images were matched: {distances}")

    def test_clusters_group_copies_and_exclude_others(self):
        from argus.parsers.media.perceptual import PerceptualIndex, hash_image
        index = PerceptualIndex()
        for path in sorted(self.tmp.glob("*.jpg")):
            index.add(path.name, hash_image(path), label=path.name,
                      exhibit="EXH-A",
                      sha256=hash_bytes(path.read_bytes()).sha256)
        clusters = index.clusters()
        self.assertEqual(len(clusters), 1)
        members = {m["label"] for m in clusters[0]["members"]}
        self.assertNotIn("different.jpg", members)
        self.assertTrue(clusters[0]["re_encoded"])

    def test_tiny_image_refused(self):
        from PIL import Image
        from argus.parsers.media.perceptual import hash_image
        tiny = self.tmp / "tiny.jpg"
        Image.new("RGB", (8, 8), (1, 2, 3)).save(tiny, "JPEG")
        result = hash_image(tiny)
        self.assertFalse(result.available)
        self.assertIn("too small", result.error)


# ===========================================================================
class TestHashSets(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.system = hash_bytes(b"an android system library")
        self.bad = hash_bytes(b"material of interest")
        self.user = hash_bytes(b"a user's own photograph")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _registry(self):
        from argus.core.hashsets import HashSetRegistry
        (self.tmp / "nsrl_good.csv").write_text(
            '"SHA-1","MD5","CRC32","FileName","FileSize"\n'
            f'"{self.system.sha1}","{self.system.md5}","0","libc.so","1024"\n')
        (self.tmp / "blocklist_bad.txt").write_text(
            f"# curated set\n{self.bad.sha256}  sample_A\n")
        registry = HashSetRegistry()
        registry.load_directory(self.tmp)
        return registry

    def test_nsrl_csv_detected(self):
        registry = self._registry()
        good = [s for s in registry.sets if s.kind == "known-good"]
        self.assertTrue(good)
        self.assertIn("sha1", good[0].algorithms)

    def test_kind_inferred_from_filename(self):
        registry = self._registry()
        kinds = {s.name: s.kind for s in registry.sets}
        self.assertEqual(kinds["blocklist_bad"], "known-bad")
        self.assertEqual(kinds["nsrl_good"], "known-good")

    def test_screening_verdicts(self):
        registry = self._registry()
        self.assertEqual(
            registry.screen(md5=self.system.md5, sha1=self.system.sha1,
                            sha256=self.system.sha256).status, "known-good")
        self.assertEqual(registry.screen(sha256=self.bad.sha256).status,
                         "known-bad")
        self.assertEqual(registry.screen(sha256=self.user.sha256).status,
                         "unknown")

    def test_known_bad_beats_known_good(self):
        """A file in both lists must be flagged, never suppressed."""
        from argus.core.hashsets import HashSet, HashSetRegistry
        digest = hash_bytes(b"in both lists")
        good = HashSet(name="g", kind="known-good")
        good.add(digest.sha256)
        bad = HashSet(name="b", kind="known-bad")
        bad.add(digest.sha256)
        registry = HashSetRegistry()
        registry.add(good)
        registry.add(bad)
        self.assertEqual(registry.screen(sha256=digest.sha256).status,
                         "known-bad")

    def test_matching_is_per_algorithm(self):
        from argus.core.hashsets import HashSet, HashSetRegistry
        digest = hash_bytes(b"md5 only")
        hs = HashSet(name="md5only", kind="known-good")
        hs.add(digest.md5)
        registry = HashSetRegistry()
        registry.add(hs)
        self.assertEqual(registry.screen(sha256=digest.sha256).status, "unknown")
        self.assertEqual(registry.screen(md5=digest.md5).status, "known-good")

    def test_malformed_counted_not_fatal(self):
        from argus.core.hashsets import load_hashset
        path = self.tmp / "messy.txt"
        path.write_text("nonsense\nzz\n" + hash_bytes(b"ok").sha256 + "\n")
        hs = load_hashset(path)
        self.assertEqual(hs.size, 1)
        self.assertEqual(hs.malformed, 2)

    def test_provenance_recorded(self):
        registry = self._registry()
        for entry in registry.provenance():
            self.assertTrue(entry["loaded_at"])
            self.assertTrue(entry["source"])


# ===========================================================================
class TestConversations(unittest.TestCase):

    def _artifact(self, body, outgoing, ts, deleted=False, app="WhatsApp",
                  party="+919876543210"):
        art = Artifact(
            category=Category.MESSAGE, body=body, timestamp=ts, app=app,
            direction=Direction.OUTGOING if outgoing else Direction.INCOMING,
            recovery=Recovery.DELETED_FREELIST if deleted else Recovery.ALLOCATED)
        if outgoing:
            art.add_participant("", "Owner", role="from", is_owner=True)
            art.add_participant(party, "Priya Nair", role="to")
        else:
            art.add_participant(party, "Priya Nair", role="from")
            art.add_participant("", "Owner", role="to", is_owner=True)
        return art

    def test_threading_and_turn_order(self):
        from argus.analyze.conversations import ConversationBuilder
        base = 1_780_000_000_000_000
        arts = [self._artifact(f"m{i}", i % 2 == 0, base + i * 60_000_000)
                for i in range(6)]
        builder = ConversationBuilder()
        builder.add(reversed(arts))          # deliberately out of order
        threads = builder.build()
        self.assertEqual(len(threads), 1)
        thread = threads[0]
        self.assertEqual([t.body for t in thread.turns],
                         [f"m{i}" for i in range(6)])
        self.assertEqual(thread.label, "Priya Nair")

    def test_reply_latency_measured_across_direction_change(self):
        """Consecutive same-direction messages must not count as replies."""
        from argus.analyze.conversations import ConversationBuilder
        base = 1_780_000_000_000_000
        arts = [
            self._artifact("a", True, base),
            self._artifact("b", True, base + 1_000_000),      # same direction
            self._artifact("c", False, base + 120_000_000),   # the actual reply
        ]
        builder = ConversationBuilder()
        builder.add(arts)
        thread = builder.build()[0]
        self.assertIsNotNone(thread.median_reply_seconds)
        self.assertGreaterEqual(thread.median_reply_seconds, 100)

    def test_deleted_positions_recorded(self):
        from argus.analyze.conversations import ConversationBuilder
        base = 1_780_000_000_000_000
        arts = [self._artifact("live1", True, base),
                self._artifact("gone", False, base + 60_000_000, deleted=True),
                self._artifact("live2", True, base + 120_000_000)]
        builder = ConversationBuilder()
        builder.add(arts)
        thread = builder.build()[0]
        self.assertEqual(thread.deleted_positions, [1])
        self.assertEqual(thread.deleted, 1)

    def test_transcript_marks_recovered_content(self):
        from argus.analyze.conversations import ConversationBuilder
        base = 1_780_000_000_000_000
        builder = ConversationBuilder()
        builder.add([self._artifact("secret", False, base, deleted=True)])
        transcript = builder.build(min_turns=1)[0].transcript()
        self.assertIn("RECOVERED FROM DELETED SPACE", transcript)

    def test_voice_channels_excluded_from_channel_switching(self):
        """A phone call is not 'another messaging app'."""
        from argus.analyze.conversations import ConversationBuilder
        base = 1_780_000_000_000_000
        arts = [self._artifact("m", True, base, app="WhatsApp"),
                self._artifact("m", True, base + 1_000_000, app="WhatsApp"),
                self._artifact("m", True, base + 2_000_000,
                               app="Android Phone"),
                self._artifact("m", True, base + 3_000_000,
                               app="Android Phone")]
        builder = ConversationBuilder()
        builder.add(arts)
        rel = builder.relationships(min_turns=1)[0]
        self.assertEqual(rel["messaging_channel_count"], 1)
        self.assertFalse(rel["multi_channel"])


# ===========================================================================
class TestEventFusion(unittest.TestCase):

    def _message(self, ts, body="hello"):
        art = Artifact(category=Category.MESSAGE, body=body, timestamp=ts,
                       app="WhatsApp", direction=Direction.OUTGOING)
        art.add_participant("", "Owner", role="from", is_owner=True)
        art.add_participant("+919876543210", "Priya", role="to")
        return art

    def _usage(self, ts, app="WhatsApp", event="moved to foreground"):
        return Artifact(category=Category.ACTIVITY,
                        subtype="KnowledgeC: App in foreground",
                        body=f"{app} foreground", timestamp=ts, app=app,
                        attributes={"stream": "/app/inFocus", "value": app,
                                    "event": event})

    def _lock(self, ts, locked):
        return Artifact(category=Category.SECURITY,
                        subtype="KnowledgeC: Device lock state",
                        body="lock", timestamp=ts, app="iOS",
                        attributes={"stream": "/device/isLocked",
                                    "value": "1" if locked else "0"})

    def test_simultaneous_usage_attributes(self):
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        fuser.add([self._message(base), self._usage(base)])
        event = fuser.fuse()[0]
        self.assertEqual(event.attribution, "attributed")
        self.assertGreaterEqual(event.corroboration_count, 1)

    def test_locked_device_is_unattributed(self):
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        fuser.add([self._message(base), self._lock(base, locked=True)])
        self.assertEqual(fuser.fuse()[0].attribution, "unattributed")

    def test_no_telemetry_is_unknown_not_unattributed(self):
        """The most dangerous possible confusion must not occur."""
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        fuser.add([self._message(base)])
        event = fuser.fuse()[0]
        self.assertEqual(event.attribution, "unknown")
        self.assertIn("not evidence that nobody was present",
                      " ".join(event.notes))

    def test_distant_telemetry_does_not_attribute(self):
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        # 10 minutes away: same session, not simultaneous.
        fuser.add([self._message(base), self._usage(base + 600_000_000)])
        self.assertNotEqual(fuser.fuse()[0].attribution, "attributed")

    def test_attribution_never_names_a_person(self):
        from argus.intel.fusion import ATTRIBUTION
        for meaning in ATTRIBUTION.values():
            self.assertNotIn("owner sent", meaning.lower())
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        fuser.add([self._message(base), self._usage(base)])
        notes = " ".join(fuser.fuse()[0].notes).lower()
        self.assertIn("cannot establish", notes)

    def test_summary_reports_coverage(self):
        from argus.intel.fusion import EventFuser
        base = 1_780_000_000_000_000
        fuser = EventFuser()
        fuser.add([self._message(base + i * 3_600_000_000) for i in range(10)]
                  + [self._usage(base)])
        summary = fuser.summary()
        self.assertEqual(summary["events"], 10)
        self.assertLess(summary["coverage"], 0.5)
        self.assertIn("does NOT mean", summary["note"])


# ===========================================================================
def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(f"\n{'=' * 62}")
    print(f"  {result.testsRun} tests · "
          f"{result.testsRun - len(result.failures) - len(result.errors)} passed · "
          f"{len(result.failures)} failed · {len(result.errors)} errors")
    print(f"{'=' * 62}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
