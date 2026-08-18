"""MSAB XRY extraction — case resolution, native staging, XML provenance."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from argus.acquire import adapters
from argus.acquire.msab import (inspect_header, read_xry_report, resolve_case,
                                stage_native)
from argus.core.errors import AcquisitionError


def _sqlite_bytes(path: Path, rows: int = 20) -> bytes:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, body TEXT)")
    con.executemany("INSERT INTO sms (body) VALUES (?)",
                    [(f"msg {i}",) for i in range(rows)])
    con.commit()
    con.close()
    return path.read_bytes()


class CaseResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-msab-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_index_resolves_to_companion_xry(self) -> None:
        index = self.dir / "Case42.xrycase"
        data = self.dir / "Case42.xry"
        index.write_bytes(b"XRY\x00" + os.urandom(8000))
        data.write_bytes(b"XRY\x00" + os.urandom(500_000))

        resolved = resolve_case(index)
        self.assertEqual(resolved.data_path, data)
        self.assertFalse(resolved.is_index_only)
        self.assertTrue(any("companion" in n.lower() for n in resolved.notes))

    def test_largest_sibling_used_when_stem_differs(self) -> None:
        index = self.dir / "index.xrycase"
        small = self.dir / "other.xry"
        big = self.dir / "extraction.xry"
        index.write_bytes(b"XRY\x00" + os.urandom(4000))
        small.write_bytes(b"XRY\x00" + os.urandom(20_000))
        big.write_bytes(b"XRY\x00" + os.urandom(2_000_000))

        resolved = resolve_case(index)
        self.assertEqual(resolved.data_path, big)

    def test_index_without_companion_is_flagged(self) -> None:
        index = self.dir / "lonely.xrycase"
        index.write_bytes(b"XRY\x00" + os.urandom(5000))
        resolved = resolve_case(index)
        self.assertTrue(resolved.is_index_only)
        self.assertIsNone(resolved.data_path)


class NativeStaging(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-msab-stage-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_zip_in_disguise_is_extracted(self) -> None:
        container = self.dir / "export.xry"
        with zipfile.ZipFile(container, "w") as archive:
            archive.writestr("data/msgstore.db", b"x" * 100)
            archive.writestr("report.xml", "<xry/>")

        dest = self.dir / "staged"
        staged = adapters.StagedSource(root=dest, adapter="msab.xry",
                                       source_format="test")
        stage_native(container, dest, staged)
        self.assertGreater(staged.files, 0)
        self.assertTrue((dest / "data" / "msgstore.db").exists())

    def test_embedded_sqlite_is_carved(self) -> None:
        inner = _sqlite_bytes(self.dir / "inner.db")
        container = self.dir / "opaque.xry"
        container.write_bytes(b"XRY\x00VENDOR" + os.urandom(400) + inner)

        dest = self.dir / "staged"
        staged = adapters.StagedSource(root=dest, adapter="msab.xry",
                                       source_format="test")
        stage_native(container, dest, staged)
        self.assertGreater(staged.files, 0)
        carved = [p for p in (dest / "_carved").rglob("*") if p.is_file()]
        self.assertTrue(carved)
        self.assertTrue(
            any(p.suffix == ".db" or p.name.endswith("db") for p in carved),
            [p.name for p in carved])

    def test_index_import_raises_with_clear_message(self) -> None:
        index = self.dir / "only.xrycase"
        index.write_bytes(b"XRY\x00" + os.urandom(3000))
        dest = self.dir / "staged"
        staged = adapters.StagedSource(root=dest, adapter="msab.xry",
                                       source_format="test")
        with self.assertRaises(AcquisitionError) as ctx:
            stage_native(index, dest, staged)
        self.assertIn("case index", str(ctx.exception).lower())

    def test_encrypted_container_refused_cleanly(self) -> None:
        container = self.dir / "encrypted.xry"
        container.write_bytes(b"XRY\x00" + os.urandom(2_000_000))
        dest = self.dir / "staged"
        staged = adapters.StagedSource(root=dest, adapter="msab.xry",
                                       source_format="test")
        with self.assertRaises(AcquisitionError) as ctx:
            stage_native(container, dest, staged)
        self.assertIn("entropy", str(ctx.exception).lower())


class XmlProvenance(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-msab-xml-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_xry_report_records_foreign_decoded(self) -> None:
        report = self.dir / "report.xml"
        report.write_text("""<?xml version="1.0"?>
<xry>
  <Device name="Samsung Galaxy S21" />
  <model type="SMS">1</model>
  <model type="SMS">2</model>
  <model type="Call">1</model>
  <IMEI>359123456789012</IMEI>
</xry>""", encoding="utf-8")
        device, decoded, notes = read_xry_report(report)
        self.assertIn("Samsung", device.get("name", device.get("device", "")))
        kinds = {d["model"] for d in decoded}
        self.assertIn("SMS", kinds)
        self.assertTrue(any("foreign" in n.lower() for n in notes))

    def test_adapter_stages_xml_export_folder(self) -> None:
        export = self.dir / "export"
        export.mkdir()
        (export / "report.xml").write_text(
            '<?xml version="1.0"?><xry><Device name="iPhone 12"/></xry>',
            encoding="utf-8")
        (export / "files").mkdir()
        (export / "files" / "sms.db").write_bytes(
            b"SQLite format 3\x00" + b"\x00" * 80)

        dest = self.dir / "staged"
        staged = adapters._stage_xry(export, dest, None)
        self.assertEqual(staged.adapter, "msab.xry")
        self.assertTrue((dest / "files" / "sms.db").exists())

class EndToEndImport(unittest.TestCase):
    """Native .xry import through the acquisition engine."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-msab-e2e-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_carved_xry_imports_and_seals(self) -> None:
        inner = _sqlite_bytes(self.dir / "inner.db")
        container = self.dir / "device.xry"
        container.write_bytes(b"XRY\x00VENDOR" + os.urandom(400) + inner)

        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        from argus.core.case import Case, Exhibit

        case = Case.create(self.dir / "cases", case_id="MSAB",
                           investigator="Tester")
        case.add_exhibit(Exhibit("EXH-XRY", make="MSAB", model="test fixture"))
        plan = AcquisitionPlan(method="import", source_path=container,
                               operator="Tester", exhibit_id="EXH-XRY",
                               device_name="MSAB test fixture")
        report = AcquisitionEngine(case).run(plan)
        self.assertTrue(report.status.startswith("Completed"), report.warnings)
        self.assertGreater(report.files_acquired, 0)
        self.assertTrue(report.seal.get("container_seal"))

    def test_xrycase_resolves_to_companion_on_import(self) -> None:
        index = self.dir / "Case99.xrycase"
        data = self.dir / "Case99.xry"
        inner = _sqlite_bytes(self.dir / "inner.db")
        index.write_bytes(b"XRY\x00" + os.urandom(5000))
        data.write_bytes(b"XRY\x00VENDOR" + os.urandom(300) + inner)

        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        from argus.core.case import Case, Exhibit

        case = Case.create(self.dir / "cases2", case_id="MSAB2",
                           investigator="Tester")
        case.add_exhibit(Exhibit("EXH-IDX", make="MSAB", model="index test"))
        plan = AcquisitionPlan(method="import", source_path=index,
                               operator="Tester", exhibit_id="EXH-IDX")
        report = AcquisitionEngine(case).run(plan)
        self.assertTrue(report.status.startswith("Completed"), report.warnings)
        self.assertGreater(report.files_acquired, 0)


class WorkbenchClassify(unittest.TestCase):
    """Workbench source classification for vendor containers."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-wb-classify-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_msab_xry_is_classified_with_triage(self) -> None:
        import sqlite3
        from argus.server.workbench import _classify_source

        db = self.dir / "inner.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE t (x TEXT)")
        con.commit()
        con.close()
        container = self.dir / "device.xry"
        container.write_bytes(b"XRY\x00" + os.urandom(200) + db.read_bytes())

        info = _classify_source(str(container))
        self.assertEqual(info["kind"], "msab-xry")
        self.assertTrue(info.get("carvable"))


class HeaderInspection(unittest.TestCase):
    def test_xry_magic_is_recognised(self) -> None:
        path = Path(tempfile.mktemp())
        try:
            path.write_bytes(b"XRY\x00\x01\x00\x00\x00")
            info = inspect_header(path)
            self.assertEqual(info["magic"], "XRY")
            self.assertEqual(info["wrapper"], "msab.xry")
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
