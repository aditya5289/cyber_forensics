"""Tests for field custody parity and USB device watching."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from argus.core.custody import (append_entry, import_field_log, verify_chain,
                                CUSTODY_FILE)
from argus.core.resume import open_for_resume
from argus.devices.watch import DeviceWatcher


class TestFieldCustody(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="argus-custody-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chain_links_and_verifies(self) -> None:
        append_entry(self.tmp, "acquire.start", {"files": 0})
        append_entry(self.tmp, "acquire.complete", {"files": 12})
        report = verify_chain(self.tmp)
        self.assertTrue(report["ok"])
        self.assertEqual(report["entries"], 2)

    def test_tamper_detected(self) -> None:
        append_entry(self.tmp, "step.one", {})
        log = self.tmp / CUSTODY_FILE
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["action"] = "tampered"
        lines[0] = json.dumps(entry)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(verify_chain(self.tmp)["ok"])

    def test_import_from_field_folder(self) -> None:
        field = self.tmp / "field_acq"
        field.mkdir()
        append_entry(field, "mtp.copy", {"device": "PHONE"})
        dest = self.tmp / "staged"
        dest.mkdir()
        _, report = import_field_log(field, dest)
        self.assertTrue(report["imported"])
        self.assertTrue((dest / CUSTODY_FILE).exists())
        self.assertTrue(verify_chain(dest)["ok"])


class TestDeviceWatcher(unittest.TestCase):
    def test_emits_connect_event(self) -> None:
        watcher = DeviceWatcher()
        watcher._bootstrapped = True
        watcher._seen = set()

        fake = {
            "devices": [{"transport": "adb", "serial": "ABC",
                         "name": "Samsung Galaxy"}],
            "diagnostics": [],
            "toolchain": {},
        }
        orig = __import__("argus.devices.watch", fromlist=["detect_all"]).detect_all
        try:
            import argus.devices.watch as watch_mod
            watch_mod.detect_all = lambda: fake
            result = watcher.poll()
            self.assertEqual(len(result["events"]), 1)
            self.assertEqual(result["events"][0]["kind"], "connected")
        finally:
            watch_mod.detect_all = orig


class TestResume(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="argus-resume-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_find_and_open_incomplete(self) -> None:
        from argus.core.case import Case, Exhibit
        from argus.core.container import ExtractionMeta
        from argus.core.resume import INCOMPLETE_MARKER, find_incomplete

        case = Case.create(self.tmp, case_id="RES-001", investigator="Op")
        case.add_exhibit(Exhibit(exhibit_id="EXH-1"))
        meta = ExtractionMeta(exhibit_id="EXH-1", operator="Op", method="logical")
        container = case.new_container("EXH-1", meta, label="logical")
        (container.path / INCOMPLETE_MARKER).write_text(
            json.dumps({"format": "argus-incomplete/1", "method": "logical",
                        "exhibit_id": "EXH-1"}), encoding="utf-8")
        container.close()

        hits = find_incomplete(case, "EXH-1", "logical")
        self.assertEqual(len(hits), 1)
        reopened = open_for_resume(case, hits[0]["path"], operator="Op")
        self.assertEqual(reopened.mode, "a")
        reopened.close()


if __name__ == "__main__":
    unittest.main()
