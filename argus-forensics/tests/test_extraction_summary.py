"""Tests for acquisition summary builder."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from argus.acquire.summary import build_acquisition_summary, write_acquisition_summary


class TestAcquisitionSummary(unittest.TestCase):
    def test_builds_from_adb_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {
                "passes": ["logical", "comms"],
                "summary": {"pulled": 5, "failed": 1, "bytes": 9999},
                "providers": [
                    {"key": "sms", "rows": 42, "uri": "content://sms"},
                    {"key": "mms", "rows": 100, "uri": "content://mms"},
                ],
            }
            (root / "argus-adb-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            summary = build_acquisition_summary(root, method="comprehensive")
            self.assertEqual(summary["comms_row_total"], 142)
            self.assertEqual(summary["adb"]["pulled"], 5)
            self.assertEqual(len(summary["comms_providers"]), 2)

    def test_physical_manifest_and_caveats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            phys_dir = root / "physical"
            phys_dir.mkdir()
            manifest = {
                "rooted": True,
                "crypto": "file",
                "bytes": 4096,
                "carved_files": 3,
                "dumped": ["userdata", "metadata"],
                "hashes": {"userdata": "abc123"},
                "notes": ["FBE ciphertext"],
            }
            (phys_dir / "argus-physical-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            summary = build_acquisition_summary(root, method="physical")
            self.assertEqual(summary["physical"]["dumped"],
                             ["userdata", "metadata"])
            self.assertTrue(any("encrypted" in c.lower()
                                for c in summary["caveats"]))

    def test_write_summary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = write_acquisition_summary(root, method="logical")
            self.assertTrue(out.is_file())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["method"], "logical")
