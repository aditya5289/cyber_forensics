"""dumpsys communication parser tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.parsers.android.dumpsys_comms import parse_dumpsys
from argus.parsers.registry import ParseContext


class TestDumpsysComms(unittest.TestCase):
    def test_call_log_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "call_log.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "CallLog calls:\n"
                "number=+919876543210, date=1700000000000, duration=42\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertEqual(res.artifacts[0].category.value, "Calls")

    def test_location_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dumpsys" / "location.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Last known location: latitude=12.971600 longitude=77.594600\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            res = parse_dumpsys(path, ctx)
            self.assertGreaterEqual(len(res.artifacts), 1)
            self.assertIsNotNone(res.artifacts[0].latitude)


if __name__ == "__main__":
    unittest.main()
