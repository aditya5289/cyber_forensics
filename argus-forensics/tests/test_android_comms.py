"""Tests for communications acquisition and ADB content parsing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.core.models import Category
from argus.parsers.android.adb_content import _parse_row_fields, _parse_rows
from argus.parsers.registry import ParseContext, dispatch, load_all


class TestAdbContentRowParser(unittest.TestCase):
    def test_commas_in_sms_body(self) -> None:
        blob = "address=+15551212, body=Hello, world, how are you?, date=1700000000000"
        fields = _parse_row_fields(blob)
        self.assertEqual(fields.get("address"), "+15551212")
        self.assertEqual(fields.get("body"), "Hello, world, how are you?")
        self.assertEqual(fields.get("date"), "1700000000000")

    def test_parse_rows_from_dump(self) -> None:
        text = (
            "Row: 0 _id=1, address=+1234, body=Hi, there, date=1700000000000\n"
            "Row: 1 _id=2, address=+5678, body=Plain, date=1700000000001\n"
        )
        rows = _parse_rows(text)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["body"], "Hi, there")

    def test_decode_sms_dump(self) -> None:
        load_all()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "logical" / "content" / "sms.txt"
            target.parent.mkdir(parents=True)
            target.write_text(
                "Row: 0 _id=1, address=+15550001, body=Test message, date=1700000000000\n",
                encoding="utf-8")
            ctx = ParseContext(evidence_root=root, platform="android")
            result = dispatch(target, ctx)
            self.assertGreater(len(result.artifacts), 0)
            self.assertEqual(result.artifacts[0].category, Category.MESSAGE)


class TestAndroidCommsModule(unittest.TestCase):
    def test_comms_providers_cover_core_types(self) -> None:
        from argus.acquire.android_comms import COMMS_PROVIDERS
        keys = {k for k, _, _ in COMMS_PROVIDERS}
        self.assertIn("sms", keys)
        self.assertIn("mms", keys)
        self.assertIn("contacts", keys)
        self.assertIn("calls", keys)
        self.assertIn("mms_part", keys)
