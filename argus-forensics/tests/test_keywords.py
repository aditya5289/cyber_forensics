"""Keyword lists, SMS Backup+ XML, and CSV export."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.analyze.keywords import aql_for_term, parse_keyword_text
from argus.core.models import Category
from argus.parsers.android.smsbackup import parse_smsbackup
from argus.parsers.registry import ParseContext, load_all


class TestKeywordParse(unittest.TestCase):
    def test_lines_comments_and_csv(self) -> None:
        terms = parse_keyword_text(
            "# ignore\ncash\n\"meet tonight\"\nalice, bob\n")
        self.assertEqual(terms, ["cash", "meet tonight", "alice", "bob"])

    def test_aql_quotes_phrase(self) -> None:
        self.assertEqual(aql_for_term("meet tonight"), '"meet tonight"')


class TestSmsBackupXml(unittest.TestCase):
    def test_sms_and_calls(self) -> None:
        load_all()
        xml = """<?xml version="1.0"?>
        <smses count="1">
          <sms protocol="0" address="+919555000111" date="1718121600000"
               type="1" body="Move the container tonight" contact_name="Ravi"/>
          <call number="+919555000222" date="1718121660000" duration="42"
                type="2" name="Asha"/>
        </smses>
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sms-20240611.xml"
            path.write_text(xml, encoding="utf-8")
            ctx = ParseContext(evidence_root=Path(tmp), platform="android")
            result = parse_smsbackup(path, ctx)
        cats = {a.category for a in result.artifacts}
        self.assertIn(Category.MESSAGE, cats)
        self.assertIn(Category.CALL, cats)
        bodies = [a.body for a in result.artifacts]
        self.assertTrue(any("container" in b for b in bodies))


if __name__ == "__main__":
    unittest.main()
