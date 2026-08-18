"""The same conversation, stored the way successive app versions stored it.

A parser written against one schema generation and tested against the same
generation proves nothing about the next handset that arrives. The usual failure
is silent: the query matches no rows, the parser reports zero artifacts, and the
report says the device held no messages.

Each variant here plants identical content in a different schema, so the tests
can assert the same facts come out regardless of which generation produced the
file. The Google Messages case is not hypothetical — `bugle_db` is the default
SMS store on modern Android, and it was returning a message per row with an
empty body until this suite caught it.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus.core.models import Category, Recovery
from argus.parsers.registry import ParseContext, dispatch, ensure_loaded

import make_variants as variants


class MessageSchemaVariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="argus-variants-"))
        cls.built = variants.build_all(cls.tmp)
        ensure_loaded()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _parse(self, label: str):
        path = self.built[label]
        return dispatch(path, ParseContext(evidence_root=path.parent))

    def _messages(self, label: str):
        return [a for a in self._parse(label).artifacts
                if a.category == Category.MESSAGE]

    def _bodies(self, label: str) -> set:
        return {str(a.body).strip() for a in self._messages(label)}

    # ------------------------------------------------------------- coverage
    def test_every_variant_recovers_every_live_message(self) -> None:
        expected = {body for _peer, body, _out, _ts in variants.CONVERSATION}
        for label in variants.MESSAGE_VARIANTS:
            got = self._bodies(label)
            missing = expected - got
            self.assertEqual(missing, set(),
                             f"{label} lost {len(missing)} message(s): "
                             f"{sorted(missing)[:2]}")

    def test_every_variant_recovers_the_deleted_message(self) -> None:
        """Deletion works differently per schema.

        In bugle the message row survives while its text part is removed, so
        recovery means carving a different table from the one the message lives
        in.
        """
        for label in variants.MESSAGE_VARIANTS:
            self.assertIn(variants.DELETED[1], self._bodies(label),
                          f"{label} did not recover the deleted message")

    def test_no_variant_returns_a_message_with_an_empty_body(self) -> None:
        """The failure this suite was written to catch.

        A parser that walks every row of an unfamiliar schema emits one artifact
        each with nothing in it. The count looks healthy; the evidence is
        absent; and a report reads "12 messages" with twelve blanks under it.
        """
        for label in variants.MESSAGE_VARIANTS:
            blank = [a for a in self._messages(label)
                     if not str(a.body).strip()
                     and not a.attributes.get("body_unrecoverable")]
            self.assertEqual(
                blank, [],
                f"{label} produced {len(blank)} message(s) with no body and no "
                f"explanation")

    def test_correspondent_is_recovered_in_every_variant(self) -> None:
        expected = {peer.lstrip("+")
                    for peer, _b, _o, _t in variants.ALL_MESSAGES}
        for label in variants.MESSAGE_VARIANTS:
            seen = set()
            for artifact in self._messages(label):
                for party in artifact.participants:
                    if party.identifier:
                        seen.add(party.identifier.lstrip("+").split("@")[0])
            self.assertTrue(
                expected & seen,
                f"{label} recovered no correspondent at all; the messages "
                f"cannot be attributed to anyone")

    def test_timestamps_land_in_the_right_decade(self) -> None:
        """bugle stores microseconds where the legacy store used milliseconds.

        Reading one as the other dates every message to 1970. A timeline
        anchored to the wrong decade is worse than no timeline, because it looks
        usable.
        """
        lo = 1_600_000_000_000_000      # 2020, in microseconds
        hi = 1_900_000_000_000_000      # 2030
        for label in variants.MESSAGE_VARIANTS:
            for artifact in self._messages(label):
                if artifact.timestamp is None:
                    continue
                self.assertTrue(
                    lo < artifact.timestamp < hi,
                    f"{label}: timestamp {artifact.timestamp} is outside the "
                    f"plausible range — the epoch was misread")


class CallSchemaVariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="argus-callvar-"))
        cls.built = variants.build_all(cls.tmp)
        ensure_loaded()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_standard_call_log_is_fully_decoded(self) -> None:
        path = self.built["calls_legacy"]
        result = dispatch(path, ParseContext(evidence_root=path.parent))
        calls = [a for a in result.artifacts if a.category == Category.CALL]
        numbers = {p.identifier.lstrip("+")
                   for a in calls for p in a.participants if p.identifier}
        for expected, _ts, _dur, _type in variants.ALL_CALLS:
            self.assertIn(expected.lstrip("+"), numbers)

    def test_deleted_call_is_recovered(self) -> None:
        path = self.built["calls_legacy"]
        result = dispatch(path, ParseContext(evidence_root=path.parent))
        carved = [a for a in result.artifacts
                  if a.category == Category.CALL
                  and a.recovery != Recovery.ALLOCATED]
        self.assertTrue(carved, "the deleted call was not recovered")

    def test_unrecognised_schema_is_surfaced_not_dropped(self) -> None:
        """An unknown vendor layout must still appear somewhere.

        Guessing at column synonyms would invent structure. Reporting the file
        with its real table and row counts tells the examiner it exists and is
        worth looking at by hand, which is the honest answer.
        """
        path = self.built["calls_renamed"]
        result = dispatch(path, ParseContext(evidence_root=path.parent))
        self.assertTrue(result.artifacts,
                        "a renamed schema vanished from the examination")
        described = " ".join(str(a.body) for a in result.artifacts)
        self.assertIn("calllog.db", described)


class FallbackWhenAParserClaimsButDecodesNothing(unittest.TestCase):
    """A parser claiming a file suppresses the generic survey.

    That is right when it succeeds and wrong when it does not: a vendor renames
    a column, the specific parser matches the filename, recognises nothing, and
    returns empty — and the fallback that would at least have surveyed the
    tables never runs. The file then appears in no view at all, which an
    examiner cannot distinguish from the device never having held it.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="argus-fallback-"))
        ensure_loaded()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _hostile_sms_store(self) -> Path:
        """Named and shaped so `android.sms` claims it, but every column
        renamed so it decodes nothing."""
        path = self.tmp / "mmssms.db"
        con = sqlite3.connect(path)
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE sms (pk INTEGER PRIMARY KEY, peer TEXT, "
                    "when_us INTEGER, content TEXT, dir INTEGER)")
        con.executemany(
            "INSERT INTO sms (peer,when_us,content,dir) VALUES (?,?,?,?)",
            [(f"+4477009001{i:02d}", 1700000000000 + i * 1000,
              f"Hidden message {i} about the drop", i % 2) for i in range(12)])
        con.commit()
        con.close()
        return path

    def test_the_file_is_not_silently_lost(self) -> None:
        path = self._hostile_sms_store()
        result = dispatch(path, ParseContext(evidence_root=self.tmp))
        surveyed = [a for a in result.artifacts
                    if a.category == Category.APP]
        self.assertTrue(
            surveyed,
            "a claimed-but-undecoded file produced no survey, so it is "
            "invisible in every view")

    def test_the_examiner_is_told_why(self) -> None:
        path = self._hostile_sms_store()
        result = dispatch(path, ParseContext(evidence_root=self.tmp))
        joined = " ".join(result.notes)
        self.assertIn("decoded nothing", joined)
        self.assertIn("variant", joined)

    def test_a_working_parser_does_not_trigger_the_fallback(self) -> None:
        """The fallback must not fire when the specific parser succeeded,
        or every file would carry a redundant survey."""
        path = self.tmp / "mmssms.db"
        con = sqlite3.connect(path)
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, "
                    "date INTEGER, body TEXT, type INTEGER)")
        con.executemany(
            "INSERT INTO sms (address,date,body,type) VALUES (?,?,?,?)",
            [(f"+4477{i:06d}", 1700000000000 + i * 1000,
              f"Message {i} about the yard", i % 2) for i in range(10)])
        con.commit()
        con.close()

        result = dispatch(path, ParseContext(evidence_root=self.tmp))
        surveys = [a for a in result.artifacts
                   if a.category == Category.APP]
        self.assertEqual(surveys, [])
        self.assertNotIn("decoded nothing", " ".join(result.notes))


if __name__ == "__main__":
    unittest.main()
