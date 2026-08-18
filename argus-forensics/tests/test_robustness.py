"""Behaviour on evidence that is damaged, truncated or hostile.

Every other test in this suite feeds ARGUS files built by the same mind that
wrote the parsers, which is circular reasoning: the tool passes because the
fixtures encode the assumptions the code already makes. Real evidence does not
cooperate — it is truncated mid-write, partially overwritten by later
allocations, damaged by a failing controller, or spliced together by a recovery
tool that guessed wrong.

Two properties are asserted against inputs nobody designed for:

  **No crash.** A parser that raises on exhibit 40 of 300 has silently removed a
  device from the examination. Worse, an unhandled traceback mid-acquisition is
  indistinguishable from "this phone was empty".

  **No fabricated content.** Garbage must not produce confident-looking records.
  A crash is at least visible; an invented message attributed to a real phone
  number is not, and that is what ends up in a report and then in a courtroom.

Note what the second property does *not* forbid. Cataloguing a zero-byte file as
a file that exists, marked `unrecognised`, is a true statement about the
evidence and must keep working. The line is between claims about a file's
existence and claims about content recovered from inside it.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus.core.models import Category
from argus.parsers.registry import ParseContext, dispatch, ensure_loaded

import corrupt
import make_platforms
import make_sim

# Categories representing content recovered from *inside* a file. A file
# inventory row is a fact about the filesystem, not a decode, so it is excluded.
CONTENT_CATEGORIES = {
    Category.MESSAGE, Category.CALL, Category.CONTACT, Category.WEB,
    Category.CHAT, Category.NOTE, Category.CALENDAR,
}

# Mutations that destroy the content entirely. Anything decoded from these is
# invented, by definition — there is nothing left to decode.
PURE_GARBAGE = {"random_noise", "repeated_byte", "empty", "tiny", "header_only"}

# Ten seeds keeps the shipped suite fast while still running ~1000 corrupted
# parses. Widen this locally when changing a parser — the sweep has been run to
# seed 25 (2,475 parses) with no further findings.
SEEDS = tuple(range(1, 11))


def _build_database(path: Path, table: str, ddl: str, insert: str,
                    rows: list) -> bytes:
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute(ddl)
    con.executemany(insert, rows)
    con.commit()
    con.execute(f"DELETE FROM {table} WHERE rowid % 5 = 0")
    con.commit()
    con.close()
    return path.read_bytes()


class CorruptEvidence(unittest.TestCase):
    """The full mutator sweep across every evidence type ARGUS claims to read."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="argus-fuzz-"))
        build = cls.tmp / "build"
        build.mkdir()
        cls.sources = {}

        cls.sources["mmssms.db"] = _build_database(
            build / "a.db", "sms",
            "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, "
            "date INTEGER, body TEXT, type INTEGER)",
            "INSERT INTO sms (address,date,body,type) VALUES (?,?,?,?)",
            [(f"+4477{i:06d}", 1700000000000 + i * 1000,
              f"Message {i} about the yard", i % 2) for i in range(120)])

        cls.sources["calllog.db"] = _build_database(
            build / "b.db", "calls",
            "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, "
            "date INTEGER, duration INTEGER, type INTEGER)",
            "INSERT INTO calls (number,date,duration,type) VALUES (?,?,?,?)",
            [(f"+4477{i:06d}", 1700000000000 + i * 1000, i * 7, i % 3 + 1)
             for i in range(100)])

        cls.sources["contacts2.db"] = _build_database(
            build / "c.db", "raw_contacts",
            "CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, "
            "display_name TEXT)",
            "INSERT INTO raw_contacts (display_name) VALUES (?)",
            [(f"Person {i}",) for i in range(80)])

        cls.sources["msgstore.db"] = _build_database(
            build / "d.db", "messages",
            "CREATE TABLE messages (_id INTEGER PRIMARY KEY, "
            "key_remote_jid TEXT, data TEXT, timestamp INTEGER, "
            "key_from_me INTEGER)",
            "INSERT INTO messages (key_remote_jid,data,timestamp,key_from_me) "
            "VALUES (?,?,?,?)",
            [(f"4477{i:06d}@s.whatsapp.net", f"Chat {i} regarding delivery",
              1700000000000 + i * 1000, i % 2) for i in range(110)])

        cls.sources["sim.bin"] = make_sim.build()

        platforms = make_platforms.build_all(str(cls.tmp / "platforms"))
        cls.sources["store.vol"] = Path(platforms["windowsphone"]).read_bytes()
        cls.sources["pbook.dat"] = Path(platforms["featurephone"]).read_bytes()
        cls.sources["idb.sqlite"] = Path(platforms["kaios"]).read_bytes()

        cls.sources["Info.plist"] = plistlib.dumps(
            {"Device Name": "iPhone", "IMEI": "350000000000006"},
            fmt=plistlib.FMT_BINARY)

        cls.work = cls.tmp / "work"
        cls.work.mkdir()
        cls.ctx = ParseContext(evidence_root=cls.work)
        ensure_loaded()

        # Run the sweep once; the tests below interrogate the outcome.
        cls.crashes = []
        cls.fabrications = []
        cls.parses = 0
        for name, data in cls.sources.items():
            for mutator, seed, mutated in corrupt.variants(data, seeds=SEEDS):
                cls.parses += 1
                target = cls.work / name
                target.write_bytes(mutated)
                try:
                    result = dispatch(target, cls.ctx)
                except Exception as exc:            # noqa: BLE001 - that is the point
                    cls.crashes.append(
                        f"{name} + {mutator}(seed={seed}): "
                        f"{type(exc).__name__}: {exc}")
                    continue
                if mutator in PURE_GARBAGE:
                    for artifact in result.artifacts:
                        if artifact.category in CONTENT_CATEGORIES:
                            cls.fabrications.append(
                                f"{name} + {mutator}(seed={seed}) produced "
                                f"{artifact.category.value}: "
                                f"{str(artifact.body)[:70]!r}")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_sweep_actually_ran(self) -> None:
        """Guard against a silently empty fixture making this suite vacuous."""
        expected = len(self.sources) * len(corrupt.MUTATORS) * len(SEEDS)
        self.assertEqual(self.parses, expected)
        self.assertGreater(self.parses, 400)

    def test_no_parser_crashes_on_damaged_evidence(self) -> None:
        self.assertEqual(
            self.crashes, [],
            "a parser raised on damaged evidence; in a real acquisition this "
            "silently drops the exhibit:\n  " + "\n  ".join(self.crashes[:15]))

    def test_no_content_is_invented_from_garbage(self) -> None:
        self.assertEqual(
            self.fabrications, [],
            "content was decoded from bytes that contain none:\n  "
            + "\n  ".join(self.fabrications[:15]))


class GarbageInNothingOut(unittest.TestCase):
    """Targeted cases, kept separate so a failure names the exact input."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="argus-garbage-"))
        cls.ctx = ParseContext(evidence_root=cls.tmp)
        ensure_loaded()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _content(self, filename: str, payload: bytes) -> list:
        target = self.tmp / filename
        target.write_bytes(payload)
        result = dispatch(target, self.ctx)
        return [a for a in result.artifacts if a.category in CONTENT_CATEGORIES]

    def test_random_bytes_named_as_a_sim_yield_nothing(self) -> None:
        payload = corrupt.mutate(make_sim.build(), "random_noise", 3)
        self.assertEqual(self._content("sim.bin", payload), [])

    def test_all_ff_padding_is_not_a_message(self) -> None:
        """0xFF unpacks to a printable GSM-7 character.

        This is the trap that made the SIM parser report runs of 'à' as
        recovered SMS.
        """
        self.assertEqual(self._content("sim.bin", b"\xff" * 8192), [])

    def test_all_zero_bytes_yield_nothing(self) -> None:
        self.assertEqual(self._content("sim.bin", b"\x00" * 8192), [])

    def test_sqlite_header_with_no_body_yields_nothing(self) -> None:
        self.assertEqual(
            self._content("mmssms.db", b"SQLite format 3\x00" + b"\x00" * 84),
            [])

    def test_empty_file_yields_no_content(self) -> None:
        for name in ("mmssms.db", "sim.bin", "store.vol", "pbook.dat"):
            self.assertEqual(self._content(name, b""), [], name)

    def test_empty_file_is_still_catalogued_as_a_file(self) -> None:
        """The counterpart. A file that exists is a fact about the evidence.

        Suppressing it would hide a file the device really held, and an
        examiner would have no way to know it had been dropped.
        """
        target = self.tmp / "IMG_0001.jpg"
        target.write_bytes(b"")
        result = dispatch(target, self.ctx)
        files = [a for a in result.artifacts if a.category == Category.FILE]
        self.assertEqual(len(files), 1)
        attributes = files[0].attributes
        self.assertEqual(attributes.get("size_bytes"), 0)
        # And it must not pretend to know what the file was.
        self.assertIn(attributes.get("file_type"), ("unrecognised", "unknown"))


class TextGatesRejectNoise(unittest.TestCase):
    """The gates that decide whether recovered bytes become evidence."""

    def test_random_letter_pair_is_not_a_contact_name(self) -> None:
        from argus.parsers.platforms import _plausible_alpha_tag
        # Two random consonants beside a plausible BCD field is what noise
        # produces; a real short name has a vowel.
        for noise in ("NW", "XZ", "KJ", "BT"):
            self.assertFalse(_plausible_alpha_tag(noise), noise)

    def test_genuine_short_names_still_accepted(self) -> None:
        from argus.parsers.platforms import _plausible_alpha_tag
        for name in ("Ma", "Jo", "Al", "Priya Nair", "Dockside Office"):
            self.assertTrue(_plausible_alpha_tag(name), name)

    def test_mojibake_is_not_a_message(self) -> None:
        from argus.parsers.platforms import _plausible_sms_text
        for noise in ("fh;-?6DaÆΓ31ik4æGW:NUx-/9)¥/7Ö=XÇ-ΘN§BS+",
                      "x9ßh8XòÑ<x8Θòæ:zÆh42Γòñ(;Θ¿",
                      "à" * 40):
            self.assertFalse(_plausible_sms_text(noise), noise[:30])

    def test_genuine_messages_still_accepted(self) -> None:
        from argus.parsers.platforms import _plausible_sms_text
        for text in ("The shipment arrives at berth 4 tonight",
                     "Burn the manifest once it is signed",
                     "Nobody can trace this SIM to me",
                     "Meet me at the dock at nine",
                     "call me back when you can"):
            self.assertTrue(_plausible_sms_text(text), text)

    def test_truncated_firmware_banner_is_rejected(self) -> None:
        """A carved fragment can begin mid-word.

        "Copyright MediaTek" arrived from the corruption sweep as
        "kCopyright MediaTek" and defeated a boundary-anchored marker, so the
        markers are matched anywhere in the string.
        """
        from argus.parsers.platforms import looks_like_message
        for banner in ("kCopyright MediaTek Inc All rights reser",
                       "xSOFTWARE Microsoft Windows Phone Messaging",
                       "6MTK6261 NVRAM LID BIN VER 1 0 0"):
            self.assertFalse(looks_like_message(banner), banner[:34])

    def test_text_without_vowels_is_rejected(self) -> None:
        """Consonant soup is a hash fragment, not a sentence."""
        from argus.parsers.platforms import _plausible_sms_text
        self.assertFalse(_plausible_sms_text("bcdfg hjklm npqrs tvwxz"))


class ReaderFailsCleanly(unittest.TestCase):
    """Construction failures must release resources and explain themselves.

    Both defects here were found by the corruption sweep, not by design review.
    """

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-reader-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _open(self, name: str, payload: bytes):
        from argus.parsers.sqlite_reader import ForensicSQLite
        target = self.dir / name
        target.write_bytes(payload)
        return ForensicSQLite(target)

    def test_zeroed_page_size_is_refused_not_a_zero_division(self) -> None:
        """Every later calculation divides by the page size.

        An invalid value does not yield a wrong answer, it yields a
        ZeroDivisionError several frames down that reads like a bug in ARGUS
        rather than a fact about the evidence.
        """
        from argus.core.errors import ParserError
        with self.assertRaises(ParserError) as caught:
            self._open("zero.db", b"SQLite format 3\x00" + b"\x00" * 84)
        self.assertIn("page size", str(caught.exception))

    def test_non_power_of_two_page_size_is_refused(self) -> None:
        import struct
        from argus.core.errors import ParserError
        for bad in (3, 100, 5000):
            with self.assertRaises(ParserError, msg=str(bad)):
                self._open(f"bad{bad}.db",
                           b"SQLite format 3\x00" + struct.pack(">H", bad)
                           + b"\x00" * 82)

    def test_every_valid_page_size_is_accepted(self) -> None:
        import struct
        for size in (512, 1024, 2048, 4096, 8192, 16384, 32768):
            reader = self._open(f"ok{size}.db",
                                b"SQLite format 3\x00"
                                + struct.pack(">H", size) + b"\x00" * 82)
            try:
                self.assertEqual(reader.page_size, size)
            finally:
                reader.close()

    def test_65536_is_encoded_as_one(self) -> None:
        """The field is 16 bits, so the largest legal page size wraps to 1."""
        import struct
        reader = self._open("big.db", b"SQLite format 3\x00"
                            + struct.pack(">H", 1) + b"\x00" * 82)
        try:
            self.assertEqual(reader.page_size, 65536)
        finally:
            reader.close()

    def test_failed_construction_does_not_leak_a_file_handle(self) -> None:
        """A pass over an exhibit full of unreadable files must not exhaust fds.

        Running out of descriptors partway through an acquisition looks like a
        corrupt exhibit, not like a resource bug in the reader.
        """
        import gc
        import warnings
        from argus.core.errors import ParserError

        payloads = [b"", b"not sqlite", b"SQLite format 3\x00" + b"\x00" * 84,
                    b"\xff" * 4096]
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            for round_number in range(40):
                for index, payload in enumerate(payloads):
                    try:
                        self._open(f"leak{index}.db", payload).close()
                    except ParserError:
                        pass
            gc.collect()


if __name__ == "__main__":
    unittest.main()
