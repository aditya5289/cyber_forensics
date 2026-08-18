"""Behaviour at evidence scale, and the integrity guarantee that pays for it.

The reader no longer copies every database before opening it, and no longer
reads it into memory. Both changes are what make a multi-gigabyte exhibit
workable, and both touch the one property that must never bend: the evidence
file is not modified by examining it.

So the integrity tests here are not incidental to the performance work — they
are the reason the performance work is allowed to stand. A tool that is fast
because it stopped protecting the evidence is not faster, it is broken.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from argus.parsers.sqlite_reader import ForensicSQLite, MappedFile


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_db(path: Path, rows: int = 500, wal: bool = False):
    """Build a database. With ``wal=True`` the open connection is returned.

    Closing a WAL connection checkpoints and removes the -wal file, so a fixture
    that closes cannot produce the state this test is about. A device seized
    while an app is running is exactly the uncheckpointed case, and it is the
    reason the reader still copies at all.
    """
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA journal_mode={'WAL' if wal else 'DELETE'}")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, "
                "date INTEGER, body TEXT)")
    con.executemany(
        "INSERT INTO sms (address,date,body) VALUES (?,?,?)",
        [(f"+44770090{i:04d}", 1700000000000 + i, f"Message {i} about the run")
         for i in range(rows)])
    con.commit()
    if not wal:
        con.close()
        return path
    con.execute("INSERT INTO sms (address,date,body) VALUES "
                "('+447700999999', 1700000999999, 'Uncheckpointed record')")
    con.commit()
    return path, con


class EvidenceIsNeverModified(unittest.TestCase):
    """The guarantee the whole tool rests on."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-scale-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_reading_in_place_does_not_alter_the_file(self) -> None:
        db = _make_db(self.dir / "mmssms.db")
        before = _digest(db)
        before_mtime = db.stat().st_mtime_ns

        with ForensicSQLite(db) as reader:
            list(reader.rows("sms"))
            list(reader.carve("sms"))
            reader.page(1)

        self.assertEqual(_digest(db), before,
                         "examining the database changed its bytes")
        self.assertEqual(db.stat().st_mtime_ns, before_mtime,
                         "examining the database changed its mtime")

    def test_no_stray_sidecars_are_created_next_to_the_evidence(self) -> None:
        """A read-only connection can still leave a -wal or -shm behind."""
        db = _make_db(self.dir / "contacts2.db")
        with ForensicSQLite(db) as reader:
            list(reader.rows("sms"))
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(Path(str(db) + suffix).exists(),
                             f"reader created a {suffix} beside the evidence")

    def test_database_with_sidecars_is_copied_before_opening(self) -> None:
        """WAL replay writes, so that case must work on a copy, not in place."""
        db, con = _make_db(self.dir / "walstore.db", wal=True)
        try:
            self.assertTrue(Path(str(db) + "-wal").exists(),
                            "fixture did not produce a WAL")
            before = _digest(db)
            with ForensicSQLite(db) as reader:
                self.assertTrue(
                    reader._copied,
                    "a database with a WAL must not be opened in place")
                list(reader.rows("sms"))
            self.assertEqual(_digest(db), before)
        finally:
            con.close()

    def test_database_without_sidecars_is_not_copied(self) -> None:
        db = _make_db(self.dir / "plain.db")
        with ForensicSQLite(db) as reader:
            self.assertFalse(reader._copied)
            self.assertEqual(Path(reader._work), db)


class MemoryIsDecoupledFromEvidenceSize(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-mapped-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_mapped_file_exposes_the_bytes_interface_used(self) -> None:
        target = self.dir / "blob.bin"
        payload = b"SQLite format 3\x00" + os.urandom(4096)
        target.write_bytes(payload)

        mapped = MappedFile(target)
        try:
            self.assertEqual(len(mapped), len(payload))
            self.assertTrue(mapped.startswith(b"SQLite format 3\x00"))
            self.assertEqual(mapped[16:32], payload[16:32])
            self.assertEqual(mapped[:4], payload[:4])
            self.assertEqual(mapped.find(b"SQLite"), 0)
        finally:
            mapped.close()

    def test_empty_file_does_not_raise(self) -> None:
        target = self.dir / "empty.bin"
        target.write_bytes(b"")
        mapped = MappedFile(target)
        try:
            self.assertEqual(len(mapped), 0)
            self.assertEqual(mapped[0:10], b"")
            self.assertFalse(mapped.startswith(b"x"))
        finally:
            mapped.close()

    def test_close_is_idempotent(self) -> None:
        target = self.dir / "x.bin"
        target.write_bytes(b"0" * 128)
        mapped = MappedFile(target)
        mapped.close()
        mapped.close()

    def test_reader_does_not_hold_the_database_in_memory(self) -> None:
        """`raw` must be a view, not a copy.

        This is the assertion that stops the mmap change being quietly reverted
        to `read_bytes()` by a later edit that looks harmless.
        """
        db = _make_db(self.dir / "view.db")
        with ForensicSQLite(db) as reader:
            self.assertIsInstance(reader.raw, MappedFile)
            self.assertNotIsInstance(reader.raw, bytes)


class ParallelIngestIsDeterministic(unittest.TestCase):
    """Concurrency must not change what the tool reports.

    Two runs over the same evidence have to produce the same artifacts in the
    same order. If ordering varied with thread scheduling the container hash
    would vary too, and an examiner could not reproduce their own result — which
    is the first thing a defence expert will try to do.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = Path(tempfile.mkdtemp(prefix="argus-determinism-"))
        for i in range(12):
            _make_db(cls.dir / f"store{i:02d}.db", rows=60)
        (cls.dir / "notes.txt").write_bytes(b"handover at the usual place\n" * 20)
        (cls.dir / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(2048))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _run(self, workers):
        from argus.acquire.filesystem import ingest_tree
        from argus.parsers.registry import ParseContext
        ctx = ParseContext(evidence_root=self.dir)
        return ingest_tree(self.dir, ctx, container=None, workers=workers)

    def _fingerprint(self, result):
        return [
            (a.category.value, a.subtype, a.body, a.source_path, a.source_table)
            for a in result.artifacts
        ]

    def test_serial_and_parallel_agree_exactly(self) -> None:
        serial = self._run(1)
        parallel = self._run(8)
        self.assertEqual(serial.files_parsed, parallel.files_parsed)
        self.assertEqual(serial.deleted_recovered, parallel.deleted_recovered)
        self.assertEqual(self._fingerprint(serial), self._fingerprint(parallel))

    def test_repeated_parallel_runs_agree(self) -> None:
        first = self._fingerprint(self._run(8))
        second = self._fingerprint(self._run(8))
        self.assertEqual(first, second)

    def test_by_parser_counts_match(self) -> None:
        self.assertEqual(self._run(1).by_parser, self._run(6).by_parser)


class RegistryIsCompleteBeforeAnyFileIsClassified(unittest.TestCase):
    """Output must not depend on how long the process has been running.

    Parser modules self-register at import time. Until this was made explicit
    they were imported incidentally, part-way through the first ingest, so files
    examined early in a fresh process were matched against a smaller registry
    than files examined later — and the first exhibit of a session could be
    attributed differently from the same exhibit ingested second.
    """

    def test_registry_is_stable_across_repeated_calls(self) -> None:
        from argus.parsers.registry import all_parsers
        first = [s.name for s in all_parsers()]
        second = [s.name for s in all_parsers()]
        self.assertEqual(first, second)
        self.assertGreater(len(first), 20)

    def test_first_ingest_matches_the_second(self) -> None:
        from argus.acquire.filesystem import ingest_tree
        from argus.parsers.registry import ParseContext

        directory = Path(tempfile.mkdtemp(prefix="argus-firstrun-"))
        try:
            _make_db(directory / "mmssms.db", rows=40)
            (directory / "notes.txt").write_bytes(b"meet at the yard\n" * 30)
            ctx = ParseContext(evidence_root=directory)
            first = ingest_tree(directory, ctx, container=None, workers=1)
            second = ingest_tree(directory, ctx, container=None, workers=1)
            self.assertEqual(first.by_parser, second.by_parser)
            self.assertEqual(first.files_parsed, second.files_parsed)
        finally:
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
