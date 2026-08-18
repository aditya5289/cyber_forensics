"""MTP acquisition, and the shortfall Explorer never mentions.

Dragging a phone's storage out in Explorer works, and produces no hashes, no
record of what was taken, and no record of what was missed. That last gap is the
dangerous one: MTP transfers fail individually and quietly, so an examiner who
copies 4,000 files and receives 3,960 has no way to know. Concluding a
photograph was absent when the copy dropped it is an error that survives all the
way into a report.

These tests hold the two properties that make this an acquisition rather than a
file copy: every arrival is hashed, and every listed file that did not arrive is
named.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Optional

from argus.acquire import mtp


class _DoneProc:
    """Fake subprocess that finished immediately (for unit tests)."""

    def __init__(self) -> None:
        self.stdout = StringIO("DONE|0\n")
        self.stderr = StringIO("")

    def poll(self) -> int:
        return 0

    def wait(self, timeout: Optional[float] = None) -> int:
        return 0

    def communicate(self, timeout: Optional[float] = None) -> tuple[str, str]:
        return "DONE|0\n", ""


class Reconciliation(unittest.TestCase):
    """Comparing what was listed against what landed."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-mtp-"))
        self.dest = self.dir / "dest"
        self.dest.mkdir()
        self._real_available = mtp.available
        self._real_list = mtp.list_tree
        self._real_shell = mtp._powershell
        self._real_start = mtp._powershell_start
        mtp.available = lambda: True
        mtp._powershell = lambda script, timeout=900: ("DONE", "")
        mtp._powershell_start = lambda script, timeout=14400: (_DoneProc(), "")

    def tearDown(self) -> None:
        mtp.available = self._real_available
        mtp.list_tree = self._real_list
        mtp._powershell = self._real_shell
        mtp._powershell_start = self._real_start
        shutil.rmtree(self.dir, ignore_errors=True)

    def _land(self, relative: str, payload: bytes) -> None:
        target = self.dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    def test_a_complete_copy_reports_nothing_missing(self) -> None:
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "DCIM/IMG_001.jpg", "size": 10},
            {"kind": "F", "path": "DCIM/IMG_002.jpg", "size": 10},
        ]
        self._land("DCIM/IMG_001.jpg", b"0123456789")
        self._land("DCIM/IMG_002.jpg", b"0123456789")

        result = mtp.acquire("PHONE", self.dest)
        self.assertEqual(result.files_copied, 2)
        self.assertEqual(result.missing, [])
        self.assertTrue(result.complete)

    def test_a_dropped_file_is_named(self) -> None:
        """The whole point. Explorer would report success and move on."""
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "DCIM/IMG_001.jpg", "size": 10},
            {"kind": "F", "path": "DCIM/IMG_LOCKED.jpg", "size": 4096},
        ]
        self._land("DCIM/IMG_001.jpg", b"0123456789")

        result = mtp.acquire("PHONE", self.dest)
        self.assertFalse(result.complete)
        self.assertEqual(len(result.missing), 1)
        self.assertEqual(result.missing[0]["path"], "DCIM/IMG_LOCKED.jpg")

    def test_the_shortfall_carries_a_warning_not_just_a_count(self) -> None:
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "a.jpg", "size": 1},
            {"kind": "F", "path": "b.jpg", "size": 1},
        ]
        self._land("a.jpg", b"x")
        result = mtp.acquire("PHONE", self.dest)
        joined = " ".join(result.warnings)
        self.assertIn("did not arrive", joined)

    def test_absence_is_never_stated_as_a_finding(self) -> None:
        """A missing file means the copy failed, not that the phone lacked it.

        Reversing those two is how a report ends up asserting something the
        evidence does not support.
        """
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "gone.jpg", "size": 1}]
        result = mtp.acquire("PHONE", self.dest)
        self.assertIn("not necessarily absent", result.method_note)
        self.assertIn("Do not treat their absence",
                      " ".join(result.warnings))

    def test_copy_script_waits_for_expected_file_count(self) -> None:
        """CopyHere is async; the script must embed the expected file total."""
        captured: list[str] = []

        def fake_start(script: str, timeout: int = 14400):
            captured.append(script)
            return _DoneProc(), ""

        mtp._powershell_start = fake_start
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "a.jpg", "size": 1},
            {"kind": "F", "path": "b.jpg", "size": 1},
        ]
        self._land("a.jpg", b"x")
        self._land("b.jpg", b"y")
        result = mtp.acquire("PHONE", self.dest)
        self.assertEqual(result.files_copied, 2)
        self.assertIn("$expectedFiles = 2", captured[0])
        self.assertIn("Wait-ForCopySettle", captured[0])
        self.assertIn("Copy-MtpItem", captured[0])
        self.assertIn("Copy-MtpFolderChildren", captured[0])
        self.assertIn("Get-CopyPriority", captured[0])
        self.assertIn("CopyHere", captured[0])
        self.assertIn("DoEvents", captured[0])
        self.assertIn("$skipExisting = $true", captured[0])

    def test_directories_are_not_counted_as_missing_files(self) -> None:
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "D", "path": "DCIM", "size": 0},
            {"kind": "F", "path": "DCIM/a.jpg", "size": 1},
        ]
        self._land("DCIM/a.jpg", b"x")
        self.assertEqual(mtp.acquire("PHONE", self.dest).missing, [])


class Hashing(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-mtp-hash-"))
        self.dest = self.dir / "dest"
        self.dest.mkdir()
        self._real_available = mtp.available
        self._real_list = mtp.list_tree
        self._real_shell = mtp._powershell
        self._real_start = mtp._powershell_start
        mtp.available = lambda: True
        mtp._powershell = lambda script, timeout=900: ("DONE", "")
        mtp._powershell_start = lambda script, timeout=14400: (_DoneProc(), "")
        mtp.list_tree = lambda name, max_depth=6: [
            {"kind": "F", "path": "photo.jpg", "size": 5}]

    def tearDown(self) -> None:
        mtp.available = self._real_available
        mtp.list_tree = self._real_list
        mtp._powershell = self._real_shell
        mtp._powershell_start = self._real_start
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_every_arrival_is_hashed(self) -> None:
        payload = b"hello"
        (self.dest / "photo.jpg").write_bytes(payload)
        result = mtp.acquire("PHONE", self.dest)
        self.assertEqual(result.hashes["photo.jpg"],
                         hashlib.sha256(payload).hexdigest())

    def test_hashing_can_be_skipped_deliberately(self) -> None:
        (self.dest / "photo.jpg").write_bytes(b"hello")
        result = mtp.acquire("PHONE", self.dest, hash_files=False)
        self.assertEqual(result.hashes, {})

    def test_manifest_records_hashes_and_shortfall(self) -> None:
        (self.dest / "photo.jpg").write_bytes(b"hello")
        result = mtp.acquire("PHONE", self.dest)
        target = mtp.write_manifest(result, self.dir / "manifest.json")
        data = json.loads(target.read_text(encoding="utf-8"))
        self.assertIn("hashes", data)
        self.assertIn("missing", data)
        self.assertIn("method_note", data)
        self.assertEqual(data["format"], "argus-mtp-manifest/1")


class StatesWhatItIs(unittest.TestCase):
    """MTP is a media-provider copy, and the report must not imply otherwise."""

    def test_the_method_note_disclaims_being_an_image(self) -> None:
        self.assertIn("not an image", mtp.METHOD_NOTE)

    def test_the_method_note_names_what_it_cannot_reach(self) -> None:
        self.assertIn("/data/data", mtp.METHOD_NOTE)

    def test_the_method_note_warns_about_access_times(self) -> None:
        self.assertIn("access time", mtp.METHOD_NOTE)


class ParallelJobs(unittest.TestCase):
    def test_single_volume_returns_one_volume_job(self) -> None:
        listing = [
            {"kind": "F", "path": "Internal storage/DCIM/a.jpg", "size": 1},
            {"kind": "F", "path": "Internal storage/DCIM/b.jpg", "size": 1},
            {"kind": "F", "path": "Internal storage/Download/c.pdf", "size": 1},
            {"kind": "F", "path": "Internal storage/Download/d.pdf", "size": 1},
        ]
        jobs = mtp._parallel_copy_jobs(listing, min_files=1)
        self.assertEqual(jobs, [("Internal storage", 4)])

    def test_two_volumes_return_two_jobs(self) -> None:
        listing = [
            {"kind": "F", "path": "Internal storage/DCIM/a.jpg", "size": 1},
            {"kind": "F", "path": "SD card/Music/b.mp3", "size": 1},
        ]
        jobs = mtp._parallel_copy_jobs(listing)
        paths = {j[0] for j in jobs}
        self.assertIn("Internal storage", paths)
        self.assertIn("SD card", paths)

    def test_mtp_worker_cap(self) -> None:
        self.assertLessEqual(mtp._mtp_workers(20, True), 3)
        self.assertLessEqual(mtp._mtp_workers(20, False), 2)
        self.assertEqual(mtp._mtp_workers(1, True), 1)

    def test_coalesce_merges_folder_jobs_to_volume(self) -> None:
        raw = [
            ("Internal storage/DCIM", 0),
            ("Internal storage/Download", 0),
            ("Internal storage/Android", 0),
        ]
        merged = mtp._coalesce_copy_jobs(raw)
        self.assertEqual(merged, [("Internal storage", 0)])

    def test_no_parallel_for_flat_device_root(self) -> None:
        listing = [{"kind": "F", "path": "a.jpg", "size": 1}]
        self.assertEqual(mtp._parallel_copy_jobs(listing), [])

    def test_list_copy_jobs_returns_volumes(self) -> None:
        real_vol = mtp.list_volumes
        mtp.list_volumes = lambda name: ["Internal storage", "SD card"]
        try:
            jobs = mtp.list_copy_jobs("PHONE")
        finally:
            mtp.list_volumes = real_vol
        self.assertEqual([j[0] for j in jobs],
                         ["Internal storage", "SD card"])


class ProgressCopyText(unittest.TestCase):
    def test_never_says_of_zero(self) -> None:
        msg = mtp._copy_progress_message(407, 0, jobs_done=0, jobs_total=1)
        self.assertNotIn("of 0", msg)
        self.assertIn("407", msg)
        self.assertIn("0/1", msg)

    def test_known_total_uses_denominator(self) -> None:
        msg = mtp._copy_progress_message(100, 800)
        self.assertIn("100 of 800", msg)

    def test_folder_denominator_while_listing(self) -> None:
        tot = mtp._copy_progress_total(0, 407, 0, 1)
        self.assertGreater(tot, 0)
        self.assertNotEqual(tot, 0)

    def test_progress_total_grows_with_arrivals(self) -> None:
        self.assertEqual(mtp._copy_progress_total(2908, 5950, 1, 1), 5950)

    def test_resolve_listed_path_case_insensitive(self) -> None:
        arrived = {"Internal storage/DCIM/Photo.JPG": Path("/x")}
        by_lower, by_tail = mtp._build_arrival_lookup(arrived)
        hit = mtp._resolve_listed_path(
            "internal storage/dcim/photo.jpg", arrived, by_lower, by_tail)
        self.assertEqual(hit, "Internal storage/DCIM/Photo.JPG")

    def test_stable_polls_scale_with_shortfall(self) -> None:
        self.assertGreater(
            mtp._stable_polls_needed(10000, 5000, 4), 20)

    def test_stalled_progress_message(self) -> None:
        msg = mtp._copy_progress_message(
            5954, 7130, bytes_cur=332_700_000, bytes_total=1_040_000_000,
            stalled=True, elapsed="2m 10s elapsed")
        self.assertIn("Stalled", msg)
        self.assertIn("recovery", msg)
        self.assertNotIn("Copying", msg)

    def test_powershell_uses_utf8_encoding(self) -> None:
        seen: Dict[str, Any] = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen.update(kwargs)
            class _Done:
                stdout = "ok"
                stderr = ""
            return _Done()

        real_run = subprocess.run
        try:
            subprocess.run = fake_run
            out, _ = mtp._powershell("Write-Output 'test'")
            self.assertEqual(out, "ok")
            self.assertEqual(seen.get("encoding"), "utf-8")
            self.assertEqual(seen.get("errors"), "replace")
            self.assertIn("OutputEncoding", seen["cmd"][-1])
        finally:
            subprocess.run = real_run

    def test_skip_retry_when_copy_exceeded_inventory(self) -> None:
        expected = {f"f{i}.jpg": 1 for i in range(100)}
        arrived = {f"g{i}.jpg": Path("/x") for i in range(150)}
        missing = [{"path": "a.jpg", "size": 1}]
        self.assertFalse(
            mtp._should_retry_missing(expected, arrived, missing))


class FolderGapDetection(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-mtp-gap-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_missing_top_folders_detects_absent(self) -> None:
        listing = [
            {"kind": "F", "path": f"Internal storage/Android/data/f{i}.txt",
             "size": 1}
            for i in range(10)
        ] + [
            {"kind": "F", "path": "Internal storage/DCIM/b.jpg", "size": 1},
        ]
        dest = self.dir / "dest"
        dest.mkdir()
        (dest / "Internal storage" / "DCIM").mkdir(parents=True)
        (dest / "Internal storage" / "DCIM" / "b.jpg").write_bytes(b"x")
        gaps = mtp._missing_top_folders(dest, listing, "Internal storage")
        names = [g[0] for g in gaps]
        self.assertTrue(any("Android" in n for n in names))

    def test_manifest_includes_completeness(self) -> None:
        result = mtp.AcquisitionResult(
            files_copied=80, files_listed=100,
            missing=[{"path": "Internal storage/Android/x", "size": 1}] * 5)
        path = mtp.write_manifest(result, self.dir / "manifest.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["completeness_pct"], 80.0)
        self.assertTrue(data.get("top_missing_folders"))


class DegradesQuietly(unittest.TestCase):
    def test_unsupported_platform_explains_the_alternative(self) -> None:
        real = mtp.available
        mtp.available = lambda: False
        try:
            result = mtp.acquire("PHONE", tempfile.mkdtemp())
            self.assertTrue(result.warnings)
            self.assertIn("mount the handset", " ".join(result.warnings))
        finally:
            mtp.available = real

    def test_no_devices_is_not_an_error(self) -> None:
        real = mtp.available
        mtp.available = lambda: False
        try:
            self.assertEqual(mtp.devices(), [])
        finally:
            mtp.available = real


if __name__ == "__main__":
    unittest.main()
