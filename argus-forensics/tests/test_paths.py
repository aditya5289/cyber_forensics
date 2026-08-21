"""Host path helpers for Windows long paths and adb destinations."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from argus.core import paths


class TestHostPaths(unittest.TestCase):
    def test_win_path_error_detects_adb_cannot_create(self) -> None:
        msg = ("adb: error: cannot create "
               "'C:\\Users\\Administrator\\ARGUS\\cases\\...\\com.whatsapp\\Wh")
        self.assertTrue(paths.is_win_path_error(msg))
        self.assertFalse(paths.is_win_path_error("permission denied"))

    def test_rmdir_if_empty_leaves_populated_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            filled = Path(tmp) / "filled"
            filled.mkdir()
            (filled / "a.bin").write_bytes(b"x")
            self.assertTrue(paths.rmdir_if_empty(empty))
            self.assertFalse(empty.exists())
            self.assertFalse(paths.rmdir_if_empty(filled))
            self.assertTrue((filled / "a.bin").exists())

    def test_relocate_tree_copies_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            dst = Path(tmp) / "dst" / "nested"
            (src / "WhatsApp" / "Media").mkdir(parents=True)
            (src / "WhatsApp" / "Media" / "IMG.jpg").write_bytes(b"abc")
            paths.relocate_tree(src, dst)
            self.assertEqual(
                (dst / "WhatsApp" / "Media" / "IMG.jpg").read_bytes(), b"abc")

    def test_host_fs_path_is_absolute(self) -> None:
        raw = paths.host_fs_path("relative-name")
        self.assertTrue(os.path.isabs(raw.replace("\\\\?\\", "")))

    def test_safe_dest_hashes_long_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            dest = paths.safe_dest(parent, "W" * 130)
            self.assertTrue(dest.name.startswith("lp_"))
            self.assertTrue((parent / "argus-longpaths.json").exists())
