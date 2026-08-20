"""Installation verification.

An examiner is asked which build produced an exhibit and how they know it was
not altered. A validation certificate is issued against a specific build, so if
the installed files can drift from that build without anyone noticing, the
certificate stops describing reality.

These tests check the property that matters: a modified installation must be
detected and named, not merely suspected.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from argus.core.selfcheck import (
    build_manifest,
    installation_id,
    optional_features,
    report,
    verify_installation,
)


class Manifest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-manifest-"))
        (self.dir / "sub").mkdir()
        (self.dir / "a.py").write_text("print('a')\n")
        (self.dir / "sub" / "b.py").write_text("print('b')\n")
        (self.dir / "page.html").write_text("<p>hi</p>")
        # Noise that must not be manifested.
        (self.dir / "__pycache__").mkdir()
        (self.dir / "__pycache__" / "a.cpython-311.pyc").write_bytes(b"\x00")
        (self.dir / "evidence.afc").write_bytes(b"\x00" * 32)

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_covers_shipped_sources_only(self) -> None:
        m = build_manifest(self.dir)
        self.assertEqual(sorted(m["files"]), ["a.py", "page.html", "sub/b.py"])

    def test_caches_and_evidence_are_excluded(self) -> None:
        """A manifest that flags the examiner's own files becomes noise, and
        noise is what gets ignored when a real mismatch appears."""
        files = build_manifest(self.dir)["files"]
        self.assertNotIn("evidence.afc", files)
        self.assertFalse(any("__pycache__" in f for f in files))

    def test_paths_are_posix_so_it_verifies_cross_platform(self) -> None:
        self.assertIn("sub/b.py", build_manifest(self.dir)["files"])

    def test_installation_id_is_stable(self) -> None:
        self.assertEqual(installation_id(self.dir), installation_id(self.dir))

    def test_installation_id_changes_with_content(self) -> None:
        before = installation_id(self.dir)
        (self.dir / "a.py").write_text("print('changed')\n")
        self.assertNotEqual(installation_id(self.dir), before)

    def test_installation_id_changes_when_a_file_is_added(self) -> None:
        before = installation_id(self.dir)
        (self.dir / "c.py").write_text("print('c')\n")
        self.assertNotEqual(installation_id(self.dir), before)


class Verification(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-verify-"))
        (self.dir / "a.py").write_text("print('a')\n")
        (self.dir / "b.py").write_text("print('b')\n")
        self.manifest = self.dir / "MANIFEST.json"
        self.manifest.write_text(json.dumps(build_manifest(self.dir)))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_untouched_installation_verifies(self) -> None:
        r = verify_installation(self.dir)
        self.assertTrue(r.ok, r.summary())
        self.assertEqual(r.expected_id, r.actual_id)

    def test_modified_file_is_detected_and_named(self) -> None:
        (self.dir / "a.py").write_text("print('tampered')\n")
        r = verify_installation(self.dir)
        self.assertFalse(r.ok)
        self.assertEqual(r.modified, ["a.py"])
        self.assertIn("does NOT match", r.summary())

    def test_a_single_byte_change_is_enough(self) -> None:
        (self.dir / "b.py").write_text("print('b') \n")
        self.assertFalse(verify_installation(self.dir).ok)

    def test_deleted_file_is_detected(self) -> None:
        (self.dir / "b.py").unlink()
        r = verify_installation(self.dir)
        self.assertFalse(r.ok)
        self.assertEqual(r.missing, ["b.py"])

    def test_added_file_is_reported_without_failing_verification(self) -> None:
        """An extra file does not alter the verified ones — but it can shadow
        a released module, so it is named rather than ignored."""
        (self.dir / "c.py").write_text("print('c')\n")
        r = verify_installation(self.dir)
        self.assertTrue(r.ok)
        self.assertEqual(r.unexpected, ["c.py"])
        self.assertIn("shadow", r.note)

    def test_failure_note_tells_the_examiner_what_to_do(self) -> None:
        (self.dir / "a.py").write_text("x = 1\n")
        r = verify_installation(self.dir)
        self.assertIn("casework", r.note)

    def test_missing_manifest_is_not_reported_as_verified(self) -> None:
        """The dangerous default: no manifest must never read as 'fine'."""
        self.manifest.unlink()
        r = verify_installation(self.dir)
        self.assertFalse(r.ok)
        self.assertFalse(r.manifest_present)
        self.assertIn("cannot be verified", r.summary())

    def test_corrupt_manifest_is_not_reported_as_verified(self) -> None:
        self.manifest.write_text("{not json")
        r = verify_installation(self.dir)
        self.assertFalse(r.ok)


class Environment(unittest.TestCase):
    def test_optional_features_state_the_consequence_of_absence(self) -> None:
        for name, info in optional_features().items():
            self.assertIn("available", info)
            self.assertTrue(info["consequence_if_absent"], name)

    def test_report_identifies_the_build(self) -> None:
        data = report()
        self.assertTrue(data["installation_id"])
        self.assertTrue(data["version"])
        self.assertIn("verification", data)


class InstallHints(unittest.TestCase):
    """Instructions must match the machine the examiner is sitting at.

    Telling a Windows user to run `apt install` is not a hint, it is a dead
    end — and on a locked-down workstation they cannot discover it is wrong by
    trying it.
    """

    def test_every_platform_has_a_hint_for_every_tool(self) -> None:
        from argus.devices.detect import INSTALL_HINTS
        for tool, hints in INSTALL_HINTS.items():
            for platform_key in ("win32", "darwin", "linux"):
                self.assertTrue(hints.get(platform_key), f"{tool}/{platform_key}")

    def test_windows_is_not_told_to_use_apt(self) -> None:
        from argus.devices.detect import INSTALL_HINTS
        for tool, hints in INSTALL_HINTS.items():
            self.assertNotIn("apt ", hints["win32"], tool)
            self.assertNotIn("brew ", hints["win32"], tool)

    def test_macos_is_not_told_to_use_apt(self) -> None:
        from argus.devices.detect import INSTALL_HINTS
        for tool, hints in INSTALL_HINTS.items():
            self.assertNotIn("apt ", hints["darwin"], tool)

    def test_hint_selection_follows_sys_platform(self) -> None:
        import argus.devices.detect as detect
        original = detect.sys.platform
        try:
            for fake, expect in (("win32", "PATH"), ("darwin", "brew"),
                                 ("linux", "apt")):
                detect.sys.platform = fake
                self.assertIn(expect, detect._hint("adb"), fake)
        finally:
            detect.sys.platform = original

    def test_absent_toolchain_says_import_still_works(self) -> None:
        """The message must not read as a hard stop when it is not one."""
        from argus.devices.detect import toolchain_status
        for name, info in toolchain_status().items():
            self.assertTrue(info["not_needed_for"], name)
            self.assertIn("mport", info["not_needed_for"], name)


class NoDeviceGuidance(unittest.TestCase):
    """The panel an examiner sees when nothing is plugged in.

    Every state must say, exactly once, that import does not need these tools.
    Saying it twice makes the panel read as boilerplate and it gets skimmed
    past — including the sentence that tells them they are not actually stuck.
    """

    def _diagnostics(self, adb: bool, idevice: bool) -> list:
        import argus.devices.detect as detect
        real = detect.shutil.which

        def fake(name):
            if name == "adb":
                return "/nonexistent/adb" if adb else None
            if name in ("idevice_id", "ideviceinfo"):
                return "/nonexistent/idev" if idevice else None
            return real(name)

        detect.shutil.which = fake
        # find_tool falls back to well-known install locations after PATH, so
        # "absent" must also survive a machine that genuinely has adb (or
        # libimobiledevice) unpacked at one of those locations — this ran on
        # a workstation with a real adb.exe sitting at C:\platform-tools, and
        # mocking shutil.which alone was not enough to simulate absence there.
        key = detect._platform_key()
        absent_tools = [t for t, present in
                        (("adb", adb), ("idevice_id", idevice),
                         ("ideviceinfo", idevice)) if not present]
        saved = {t: detect.WELL_KNOWN[t][key] for t in absent_tools}
        for t in absent_tools:
            detect.WELL_KNOWN[t][key] = []
        try:
            return detect.detect_all()["diagnostics"]
        finally:
            detect.shutil.which = real
            for t, candidates in saved.items():
                detect.WELL_KNOWN[t][key] = candidates

    def test_import_advice_appears_exactly_once_in_every_state(self) -> None:
        for adb in (True, False):
            for idevice in (True, False):
                diagnostics = self._diagnostics(adb, idevice)
                mentions = sum(1 for d in diagnostics if "Choose Import" in d)
                self.assertEqual(
                    mentions, 1,
                    f"adb={adb} libimobiledevice={idevice} mentioned import "
                    f"{mentions} times")

    def test_each_absent_tool_is_named_once(self) -> None:
        diagnostics = self._diagnostics(adb=False, idevice=False)
        self.assertEqual(sum(1 for d in diagnostics if d.startswith("adb")), 1)
        self.assertEqual(
            sum(1 for d in diagnostics if d.startswith("libimobiledevice")), 1)

    def test_a_broken_binary_on_path_does_not_crash_detection(self) -> None:
        """A binary on PATH is not a binary that runs.

        A broken install, the wrong architecture, or a policy block yields an
        executable returning nothing — and indexing into that empty output
        crashed device detection outright.
        """
        for adb in (True, False):
            for idevice in (True, False):
                self.assertIsInstance(self._diagnostics(adb, idevice), list)

    def test_first_line_tolerates_empty_output(self) -> None:
        from argus.devices.detect import _first_line
        self.assertEqual(_first_line(""), "")
        self.assertEqual(_first_line("\n\n"), "")
        self.assertEqual(_first_line("\nAndroid Debug Bridge v1.0.41\nx"),
                         "Android Debug Bridge v1.0.41")


class ToolDiscovery(unittest.TestCase):
    """Finding tools that are installed but not on PATH.

    PATH is read once when the process starts. An examiner who installs adb
    while ARGUS is open and presses "Scan again" is told the tool is still
    missing, which reads as the install having failed. And the most common
    Windows install is an unzip to a folder that was never added to PATH at
    all, which no amount of rescanning would ever find.
    """

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-tools-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def _fake_executable(self, name: str) -> Path:
        import stat as stat_module
        target = self.dir / name
        target.write_text("#!/bin/sh\necho 'version 1.0.41'\n")
        target.chmod(target.stat().st_mode | stat_module.S_IEXEC)
        return target

    def test_path_is_searched_first(self) -> None:
        from argus.devices.detect import find_tool
        import shutil as shutil_module
        self.assertEqual(find_tool("python3") or "",
                         shutil_module.which("python3") or "")

    def _adb_off_path(self, detect):
        """Force find_tool's PATH lookup to miss, regardless of whether this
        machine genuinely has an adb on PATH — the point of these tests is
        the well-known-locations fallback, not this workstation's PATH."""
        real = detect.shutil.which

        def fake(name):
            return None if name == "adb" else real(name)

        return unittest.mock.patch.object(detect.shutil, "which", fake)

    def test_tool_off_path_is_still_found(self) -> None:
        import argus.devices.detect as detect
        target = self._fake_executable("adb")
        original = detect.WELL_KNOWN["adb"][detect._platform_key()]
        detect.WELL_KNOWN["adb"][detect._platform_key()] = [str(target)]
        try:
            with self._adb_off_path(detect):
                self.assertEqual(detect.find_tool("adb"), str(target))
        finally:
            detect.WELL_KNOWN["adb"][detect._platform_key()] = original

    def test_a_genuinely_absent_tool_returns_empty(self) -> None:
        from argus.devices.detect import find_tool
        self.assertEqual(find_tool("definitely-not-installed-anywhere"), "")

    def test_unexpanded_variables_are_skipped_not_probed(self) -> None:
        """An unset %LOCALAPPDATA% must not become a literal path lookup."""
        import argus.devices.detect as detect
        original = detect.WELL_KNOWN["adb"][detect._platform_key()]
        detect.WELL_KNOWN["adb"][detect._platform_key()] = [
            r"%NOT_A_REAL_VARIABLE%\adb.exe"]
        try:
            with self._adb_off_path(detect):
                self.assertEqual(detect.find_tool("adb"), "")
        finally:
            detect.WELL_KNOWN["adb"][detect._platform_key()] = original

    def test_every_platform_has_candidate_locations(self) -> None:
        from argus.devices.detect import WELL_KNOWN
        for tool, per_platform in WELL_KNOWN.items():
            for key in ("win32", "darwin", "linux"):
                self.assertTrue(per_platform.get(key), f"{tool}/{key}")

    def test_windows_candidates_include_the_common_unzip_location(self) -> None:
        """C:\\platform-tools is where the Google zip lands by default."""
        from argus.devices.detect import WELL_KNOWN
        joined = " ".join(WELL_KNOWN["adb"]["win32"]).lower()
        self.assertIn("platform-tools", joined)
        self.assertIn("localappdata", joined)


class SourceIsClean(unittest.TestCase):
    """The shipped package must import without warnings.

    An invalid escape sequence — a Windows path written in a plain docstring —
    is only a warning on Python 3.12/3.13, but it prints to the examiner's
    console during an otherwise clean run, and a future release rejects it
    outright. Neither is acceptable in a tool whose output is meant to be
    quotable.
    """

    def _package_sources(self):
        import argus
        root = Path(argus.__file__).resolve().parent
        return sorted(root.rglob("*.py"))

    def test_no_invalid_escape_sequences(self) -> None:
        import warnings

        offenders = []
        for source in self._package_sources():
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                compile(source.read_text(encoding="utf-8"), str(source), "exec")
                for warning in caught:
                    if "escape" in str(warning.message):
                        offenders.append(
                            f"{source.name}:{warning.lineno} "
                            f"{warning.message}")
        self.assertEqual(
            offenders, [],
            "invalid escape sequences will become SyntaxError in a future "
            "Python:\n  " + "\n  ".join(offenders))

    def test_every_module_compiles(self) -> None:
        for source in self._package_sources():
            try:
                compile(source.read_text(encoding="utf-8"), str(source), "exec")
            except SyntaxError as exc:
                self.fail(f"{source.name} does not compile: {exc}")


if __name__ == "__main__":
    unittest.main()
