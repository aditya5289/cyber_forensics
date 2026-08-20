"""The scan, against several handsets in several states at once.

Three faults made a plugged-in phone report as "no device detected", and each
was invisible on its own:

* the scan searched PATH for adb while `selfcheck` searched the standard install
  locations, so the two disagreed about whether adb existed;
* the listing was split on whitespace, turning the state `no permissions` into
  `no`;
* anything not in state `device` was discarded, so a handset that was plugged in
  and enumerating simply vanished.

A device that is present but unauthorised is not "no device". It is a device
with a specific, fixable problem, and reporting it as absent sends the examiner
to check the cable.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import argus.devices.detect as detect

FAKE_ADB = """#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Android Debug Bridge version 1.0.41"; exit 0
fi
if [ "$1" = "devices" ]; then
cat <<'OUT'
List of devices attached
CPH2239xyz\tunauthorized usb:1-3 transport_id:2
SM991Babcd\tdevice usb:1-4 product:o1s model:SM_G991B device:o1s transport_id:3
pixel6zzz\toffline usb:2-1 transport_id:5
oldphone01\tno permissions usb:2-2
OUT
exit 0
fi
if [ "$1" = "-s" ]; then
  case "$4" in
    getprop)
      echo "[ro.product.manufacturer]: [Samsung]"
      echo "[ro.product.model]: [SM-G991B]"
      echo "[ro.build.version.release]: [14]"
      echo "[ro.board.platform]: [exynos2100]"
      echo "[ro.crypto.state]: [encrypted]"
      exit 0;;
    dumpsys) echo "  level: 87"; exit 0;;
    which) exit 1;;
  esac
fi
exit 0
"""

EMPTY_ADB = """#!/bin/sh
if [ "$1" = "version" ]; then echo "Android Debug Bridge version 1.0.41"; exit 0; fi
if [ "$1" = "devices" ]; then echo "List of devices attached"; echo ""; exit 0; fi
exit 0
"""

# Windows cannot execute a `#!/bin/sh` script directly — CreateProcess needs a
# recognised extension (.bat) to know how to run a file at all, and without
# one every _run() call fails with WinError 193 and is silently swallowed,
# leaving detect_android() with nothing to parse. Same behaviour, batch
# syntax, so the fixture actually exercises the pipeline on Windows instead
# of vacuously no-op'ing.
WIN_FAKE_ADB = """@echo off
if "%1"=="version" (
  echo Android Debug Bridge version 1.0.41
  exit /b 0
)
if "%1"=="devices" (
  echo List of devices attached
  echo CPH2239xyz\tunauthorized usb:1-3 transport_id:2
  echo SM991Babcd\tdevice usb:1-4 product:o1s model:SM_G991B device:o1s transport_id:3
  echo pixel6zzz\toffline usb:2-1 transport_id:5
  echo oldphone01\tno permissions usb:2-2
  exit /b 0
)
if "%1"=="-s" (
  if "%4"=="getprop" (
    echo [ro.product.manufacturer]: [Samsung]
    echo [ro.product.model]: [SM-G991B]
    echo [ro.build.version.release]: [14]
    echo [ro.board.platform]: [exynos2100]
    echo [ro.crypto.state]: [encrypted]
    exit /b 0
  )
  if "%4"=="dumpsys" (
    echo   level: 87
    exit /b 0
  )
  if "%4"=="which" exit /b 1
)
exit /b 0
"""

WIN_EMPTY_ADB = """@echo off
if "%1"=="version" (
  echo Android Debug Bridge version 1.0.41
  exit /b 0
)
if "%1"=="devices" (
  echo List of devices attached
  echo.
  exit /b 0
)
exit /b 0
"""


def _write_fake_adb(directory: Path, posix_source: str, win_source: str) -> Path:
    """Write a fake adb executable in whichever form this OS can actually run."""
    if sys.platform == "win32":
        path = directory / "adb.bat"
        path.write_text(win_source)
        return path
    path = directory / "adb"
    path.write_text(posix_source)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


class ScanAcrossStates(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = Path(tempfile.mkdtemp(prefix="argus-scan-"))
        cls.adb = _write_fake_adb(cls.dir, FAKE_ADB, WIN_FAKE_ADB)
        cls._real_find = detect.find_tool
        detect.find_tool = lambda name: str(cls.adb) if name == "adb" else ""
        cls.devices = detect.detect_android()

    @classmethod
    def tearDownClass(cls) -> None:
        detect.find_tool = cls._real_find
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_every_attached_handset_is_reported(self) -> None:
        """Four are on the bus. Reporting only the one that is ready hides
        three devices an examiner can see with their own eyes."""
        self.assertEqual(len(self.devices), 4)

    def test_serials_are_not_confused(self) -> None:
        serials = {d.serial for d in self.devices}
        self.assertEqual(serials, {"CPH2239xyz", "SM991Babcd", "pixel6zzz",
                                   "oldphone01"})

    def test_the_ready_device_is_fully_interrogated(self) -> None:
        ready = [d for d in self.devices if d.raw.get("ready")]
        self.assertEqual(len(ready), 1)
        device = ready[0]
        self.assertEqual(device.make, "Samsung")
        self.assertEqual(device.model, "SM-G991B")
        self.assertEqual(device.os_version, "14")
        self.assertEqual(device.battery, 87)

    def test_unready_devices_are_marked_and_explained(self) -> None:
        for device in self.devices:
            if device.raw.get("ready"):
                continue
            self.assertTrue(device.raw.get("meaning"), device.serial)
            self.assertTrue(device.raw.get("hint"), device.serial)

    def test_no_permissions_state_survives_parsing(self) -> None:
        """Splitting on whitespace turned this into "no", matching nothing."""
        states = {d.serial: d.raw.get("adb_state") for d in self.devices}
        self.assertEqual(states["oldphone01"], "no permissions")

    def test_unauthorized_is_not_reported_as_absent(self) -> None:
        match = [d for d in self.devices if d.serial == "CPH2239xyz"]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].raw["adb_state"], "unauthorized")
        self.assertFalse(match[0].raw["ready"])

    def test_offline_is_distinguished_from_unauthorized(self) -> None:
        by_serial = {d.serial: d.raw for d in self.devices}
        self.assertNotEqual(by_serial["pixel6zzz"]["meaning"],
                            by_serial["CPH2239xyz"]["meaning"])

    def test_properties_are_only_read_from_the_ready_device(self) -> None:
        """Querying an unauthorised handset produces nothing useful, and
        attributing another device's properties to it would be far worse."""
        for device in self.devices:
            if not device.raw.get("ready"):
                self.assertFalse(device.os_version, device.serial)
                self.assertFalse(device.imei, device.serial)


class AdbFoundOffPath(unittest.TestCase):
    """The scan and selfcheck must agree about whether adb exists.

    They did not: one searched PATH, the other searched the standard install
    locations. A perfectly good adb in C:\\platform-tools was reported as
    available by one and missing by the other.
    """

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-offpath-"))
        self.adb = _write_fake_adb(self.dir, EMPTY_ADB, WIN_EMPTY_ADB)

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_scan_uses_the_same_lookup_as_selfcheck(self) -> None:
        import inspect
        source = inspect.getsource(detect.detect_android)
        self.assertIn("find_tool", source)
        self.assertNotIn('shutil.which("adb")', source)

    def test_scan_runs_with_adb_off_path(self) -> None:
        # find_tool is fully replaced below, so this exercises "adb reports no
        # devices", not the real PATH lookup — whether the real adb happens to
        # be on this machine's PATH is irrelevant to what is under test here.
        real = detect.find_tool
        detect.find_tool = lambda name: str(self.adb) if name == "adb" else ""
        try:
            self.assertEqual(detect.detect_android(), [])
        finally:
            detect.find_tool = real

    def test_no_adb_at_all_is_not_a_crash(self) -> None:
        real = detect.find_tool
        detect.find_tool = lambda name: ""
        try:
            self.assertEqual(detect.detect_android(), [])
        finally:
            detect.find_tool = real


if __name__ == "__main__":
    unittest.main()
