"""Tests for live Android acquisition helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from argus.acquire import android_adb, android_apps


class TestAndroidApps(unittest.TestCase):
  def test_parse_package_list(self) -> None:
    text = """
package:com.whatsapp
package:com.android.chrome
package:/data/app/com.foo/base.apk=com.foo.bar
"""
    pkgs = android_apps.parse_package_list(text)
    self.assertIn("com.whatsapp", pkgs)
    self.assertIn("com.android.chrome", pkgs)
    self.assertIn("com.foo.bar", pkgs)

  def test_looks_like_database(self) -> None:
    self.assertTrue(android_apps._looks_like_database("msgstore.db"))
    self.assertTrue(android_apps._looks_like_database("chat.sqlite"))
    self.assertFalse(android_apps._looks_like_database("cache.tmp"))

  def test_discover_known_packages(self) -> None:
    session = mock.Mock()
    session.has_root = False
    session.shell.side_effect = [
      "package:com.whatsapp\npackage:com.example.other",
      "package:com.whatsapp\npackage:com.example.other",
      "msgstore.db\nwa.db",
      "",
    ]
    session.exists.return_value = True

    found = android_apps.discover_app_databases(session)
    paths = [d.remote_path for d in found]
    self.assertTrue(any("com.whatsapp" in p for p in paths))


class TestAndroidAdbPull(unittest.TestCase):
  def test_shell_coerces_none_stdout(self) -> None:
    session = android_adb.AdbSession.__new__(android_adb.AdbSession)
    session.serial = "device"
    session.timeout = 5
    with mock.patch.object(
        session, "run",
        return_value=mock.Mock(stdout=None, stderr=None, returncode=0)):
      self.assertEqual(session.shell("id"), "")
      self.assertFalse(session.shell("id").strip())

  def test_pull_retries_on_failure(self) -> None:
    session = android_adb.AdbSession.__new__(android_adb.AdbSession)
    session.serial = "emulator-5554"
    session.timeout = 5
    session._root = False

    calls = {"n": 0}

    def fake_once(remote, local, verify=True):
      calls["n"] += 1
      if calls["n"] < 2:
        return False, "transient"
      local.parent.mkdir(parents=True, exist_ok=True)
      local.write_text("ok", encoding="utf-8")
      return True, "ok"

    with mock.patch.object(session, "_pull_once", side_effect=fake_once):
      with tempfile.TemporaryDirectory() as tmp:
        ok, msg = session.pull("/sdcard/test.txt", Path(tmp) / "test.txt",
                                retries=2)
    self.assertTrue(ok)
    self.assertEqual(calls["n"], 2)


class TestComprehensiveAcquire(unittest.TestCase):
  def test_comprehensive_merges_passes(self) -> None:
    session = mock.Mock()
    session.has_root = False
    logical = android_adb.PullResult(pulled=["uri1"], bytes_total=10)
    filesystem = android_adb.PullResult(
      pulled=["/data/x"], bytes_total=20, failed=["/data/y: denied"])

    with mock.patch("argus.acquire.android_adb.logical_query",
                    return_value=logical) as lq:
      with mock.patch("argus.acquire.android_apps.discover_app_databases",
                      return_value=[]) as disc:
        with mock.patch("argus.acquire.android_adb.pull_filesystem",
                        return_value=filesystem) as fs:
          with mock.patch(
              "argus.acquire.android_adb.acquire_comms_supplement",
              return_value=android_adb.PullResult()) as comms:
            with mock.patch("argus.acquire.android_apps.pull_user_apks",
                            return_value=android_adb.PullResult(
                                pulled=["/data/app/a.apk"], bytes_total=5)):
              with mock.patch(
                  "argus.acquire.android_apps.discover_shared_crypt",
                  return_value=[]):
                with mock.patch(
                    "argus.acquire.android_apps.pull_shared_app_trees",
                    return_value=android_adb.PullResult()):
                  with mock.patch(
                      "argus.acquire.android_apps.pull_root_app_trees",
                      return_value=android_adb.PullResult()):
                    with mock.patch(
                        "argus.acquire.android_adb.capture_live_state",
                        return_value=android_adb.PullResult()):
                      with tempfile.TemporaryDirectory() as tmp:
                        dest = Path(tmp)
                        result = android_adb.comprehensive_acquire(session, dest)
    self.assertEqual(len(result.pulled), 3)
    self.assertEqual(result.bytes_total, 35)
    self.assertEqual(result.failed, ["/data/y: denied"])
    lq.assert_called_once()
    disc.assert_called_once()
    fs.assert_called_once()
    comms.assert_called_once()


class TestEngineAndroidAdbImport(unittest.TestCase):
    def test_comprehensive_path_uses_module_level_android_adb(self) -> None:
        """Inner ``from . import android_adb`` in the MTP branch must not
        shadow the module import and break logical/filesystem/comprehensive."""
        from argus.acquire.engine import (AcquisitionEngine, AcquisitionPlan,
                                          AcquisitionReport)
        from argus.core.case import Case, Exhibit
        from argus.devices.detect import DetectedDevice

        from argus.core.container import ExtractionMeta

        case = Case.create(Path(tempfile.mkdtemp()), case_id="ENG",
                           investigator="t")
        case.add_exhibit(Exhibit("EXH-001", make="vivo"))
        engine = AcquisitionEngine(case)
        dev = DetectedDevice(
            transport="adb", serial="abc123", make="vivo", model="V2217",
            marketing_name="vivo Y02", os_family="Android", os_version="12",
            battery=80)
        meta = ExtractionMeta(exhibit_id="EXH-001", operator="t",
                              method="comprehensive")
        container = case.new_container("EXH-001", meta, label="comprehensive")
        report = AcquisitionReport()
        staging = Path(tempfile.mkdtemp())
        plan = AcquisitionPlan(
            method="comprehensive", operator="t", exhibit_id="EXH-001",
            serial="abc123", turbo=True, skip_device_report=True)

        pull = android_adb.PullResult(pulled=["/sdcard"], bytes_total=100)
        with mock.patch.object(android_adb, "AdbSession"):
            with mock.patch.object(android_adb, "device_report"):
                with mock.patch.object(
                    android_adb, "comprehensive_acquire",
                    return_value=pull) as comp:
                    raw = engine._acquire(
                        plan, container, staging, dev, report, resumed=False)
        self.assertTrue(raw.exists())
        comp.assert_called_once()


class TestSharedHarvest(unittest.TestCase):
  def test_parse_find_paths(self) -> None:
    text = "/sdcard/WhatsApp/Databases/msgstore.db.crypt14\nnot a path\n/sdcard/key\n"
    paths = android_apps.parse_find_paths(text)
    self.assertEqual(paths[0].endswith("crypt14"), True)
    self.assertIn("/sdcard/key", paths)

  def test_live_state_skips_mock_shell(self) -> None:
    session = mock.Mock()
    session.shell.return_value = mock.Mock()
    with tempfile.TemporaryDirectory() as tmp:
      result = android_adb.capture_live_state(session, Path(tmp))
    self.assertEqual(result.pulled, [])

  def test_live_state_writes_settings(self) -> None:
    session = mock.Mock()
    session.shell.return_value = "android_id=abc123\n" * 4
    with tempfile.TemporaryDirectory() as tmp:
      dest = Path(tmp)
      result = android_adb.capture_live_state(session, dest)
      self.assertGreater(len(result.pulled), 0)
      self.assertTrue((dest / "live_state" / "settings_secure.txt").is_file())


if __name__ == "__main__":
  unittest.main()
