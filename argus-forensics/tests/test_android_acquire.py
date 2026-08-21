"""Tests for live Android acquisition helpers."""

from __future__ import annotations

import os
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

    def fake_once(remote, local, verify=True, timeout=180):
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

  def test_want_tar_stream_covers_whatsapp_media(self) -> None:
    self.assertTrue(
        android_adb._want_tar_stream("/sdcard/Android/media/com.whatsapp"))
    self.assertTrue(
        android_adb._want_tar_stream("/sdcard/Android/data/com.whatsapp"))
    self.assertFalse(android_adb._want_tar_stream("/data/data/com.whatsapp"))

  def test_empty_dest_is_removed_before_adb_pull(self) -> None:
    """adb pull nests remote basename if dest already exists as a folder."""
    session = android_adb.AdbSession.__new__(android_adb.AdbSession)
    session.serial = "device"
    session.timeout = 5
    session._root = False
    seen: dict = {}

    def fake_pull(remote, dest, timeout):
      seen["dest"] = dest
      seen["existed"] = os.path.isdir(dest)
      target = Path(dest)
      target.mkdir(parents=True, exist_ok=True)
      (target / "IMG_001.jpg").write_bytes(b"abc")
      return mock.Mock(returncode=0, stderr="", stdout="")

    with tempfile.TemporaryDirectory() as tmp:
      local = Path(tmp) / "com.whatsapp"
      local.mkdir()
      self.assertTrue(local.is_dir())
      with mock.patch.object(session, "_is_remote_dir", return_value=True):
        with mock.patch.object(session, "_pull_tar_stream", return_value=False):
          with mock.patch.object(session, "_adb_pull_to", side_effect=fake_pull):
            ok, _msg = session._pull_once(
                "/sdcard/Android/media/com.whatsapp", local, verify=False)
      self.assertTrue(ok)
      self.assertIn("dest", seen)
      self.assertFalse(seen["existed"])
      self.assertTrue((local / "IMG_001.jpg").exists())
      self.assertFalse((local / "com.whatsapp").exists())

  def test_filter_shared_media_keeps_databases(self) -> None:
    targets = [
      ("/sdcard/DCIM", "Files & Media"),
      ("/sdcard/Android/media/com.whatsapp", "Chats"),
      ("/sdcard/Android/media/com.whatsapp/WhatsApp/Databases", "Chats"),
      ("/data/system/usagestats", "Applications"),
    ]
    out = [p for p, _ in android_adb.filter_shared_media_targets(
        targets, skip=True)]
    self.assertNotIn("/sdcard/DCIM", out)
    self.assertNotIn("/sdcard/Android/media/com.whatsapp", out)
    self.assertIn(
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases", out)
    self.assertIn("/data/system/usagestats", out)

  def test_filter_shared_media_keeps_call_recordings_and_vcard(self) -> None:
    targets = [
      ("/sdcard/DCIM", "Files & Media"),
      ("/sdcard/Bluetooth", "Files & Media"),
      ("/sdcard/Recordings/Call", "Calls"),
      ("/sdcard/Download/contacts.vcf", "Contacts"),
    ]
    out = [p for p, _ in android_adb.filter_shared_media_targets(
        targets, skip=True)]
    self.assertNotIn("/sdcard/DCIM", out)
    self.assertIn("/sdcard/Bluetooth", out)
    self.assertIn("/sdcard/Recordings/Call", out)
    self.assertIn("/sdcard/Download/contacts.vcf", out)

  def test_discover_shared_evidence_categorizes_find_hits(self) -> None:
    session = mock.Mock()
    session.shell.return_value = (
        "/sdcard/Download/contacts.vcf\n"
        "/sdcard/SMSBackup/sms.xml\n"
        "/sdcard/WhatsApp/Databases/msgstore.db.crypt15\n"
        "/sdcard/Recordings/Call/clip.m4a\n"
    )
    found = android_adb.discover_shared_evidence(session)
    by_path = dict(found)
    self.assertEqual(by_path["/sdcard/Download/contacts.vcf"], "Contacts")
    self.assertEqual(by_path["/sdcard/SMSBackup/sms.xml"], "Messages")
    self.assertEqual(
        by_path["/sdcard/WhatsApp/Databases/msgstore.db.crypt15"], "Chats")
    self.assertEqual(by_path["/sdcard/Recordings/Call/clip.m4a"], "Calls")

  def test_prepare_handset_requests_mtp_adb_bridge(self) -> None:
    session = mock.Mock()
    session.shell.return_value = "mtp,adb"
    info = android_adb.prepare_handset(session, usb_bridge=True)
    cmds = [c[0][0] for c in session.shell.call_args_list]
    self.assertTrue(any("setFunctions mtp,adb" in c for c in cmds))
    self.assertEqual(info.get("usb_config"), "mtp,adb")

  def test_wait_for_authorized_adb_skips_restart_when_live(self) -> None:
    with mock.patch("argus.acquire.android_adb.adb_device_states",
                    return_value={"device": ["SERIAL1"],
                                  "unauthorized": [],
                                  "offline": []}):
      with mock.patch("argus.acquire.android_adb._restart_adb_server") as restart:
        serial = android_adb.wait_for_authorized_adb(timeout=1)
    self.assertEqual(serial, "SERIAL1")
    restart.assert_not_called()

  def test_needs_root_skips_sandbox_keeps_usagestats(self) -> None:
    self.assertTrue(android_adb.needs_root(
        "/data/data/com.whatsapp/databases/msgstore.db"))
    self.assertTrue(android_adb.needs_root("/data/system/locksettings.db"))
    self.assertFalse(android_adb.needs_root("/data/system/usagestats"))
    self.assertFalse(android_adb.needs_root("/sdcard/DCIM"))
    self.assertFalse(android_adb.needs_root("/data/user_de/0"))

  def test_dedupe_drops_android_media_parent(self) -> None:
    targets = [
      ("/sdcard/Android/media", "Files & Media"),
      ("/sdcard/Android/media/com.whatsapp", "Chats"),
      ("/data/system/usagestats", "Applications"),
    ]
    out = [p for p, _ in android_adb.dedupe_pull_targets(targets)]
    self.assertNotIn("/sdcard/Android/media", out)
    self.assertIn("/sdcard/Android/media/com.whatsapp", out)
    self.assertIn("/data/system/usagestats", out)

  def test_chunked_pull_continues_after_child_failure(self) -> None:
    session = android_adb.AdbSession.__new__(android_adb.AdbSession)
    session.serial = "dev"
    session.timeout = 5
    session._root = False

    def fake_once(remote, local, verify=True, timeout=180):
      name = remote.rsplit("/", 1)[-1]
      if name == "bad":
        return False, "cannot create '...\\\\Wh'"
      local.parent.mkdir(parents=True, exist_ok=True)
      local.write_bytes(b"ok")
      return True, "ok"

    with tempfile.TemporaryDirectory() as tmp:
      dest = Path(tmp) / "tree"
      with mock.patch.object(session, "list_remote_children",
                             return_value=["good.jpg", "bad"]):
        with mock.patch.object(session, "_is_remote_dir", return_value=False):
          with mock.patch.object(session, "_pull_once", side_effect=fake_once):
            ok, msg = session._pull_tree_chunked(
                "/sdcard/media", dest, False, 180, None)
    self.assertTrue(ok)
    self.assertIn("ok-chunked:1/2", msg)


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

  def test_god_forces_app_discovery(self) -> None:
    session = mock.Mock()
    session.has_root = False
    empty = android_adb.PullResult()
    with mock.patch("argus.acquire.android_adb.logical_query", return_value=empty), \
         mock.patch("argus.acquire.android_apps.discover_app_databases",
                    return_value=[]) as disc, \
         mock.patch("argus.acquire.android_adb.pull_filesystem", return_value=empty), \
         mock.patch("argus.acquire.android_adb.acquire_comms_supplement",
                    return_value=empty), \
         mock.patch("argus.acquire.android_apps.pull_user_apks", return_value=empty), \
         mock.patch("argus.acquire.android_apps.discover_shared_crypt",
                    return_value=[]), \
         mock.patch("argus.acquire.android_apps.pull_shared_app_trees",
                    return_value=empty), \
         mock.patch("argus.acquire.android_apps.pull_root_app_trees",
                    return_value=empty), \
         mock.patch("argus.acquire.android_adb.capture_live_state",
                    return_value=empty), \
         mock.patch("argus.acquire.android_adb.capture_screenshot",
                    return_value=empty), \
         mock.patch("argus.acquire.android_adb.enable_keep_awake",
                    return_value=True), \
         mock.patch("argus.acquire.android_adb.export_dumpsys",
                    return_value=empty):
      with tempfile.TemporaryDirectory() as tmp:
        android_adb.comprehensive_acquire(
            session, Path(tmp), skip_app_discovery=True, god=True)
    disc.assert_called()
    self.assertGreaterEqual(disc.call_args.kwargs.get("limit", 0), 400)


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
                with mock.patch.object(android_adb, "ensure_device_ready",
                                       return_value=True):
                    with mock.patch.object(
                        android_adb, "comprehensive_acquire",
                        return_value=pull) as comp:
                        raw = engine._acquire(
                            plan, container, staging, dev, report,
                            resumed=False)
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

  def test_live_state_god_adds_package_dump(self) -> None:
    session = mock.Mock()
    session.shell.return_value = "package:com.whatsapp uid:10123\n" * 4
    with tempfile.TemporaryDirectory() as tmp:
      dest = Path(tmp)
      result = android_adb.capture_live_state(session, dest, god=True)
      names = {p.name for p in (dest / "live_state").iterdir()}
    self.assertIn("packages.txt", names)
    self.assertIn("props.txt", names)
    self.assertGreater(len(result.pulled), 7)


class TestAdbOverlayInto(unittest.TestCase):
  def test_writes_pending_when_adb_missing(self) -> None:
    from argus.acquire.engine import (AcquisitionEngine, AcquisitionPlan,
                                      AcquisitionReport)
    from argus.core.case import Case

    case = Case.create(Path(tempfile.mkdtemp()), case_id="OV", investigator="t")
    engine = AcquisitionEngine(case)
    plan = AcquisitionPlan(operator="t", exhibit_id="EXH-001", method="mtp")
    report = AcquisitionReport()
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      with mock.patch("argus.acquire.android_adb.wait_for_authorized_adb",
                      return_value=None):
        engine._adb_overlay_into(root, report, plan, log=lambda *a, **k: None)
      self.assertTrue((root / "argus-overlay-pending.json").is_file())
    self.assertTrue(any("overlay pending" in n.lower() for n in report.notes))

  def test_overlay_required_raises_without_adb(self) -> None:
    from argus.acquire.engine import (AcquisitionEngine, AcquisitionPlan,
                                      AcquisitionReport)
    from argus.core.case import Case
    from argus.core.errors import AcquisitionError

    case = Case.create(Path(tempfile.mkdtemp()), case_id="OV2", investigator="t")
    engine = AcquisitionEngine(case)
    plan = AcquisitionPlan(operator="t", exhibit_id="EXH-001",
                           method="comprehensive", overlay_only=True)
    report = AcquisitionReport()
    with tempfile.TemporaryDirectory() as tmp:
      with mock.patch("argus.acquire.android_adb.wait_for_authorized_adb",
                      return_value=None):
        with self.assertRaises(AcquisitionError):
          engine._adb_overlay_into(Path(tmp), report, plan,
                                   log=lambda *a, **k: None, required=True)


if __name__ == "__main__":
  unittest.main()
