"""Tests for god-level device scanning."""

from __future__ import annotations

import unittest
from unittest import mock

from argus.devices.detect import DetectedDevice
from argus.devices.scan import (
    _merge_devices,
    _physical_key,
    _recommend,
    scan_devices,
)


class TestScanMerge(unittest.TestCase):
    def _mtp(self) -> DetectedDevice:
        path = (r"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\\?\usb#"
                r"vid_2d95&pid_6002#10bcc10pbl0005n#{6ac27878-a6fa-4155-ba85-f98f491d4f33}")
        return DetectedDevice(
            transport="mtp",
            serial=path,
            model="OnePlus Nord",
            marketing_name="OnePlus Nord",
            os_family="Android",
            raw={"mtp_path": path, "mtp_name": "OnePlus Nord", "ready": True},
        )

    def _adb_blocked(self) -> DetectedDevice:
        return DetectedDevice(
            transport="adb",
            serial="10bcc10pbl0005n",
            model="OnePlus Nord",
            marketing_name="OnePlus Nord",
            os_family="Android",
            raw={"adb_state": "unauthorized", "ready": False,
                 "hint": "Accept prompt"},
        )

    def test_physical_key_matches_usb_fragment(self) -> None:
        self.assertEqual(_physical_key(self._mtp()), _physical_key(self._adb_blocked()))

    def test_merge_unifies_mtp_and_adb(self) -> None:
        merged = _merge_devices([self._mtp(), self._adb_blocked()])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].transport, "mtp")
        alts = merged[0].raw.get("alternate_transports", [])
        self.assertEqual(len(alts), 1)
        self.assertEqual(alts[0]["transport"], "adb")

    def test_recommend_mtp_when_only_mtp_ready(self) -> None:
        dev = self._mtp()
        _recommend(dev)
        self.assertEqual(dev.raw["recommended_method"], "mtp")

    def test_recommend_turbo_for_ready_adb(self) -> None:
        dev = DetectedDevice(
            transport="adb", serial="ABC", model="Pixel",
            marketing_name="Pixel", os_family="Android",
            raw={"ready": True, "adb_state": "device"},
        )
        _recommend(dev)
        self.assertEqual(dev.raw["recommended_method"], "turbo")


class TestScanDevices(unittest.TestCase):
    def test_scan_returns_metadata(self) -> None:
        fake_android = [DetectedDevice(
            transport="adb", serial="X", model="Phone",
            marketing_name="Phone", os_family="Android",
            raw={"ready": True, "adb_state": "device"},
        )]
        with mock.patch("argus.devices.scan.detect_android", return_value=fake_android), \
             mock.patch("argus.devices.scan.detect_ios", return_value=[]), \
             mock.patch("argus.devices.scan._detect_mtp_devices", return_value=[]), \
             mock.patch("argus.devices.bus.mobile_devices_on_bus", return_value=[]):
            report = scan_devices(deep=False)
        self.assertEqual(report["count"], 1)
        self.assertIn("scan", report)
        self.assertIn("elapsed_ms", report["scan"])
        self.assertIn("stages", report["scan"])
        self.assertEqual(report["ready_count"], 1)


if __name__ == "__main__":
    unittest.main()
