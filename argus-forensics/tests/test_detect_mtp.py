"""Tests for MTP device detection and serial matching."""

from __future__ import annotations

import unittest

from argus.devices.detect import (DetectedDevice, _find_by_serial,
                                  _serial_matches, get_device,
                                  list_connected)


class TestMtpSerialMatching(unittest.TestCase):
    def _mtp_device(self) -> DetectedDevice:
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

    def test_usb_fragment_matches_escaped_variants(self) -> None:
        dev = self._mtp_device()
        variant = dev.serial.replace("\\\\", "\\")
        self.assertTrue(_serial_matches(variant, dev))
        self.assertTrue(_serial_matches(
            r"usb#vid_2d95&pid_6002#10bcc10pbl0005n", dev))

    def test_find_by_serial_returns_device(self) -> None:
        dev = self._mtp_device()
        hit = _find_by_serial(dev.serial, [dev])
        self.assertIs(hit, dev)

    def test_get_device_uses_list_connected(self) -> None:
        dev = self._mtp_device()
        import argus.devices.detect as detect_mod
        orig = detect_mod.list_connected
        try:
            detect_mod.list_connected = lambda: [dev]
            got = get_device(dev.serial.replace("\\\\", "\\"))
            self.assertEqual(got.transport, "mtp")
        finally:
            detect_mod.list_connected = orig

    def test_synthetic_mtp_fallback_when_path_cached(self) -> None:
        dev = self._mtp_device()
        import argus.devices.detect as detect_mod
        from argus.acquire import mtp

        orig_lc = detect_mod.list_connected
        orig_mtp = mtp.devices
        orig_avail = mtp.available
        try:
            detect_mod.list_connected = lambda: []
            mtp.available = lambda: True
            mtp.devices = lambda: []
            got = detect_mod.resolve_device(
                dev.serial,
                transport="mtp",
                mtp_name="OnePlus Nord",
            )
            self.assertEqual(got.transport, "mtp")
            self.assertTrue((got.raw or {}).get("synthetic"))
        finally:
            detect_mod.list_connected = orig_lc
            mtp.devices = orig_mtp
            mtp.available = orig_avail
        import argus.devices.detect as detect_mod
        from argus.acquire import mtp

        fake = DetectedDevice(transport="adb", serial="ABC123",
                              model="Pixel", marketing_name="Pixel")
        mtp_dev = mtp.MTPDevice(name="TestPhone", path="::mtp-path")
        orig_android = detect_mod.detect_android
        orig_ios = detect_mod.detect_ios
        orig_mtp = detect_mod._detect_mtp_devices
        try:
            detect_mod.detect_android = lambda: [fake]
            detect_mod.detect_ios = lambda: []
            detect_mod._detect_mtp_devices = lambda existing: [
                DetectedDevice(transport="mtp", serial=mtp_dev.path,
                               model=mtp_dev.name, marketing_name=mtp_dev.name,
                               os_family="Android",
                               raw={"mtp_path": mtp_dev.path,
                                    "mtp_name": mtp_dev.name})]
            found = list_connected()
            transports = {d.transport for d in found}
            self.assertIn("adb", transports)
            self.assertIn("mtp", transports)
        finally:
            detect_mod.detect_android = orig_android
            detect_mod.detect_ios = orig_ios
            detect_mod._detect_mtp_devices = orig_mtp


if __name__ == "__main__":
    unittest.main()
