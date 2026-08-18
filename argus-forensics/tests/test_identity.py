"""Device identity helpers — VID/PID, ADB props, identity files."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from argus.devices.identity import (
    android_identity_from_props,
    ios_marketing_name,
    parse_usb_ids,
    parse_usb_instance_serial,
    snapshot_from_detected,
    usb_identity_from_path,
    vendor_for_vid,
    write_identity,
)
from argus.devices.detect import DetectedDevice
from argus.devices.scan import _enrich_from_bus


class TestUsbIdentity(unittest.TestCase):
    PATH = (r"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\\?\usb#"
            r"vid_2d95&pid_6002#10bcc10pbl0005n#{6ac27878-a6fa-4155-ba85-f98f491d4f33}")

    def test_parse_vid_pid_from_mtp_path(self) -> None:
        vid, pid = parse_usb_ids(self.PATH)
        self.assertEqual(vid, "2d95")
        self.assertEqual(pid, "6002")

    def test_instance_serial(self) -> None:
        self.assertEqual(parse_usb_instance_serial(self.PATH), "10bcc10pbl0005n")

    def test_vendor_for_y_series_vid(self) -> None:
        self.assertIn("Vivo", vendor_for_vid("2d95"))

    def test_usb_identity_includes_mode(self) -> None:
        ident = usb_identity_from_path(self.PATH)
        self.assertEqual(ident["usb_mode"], "MTP / file transfer")
        self.assertTrue(ident["usb_vendor"])


class TestAndroidIdentity(unittest.TestCase):
    def test_props_map(self) -> None:
        ident = android_identity_from_props({
            "ro.product.manufacturer": "vivo",
            "ro.product.model": "Y02",
            "ro.build.version.release": "12",
            "ro.build.version.sdk": "31",
            "ro.build.version.security_patch": "2024-06-01",
            "ro.board.platform": "mt6765",
        })
        self.assertEqual(ident["make"], "vivo")
        self.assertEqual(ident["model"], "Y02")
        self.assertEqual(ident["sdk"], 31)
        self.assertEqual(ident["chipset"], "mt6765")

    def test_write_identity_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_identity(tmp, {"make": "vivo", "model": "Y02"})
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["model"], "Y02")
            self.assertIn("format", data)


class TestIosNames(unittest.TestCase):
    def test_iphone_16(self) -> None:
        self.assertEqual(ios_marketing_name("iPhone17,3"), "iPhone 16")


class TestSnapshotAndBusEnrich(unittest.TestCase):
    def test_snapshot_from_mtp_device(self) -> None:
        path = TestUsbIdentity.PATH
        dev = DetectedDevice(
            transport="mtp", serial=path, model="Y02",
            marketing_name="Y02", os_family="Android",
            raw={"mtp_path": path, "mtp_name": "Y02", "ready": True,
                 "volumes": ["Internal storage"]},
        )
        snap = snapshot_from_detected(dev)
        self.assertEqual(snap["usb_vid"], "2d95")
        self.assertEqual(snap["volumes"], ["Internal storage"])

    def test_enrich_from_bus_fills_make(self) -> None:
        path = TestUsbIdentity.PATH
        dev = DetectedDevice(
            transport="mtp", serial=path, make="", model="Y02",
            marketing_name="Y02", os_family="Android",
            raw={"mtp_path": path, "ready": True},
        )

        class Bus:
            vendor_id = "2d95"
            product_id = "6002"
            vendor = "Vivo / iQOO / Y-series (BBK)"
            description = "Y02"
            mode_name = ""
            mode_note = "The handset appears to be in file-transfer (MTP) mode."

        _enrich_from_bus([dev], [Bus()])
        self.assertTrue(dev.make)
        self.assertEqual(dev.raw["usb_vid"], "2d95")
        self.assertEqual(dev.raw["confidence"], "usb+bus")


if __name__ == "__main__":
    unittest.main()
