"""Everything attached, not merely everything that answers adb.

The old scan asked adb and libimobiledevice, and when neither replied it said
"no device detected" — to an examiner looking directly at a phone plugged into
the machine. That is the tool contradicting the evidence of their own eyes, and
it sends them hunting for a broken cable when the cable is fine.

The operating system knows what is on the bus regardless of whether any forensic
tool can talk to it. A USB device carrying Oppo's vendor ID is a fact about the
hardware, and reporting it changes the diagnosis entirely: the physical link
works, so the problem is USB debugging, the connection mode, or the driver.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import argus.devices.bus as bus

LSUSB = """Bus 001 Device 004: ID 22d9:2765 Oppo Electronics Corp. CPH2239
Bus 001 Device 005: ID 0e8d:0003 MediaTek Inc. MT65xx Preloader
Bus 001 Device 006: ID 05c6:9008 Qualcomm, Inc. Gobi Wireless Modem (QDL mode)
Bus 001 Device 002: ID 8087:0026 Intel Corp. AX201 Bluetooth
"""


class VendorIdentification(unittest.TestCase):
    def setUp(self) -> None:
        self._real_run = bus._run
        self._real_platform = bus.sys.platform
        bus.sys.platform = "linux"
        bus._run = lambda cmd, timeout=20: (
            LSUSB if cmd and cmd[0] == "lsusb" else "")

    def tearDown(self) -> None:
        bus._run = self._real_run
        bus.sys.platform = self._real_platform

    def test_handset_vendors_are_named(self) -> None:
        vendors = {d.vendor for d in bus.mobile_devices_on_bus()}
        self.assertIn("Oppo", vendors)

    def test_unrelated_hardware_is_not_claimed_as_a_handset(self) -> None:
        """An Intel Bluetooth radio is not a phone.

        Reporting every USB device as a possible handset would make the list
        useless and the examiner would stop reading it.
        """
        for device in bus.mobile_devices_on_bus():
            self.assertNotIn("Intel", device.description)

    def test_all_usb_devices_are_still_enumerated(self) -> None:
        """The unfiltered list matters for the total count."""
        self.assertEqual(len(bus.usb_devices()), 4)

    def test_low_level_modes_are_explained(self) -> None:
        """EDL and BootROM are where physical acquisition becomes possible.

        Naming the vendor without saying what the mode permits wastes the most
        useful thing the scan found.
        """
        notes = {(d.vendor_id, d.product_id): d.mode_note
                 for d in bus.mobile_devices_on_bus()}
        self.assertIn("Emergency Download", notes.get(("05c6", "9008"), ""))
        self.assertIn("below the operating system",
                      notes.get(("0e8d", "0003"), ""))

    def test_a_vendor_id_alone_does_not_imply_a_mode(self) -> None:
        """MediaTek's 0e8d covers the preloader, the BootROM, and perfectly
        ordinary MTP and ADB interfaces.

        Announcing "BootROM — physical acquisition is a candidate" for a phone
        sitting in file-transfer mode is a confident wrong answer, and it points
        the examiner at low-level tooling for a device that is browsable in the
        file manager.
        """
        normal = bus._identify("0e8d", "201d", "OPPO F11", "test")
        self.assertEqual(normal.mode_name, "")
        qualcomm_normal = bus._identify("05c6", "f00e", "Modem", "test")
        self.assertEqual(qualcomm_normal.mode_name, "")

    def test_mtp_mode_is_reported_as_a_route_to_evidence(self) -> None:
        """A browsable handset needs no adb at all — just a file copy."""
        device = bus._identify("0e8d", "2008", "OPPO F11 MTP Device", "test")
        self.assertIn("file-transfer", device.mode_note)
        self.assertIn("copied off", device.mode_note)

    def test_ordinary_handsets_carry_no_low_level_claim(self) -> None:
        oppo = bus._identify("22d9", "2765", "OPPO F11", "test")
        self.assertEqual(oppo.mode_name, "")

    def test_vendor_ids_are_well_formed(self) -> None:
        """A malformed key silently never matches anything."""
        for vendor_id in bus.MOBILE_VENDORS:
            self.assertEqual(len(vendor_id), 4, vendor_id)
            self.assertTrue(all(c in "0123456789abcdef" for c in vendor_id),
                            vendor_id)

    def test_mode_keys_are_well_formed(self) -> None:
        for vendor_id, product_id in bus.LOW_LEVEL_MODES:
            self.assertEqual(len(vendor_id), 4, vendor_id)
            self.assertEqual(len(product_id), 4, product_id)


class TheVerdictChangesTheDiagnosis(unittest.TestCase):
    def setUp(self) -> None:
        self._real_run = bus._run
        self._real_platform = bus.sys.platform
        bus.sys.platform = "linux"
        bus._run = lambda cmd, timeout=20: (
            LSUSB if cmd and cmd[0] == "lsusb" else "")

    def tearDown(self) -> None:
        bus._run = self._real_run
        bus.sys.platform = self._real_platform

    def test_hardware_present_means_the_cable_is_exonerated(self) -> None:
        """The single most useful thing the scan can say.

        "Check your cable" is the standard advice and it is wrong whenever the
        device is enumerating.
        """
        notes = " ".join(bus.scan_all()["notes"])
        self.assertIn("cable and port are therefore working", notes)

    def test_the_remaining_causes_are_named(self) -> None:
        notes = " ".join(bus.scan_all()["notes"]).lower()
        for cause in ("usb debugging", "connection mode", "driver"):
            self.assertIn(cause, notes)

    def test_scan_reports_every_category(self) -> None:
        report = bus.scan_all()
        for key in ("usb_total", "mobile_hardware", "volumes", "fastboot",
                    "notes"):
            self.assertIn(key, report)


class Volumes(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="argus-vol-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_handset_directories_mark_a_volume_as_evidence(self) -> None:
        """A mounted card with DCIM on it can be imported immediately —
        no adb, no vendor tooling, no waiting."""
        for name in ("DCIM", "Android", "LOST.DIR"):
            (self.dir / name).mkdir()
        real = bus._candidate_mounts
        bus._candidate_mounts = lambda include_fixed: [(str(self.dir), True)]
        try:
            found = bus.volumes()
            self.assertEqual(len(found), 1)
            self.assertTrue(found[0].looks_like_evidence)
            self.assertIn("DCIM", found[0].markers)
        finally:
            bus._candidate_mounts = real

    def test_an_ordinary_folder_is_not_flagged(self) -> None:
        (self.dir / "Documents").mkdir()
        real = bus._candidate_mounts
        bus._candidate_mounts = lambda include_fixed: [(str(self.dir), True)]
        try:
            self.assertFalse(bus.volumes()[0].looks_like_evidence)
        finally:
            bus._candidate_mounts = real

    def test_an_unreadable_volume_does_not_raise(self) -> None:
        real = bus._candidate_mounts
        bus._candidate_mounts = lambda include_fixed: [
            ("/nonexistent/path/xyz", True)]
        try:
            found = bus.volumes()
            self.assertEqual(len(found), 1)
            self.assertFalse(found[0].looks_like_evidence)
        finally:
            bus._candidate_mounts = real


class DegradesQuietly(unittest.TestCase):
    """A scan that raises is worse than one that finds nothing."""

    def test_no_enumeration_tool_available(self) -> None:
        real = bus._run
        bus._run = lambda cmd, timeout=20: ""
        try:
            self.assertIsInstance(bus.usb_devices(), list)
            self.assertIsInstance(bus.scan_all(), dict)
        finally:
            bus._run = real

    def test_fastboot_absent_is_not_an_error(self) -> None:
        import argus.devices.detect as detect
        real = detect.find_tool
        detect.find_tool = lambda name: ""
        try:
            self.assertEqual(bus.fastboot_devices(), [])
        finally:
            detect.find_tool = real

    def test_detect_all_still_works_when_the_bus_scan_fails(self) -> None:
        """Bus enumeration is an enhancement, not a dependency."""
        from argus.devices.detect import detect_all
        real = bus.mobile_devices_on_bus
        bus.mobile_devices_on_bus = lambda: (_ for _ in ()).throw(
            RuntimeError("boom"))
        try:
            report = detect_all()
            self.assertIn("diagnostics", report)
        finally:
            bus.mobile_devices_on_bus = real


if __name__ == "__main__":
    unittest.main()
