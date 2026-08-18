"""Naming the actual cause when a handset will not connect.

"Check the cable, confirm USB debugging, confirm the device is powered on" is
not a diagnosis — it is a list of everything that could be wrong, handed to
someone who has already checked most of it. adb knows precisely what state the
device is in, and the old message never asked.

Each state needs a different response. `unauthorized` is a prompt on the screen;
`offline` is usually the USB mode or a stale daemon; an empty list is most often
a charge-only cable. Collapsing them into one message means the examiner tries
everything in turn.
"""
from __future__ import annotations

import unittest

from argus.devices.diagnose import (
    STATE_MEANING,
    VENDOR_NOTES,
    Diagnosis,
    parse_devices,
    vendor_guidance_for,
)


class Parsing(unittest.TestCase):
    def test_ready_device_with_full_attributes(self) -> None:
        devices = parse_devices(
            "List of devices attached\n"
            "CPH2239abc\tdevice usb:1-3 product:oppo_CPH2239 "
            "model:CPH2239 device:OP4F2F transport_id:4\n")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].state, "device")
        self.assertEqual(devices[0].model, "CPH2239")

    def test_state_containing_a_space_is_not_truncated(self) -> None:
        """"no permissions" splits into two words.

        Taking whitespace-separated field two mislabels it as "no", which
        matches no known state and produces "unrecognised" for a problem that
        has a perfectly good explanation.
        """
        devices = parse_devices(
            "List of devices attached\nabc123\tno permissions usb:2-1\n")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].state, "no permissions")
        self.assertIn(devices[0].state, STATE_MEANING)

    def test_every_state_seen_is_explained(self) -> None:
        for state in ("device", "unauthorized", "offline", "no permissions",
                      "recovery", "sideload", "bootloader", "authorizing"):
            self.assertIn(state, STATE_MEANING, state)
            meaning, fix = STATE_MEANING[state]
            self.assertTrue(meaning and fix, state)

    def test_empty_listing_yields_no_devices(self) -> None:
        self.assertEqual(parse_devices("List of devices attached\n\n"), [])

    def test_daemon_startup_noise_is_ignored(self) -> None:
        devices = parse_devices(
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\nabc\tdevice\n")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].serial, "abc")

    def test_multiple_devices_are_all_returned(self) -> None:
        devices = parse_devices(
            "List of devices attached\n"
            "aaa\tdevice model:Pixel_6\n"
            "bbb\tunauthorized\n"
            "ccc\toffline\n")
        self.assertEqual([d.state for d in devices],
                         ["device", "unauthorized", "offline"])


class VendorGuidance(unittest.TestCase):
    """Skins hide extra switches, and the symptom looks like a hardware fault."""

    def test_oppo_mentions_the_permission_monitoring_toggle(self) -> None:
        notes = " ".join(VENDOR_NOTES["oppo"]).lower()
        self.assertIn("permission monitoring", notes)

    def test_xiaomi_mentions_the_security_settings_toggle(self) -> None:
        notes = " ".join(VENDOR_NOTES["xiaomi"]).lower()
        self.assertIn("security settings", notes)

    def test_vendor_is_detected_from_the_model_string(self) -> None:
        devices = parse_devices(
            "List of devices attached\n"
            "x\tdevice product:oppo_CPH2239 model:CPH2239 device:OP4F2F\n")
        self.assertEqual(devices[0].vendor_hint, "oppo")

    def test_guidance_available_by_make_when_adb_sees_nothing(self) -> None:
        """With no device on the bus there is no model string to key on.

        The examiner still knows what they plugged in.
        """
        self.assertTrue(vendor_guidance_for("Oppo"))
        self.assertTrue(vendor_guidance_for("xiaomi"))
        self.assertEqual(vendor_guidance_for("Nokia"), [])

    def test_every_vendor_has_at_least_one_note(self) -> None:
        for vendor, notes in VENDOR_NOTES.items():
            self.assertTrue(notes, vendor)


class DiagnosisShape(unittest.TestCase):
    def test_missing_adb_is_a_named_problem_not_a_crash(self) -> None:
        from argus.devices.diagnose import diagnose
        report = diagnose(adb="")
        self.assertIsInstance(report, Diagnosis)
        # Either adb was found on this machine, or the absence is reported.
        if not report.adb_available:
            self.assertTrue(report.problems)
            self.assertIn("adb", report.problems[0]["issue"].lower())

    def test_missing_adb_still_points_at_import(self) -> None:
        """Live acquisition needs adb. Import does not, and saying so stops an
        examiner concluding they are blocked."""
        from argus.devices.diagnose import diagnose
        report = diagnose(adb="")
        if not report.adb_available:
            self.assertIn("Import", " ".join(report.next_steps))

    def test_serialises_for_the_ui(self) -> None:
        from argus.devices.diagnose import diagnose
        data = diagnose(adb="").as_dict()
        for key in ("adb", "devices", "problems", "next_steps",
                    "vendor_guidance"):
            self.assertIn(key, data)

    def test_every_problem_carries_a_fix(self) -> None:
        from argus.devices.diagnose import diagnose
        for problem in diagnose(adb="").problems:
            self.assertTrue(problem.get("fix"),
                            "a problem was reported with no remedy")


if __name__ == "__main__":
    unittest.main()
