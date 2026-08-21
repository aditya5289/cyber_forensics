"""Tests for god-level device scanning."""

from __future__ import annotations

import time
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

    def test_recommend_comprehensive_for_ready_adb(self) -> None:
        dev = DetectedDevice(
            transport="adb", serial="ABC", model="Pixel",
            marketing_name="Pixel", os_family="Android",
            raw={"ready": True, "adb_state": "device"},
        )
        _recommend(dev)
        self.assertEqual(dev.raw["recommended_method"], "comprehensive")

    def test_recommend_sim_when_handset_is_blocked(self) -> None:
        blocked = self._adb_blocked()
        _recommend(blocked)
        self.assertEqual(blocked.raw["recommended_method"], "sim")
        self.assertIn("SIM", blocked.raw["recommended_action"])

    def test_recommend_sim_when_visible_but_not_ready(self) -> None:
        dev = DetectedDevice(
            transport="adb", serial="X", model="Y02",
            marketing_name="Y02", os_family="Android",
            raw={"ready": False, "adb_state": "unknown"},
        )
        _recommend(dev)
        self.assertEqual(dev.raw["recommended_method"], "sim")


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


class TestScanConcurrency(unittest.TestCase):
    """The scan claims to run its detectors in parallel; hold it to that.

    The USB bus enumeration takes no input from the other detectors, but used
    to run last and alone — and then a second time inside the diagnostics for
    the no-device case, which is exactly when the examiner is already waiting.
    """

    DELAY = 0.4

    def _slow(self, value, counter=None, key=""):
        def run(*_a, **_k):
            if counter is not None:
                counter[key] = counter.get(key, 0) + 1
            time.sleep(self.DELAY)
            return value
        return run

    def _run_scan(self, counter=None):
        with mock.patch("argus.devices.scan.detect_android",
                        self._slow([])), \
             mock.patch("argus.devices.scan.detect_ios", self._slow([])), \
             mock.patch("argus.devices.scan._detect_mtp_devices",
                        self._slow([])), \
             mock.patch("argus.devices.bus.mobile_devices_on_bus",
                        self._slow([], counter, "bus")), \
             mock.patch("argus.devices.bus.fastboot_devices",
                        return_value=[]), \
             mock.patch("argus.devices.bus.volumes", return_value=[]):
            start = time.perf_counter()
            report = scan_devices(deep=True)
            return report, time.perf_counter() - start

    def test_the_bus_query_overlaps_the_other_detectors(self) -> None:
        _report, elapsed = self._run_scan()
        # android|ios|bus together, then mtp: two delays, not four.
        self.assertLess(elapsed, self.DELAY * 3.5,
                        "the bus enumeration is running serially again")

    def test_the_bus_is_enumerated_once_not_twice(self) -> None:
        counter: dict = {}
        self._run_scan(counter)
        self.assertEqual(counter["bus"], 1)

    def test_each_stage_reports_its_own_duration(self) -> None:
        """Timing from the main thread reported whichever stage was collected
        second as taking no time at all."""
        report, _elapsed = self._run_scan()
        stages = {s["name"]: s["elapsed_ms"] for s in report["scan"]["stages"]}
        floor = self.DELAY * 1000 * 0.5
        for name in ("android", "ios", "mtp", "bus"):
            self.assertGreater(stages[name], floor,
                               f"{name} reported {stages[name]}ms for work "
                               f"that took {self.DELAY * 1000:.0f}ms")

    def test_every_stage_is_still_reported_in_order(self) -> None:
        report, _elapsed = self._run_scan()
        self.assertEqual(
            [s["name"] for s in report["scan"]["stages"]],
            ["toolchain", "android", "ios", "mtp", "bus", "merge"])


if __name__ == "__main__":
    unittest.main()
