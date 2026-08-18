"""Tests for multi-device batch acquisition."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from argus.acquire.batch import (BatchAcquisitionEngine, BatchAcquisitionPlan,
                                 BatchDeviceSpec, build_specs_from_connected,
                                 ensure_exhibit, next_exhibit_id)
from argus.acquire.engine import AcquisitionReport
from argus.core.case import Case, Exhibit
from argus.core.errors import AcquisitionError
from argus.devices.detect import DetectedDevice


class TestBatchHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="argus-batch-"))
        self.case = Case.create(self.tmp, case_id="BATCH-001",
                                investigator="Tester")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_next_exhibit_id_skips_existing(self) -> None:
        self.case.add_exhibit(Exhibit(exhibit_id="EXH-001", description="first"))
        self.assertEqual(next_exhibit_id(self.case), "EXH-002")

    def test_ensure_exhibit_registers_when_missing(self) -> None:
        spec = BatchDeviceSpec(serial="ABC123", device_name="Galaxy S21")
        dev = DetectedDevice(transport="adb", serial="ABC123",
                             make="Samsung", model="SM-G991B")
        eid = ensure_exhibit(self.case, spec, dev)
        self.assertEqual(eid, "EXH-001")
        self.assertIn("EXH-001", self.case.data["exhibits"])

    def test_build_specs_from_connected_skips_not_ready(self) -> None:
        fake = {
            "devices": [
                {"serial": "OK1", "name": "Phone A", "raw": {"ready": True}},
                {"serial": "BAD", "name": "Phone B", "raw": {"ready": False}},
                {"serial": "OK2", "name": "Phone C", "raw": {}},
            ],
        }
        with mock.patch("argus.acquire.batch.detect_all", return_value=fake):
            specs = build_specs_from_connected(prefix="RAID")
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].exhibit_id, "RAID-001")
        self.assertEqual(specs[1].exhibit_id, "RAID-002")


class TestBatchEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="argus-batch-run-"))
        self.case = Case.create(self.tmp, case_id="BATCH-RUN",
                                investigator="Op")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_apply_turbo_settings(self) -> None:
        from argus.acquire.engine import AcquisitionPlan, apply_turbo_settings

        plan = AcquisitionPlan(
            operator="Op", exhibit_id="EXH-001", method="turbo")
        apply_turbo_settings(plan)
        self.assertEqual(plan.method, "filesystem")
        self.assertFalse(plan.recover_deleted)
        self.assertFalse(plan.verify_pulls)
        self.assertGreaterEqual(plan.parallel_pulls, 4)
        self.assertTrue(plan.skip_app_discovery)
        with self.assertRaises(AcquisitionError):
            BatchAcquisitionPlan(operator="", devices=[]).validate()
        with self.assertRaises(AcquisitionError):
            BatchAcquisitionPlan(operator="Op", devices=[]).validate()

    def test_serial_queue_completes_two_devices(self) -> None:
        plan = BatchAcquisitionPlan(
            operator="Op",
            devices=[
                BatchDeviceSpec(serial="S1", device_name="Phone 1"),
                BatchDeviceSpec(serial="S2", device_name="Phone 2"),
            ],
            auto_register_exhibits=True,
        )
        fake_dev = DetectedDevice(transport="adb", serial="S1",
                                  make="Test", model="T1")
        acq_report = AcquisitionReport(
            container=str(self.tmp / "out.afc"),
            artifacts=42, status="Completed", duration_seconds=1.2)

        events: list = []

        def fake_run(self, acq_plan, device=None):
            return acq_report

        with mock.patch("argus.acquire.batch.resolve_device",
                        return_value=fake_dev), \
             mock.patch("argus.acquire.batch.AcquisitionEngine.run",
                        fake_run):
            engine = BatchAcquisitionEngine(
                self.case, progress=lambda e: events.append(e))
            report = engine.run(plan)

        self.assertEqual(report.completed, 2)
        self.assertEqual(report.failed, 0)
        self.assertEqual(len(report.results), 2)
        self.assertTrue(any(e.get("batch_total") == 2 for e in events))

    def test_stop_on_error_halts_queue(self) -> None:
        plan = BatchAcquisitionPlan(
            operator="Op",
            devices=[
                BatchDeviceSpec(serial="BAD"),
                BatchDeviceSpec(serial="SKIP"),
            ],
            stop_on_error=True,
        )
        fake_dev = DetectedDevice(transport="adb", serial="BAD")

        with mock.patch("argus.acquire.batch.resolve_device",
                        return_value=fake_dev), \
             mock.patch("argus.acquire.batch.AcquisitionEngine.run",
                        side_effect=RuntimeError("pull failed")):
            report = BatchAcquisitionEngine(self.case).run(plan)

        self.assertEqual(report.completed, 0)
        self.assertEqual(report.failed, 1)
        self.assertEqual(len(report.results), 1)


if __name__ == "__main__":
    unittest.main()
