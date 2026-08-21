"""Physical acquisition helpers — partition maps and dump selection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.acquire import android_physical as phys


PROC = """\
major minor  #blocks  name

 179        0  30535680 mmcblk0
 179        1      8192 mmcblk0p1
 179       43  22020096 mmcblk0p43
 259        0     65536 userdata
"""

BY_NAME = """\
lrwxrwxrwx 1 root root 21 userdata -> /dev/block/mmcblk0p43
lrwxrwxrwx 1 root root 21 metadata -> /dev/block/mmcblk0p42
lrwxrwxrwx 1 root root 16 boot -> /dev/block/mmcblk0p10
lrwxrwxrwx 1 root root 16 system -> /dev/block/mmcblk0p20
lrwxrwxrwx 1 root root 21 persist -> /dev/block/mmcblk0p15
"""


class TestPartitionParsing(unittest.TestCase):
    def test_parse_proc_partitions_kb_to_bytes(self) -> None:
        sizes = phys.parse_proc_partitions(PROC)
        self.assertEqual(sizes["mmcblk0p43"], 22020096 * 1024)
        self.assertEqual(sizes["userdata"], 65536 * 1024)

    def test_parse_by_name_listing(self) -> None:
        named = phys.parse_by_name_listing(BY_NAME)
        names = {n: d for n, d in named}
        self.assertEqual(names["userdata"], "/dev/block/mmcblk0p43")
        self.assertEqual(names["boot"], "/dev/block/mmcblk0p10")

    def test_select_skips_os_keeps_userdata(self) -> None:
        named = phys.parse_by_name_listing(BY_NAME)
        sizes = phys.parse_proc_partitions(PROC)
        selected = phys.select_partitions(named, sizes, full=False)
        names = [p.name for p in selected]
        self.assertIn("userdata", names)
        self.assertIn("persist", names)
        self.assertNotIn("boot", names)
        self.assertNotIn("system", names)

    def test_full_includes_os_partitions(self) -> None:
        named = phys.parse_by_name_listing(BY_NAME)
        sizes = phys.parse_proc_partitions(PROC)
        selected = phys.select_partitions(named, sizes, full=True)
        names = [p.name for p in selected]
        self.assertIn("boot", names)
        self.assertIn("system", names)


class TestPhysicalResult(unittest.TestCase):
    def test_as_pull_exposes_dumped_paths(self) -> None:
        result = phys.PhysicalResult(dumped=["userdata"], bytes_total=100)
        pull = result.as_pull()
        self.assertEqual(pull.pulled, ["userdata"])
        self.assertEqual(pull.bytes_total, 100)
        self.assertEqual(pull.passes, ["physical"])


class TestEngineImportMethods(unittest.TestCase):
    def test_sim_and_cloud_are_gated_as_imports(self) -> None:
        from argus.acquire.engine import AcquisitionEngine, AcquisitionPlan
        from argus.core.case import Case
        from argus.core.errors import DeviceNotSupportedError

        case = Case.create(Path(tempfile.mkdtemp()), case_id="SIM",
                           investigator="t")
        engine = AcquisitionEngine(case)
        for method in ("sim", "cloud"):
            cap = engine.check_support(AcquisitionPlan(method=method))
            self.assertEqual(cap["method"], method)

        with self.assertRaises(DeviceNotSupportedError):
            engine.check_support(AcquisitionPlan(
                method="physical", device_name="iPhone 8"))
