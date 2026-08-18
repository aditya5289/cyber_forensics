"""Tests for acquisition progress telemetry."""

from __future__ import annotations

import time
import unittest

from argus.acquire.progress import ProgressMeter


class TestProgressMeter(unittest.TestCase):
    def test_eta_computed_from_rate(self) -> None:
        meter = ProgressMeter()
        meter.set_phase("transfer")
        meter.anchor_at = time.time() - 10
        meter.anchor_cur = 50
        snap = meter.snapshot(current=59, total=1000)
        self.assertEqual(snap["phase"], "transfer")
        self.assertEqual(snap["progress_current"], 59)
        self.assertGreater(snap["eta_seconds"], 0)
        self.assertGreater(snap["rate"], 0)


if __name__ == "__main__":
    unittest.main()
