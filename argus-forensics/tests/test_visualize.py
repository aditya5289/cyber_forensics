"""Tests for visualization helpers."""

from __future__ import annotations

import unittest

from argus.analyze.visualize import (chart_series, cluster_places,
                                     timeline_buckets)


class TestVisualize(unittest.TestCase):
    def test_timeline_buckets_hourly(self) -> None:
        entries = [
            {"timestamp": 1_700_000_000_000_000, "category": "Messages"},
            {"timestamp": 1_700_000_360_000_000, "category": "Calls"},
            {"timestamp": 1_700_000_720_000_000, "category": "Messages"},
        ]
        out = timeline_buckets(entries, resolution="hour")
        self.assertGreater(out["total"], 0)
        self.assertIn("Messages", out["categories"])

    def test_cluster_places_groups_nearby(self) -> None:
        pts = [
            {"latitude": 12.9716, "longitude": 77.5946, "category": "Locations",
             "artifact_id": "a1", "iso": "2026-01-01", "timestamp": 1},
            {"latitude": 12.9717, "longitude": 77.5947, "category": "Locations",
             "artifact_id": "a2", "iso": "2026-01-01", "timestamp": 2},
        ]
        out = cluster_places(pts)
        self.assertEqual(out["count"], 2)
        self.assertTrue(out["clusters"])

    def test_chart_series_normalises(self) -> None:
        hist = {
            "by_hour": [{"hour": 0, "count": 5}, {"hour": 1, "count": 10}],
            "by_weekday": [{"day": "Monday", "count": 3}],
            "night_activity_pct": 12.5,
            "peak_hour": 1,
            "active_days": 4,
        }
        out = chart_series(hist)
        self.assertEqual(len(out["hourly"]), 2)
        self.assertEqual(out["hourly"][1]["pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
