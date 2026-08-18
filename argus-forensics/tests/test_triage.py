"""Fast examiner triage snapshot."""

from __future__ import annotations

import unittest

from argus.analyze.session import AnalysisSession


class TestTriageShape(unittest.TestCase):
    def test_method_exists(self) -> None:
        self.assertTrue(callable(getattr(AnalysisSession, "triage")))

    def test_horizon_apis_exist(self) -> None:
        self.assertTrue(callable(getattr(AnalysisSession, "source_tree")))
        self.assertTrue(callable(getattr(AnalysisSession, "hex_preview")))
        import tempfile
        from pathlib import Path
        from argus.core.db import ArtifactDB
        with tempfile.TemporaryDirectory() as td:
            db = ArtifactDB(Path(td) / "a.db")
            try:
                out = db.dashboard_slices(0)
            finally:
                db.close()
        self.assertIn("domains", out)
    def test_dashboard_command_center_shape(self) -> None:
        from argus.analyze.visualize import examination_health, temporal_insights

        health = examination_health(
            integrity_ok=True, total=100, timestamped=80,
            categories=5, alerts=0, encrypted_stores=0)
        self.assertIn("score", health)
        self.assertGreaterEqual(health["score"], 0)
        temporal = temporal_insights({
            "by_day": [{"date": "2026-01-01", "count": 10},
                       {"date": "2026-01-03", "count": 40}],
            "peak_hour": 14,
            "peak_day": "2026-01-03",
            "night_activity_pct": 12.0,
            "active_days": 2,
        })
        self.assertIn("bursts", temporal)
        self.assertTrue(callable(getattr(AnalysisSession, "dashboard_visuals")))


if __name__ == "__main__":
    unittest.main()
