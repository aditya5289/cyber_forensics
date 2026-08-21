"""The examiner's folio is a complete-sentence assessment, not a KPI dump."""

from __future__ import annotations

import unittest

from argus.analyze.folio import compose_folio


class FolioProse(unittest.TestCase):
    def test_mtp_without_comms_directs_to_comprehensive(self) -> None:
        folio = compose_folio({
            "method": "mtp",
            "total_artifacts": 40,
            "device": {"make": "vivo", "model": "Y02"},
            "encryption_level": "Sealed (Merkle + hash-chained audit)",
            "integrity": {"ok": True},
            "categories": {"Files & Media": 40},
        })
        self.assertIn("MTP", folio["verdict"])
        self.assertIn("Comprehensive", folio["next_action"]["label"])
        self.assertTrue(folio["integrity_ok"])

    def test_failed_seal_is_the_first_fact(self) -> None:
        folio = compose_folio({
            "method": "comprehensive",
            "total_artifacts": 12,
            "integrity": {"ok": False},
            "device": {"make": "Samsung", "model": "A52"},
        })
        self.assertIn("cannot yet be presented", folio["verdict"])
        self.assertTrue(any("Integrity" in g for g in folio["gaps"]))

    def test_full_decode_points_at_findings_and_report(self) -> None:
        folio = compose_folio({
            "method": "comprehensive",
            "total_artifacts": 900,
            "deleted_recovered": 12,
            "encryption_level": "Sealed (Merkle + hash-chained audit)",
            "integrity": {"ok": True},
            "device": {"make": "Google", "model": "Pixel 7"},
            "categories": {"Messages": 100, "Contacts": 40, "Calls": 20},
            "operator": "A. Sharma",
        }, comms={"decoded": {"messages": 100, "contacts": 40, "calls": 20}})
        self.assertIn("900", folio["verdict"])
        self.assertIn("Findings", folio["next_action"]["label"])
        self.assertTrue(any("message" in s.lower() for s in folio["strengths"]))
        self.assertTrue(any("Sharma" in p for p in folio["paragraphs"]))


if __name__ == "__main__":
    unittest.main()
