"""Co-location, and the coordinates that must never contribute to it.

The value of this analysis is entirely in what it refuses. Every geolocated
artifact is a temptation to report a meeting, and three kinds of coordinate
look exactly like a position while being nothing of the sort:

* a searched destination — intent to travel, not presence;
* a *received* location message — the sender's position, not this device's;
* a downloaded photograph — the original photographer's position.

Include any of them and the tool starts placing two people together on the
strength of them having both looked up the same address. These tests pin the
exclusions as hard as they pin the detection, and check that a run of fixes
over one hour is reported as one encounter rather than twelve.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from argus.core.models import Artifact, Category, Direction
from argus.intel.colocation import (ColocationAnalyser, colocation_findings,
                                    haversine_m, presence_point)

US = 1_000_000
BASE = int(datetime(2026, 6, 25, 14, 0, tzinfo=timezone.utc).timestamp()) * US

# Two points ~90 m apart, and one ~5 km away.
JETTY = (19.07600, 72.87700)
JETTY_NEARBY = (19.07680, 72.87700)
ACROSS_TOWN = (19.12000, 72.87700)


def fix(ts: int, lat: float, lon: float, accuracy: float | None = None,
        subtype: str = "Significant location") -> Artifact:
    """A device position fix — the strongest kind of presence record."""
    return Artifact(category=Category.PLACE, subtype=subtype, timestamp=ts,
                    latitude=lat, longitude=lon, app="iOS Location Services",
                    attributes={"horizontal_accuracy": accuracy}
                    if accuracy is not None else {})


def maps_search(ts: int, lat: float, lon: float) -> Artifact:
    return Artifact(category=Category.PLACE, subtype="Maps search / destination",
                    timestamp=ts, latitude=lat, longitude=lon,
                    app="Google Maps", body="old jetty")


def location_message(ts: int, lat: float, lon: float,
                     direction: Direction) -> Artifact:
    return Artifact(category=Category.MESSAGE, subtype="WhatsApp location",
                    timestamp=ts, latitude=lat, longitude=lon, app="WhatsApp",
                    direction=direction)


def photo(ts: int, lat: float, lon: float, path: str,
          exif: dict | None = None) -> Artifact:
    return Artifact(category=Category.FILE, subtype="Picture", timestamp=ts,
                    latitude=lat, longitude=lon, source_path=path,
                    attributes={"exif": exif if exif is not None
                                else {"Make": "Apple", "Model": "iPhone 12"}})


class HaversineTests(unittest.TestCase):

    def test_one_degree_of_latitude_is_about_111_km(self):
        self.assertAlmostEqual(haversine_m(0.0, 0.0, 1.0, 0.0), 111_195,
                               delta=100)

    def test_longitude_shrinks_towards_the_pole(self):
        """A degree grid would silently change the match radius with latitude."""
        equator = haversine_m(0.0, 0.0, 0.0, 1.0)
        far_north = haversine_m(60.0, 0.0, 60.0, 1.0)
        self.assertAlmostEqual(far_north / equator, 0.5, delta=0.01)

    def test_identical_points_are_zero(self):
        self.assertEqual(haversine_m(19.076, 72.877, 19.076, 72.877), 0.0)


class PresenceClassificationTests(unittest.TestCase):

    def test_position_fix_is_presence(self):
        point = presence_point(fix(BASE, *JETTY), "EXH-1")
        self.assertIsNotNone(point)
        self.assertEqual(point.weight, 1.0)

    def test_maps_search_is_intent_not_presence(self):
        self.assertIsNone(presence_point(maps_search(BASE, *JETTY), "EXH-1"))

    def test_received_location_is_the_other_party_position(self):
        self.assertIsNone(presence_point(
            location_message(BASE, *JETTY, Direction.INCOMING), "EXH-1"))

    def test_sent_location_counts_but_weighs_less(self):
        point = presence_point(
            location_message(BASE, *JETTY, Direction.OUTGOING), "EXH-1")
        self.assertIsNotNone(point)
        self.assertLess(point.weight, 1.0)

    def test_camera_original_counts_and_downloaded_media_does_not(self):
        original = presence_point(
            photo(BASE, *JETTY, "sdcard/DCIM/Camera/IMG_0042.jpg"), "EXH-1")
        self.assertIsNotNone(original)
        downloaded = presence_point(
            photo(BASE, *JETTY, "sdcard/WhatsApp/Media/IMG-2026.jpg"), "EXH-1")
        self.assertIsNone(downloaded)

    def test_photo_without_maker_tags_is_not_treated_as_camera_original(self):
        self.assertIsNone(presence_point(
            photo(BASE, *JETTY, "sdcard/DCIM/Camera/x.jpg", exif={}), "EXH-1"))

    def test_fix_too_coarse_for_the_radius_is_dropped(self):
        self.assertIsNone(presence_point(
            fix(BASE, *JETTY, accuracy=3000.0), "EXH-1", radius_m=500.0))
        self.assertIsNotNone(presence_point(
            fix(BASE, *JETTY, accuracy=40.0), "EXH-1", radius_m=500.0))

    def test_a_carved_record_carries_less_weight_than_a_live_one(self):
        carved = fix(BASE, *JETTY)
        carved.confidence = 0.5
        self.assertLess(presence_point(carved, "EXH-1").weight,
                        presence_point(fix(BASE, *JETTY), "EXH-1").weight)

    def test_undated_and_unplaced_artifacts_are_ignored(self):
        self.assertIsNone(presence_point(fix(0, *JETTY), "EXH-1"))
        self.assertIsNone(presence_point(
            Artifact(category=Category.PLACE, timestamp=BASE), "EXH-1"))


class EncounterTests(unittest.TestCase):

    def analyse(self, a, b, **kw):
        an = ColocationAnalyser(**kw)
        an.add_exhibit("EXH-1", a)
        an.add_exhibit("EXH-2", b)
        return an

    def test_same_place_same_time_is_an_encounter(self):
        an = self.analyse([fix(BASE, *JETTY)],
                          [fix(BASE + 120 * US, *JETTY_NEARBY)])
        found = an.encounters()
        self.assertEqual(len(found), 1)
        self.assertLess(found[0].closest_m, 200)
        self.assertGreater(found[0].confidence, 0.6)

    def test_same_place_different_day_is_not(self):
        three_days = 3 * 86_400 * US
        an = self.analyse([fix(BASE, *JETTY)],
                          [fix(BASE + three_days, *JETTY)])
        self.assertEqual(an.encounters(), [])

    def test_same_time_different_place_is_not(self):
        an = self.analyse([fix(BASE, *JETTY)], [fix(BASE, *ACROSS_TOWN)])
        self.assertEqual(an.encounters(), [])

    def test_a_run_of_fixes_is_one_encounter_not_twelve(self):
        a = [fix(BASE + i * 300 * US, *JETTY) for i in range(12)]
        b = [fix(BASE + i * 300 * US + 30 * US, *JETTY_NEARBY)
             for i in range(12)]
        found = self.analyse(a, b).encounters()
        self.assertEqual(len(found), 1)
        self.assertGreater(found[0].point_pairs, 12)
        self.assertAlmostEqual(found[0].duration_s, 3330, delta=60)

    def test_two_places_within_one_window_stay_two_encounters(self):
        """Merging them would report a meeting at a centroid nobody visited."""
        a = [fix(BASE, *JETTY), fix(BASE + 600 * US, *ACROSS_TOWN)]
        b = [fix(BASE, *JETTY), fix(BASE + 600 * US, *ACROSS_TOWN)]
        found = self.analyse(a, b).encounters()
        self.assertEqual(len(found), 2)

    def test_searched_destinations_never_produce_an_encounter(self):
        an = self.analyse([maps_search(BASE, *JETTY)],
                          [maps_search(BASE, *JETTY)])
        self.assertEqual(an.encounters(), [])
        self.assertEqual(an.summary()["coordinates_rejected"]["EXH-1"], 1)

    def test_a_shared_pin_does_not_place_the_recipient_there(self):
        """The classic false positive: one location message, two devices."""
        an = self.analyse(
            [location_message(BASE, *JETTY, Direction.OUTGOING)],
            [location_message(BASE, *JETTY, Direction.INCOMING)])
        self.assertEqual(an.encounters(), [])

    def test_closer_and_more_simultaneous_scores_higher(self):
        tight = self.analyse([fix(BASE, *JETTY)],
                             [fix(BASE, *JETTY)]).encounters()[0]
        loose = self.analyse(
            [fix(BASE, *JETTY)],
            [fix(BASE + 800 * US, *JETTY_NEARBY)]).encounters()[0]
        self.assertGreater(tight.confidence, loose.confidence)

    def test_a_single_exhibit_can_never_meet_itself(self):
        an = ColocationAnalyser()
        an.add_exhibit("EXH-1", [fix(BASE, *JETTY), fix(BASE + 60 * US, *JETTY)])
        self.assertEqual(an.encounters(), [])


class FindingTests(unittest.TestCase):

    def _three_days(self):
        a, b = [], []
        for day in range(3):
            ts = BASE + day * 86_400 * US
            a.append(fix(ts, *JETTY))
            b.append(fix(ts + 60 * US, *JETTY_NEARBY))
        an = ColocationAnalyser()
        an.add_exhibit("EXH-1", a)
        an.add_exhibit("EXH-2", b)
        return an

    def test_repeated_meetings_are_critical_and_cite_their_artifacts(self):
        findings = colocation_findings(self._three_days())
        self.assertEqual(len(findings), 1)
        found = findings[0]
        self.assertEqual(found.rule_id, "colocation.rendezvous")
        self.assertEqual(found.severity, "critical")
        self.assertEqual(found.metrics["distinct_days"], 3)
        self.assertTrue(found.artifact_ids)
        self.assertTrue(found.caveat)

    def test_no_encounters_means_no_finding(self):
        an = ColocationAnalyser()
        an.add_exhibit("EXH-1", [fix(BASE, *JETTY)])
        an.add_exhibit("EXH-2", [fix(BASE, *ACROSS_TOWN)])
        self.assertEqual(colocation_findings(an), [])

    def test_summary_is_json_shaped(self):
        import json
        json.dumps(self._three_days().summary())


if __name__ == "__main__":
    unittest.main()
