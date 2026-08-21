"""Catalogue breadth and capability inference.

Breadth is only worth having if it stays honest. Two failure modes matter more
than coverage here:

* a fuzzy search resolving an unknown handset to a *similar* catalogued one,
  which would hand the examiner a capability matrix for the wrong device;
* an inferred profile presenting itself as a tested one.

Both would authorise a method the real device does not support. The tests below
exist mainly to make those two impossible.
"""
from __future__ import annotations

import unittest

from argus.core.errors import DeviceNotSupportedError
from argus.devices.families import (
    android_encryption,
    identify_chipset,
    infer,
)
from argus.devices.manual import DeviceManual


class CatalogueBreadth(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manual = DeviceManual()

    def test_catalogue_covers_the_common_vendors(self) -> None:
        makes = {p.make for p in self.manual.profiles}
        for expected in ("Apple", "Samsung", "Xiaomi", "Google", "OnePlus",
                         "Motorola", "Oppo", "Vivo", "Realme", "Nokia",
                         "Huawei", "Honor", "Sony", "Tecno", "Infinix",
                         "itel"):
            self.assertIn(expected, makes)

    def test_catalogue_is_substantial(self) -> None:
        self.assertGreaterEqual(len(self.manual), 100)

    def test_lookup_by_model_code(self) -> None:
        for code, expected in [("SM-S911B", "Galaxy S23"),
                               ("SM-A235F", "Galaxy A23"),
                               ("iPhone15,2", "iPhone 14 Pro"),
                               ("RMX3471", "9 Pro"),
                               ("oriole", "Pixel 6")]:
            profile = self.manual.get(code)
            self.assertIn(expected.split()[-1], profile.name, code)

    def test_every_profile_offers_something_at_every_lock_state(self) -> None:
        """Even a BFU modern handset has SIM and photographic documentation.

        An empty cell reads as "nothing is possible", which is never true and
        would stop an examiner who still has lawful options.
        """
        for profile in self.manual.profiles:
            for state in ("unlocked", "afu", "bfu", "locked"):
                self.assertTrue(profile.methods_for(state),
                                f"{profile.name} has no method at {state}")

    def test_modern_ios_yields_nothing_extra_before_first_unlock(self) -> None:
        profile = self.manual.get("iPhone 15 Pro")
        methods = {c.method for c in profile.methods_for("bfu")}
        self.assertNotIn("physical", methods)
        self.assertNotIn("filesystem", methods)

    def test_checkm8_era_iphone_allows_physical_when_locked(self) -> None:
        profile = self.manual.get("iPhone 8")
        self.assertIn("physical",
                      {c.method for c in profile.methods_for("bfu")})


class NoSilentSubstitution(unittest.TestCase):
    """The catalogue must not answer for a device it does not hold."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manual = DeviceManual()

    def test_unknown_handset_is_not_resolved_to_a_lookalike(self) -> None:
        # "Galaxy S25" does not exist in the catalogue; S24 does and is a close
        # string match. Returning S24 here would be a silent substitution.
        with self.assertRaises(DeviceNotSupportedError):
            self.manual.get("Galaxy S25 Ultra Enterprise Edition")

    def test_unknown_without_chipset_refuses_rather_than_guesses(self) -> None:
        with self.assertRaises(DeviceNotSupportedError):
            self.manual.profile_or_inference("Cubot King Kong 9")


class Inference(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manual = DeviceManual()

    def test_catalogued_device_is_not_inferred(self) -> None:
        result = self.manual.profile_or_inference("Galaxy S23")
        self.assertFalse(result["inferred"])
        self.assertEqual(result["confidence"], 1.0)

    def test_uncatalogued_device_gets_a_reasoned_profile(self) -> None:
        result = self.manual.profile_or_inference(
            "Cubot King Kong 9", chipset="MediaTek Helio G99",
            os_family="Android", os_version="13")
        self.assertTrue(result["inferred"])
        inference = result["inference"]
        self.assertEqual(inference["encryption"], "FBE")
        self.assertIn("MediaTek", inference["chipset_family"])
        self.assertTrue(inference["reasoning"])

    def test_inference_never_outranks_a_catalogued_entry(self) -> None:
        result = self.manual.profile_or_inference(
            "Nonexistent X1", chipset="Snapdragon 8 Gen 3",
            os_family="Android", os_version="14")
        self.assertLess(result["confidence"], 1.0)

    def test_inference_always_carries_its_caveat(self) -> None:
        result = self.manual.profile_or_inference(
            "Nonexistent X1", chipset="Unisoc T606", os_family="Android",
            os_version="12")
        self.assertIn("inferred", result["inference"]["caveat"].lower())

    def test_bootrom_family_permits_physical_at_every_lock_state(self) -> None:
        result = infer(os_family="Android", chipset="MediaTek Helio G85",
                       os_version="11")
        for state in ("unlocked", "afu", "bfu", "locked"):
            self.assertIn("physical", result.methods[state], state)

    def test_bootrom_image_does_not_imply_readable_data(self) -> None:
        """The distinction that stops an examiner over-promising in a report."""
        result = infer(os_family="Android", chipset="MediaTek Dimensity 7020",
                       os_version="13")
        joined = " ".join(result.reasoning).lower()
        self.assertIn("encryption", joined)

    def test_unrecognised_chipset_says_so_rather_than_inventing(self) -> None:
        result = infer(os_family="Android", chipset="Frobnicator 9000",
                       os_version="13")
        self.assertIsNone(result.family)
        joined = " ".join(result.reasoning).lower()
        self.assertIn("not recognised", joined)
        # No SoC-specific route may be claimed.
        self.assertNotIn("physical", result.methods["bfu"])

    def test_missing_os_version_is_flagged_as_a_material_gap(self) -> None:
        result = infer(os_family="Android", chipset="Snapdragon 888")
        joined = " ".join(result.reasoning).lower()
        self.assertIn("version unknown", joined)


class EncryptionEras(unittest.TestCase):
    def test_android_eras(self) -> None:
        self.assertEqual(android_encryption(4.4)[0], "none")
        self.assertEqual(android_encryption(7)[0], "FDE")
        self.assertEqual(android_encryption(10)[0], "FBE")
        self.assertEqual(android_encryption(15)[0], "FBE")

    def test_unknown_version_is_unknown_not_assumed(self) -> None:
        self.assertEqual(android_encryption(0)[0], "unknown")

    def test_checkm8_era_matched_before_generic_apple(self) -> None:
        """A9/A10/A11 must resolve to the exploitable family, not the generic one."""
        for chipset in ("Apple A9", "Apple A10 Fusion", "Apple A11 Bionic"):
            family = identify_chipset(chipset)
            self.assertIsNotNone(family, chipset)
            self.assertTrue(family.bootrom_exploit, chipset)

    def test_modern_apple_is_not_marked_exploitable(self) -> None:
        for chipset in ("Apple A14 Bionic", "Apple A17 Pro", "Apple A18"):
            family = identify_chipset(chipset)
            self.assertIsNotNone(family, chipset)
            self.assertFalse(family.bootrom_exploit, chipset)


if __name__ == "__main__":
    unittest.main()
