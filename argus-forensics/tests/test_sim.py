"""SIM parsing measured against a dump whose contents are known exactly.

These assert precision as hard as recall. A SIM pads unused space with 0xFF,
and 0xFF unpacks to a valid GSM-7 index, so a naive decoder emits long runs of
a repeated character as though they were recovered messages. Fabricated content
in a forensic report is worse than a missing record, so the "no spurious"
assertions below are the point of this file, not a footnote to it.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus.parsers.platforms import (
    _plausible_alpha_tag,
    _plausible_sms_text,
    _sim_phonebook,
    _sim_sms,
)

import make_sim


class SimGroundTruth(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = make_sim.build()
        cls.messages = _sim_sms(cls.data)
        claimed = [m["_range"] for m in cls.messages if "_range" in m]
        cls.contacts = _sim_phonebook(cls.data, claimed=claimed)

    # ---------------------------------------------------------------- contacts
    def test_every_planted_contact_recovered(self) -> None:
        by_number = {c["number"].lstrip("+"): c for c in self.contacts}
        for name, number, deleted in make_sim.CONTACTS:
            key = number.lstrip("+")
            self.assertIn(key, by_number, f"lost contact {number}")
            got = by_number[key]
            self.assertEqual(got["deleted"], deleted, f"wrong state for {number}")
            if not deleted:
                self.assertEqual(got["name"], name)

    def test_no_spurious_contacts(self) -> None:
        self.assertEqual(len(self.contacts), len(make_sim.CONTACTS))

    def test_deleted_contact_reported_without_inventing_a_name(self) -> None:
        deleted = [c for c in self.contacts if c["deleted"]]
        self.assertEqual(len(deleted), 1)
        # The SIM cleared the alpha tag. Anything but an empty name here means
        # the backward read spilled into the neighbouring record.
        self.assertEqual(deleted[0]["name"], "")

    def test_numbers_are_not_truncated(self) -> None:
        """EF_ADN counts length in bytes; EF_SMS counts semi-octets.

        Applying the SMS rule to an ADN record halves every number it returns,
        and the result still looks like a plausible phone number, so nothing
        downstream catches it.
        """
        for contact in self.contacts:
            digits = contact["number"].lstrip("+")
            self.assertGreaterEqual(len(digits), 12, contact["number"])

    # ---------------------------------------------------------------- messages
    def test_every_planted_message_recovered(self) -> None:
        texts = [m["text"] for m in self.messages]
        for _status, _sender, text in make_sim.MESSAGES:
            self.assertIn(text, texts)

    def test_deleted_messages_recovered(self) -> None:
        deleted = {m["text"] for m in self.messages if m.get("deleted")}
        expected = {t for status, _s, t in make_sim.MESSAGES if status == 0x00}
        self.assertEqual(deleted, expected)

    def test_no_spurious_messages(self) -> None:
        self.assertEqual(len(self.messages), len(make_sim.MESSAGES))

    def test_padding_is_never_reported_as_a_message(self) -> None:
        for message in self.messages:
            self.assertNotIn("àààà", message["text"])


class TextGates(unittest.TestCase):
    def test_repeated_padding_character_rejected(self) -> None:
        self.assertFalse(_plausible_sms_text("à" * 40))
        self.assertFalse(_plausible_sms_text("ààààààààààààxà"))

    def test_real_message_accepted(self) -> None:
        self.assertTrue(_plausible_sms_text("Meet me at the dock at nine"))

    def test_mojibake_rejected(self) -> None:
        self.assertFalse(_plausible_sms_text("x9ßh8XòÑ<x8Θòæ:zÆh42Γòñ(;Θ¿"))

    def test_alpha_tag_fragment_rejected(self) -> None:
        # A scrap read out of an adjacent record's BCD digits.
        self.assertFalse(_plausible_alpha_tag(" w"))
        self.assertFalse(_plausible_alpha_tag("\x0f3"))

    def test_real_names_accepted(self) -> None:
        for name in ("Priya Nair", "Dockside Office", "R Menon", "O'Neill"):
            self.assertTrue(_plausible_alpha_tag(name), name)


if __name__ == "__main__":
    unittest.main()
