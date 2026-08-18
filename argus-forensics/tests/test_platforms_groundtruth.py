"""KaiOS, Windows Phone and feature-phone parsing against known contents.

Each fixture plants real records *and* structural decoys — ESE table names,
registry paths, MIME lists, firmware banners — because those are what a
printable-run scraper actually returns from these formats. The decoy assertions
are the reason this file exists: a scraper that reports "MSysObjects
MSysObjectsShadow" as a recovered message has not found evidence, it has
manufactured it, and nothing downstream can tell the difference.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from argus.core.models import Category, Recovery
from argus.parsers.platforms import (
    looks_like_message,
    parse_feature_phone,
    parse_kaios,
    parse_windows_phone,
)
from argus.parsers.registry import ParseContext

import make_platforms


class PlatformFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempfile.mkdtemp(prefix="argus-platform-test-")
        cls.built = make_platforms.build_all(cls.dir)
        cls.ctx = ParseContext(evidence_root=Path(cls.dir))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.dir, ignore_errors=True)

    def bodies(self, result) -> list:
        return [a.body or "" for a in result.artifacts]


class KaiOS(PlatformFixture):
    def setUp(self) -> None:
        self.result = parse_kaios(Path(self.built["kaios"]), self.ctx)

    def test_all_live_messages_recovered(self) -> None:
        bodies = self.bodies(self.result)
        for _number, text in make_platforms.KAIOS_MESSAGES:
            self.assertIn(text, bodies)

    def test_deleted_message_recovered(self) -> None:
        deleted = [a.body for a in self.result.artifacts
                   if a.recovery != Recovery.ALLOCATED]
        for _number, text in make_platforms.KAIOS_DELETED:
            self.assertIn(text, deleted)

    def test_utf16_clone_strings_are_read_at_all(self) -> None:
        """A UTF-8 printable sweep returns nothing from a structured clone.

        KaiOS stores JavaScript strings as UTF-16LE, so without a UTF-16 pass
        this parser silently reports an entire handset as empty.
        """
        self.assertTrue(self.result.artifacts)

    def test_no_spurious_records(self) -> None:
        expected = len(make_platforms.KAIOS_MESSAGES) + \
            len(make_platforms.KAIOS_DELETED)
        self.assertEqual(len(self.result.artifacts), expected)

    def test_extraction_method_is_disclosed(self) -> None:
        for artifact in self.result.artifacts:
            self.assertIn("blob", artifact.attributes["extraction_method"])


class WindowsPhone(PlatformFixture):
    def setUp(self) -> None:
        self.result = parse_windows_phone(
            Path(self.built["windowsphone"]), self.ctx)

    def test_all_messages_recovered(self) -> None:
        bodies = self.bodies(self.result)
        for text in make_platforms.WP_MESSAGES:
            self.assertIn(text, bodies)

    def test_ese_structural_strings_are_not_reported_as_messages(self) -> None:
        bodies = " || ".join(self.bodies(self.result))
        for decoy in make_platforms.WP_DECOYS:
            self.assertNotIn(decoy, bodies)

    def test_no_spurious_records(self) -> None:
        self.assertEqual(len(self.result.artifacts),
                         len(make_platforms.WP_MESSAGES))

    def test_scraping_limits_are_stated_on_every_artifact(self) -> None:
        """Scraped text has no timestamp or correspondent, and must say so."""
        for artifact in self.result.artifacts:
            note = artifact.attributes.get("note", "").lower()
            self.assertIn("scraping", note)
            self.assertIsNone(artifact.timestamp)


class FeaturePhone(PlatformFixture):
    def setUp(self) -> None:
        self.result = parse_feature_phone(
            Path(self.built["featurephone"]), self.ctx)

    def contacts(self) -> list:
        return [a for a in self.result.artifacts
                if a.category == Category.CONTACT]

    def messages(self) -> list:
        return [a for a in self.result.artifacts
                if a.category == Category.MESSAGE]

    def test_contacts_are_paired_with_their_numbers(self) -> None:
        pairs = {(a.attributes.get("name"),
                  (a.attributes.get("phone_numbers") or [""])[0])
                 for a in self.contacts()}
        for name, number in make_platforms.FP_CONTACTS:
            self.assertIn((name, number), pairs)

    def test_contact_names_are_not_reported_as_messages(self) -> None:
        bodies = " || ".join(a.body or "" for a in self.messages())
        for name, _number in make_platforms.FP_CONTACTS:
            self.assertNotIn(name, bodies)

    def test_all_messages_recovered(self) -> None:
        bodies = [a.body for a in self.messages()]
        for text in make_platforms.FP_MESSAGES:
            self.assertIn(text, bodies)

    def test_firmware_strings_are_not_reported_as_messages(self) -> None:
        bodies = " || ".join(a.body or "" for a in self.result.artifacts)
        for decoy in make_platforms.FP_DECOYS:
            self.assertNotIn(decoy, bodies)

    def test_no_spurious_records(self) -> None:
        self.assertEqual(len(self.messages()), len(make_platforms.FP_MESSAGES))
        self.assertEqual(len(self.contacts()), len(make_platforms.FP_CONTACTS))


class MessageGate(unittest.TestCase):
    """The single gate that decides whether scraped bytes become evidence."""

    def test_prose_accepted(self) -> None:
        for text in ("Meet me behind the depot at eleven",
                     "he says the payment cleared this morning",
                     "Do not ring this phone again tonight"):
            self.assertTrue(looks_like_message(text), text)

    def test_identifier_lists_rejected(self) -> None:
        for text in ("Message Recipient Attachment ConversationEntry",
                     "MSysObjects MSysObjectsShadow MSysUnicodeFixupVer2",
                     "SETTING PROFILE RINGTONE VOLUME LEVEL"):
            self.assertFalse(looks_like_message(text), text)

    def test_paths_and_registry_keys_rejected(self) -> None:
        for text in (r"C:\Data\Users\DefApps\APPDATA\Local\store.vol",
                     r"SOFTWARE\Microsoft\Windows Phone\Messaging",
                     "/usr/share/lib/firmware/modem.bin"):
            self.assertFalse(looks_like_message(text), text)

    def test_mime_lists_rejected(self) -> None:
        self.assertFalse(
            looks_like_message("application/x-ms-wmv video/mp4 image/jpeg"))

    def test_copyright_banners_rejected(self) -> None:
        self.assertFalse(
            looks_like_message("Copyright MediaTek Inc All rights reserved"))

    def test_short_fragments_rejected(self) -> None:
        self.assertFalse(looks_like_message("ok"))
        self.assertFalse(looks_like_message("yes no"))


if __name__ == "__main__":
    unittest.main()
