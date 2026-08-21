"""OEM path expansion — Transsion, ColorOS, Motorola aliases."""

from __future__ import annotations

import unittest

from argus.acquire import android_vendor as vendor
from argus.acquire.android_apps import KNOWN_APPS
from argus.acquire.mtp import MTPDevice, pick_device


class VendorExpansion(unittest.TestCase):
    def test_tecno_maps_to_transsion_backup_paths(self) -> None:
        paths = {p for p, _ in vendor.expand_fs_paths("Tecno")}
        self.assertTrue(any("HiOS" in p or "PhoneClone" in p or "Transsion" in p
                            for p in paths))
        comm = {p for p, _ in vendor.expand_comm_paths("Infinix")}
        self.assertTrue(any("PhoneClone" in p or "XOS" in p for p in comm))

    def test_itel_and_hios_alias(self) -> None:
        self.assertTrue(vendor.expand_fs_paths("itel A70"))
        self.assertEqual(
            vendor._normalize_make("HiOS Spark"), "transsion")

    def test_coloros_providers(self) -> None:
        keys = {k for k, _, _ in vendor.extra_providers("OPPO")}
        self.assertIn("coloros_sms", keys)
        self.assertIn("oppo_sms", keys)

    def test_vivo_still_has_easyshare(self) -> None:
        paths = {p for p, _ in vendor.expand_fs_paths("vivo", "Y02")}
        self.assertTrue(any("easyshare" in p.lower() for p in paths))

    def test_known_apps_cover_regional_messengers(self) -> None:
        for pkg in ("com.tencent.mm", "jp.naver.line.android",
                    "com.transsion.smartmessage"):
            self.assertIn(pkg, KNOWN_APPS)


class MtpPick(unittest.TestCase):
    def test_picks_matching_handset_not_first(self) -> None:
        found = [
            MTPDevice(name="Pixel 8", path="usb#vid_18d1"),
            MTPDevice(name="Y02", path="usb#vid_2d95&pid_6002#10bcc"),
        ]
        chosen = pick_device(found, name="Vivo Y02", serial="10bcc10pbl0005n")
        self.assertEqual(chosen.name, "Y02")
