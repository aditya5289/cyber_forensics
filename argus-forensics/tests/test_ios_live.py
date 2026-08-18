"""iOS live acquisition helpers."""

from __future__ import annotations

import unittest

from argus.acquire.ios_live import looks_like_apple


class TestLooksLikeApple(unittest.TestCase):
    def test_iphone_name(self) -> None:
        self.assertTrue(looks_like_apple("iPhone 15 Pro"))

    def test_usbmux_transport(self) -> None:
        self.assertTrue(looks_like_apple(transport="usbmux"))

    def test_ios_family(self) -> None:
        self.assertTrue(looks_like_apple(os_family="iOS"))

    def test_android_is_not_apple(self) -> None:
        self.assertFalse(looks_like_apple("Y02", "Android", "mtp"))

    def test_apple_name_without_family(self) -> None:
        self.assertTrue(looks_like_apple("Apple iPhone"))


if __name__ == "__main__":
    unittest.main()
