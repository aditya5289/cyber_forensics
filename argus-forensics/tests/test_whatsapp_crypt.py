"""Tests for WhatsApp crypt decryption helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argus.parsers.android import whatsapp_crypt as wc


class TestWhatsAppCrypt(unittest.TestCase):
    def test_parse_key_file_32_bytes(self) -> None:
        key = bytes(range(32))
        self.assertEqual(wc.parse_key_file(key), key)

    def test_parse_key_file_hex(self) -> None:
        raw = bytes(range(32))
        self.assertEqual(wc.parse_key_file(raw.hex().encode()), raw)

    def test_parse_key_file_158_byte_layout(self) -> None:
        blob = b"\x00" * 126 + bytes(range(32))
        self.assertEqual(wc.parse_key_file(blob), bytes(range(32)))

    def test_decrypt_fails_without_crypto_lib_on_garbage(self) -> None:
        key = bytes(range(32))
        result = wc.decrypt_crypt_payload(key, b"\x00" * 256)
        self.assertIsNone(result)

    def test_parse_recovery_key_spaced(self) -> None:
        raw = bytes(range(32))
        spaced = " ".join(raw.hex()[i:i + 4] for i in range(0, 64, 4))
        self.assertEqual(wc.parse_recovery_key(spaced), raw)

    def test_crypt15_no_key_returns_none(self) -> None:
        self.assertIsNone(wc.decrypt_crypt15(b"\x00" * 512))

    def test_find_crypt_and_key_in_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_dir = root / "filesystem" / "data" / "data" / "com.whatsapp" / "files"
            key_dir.mkdir(parents=True)
            (key_dir / "key").write_bytes(b"\x00" * 126 + bytes(range(32)))
            crypt_dir = root / "sdcard" / "WhatsApp" / "Databases"
            crypt_dir.mkdir(parents=True)
            (crypt_dir / "msgstore.db.crypt14").write_bytes(b"\x00" * 512)
            summary = wc.decrypt_whatsapp_backups(root)
            self.assertEqual(summary.attempted, 1)
            self.assertGreaterEqual(len(wc._find_key_files(root)), 1)
