"""Synthetic KaiOS, Windows Phone and feature-phone dumps with exact ground truth.

Each builder plants a known set of real messages *and* a known set of decoys:
structural noise that a naive scraper will happily report as recovered content.
The decoys are the important half. A scraper that pulls every printable run out
of a binary will produce a report full of column names, file paths and padding
presented as evidence, and an examiner has no way to tell those from the real
records. Precision is measured here, not assumed.

All content is invented.
"""
from __future__ import annotations

import os
import sqlite3
import struct
import tempfile
from typing import List, Tuple

# ─────────────────────────────────────────────────────────────────────── KaiOS
# (sender, text)
KAIOS_MESSAGES: List[Tuple[str, str]] = [
    ("+447700900112", "Bring the second handset to the lockup"),
    ("+447700900455", "Police were asking about the van again"),
    ("+447700900771", "Delete this thread when you have read it"),
]
KAIOS_DELETED: List[Tuple[str, str]] = [
    ("+447700900112", "Money is under the floor in the back room"),
]


def _structured_clone(text: str, number: str) -> bytes:
    """Approximate a Firefox structured-clone blob.

    The real format is undocumented for third parties; what matters for the
    parser is that readable strings sit inside a binary envelope, which is the
    condition it actually has to cope with.
    """
    body = text.encode("utf-16-le")
    num = number.encode("utf-16-le")
    return (b"\x00\x00\x00\x08\xff\xff\xff\x0f"          # clone header
            + struct.pack("<I", len(body)) + body
            + b"\x00\x00\x00\x04"
            + struct.pack("<I", len(num)) + num
            + b"\x13\x00\x00\x00\x00\x00\x00\x00")


def build_kaios(path: str) -> str:
    """A KaiOS IndexedDB store with live and deleted records."""
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("CREATE TABLE object_data ("
                "object_store_id INTEGER, key BLOB, index_data_values BLOB, "
                "file_ids TEXT, data BLOB)")
    rows = KAIOS_MESSAGES + KAIOS_DELETED
    for i, (number, text) in enumerate(rows, start=1):
        con.execute("INSERT INTO object_data VALUES (1,?,NULL,NULL,?)",
                    (struct.pack("<I", i), _structured_clone(text, number)))
    con.commit()
    # Delete the last record so it must be carved from free space.
    con.execute("DELETE FROM object_data WHERE key=?",
                (struct.pack("<I", len(rows)),))
    con.commit()
    con.close()
    return path


# ────────────────────────────────────────────────────────────── Windows Phone
WP_MESSAGES: List[str] = [
    "Meet me behind the depot at eleven",
    "He says the payment cleared this morning",
    "Do not use that number again",
]
# Structural strings an ESE database really does contain. A scraper that
# reports these as messages is fabricating evidence.
WP_DECOYS: List[str] = [
    "C:\\Data\\Users\\DefApps\\APPDATA\\Local\\store.vol",
    "MSysObjects MSysObjectsShadow MSysUnicodeFixupVer2",
    "Message Recipient Attachment ConversationEntry",
    "SOFTWARE\\Microsoft\\Windows Phone\\Messaging",
    "application/x-ms-wmv video/mp4 image/jpeg",
]


def build_windows_phone(path: str) -> str:
    out = bytearray()
    out += b"\x00\x00\x00\x00"
    out += b"\xef\xcd\xab\x89"                    # ESE signature
    out += b"\x00" * 24
    out += b"\xff" * 64

    def utf16(text: str) -> bytes:
        return text.encode("utf-16-le")

    for decoy in WP_DECOYS:
        out += b"\x0c\x00\x00\x00" + utf16(decoy) + b"\x00\x00"
        out += os.urandom(12)
    for message in WP_MESSAGES:
        out += b"\x7f\x00\x00\x02" + utf16(message) + b"\x00\x00"
        out += os.urandom(20)
    out += b"\xff" * 128
    with open(path, "wb") as handle:
        handle.write(bytes(out))
    return path


# ─────────────────────────────────────────────────────────────── feature phone
FP_CONTACTS: List[Tuple[str, str]] = [
    ("Danny Whelan", "+353861234567"),
    ("Garage", "+353877654321"),
    ("Ma", "+353851112223"),
]
FP_MESSAGES: List[str] = [
    "Car is ready collect it after six",
    "Do not ring this phone again tonight",
]
# Firmware strings that live in the same flat file.
FP_DECOYS: List[str] = [
    "MTK6261 NVRAM LID BIN VER 1 0 0",
    "Copyright MediaTek Inc All rights reserved",
    "SETTING PROFILE RINGTONE VOLUME LEVEL",
]


def build_feature_phone(path: str) -> str:
    out = bytearray()
    out += b"MTKNVRAM" + b"\x00" * 8

    for decoy in FP_DECOYS:
        out += decoy.encode("ascii") + b"\x00"
        out += os.urandom(8)

    out += b"\xff" * 32
    for name, number in FP_CONTACTS:                 # UCS-2 name + ASCII number
        out += b"\x01\x00"
        out += name.encode("utf-16-le") + b"\x00\x00"
        out += b"\xff" * (60 - len(name) * 2)
        out += number.encode("ascii") + b"\x00"
        out += b"\xff" * (24 - len(number))

    out += b"\xff" * 32
    for message in FP_MESSAGES:                      # ASCII SMS bodies
        out += b"\x02\x00"
        out += message.encode("ascii") + b"\x00"
        out += b"\xff" * (160 - len(message))

    out += b"\xff" * 64
    with open(path, "wb") as handle:
        handle.write(bytes(out))
    return path


def build_all(directory: str = "") -> dict:
    directory = directory or tempfile.mkdtemp(prefix="argus-platforms-")
    os.makedirs(directory, exist_ok=True)
    return {
        "kaios": build_kaios(os.path.join(directory, "idb-messages.sqlite")),
        "windowsphone": build_windows_phone(os.path.join(directory, "store.vol")),
        "featurephone": build_feature_phone(os.path.join(directory, "pbook.dat")),
        "dir": directory,
    }


if __name__ == "__main__":
    import sys
    built = build_all(sys.argv[1] if len(sys.argv) > 1 else "")
    for key, value in built.items():
        print(f"{key:14} {value}")
