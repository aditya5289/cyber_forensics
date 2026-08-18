"""Build a synthetic SIM dump with exactly known ground truth.

The layout follows ETSI TS 51.011: EF_ICCID (3F00/2FE2), EF_IMSI (7F20/6F07),
EF_ADN (7F10/6F3A) and EF_SMS (7F10/6F3C), each written at a card-specific
offset with 0xFF padding between them, because that is what a real monolithic
dump looks like — the elementary files are not contiguous and not aligned to
any stride the parser can assume.

Ground truth is asserted by tests/test_sim.py. All data is invented.
"""
from __future__ import annotations

import random
from typing import List, Tuple

ICCID = "8991101200003204510"
IMSI = "404450123456789"

# (name, number, deleted)
CONTACTS: List[Tuple[str, str, bool]] = [
    ("Priya Nair", "+919820045511", False),
    ("Dockside Office", "+912266310042", False),
    ("R Menon", "+919833100277", False),
    ("", "+919812277431", True),        # deleted: alpha tag cleared
]

# (status_byte, sender, text)
MESSAGES: List[Tuple[int, str, str]] = [
    (0x01, "+919820045511", "The shipment arrives at berth 4 tonight"),
    (0x01, "+912266310042", "Confirmed, same place as last time"),
    (0x00, "+919833100277", "Burn the manifest once it is signed"),
    (0x00, "+919812277431", "Nobody can trace this SIM to me"),
]

GSM7 = ("@£$¥èéùìòÇ\nØø\r"
        "ÅåΔ_ΦΓΛΩΠΨΣΘ"
        "Ξ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;"
        "<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
        "¿abcdefghijklmnopqrstuvwxyzäöñüà")


def swapped_bcd(digits: str, width: int) -> bytes:
    """Encode digits as swapped nibbles, right-padded with 0xF nibbles."""
    if len(digits) % 2:
        digits += "F"
    out = bytearray()
    for i in range(0, len(digits), 2):
        hi = 0xF if digits[i + 1] == "F" else int(digits[i + 1])
        lo = int(digits[i])
        out.append((hi << 4) | lo)
    return bytes(out).ljust(width, b"\xFF")[:width]


def pack_gsm7(text: str) -> Tuple[bytes, int]:
    """Pack text into 7-bit septets. Returns (bytes, septet count)."""
    septets = [GSM7.index(ch) for ch in text]
    out = bytearray()
    carry, bits = 0, 0
    for value in septets:
        carry |= value << bits
        bits += 7
        while bits >= 8:
            out.append(carry & 0xFF)
            carry >>= 8
            bits -= 8
    if bits:
        out.append(carry & 0xFF)
    return bytes(out), len(septets)


def adn_record(name: str, number: str, record_len: int = 30) -> bytes:
    """One EF_ADN record.

    Critically, the length byte counts *bytes* of TON/NPI + dialling number —
    not digits. EF_SMS address fields count semi-octets instead. Conflating the
    two conventions is the classic SIM-parser bug.
    """
    alpha_len = record_len - 14
    alpha = name.encode("ascii")[:alpha_len].ljust(alpha_len, b"\xFF")
    digits = number.lstrip("+")
    ton_npi = 0x91 if number.startswith("+") else 0x81
    dialling = swapped_bcd(digits, 10)
    length = 1 + (len(digits) + 1) // 2          # TON/NPI byte + BCD bytes
    return (alpha + bytes([length, ton_npi]) + dialling
            + b"\xFF\xFF")                        # CCP, Ext1


def sms_record(status: int, sender: str, text: str,
               record_len: int = 176) -> bytes:
    """One EF_SMS record: status byte + SMS-DELIVER TPDU, 0xFF padded."""
    smsc_digits = "919820000000"
    smsc = bytes([1 + len(smsc_digits) // 2, 0x91]) + swapped_bcd(
        smsc_digits, len(smsc_digits) // 2)

    digits = sender.lstrip("+")
    addr = (bytes([len(digits), 0x91])
            + swapped_bcd(digits, (len(digits) + 1) // 2))

    scts = swapped_bcd("52031409304500", 7)      # 2025-03-41... invented
    payload, septets = pack_gsm7(text)
    tpdu = (smsc + bytes([0x04]) + addr + bytes([0x00, 0x00]) + scts
            + bytes([septets]) + payload)
    return (bytes([status]) + tpdu).ljust(record_len, b"\xFF")[:record_len]


def build(seed: int = 7) -> bytes:
    rng = random.Random(seed)
    out = bytearray()

    def pad(count: int) -> None:
        out.extend(b"\xFF" * count)

    pad(rng.randrange(40, 120))
    out.extend(swapped_bcd(ICCID, 10))            # EF_ICCID

    pad(rng.randrange(60, 200))
    imsi_bcd = swapped_bcd("9" + IMSI, 8)         # parity/first-digit nibble
    out.extend(bytes([8]) + imsi_bcd)             # EF_IMSI

    pad(rng.randrange(80, 260))
    for name, number, _deleted in CONTACTS:       # EF_ADN
        out.extend(adn_record(name, number))

    pad(rng.randrange(100, 300))
    for status, sender, text in MESSAGES:         # EF_SMS
        out.extend(sms_record(status, sender, text))

    pad(rng.randrange(200, 600))
    return bytes(out)


if __name__ == "__main__":
    import pathlib
    import sys

    target = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "sim.bin")
    target.write_bytes(build())
    print(f"wrote {target} ({target.stat().st_size} bytes)")
