#!/usr/bin/env python3
"""Ground-truth fixtures for the ARGUS self-test, and a mirror of its parsers.

WHY THIS EXISTS

The self-test in ARGUS.ps1 checks that a corrupt JPEG yields no GPS and that a
truncated MP4 does not hang. Those are negative controls, and they are the
easier half. A parser that returned null for every input in the universe would
pass every one of them.

So this builds two files whose correct answer is known exactly - a JPEG whose
EXIF says one specific thing, and an MP4 whose atoms say another - and then
reimplements the PowerShell parsing algorithm here, step for step, to check
that the algorithm actually recovers those values. Any disagreement is a bug in
the algorithm, found before it is pointed at evidence rather than after.

The fixtures are emitted as base64 so they can be embedded in the script, which
keeps the tool a single file with no external test data to lose.
"""
from __future__ import annotations

import base64
import struct

# ---------------------------------------------------------------- ground truth
EXPECT = {
    'make': 'ARGUS',
    'model': 'TESTCAM-1',
    'taken': '2024:03:15 14:22:07',
    # Greenwich observatory, to six places.
    'lat': 51.477500,
    'lon': -0.001500,
    'video_created': '2021-06-01 09:30:00Z',
    'video_lat': 48.858200,
    'video_lon': 2.294500,
    'video_duration': 12.5,
}


# ============================================================ JPEG with EXIF
def rational(num: int, den: int) -> bytes:
    return struct.pack('<II', num, den)


def build_jpeg() -> bytes:
    """A minimal JPEG carrying EXIF: make, model, capture time and a GPS fix."""
    make = EXPECT['make'].encode() + b'\x00'
    model = EXPECT['model'].encode() + b'\x00'
    taken = EXPECT['taken'].encode() + b'\x00'

    # Latitude 51 deg 28' 39" N  ->  51 + 28/60 + 39/3600 = 51.4775
    lat_vals = rational(51, 1) + rational(28, 1) + rational(39, 1)
    # Longitude 0 deg 0' 5.4" W  ->  5.4/3600 = 0.0015
    lon_vals = rational(0, 1) + rational(0, 1) + rational(54, 10)

    # Lay the TIFF block out by hand so every offset is known.
    # TIFF header is 8 bytes; IFD0 starts at 8.
    ifd0_count = 4
    ifd0_size = 2 + ifd0_count * 12 + 4          # = 54
    ifd0_start = 8
    data_start = ifd0_start + ifd0_size          # = 62

    off = data_start
    make_off = off;  off += len(make)
    model_off = off; off += len(model)

    exif_ifd_off = off
    exif_count = 1
    exif_size = 2 + exif_count * 12 + 4          # = 18
    off += exif_size
    taken_off = off; off += len(taken)

    gps_ifd_off = off
    gps_count = 4
    gps_size = 2 + gps_count * 12 + 4            # = 54
    off += gps_size
    # NOTE: GPSLatitudeRef / GPSLongitudeRef are 2-byte ASCII, so per TIFF they
    # live INLINE in the entry's value field, not at an offset. Writing them
    # out-of-line produced a fixture that no conformant reader could parse -
    # and the parser was right to refuse it. Keeping this note because the
    # first run of this file "failed" on a bug that was in the test, not the
    # code, which is its own useful reminder.
    lat_off = off; off += 24  # 3 rationals
    lon_off = off; off += 24

    def entry(tag: int, typ: int, count: int, value: int | bytes) -> bytes:
        if isinstance(value, bytes):
            payload = value.ljust(4, b'\x00')[:4]
        else:
            payload = struct.pack('<I', value)
        return struct.pack('<HHI', tag, typ, count) + payload

    ifd0 = struct.pack('<H', ifd0_count)
    ifd0 += entry(0x010F, 2, len(make), make_off)      # Make
    ifd0 += entry(0x0110, 2, len(model), model_off)    # Model
    ifd0 += entry(0x8769, 4, 1, exif_ifd_off)          # Exif IFD pointer
    ifd0 += entry(0x8825, 4, 1, gps_ifd_off)           # GPS IFD pointer
    ifd0 += struct.pack('<I', 0)                       # no IFD1
    assert len(ifd0) == ifd0_size, (len(ifd0), ifd0_size)

    exif_ifd = struct.pack('<H', exif_count)
    exif_ifd += entry(0x9003, 2, len(taken), taken_off)   # DateTimeOriginal
    exif_ifd += struct.pack('<I', 0)
    assert len(exif_ifd) == exif_size

    gps_ifd = struct.pack('<H', gps_count)
    gps_ifd += entry(0x0001, 2, 2, b'N\x00')     # GPSLatitudeRef  (inline)
    gps_ifd += entry(0x0002, 5, 3, lat_off)      # GPSLatitude
    gps_ifd += entry(0x0003, 2, 2, b'W\x00')     # GPSLongitudeRef (inline)
    gps_ifd += entry(0x0004, 5, 3, lon_off)      # GPSLongitude
    gps_ifd += struct.pack('<I', 0)
    assert len(gps_ifd) == gps_size

    tiff = b'II' + struct.pack('<HI', 42, ifd0_start)
    tiff += ifd0 + make + model + exif_ifd + taken + gps_ifd
    tiff += lat_vals + lon_vals
    assert len(tiff) == off, (len(tiff), off)

    app1_payload = b'Exif\x00\x00' + tiff
    app1 = b'\xFF\xE1' + struct.pack('>H', len(app1_payload) + 2) + app1_payload

    # A tiny but structurally real image body so the file is a JPEG, not just
    # a header. The parser must stop at the scan and not read into it.
    body = (b'\xFF\xDB\x00\x43\x00' + bytes([16] * 64) +
            b'\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00' +
            b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00' +
            b'\x00\x00\x00\x00' + b'\xFF\xD9')
    return b'\xFF\xD8' + app1 + body


# ================================================================ MP4 fixture
def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack('>I', len(payload) + 8) + kind + payload


def build_mp4() -> bytes:
    """A minimal MP4 with a known mvhd creation time and a (c)xyz location."""
    # Seconds from 1904-01-01 to 2021-06-01 09:30:00 UTC.
    from datetime import datetime, timezone
    epoch1904 = datetime(1904, 1, 1, tzinfo=timezone.utc)
    target = datetime(2021, 6, 1, 9, 30, 0, tzinfo=timezone.utc)
    created = int((target - epoch1904).total_seconds())

    timescale = 1000
    duration = int(EXPECT['video_duration'] * timescale)

    mvhd_payload = struct.pack('>B3s', 0, b'\x00\x00\x00')
    mvhd_payload += struct.pack('>IIII', created, created, timescale, duration)
    mvhd_payload += struct.pack('>IH', 0x00010000, 0x0100)      # rate, volume
    mvhd_payload += b'\x00' * 10                                 # reserved
    mvhd_payload += b'\x00' * 36                                 # matrix
    mvhd_payload += b'\x00' * 24                                 # predefined
    mvhd_payload += struct.pack('>I', 2)                         # next track id
    mvhd = box(b'mvhd', mvhd_payload)

    loc = f"+{EXPECT['video_lat']:.4f}+{EXPECT['video_lon']:.4f}/".encode('ascii')
    xyz_payload = struct.pack('>HH', len(loc), 0x15C7) + loc
    xyz = box(b'\xA9xyz', xyz_payload)
    udta = box(b'udta', xyz)

    moov = box(b'moov', mvhd + udta)
    ftyp = box(b'ftyp', b'isom' + struct.pack('>I', 512) + b'isomiso2mp41')
    mdat = box(b'mdat', b'\x00' * 64)
    return ftyp + mdat + moov


# ============================ mirror of the PowerShell parsing algorithm =====
def read_u16(b: bytes, off: int, big: bool) -> int:
    if off < 0 or off + 2 > len(b):
        return -1
    return (b[off] << 8 | b[off + 1]) if big else (b[off + 1] << 8 | b[off])


def read_u32(b: bytes, off: int, big: bool) -> int:
    if off < 0 or off + 4 > len(b):
        return -1
    if big:
        return b[off] * 16777216 + b[off + 1] * 65536 + b[off + 2] * 256 + b[off + 3]
    return b[off + 3] * 16777216 + b[off + 2] * 65536 + b[off + 1] * 256 + b[off]


TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def get_ifd(tiff: bytes, ifd_off: int, big: bool) -> dict:
    entries = {}
    if ifd_off < 0 or ifd_off + 2 > len(tiff):
        return entries
    count = read_u16(tiff, ifd_off, big)
    if count < 0 or count > 512:
        return entries
    for i in range(count):
        e = ifd_off + 2 + i * 12
        if e + 12 > len(tiff):
            break
        tag = read_u16(tiff, e, big)
        typ = read_u16(tiff, e + 2, big)
        n = read_u32(tiff, e + 4, big)
        if tag < 0 or typ < 1 or typ > 12 or n < 0:
            continue
        nbytes = TYPE_SIZE[typ] * n
        if nbytes < 0 or nbytes > len(tiff):
            continue
        data_off = (e + 8) if nbytes <= 4 else read_u32(tiff, e + 8, big)
        if data_off < 0 or data_off + nbytes > len(tiff):
            continue
        entries[tag] = {'type': typ, 'count': n, 'offset': data_off}
    return entries


def tag_ascii(tiff: bytes, entry) -> str:
    if not entry:
        return ''
    n = entry['count']
    if n <= 0 or entry['offset'] + n > len(tiff):
        return ''
    return tiff[entry['offset']:entry['offset'] + n].decode('latin-1').strip('\x00').strip()


def tag_rationals(tiff: bytes, entry, big: bool):
    out = []
    if not entry or entry['type'] != 5:
        return out
    for i in range(entry['count']):
        o = entry['offset'] + i * 8
        num = read_u32(tiff, o, big)
        den = read_u32(tiff, o + 4, big)
        out.append(0.0 if (num < 0 or den <= 0) else num / den)
    return out


def parse_exif(data: bytes) -> dict:
    r = {'has': False, 'make': '', 'model': '', 'taken': '', 'lat': None, 'lon': None}
    if len(data) < 32 or data[0] != 0xFF or data[1] != 0xD8:
        return r
    i = 2
    tiff = None
    while i < len(data) - 4:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        i += 2
        while marker == 0xFF and i < len(data):
            marker = data[i]
            i += 1
        if marker in (0xD9, 0xDA):
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > len(data):
            break
        length = data[i] * 256 + data[i + 1]
        i += 2
        if length < 2 or i + length - 2 > len(data):
            break
        if marker == 0xE1 and length > 8:
            sig = data[i:i + 6]
            if sig[:4] == b'Exif':
                tiff = data[i + 6:i + 6 + (length - 8)]
                break
            i += length - 8 + 6
        else:
            i += length - 2
    if not tiff or len(tiff) < 8:
        return r

    big = tiff[0] == 0x4D and tiff[1] == 0x4D
    if not big and not (tiff[0] == 0x49 and tiff[1] == 0x49):
        return r
    if read_u16(tiff, 2, big) != 42:
        return r
    ifd0 = read_u32(tiff, 4, big)
    e0 = get_ifd(tiff, ifd0, big)
    if not e0:
        return r
    r['has'] = True
    r['make'] = tag_ascii(tiff, e0.get(0x010F))
    r['model'] = tag_ascii(tiff, e0.get(0x0110))
    if 0x8769 in e0:
        sub = get_ifd(tiff, read_u32(tiff, e0[0x8769]['offset'], big), big)
        dto = tag_ascii(tiff, sub.get(0x9003))
        if dto:
            r['taken'] = dto
    if 0x8825 in e0:
        gps = get_ifd(tiff, read_u32(tiff, e0[0x8825]['offset'], big), big)
        latref = tag_ascii(tiff, gps.get(0x0001))
        lonref = tag_ascii(tiff, gps.get(0x0003))
        lat = tag_rationals(tiff, gps.get(0x0002), big)
        lon = tag_rationals(tiff, gps.get(0x0004), big)
        if len(lat) >= 3 and len(lon) >= 3:
            dlat = lat[0] + lat[1] / 60 + lat[2] / 3600
            dlon = lon[0] + lon[1] / 60 + lon[2] / 3600
            if latref.upper().startswith('S'):
                dlat = -dlat
            if lonref.upper().startswith('W'):
                dlon = -dlon
            if abs(dlat) > 0.0001 or abs(dlon) > 0.0001:
                r['lat'] = round(dlat, 6)
                r['lon'] = round(dlon, 6)
    return r


def parse_mp4(data: bytes, ascii_decode: bool) -> dict:
    """ascii_decode mirrors [Text.Encoding]::ASCII vs latin-1 in the script."""
    r = {'has': False, 'created': '', 'duration': None, 'lat': None, 'lon': None}

    def find_box(start, end, wanted):
        pos = start
        while pos + 8 <= min(end, len(data)):
            size = read_u32(data, pos, True)
            kind = data[pos + 4:pos + 8]
            hlen = 8
            if size == 1:
                if pos + 16 > len(data):
                    return None
                size = int.from_bytes(data[pos + 8:pos + 16], 'big')
                hlen = 16
            elif size == 0:
                size = len(data) - pos
            if size < hlen:
                return None
            if pos + size > end or pos + size <= pos:
                return None
            if kind == wanted:
                return (pos + hlen, pos + size)
            pos += size
        return None

    moov = find_box(0, len(data), b'moov')
    if not moov:
        return r
    mvhd = find_box(moov[0], moov[1], b'mvhd')
    if mvhd:
        p = mvhd[0]
        version = data[p]
        p += 4
        if version == 1:
            created = int.from_bytes(data[p:p + 8], 'big')
            timescale = read_u32(data, p + 16, True)
            duration = int.from_bytes(data[p + 20:p + 28], 'big')
        else:
            created = read_u32(data, p, True)
            timescale = read_u32(data, p + 8, True)
            duration = read_u32(data, p + 12, True)
        if 0 < created < 4102444800:
            from datetime import datetime, timedelta, timezone
            dt = datetime(1904, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=created)
            if 1990 <= dt.year <= 2100:
                r['created'] = dt.strftime('%Y-%m-%d %H:%M:%S') + 'Z'
                r['has'] = True
        if timescale > 0 and duration > 0:
            r['duration'] = round(duration / timescale, 1)
            r['has'] = True

    udta = find_box(moov[0], moov[1], b'udta')
    if udta:
        blob = data[udta[0]:min(udta[1], udta[0] + 65536)]
        if ascii_decode:
            # THIS is what [System.Text.Encoding]::ASCII.GetString does to a
            # byte above 0x7F: it substitutes '?'. The (c) in (c)xyz is 0xA9.
            text = ''.join(chr(b) if b < 0x80 else '?' for b in blob)
        else:
            text = blob.decode('latin-1')
        marker = chr(0xA9) + 'xyz'
        idx = text.find(marker)
        if idx >= 0:
            import re
            tail = text[idx + 4:]
            m = re.search(r'([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)', tail)
            if m:
                la, lo = float(m.group(1)), float(m.group(2))
                if abs(la) <= 90 and abs(lo) <= 180 and (abs(la) > 0.0001 or abs(lo) > 0.0001):
                    r['lat'] = round(la, 6)
                    r['lon'] = round(lo, 6)
                    r['has'] = True
    return r


# ======================================================================= main
def main():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        if not good:
            ok = False
        print(f"  {'PASS' if good else 'FAIL'}  {name:<38} got={got!r} want={want!r}")

    jpeg = build_jpeg()
    mp4 = build_mp4()

    print(f"JPEG fixture: {len(jpeg)} bytes")
    print(f"MP4  fixture: {len(mp4)} bytes")
    print()

    print("EXIF algorithm against known ground truth:")
    x = parse_exif(jpeg)
    check('has EXIF', x['has'], True)
    check('make', x['make'], EXPECT['make'])
    check('model', x['model'], EXPECT['model'])
    check('capture time', x['taken'], EXPECT['taken'])
    check('latitude', x['lat'], EXPECT['lat'])
    check('longitude', x['lon'], EXPECT['lon'])
    print()

    print("EXIF negative controls:")
    check('random bytes yield nothing', parse_exif(bytes(range(64)) * 4)['has'], False)
    truncated = jpeg[:40]
    check('truncated JPEG yields no GPS', parse_exif(truncated)['lat'], None)
    print()

    print("MP4 algorithm, ASCII decode (what the script currently does):")
    v_ascii = parse_mp4(mp4, ascii_decode=True)
    check('creation time', v_ascii['created'], EXPECT['video_created'])
    check('duration', v_ascii['duration'], EXPECT['video_duration'])
    check('latitude', v_ascii['lat'], EXPECT['video_lat'])
    check('longitude', v_ascii['lon'], EXPECT['video_lon'])
    print()

    print("MP4 algorithm, latin-1 decode (byte-preserving):")
    v_latin = parse_mp4(mp4, ascii_decode=False)
    check('creation time', v_latin['created'], EXPECT['video_created'])
    check('duration', v_latin['duration'], EXPECT['video_duration'])
    check('latitude', v_latin['lat'], EXPECT['video_lat'])
    check('longitude', v_latin['lon'], EXPECT['video_lon'])
    print()

    print("Base64 fixtures for embedding in ARGUS.ps1:")
    print()
    print("JPEG_B64 =")
    b = base64.b64encode(jpeg).decode()
    for i in range(0, len(b), 100):
        print(f"    '{b[i:i+100]}' +")
    print()
    print("MP4_B64 =")
    b = base64.b64encode(mp4).decode()
    for i in range(0, len(b), 100):
        print(f"    '{b[i:i+100]}' +")

    print()
    print("RESULT:", "all checks passed" if ok else "FAILURES ABOVE")
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
