#!/usr/bin/env python3
"""Build a synthetic device tree for testing and for the lab exercise.

Produces a directory that looks like a real Android or iOS extraction, with
genuine SQLite databases in the real schemas, real JPEG files carrying real
EXIF/GPS, and — importantly — **records that are actually deleted** so the
carver has something true to recover.

This exists because you cannot responsibly develop or demonstrate a forensic
tool against a real person's handset, and a demo that fakes its findings
teaches the wrong thing. Everything here is synthetic but structurally
identical to the real artefact, so the parsers and the carver are exercised for
real.

Usage::

    python samples/make_device.py --platform android --out ./evidence/android
    python samples/make_device.py --platform ios     --out ./evidence/ios
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import sqlite3
import struct
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

APPLE_EPOCH = 978_307_200

CONTACTS = [
    ("Priya Nair",      "+919876543210"),
    ("Rahul Mehta",     "+919812345678"),
    ("Ananya Iyer",     "+917788990011"),
    ("Vikram Desai",    "+919900112233"),
    ("Sana Qureshi",    "+918855667788"),
    ("Dockyard Office", "+912228765432"),
    ("Unknown Caller",  "+919000000001"),
    ("Kabir Shah",      "+919765432109"),
]

MESSAGES = [
    "Are we still on for tomorrow?",
    "The shipment arrives at berth 4 around 23:00.",
    "Don't call this number again.",
    "Sending the documents now.",
    "Meeting moved to the warehouse.",
    "Payment received, thanks.",
    "I'll be there in twenty minutes.",
    "Delete this thread when you're done.",
    "He knows. Be careful what you write.",
    "Confirmed. Same place as last time.",
    "Can you pick up the parcel from the docks?",
    "Call me when you land.",
]

DELETED_MESSAGES = [
    "Burn the paperwork before Friday.",
    "The customs officer has been paid.",
    "Move the container tonight, not tomorrow.",
    "Nobody can trace this handset to me.",
    "Meet at the old jetty, 02:00, come alone.",
    "I told you to stop putting this in writing.",
]

URLS = [
    ("https://www.google.com/search?q=how+to+wipe+a+phone", "how to wipe a phone - Google Search"),
    ("https://mail.google.com/mail/u/0/", "Inbox - Gmail"),
    ("https://www.marinetraffic.com/en/ais/home", "MarineTraffic: Live Ship Tracking"),
    ("https://www.google.com/search?q=faraday+bag+buy", "faraday bag buy - Google Search"),
    ("https://en.wikipedia.org/wiki/Bill_of_lading", "Bill of lading - Wikipedia"),
    ("https://www.portofmumbai.in/schedules", "Vessel Schedules"),
]


def us_to_apple(dt: datetime) -> float:
    return dt.timestamp() - APPLE_EPOCH


def rand_times(n: int, days: int = 45, seed: int = 7) -> list[datetime]:
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for _ in range(n):
        # Bias toward waking hours so the histogram looks like a real person,
        # with a minority of night-time activity that stands out.
        hour = rng.choice([9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                           22, 23, 2, 3])
        out.append(base + timedelta(days=rng.uniform(0, days),
                                    hours=hour - 12,
                                    minutes=rng.randint(0, 59),
                                    seconds=rng.randint(0, 59)))
    return sorted(out)


def _connect(path: Path) -> sqlite3.Connection:
    """Open a fresh database, replacing any left by an earlier run.

    Without this, running the generator twice into the same directory fails on
    "table calls already exists" — the second run opens the first run's file and
    tries to create the schema again. The traceback points at a CREATE TABLE,
    which reads like a bug in the generator rather than the obvious "this folder
    already has a device in it".

    Regenerating is meant to be idempotent: the same command should always
    produce the same planted evidence, whatever was there before.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    for stale in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm"),
                  Path(str(path) + "-journal")):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    conn = sqlite3.connect(path)
    # Real handsets do not securely delete; without this the carver would have
    # nothing to find and the demo would misrepresent what the tool can do.
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("PRAGMA journal_mode=DELETE")
    return conn


# --------------------------------------------------------------------- JPEG
def make_jpeg(path: Path, width: int, height: int, taken: datetime,
              lat: float | None = None, lon: float | None = None,
              seed: int = 1) -> None:
    """Write a real JPEG with real EXIF (and GPS when supplied)."""
    from PIL import Image
    from exif_writer import write_jpeg_with_exif

    rng = random.Random(seed)
    img = Image.new("RGB", (width, height))
    px = img.load()
    r0, g0, b0 = rng.randint(30, 120), rng.randint(40, 130), rng.randint(60, 160)
    for y in range(height):
        for x in range(width):
            px[x, y] = ((r0 + x * 255 // max(width, 1)) % 256,
                        (g0 + y * 255 // max(height, 1)) % 256,
                        (b0 + (x + y) // 2) % 256)
    write_jpeg_with_exif(path, img, taken, latitude=lat, longitude=lon,
                         altitude=12.5 if lat is not None else None)
    os.utime(path, (taken.timestamp(), taken.timestamp()))


# ------------------------------------------------------------------ ANDROID
def build_android(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    stats = {}
    times = rand_times(260, seed=11)

    # ---------------- call log -------------------------------------------
    p = root / "data/data/com.android.providers.contacts/databases/calllog.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE calls (
        _id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT, date INTEGER,
        duration INTEGER, type INTEGER, name TEXT, numbertype INTEGER,
        new INTEGER, is_read INTEGER, geocoded_location TEXT,
        presentation INTEGER, subscription_id TEXT, via_number TEXT)""")
    rng = random.Random(3)
    rows = []
    for t in times[:120]:
        name, number = rng.choice(CONTACTS)
        ctype = rng.choices([1, 2, 3, 5], weights=[40, 45, 12, 3])[0]
        rows.append((number, int(t.timestamp() * 1000),
                     rng.randint(0, 900) if ctype in (1, 2) else 0,
                     ctype, name, 2, 0, 1, "Mumbai, Maharashtra", 1, "0", ""))
    conn.executemany("INSERT INTO calls (number,date,duration,type,name,"
                     "numbertype,new,is_read,geocoded_location,presentation,"
                     "subscription_id,via_number) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     rows)
    conn.commit()
    conn.execute("DELETE FROM calls WHERE _id % 7 = 0")     # deleted calls
    conn.commit(); conn.close()
    stats["calls"] = len(rows)

    # ---------------- contacts -------------------------------------------
    p = root / "data/data/com.android.providers.contacts/databases/contacts2.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER, display_name TEXT, account_name TEXT,
            account_type TEXT, starred INTEGER, times_contacted INTEGER,
            last_time_contacted INTEGER, deleted INTEGER,
            contact_last_updated_timestamp INTEGER);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            mimetype TEXT);
        CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT,
            data2 INTEGER, data3 TEXT);
    """)
    mimes = ["vnd.android.cursor.item/name", "vnd.android.cursor.item/phone_v2",
             "vnd.android.cursor.item/email_v2"]
    conn.executemany("INSERT INTO mimetypes (mimetype) VALUES (?)",
                     [(m,) for m in mimes])
    for i, (name, number) in enumerate(CONTACTS, 1):
        conn.execute("INSERT INTO raw_contacts (contact_id,display_name,"
                     "account_name,account_type,starred,times_contacted,"
                     "last_time_contacted,deleted,contact_last_updated_timestamp)"
                     " VALUES (?,?,?,?,?,?,?,0,?)",
                     (i, name, "owner@example.com", "com.google", i % 3 == 0,
                      random.Random(i).randint(1, 40),
                      int(times[-1].timestamp() * 1000),
                      int(times[-1].timestamp() * 1000)))
        conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                     " VALUES (?,1,?,0)", (i, name))
        conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                     " VALUES (?,2,?,2)", (i, number))
        conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                     " VALUES (?,3,?,1)",
                     (i, name.lower().replace(" ", ".") + "@example.com"))
    conn.commit()
    # A contact the user removed — the numbers survive in the data table
    conn.execute("INSERT INTO raw_contacts (contact_id,display_name,"
                 "account_name,account_type,starred,times_contacted,"
                 "last_time_contacted,deleted,contact_last_updated_timestamp)"
                 " VALUES (99,'Deleted Associate','owner@example.com',"
                 "'com.google',0,12,0,0,0)")
    rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                 " VALUES (?,1,'Deleted Associate',0)", (rid,))
    conn.execute("INSERT INTO data (raw_contact_id,mimetype_id,data1,data2)"
                 " VALUES (?,2,'+919555000111',2)", (rid,))
    conn.commit()
    conn.execute("DELETE FROM raw_contacts WHERE contact_id = 99")
    conn.execute("DELETE FROM data WHERE raw_contact_id = ?", (rid,))
    conn.commit(); conn.close()
    stats["contacts"] = len(CONTACTS)

    # ---------------- SMS / MMS ------------------------------------------
    p = root / "data/data/com.android.providers.telephony/databases/mmssms.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE sms (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER, address TEXT, person INTEGER, date INTEGER,
            date_sent INTEGER, protocol INTEGER, read INTEGER, status INTEGER,
            type INTEGER, subject TEXT, body TEXT, service_center TEXT,
            seen INTEGER, sub_id INTEGER, creator TEXT);
        CREATE TABLE pdu (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER, date INTEGER, msg_box INTEGER, sub TEXT,
            m_size INTEGER);
        CREATE TABLE addr (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id INTEGER, address TEXT, type INTEGER);
        CREATE TABLE part (_id INTEGER PRIMARY KEY AUTOINCREMENT, mid INTEGER,
            ct TEXT, name TEXT, text TEXT, _data TEXT, cl TEXT);
        CREATE TABLE canonical_addresses (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT);
    """)
    rng = random.Random(5)
    for i, t in enumerate(times[:170]):
        name, number = rng.choice(CONTACTS)
        box = rng.choice([1, 1, 2, 2, 2])
        conn.execute(
            "INSERT INTO sms (thread_id,address,person,date,date_sent,protocol,"
            "read,status,type,subject,body,service_center,seen,sub_id,creator)"
            " VALUES (?,?,0,?,?,0,1,-1,?,'',?,'+919999999999',1,1,'')",
            (abs(hash(number)) % 40, number, int(t.timestamp() * 1000),
             int(t.timestamp() * 1000), box, rng.choice(MESSAGES)))
    conn.commit()

    # Messages the user later deleted — recoverable by the carver
    del_base = times[60]
    for i, text in enumerate(DELETED_MESSAGES):
        t = del_base + timedelta(minutes=i * 11)
        conn.execute(
            "INSERT INTO sms (thread_id,address,person,date,date_sent,protocol,"
            "read,status,type,subject,body,service_center,seen,sub_id,creator)"
            " VALUES (99,'+919555000111',0,?,?,0,1,-1,1,'',?,"
            "'+919999999999',1,1,'')",
            (int(t.timestamp() * 1000), int(t.timestamp() * 1000), text))
    conn.commit()
    conn.execute("DELETE FROM sms WHERE thread_id = 99")
    conn.execute("DELETE FROM sms WHERE _id % 11 = 0")
    conn.commit()

    # MMS with an attachment
    conn.execute("INSERT INTO pdu (thread_id,date,msg_box,sub,m_size)"
                 " VALUES (5,?,1,'Photo',284512)",
                 (int(times[100].timestamp()),))
    mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO addr (msg_id,address,type) VALUES (?,?,137)",
                 (mid, "+919876543210"))
    conn.execute("INSERT INTO part (mid,ct,name,text) VALUES (?,'text/plain',"
                 "'body','Here is the berth layout')", (mid,))
    conn.execute("INSERT INTO part (mid,ct,name,_data) VALUES (?,'image/jpeg',"
                 "'berth.jpg','/data/user/0/com.android.providers.telephony/"
                 "app_parts/PART_berth.jpg')", (mid,))
    conn.commit(); conn.close()
    stats["sms"] = 170
    stats["deleted_sms"] = len(DELETED_MESSAGES)

    # ---------------- WhatsApp -------------------------------------------
    p = root / "data/data/com.whatsapp/databases/msgstore.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE jid (_id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT,
            server TEXT, raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid_row_id INTEGER, subject TEXT);
        CREATE TABLE message (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id
            INTEGER, status INTEGER, message_type INTEGER, text_data TEXT,
            timestamp INTEGER, starred INTEGER, recipient_count INTEGER,
            latitude REAL, longitude REAL);
        CREATE TABLE call_log (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid_row_id INTEGER, from_me INTEGER, call_id TEXT, timestamp INTEGER,
            video_call INTEGER, duration INTEGER, call_result INTEGER,
            is_joinable_group_call INTEGER);
    """)
    for i, (name, number) in enumerate(CONTACTS, 1):
        conn.execute("INSERT INTO jid (user,server,raw_string) VALUES (?,?,?)",
                     (number.lstrip("+"), "s.whatsapp.net",
                      f"{number.lstrip('+')}@s.whatsapp.net"))
        conn.execute("INSERT INTO chat (jid_row_id,subject) VALUES (?,'')", (i,))
    conn.execute("INSERT INTO jid (user,server,raw_string) VALUES "
                 "('919876543210-1600000000','g.us',"
                 "'919876543210-1600000000@g.us')")
    gjid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO chat (jid_row_id,subject) VALUES (?,'Berth Crew')",
                 (gjid,))
    gchat = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    rng = random.Random(9)
    for t in times[:150]:
        chat = rng.randint(1, len(CONTACTS))
        from_me = rng.random() < 0.45
        conn.execute(
            "INSERT INTO message (chat_row_id,from_me,key_id,sender_jid_row_id,"
            "status,message_type,text_data,timestamp,starred,recipient_count)"
            " VALUES (?,?,?,?,?,0,?,?,0,0)",
            (chat, int(from_me), f"KEY{rng.randint(10**9, 10**10)}",
             0 if from_me else chat, 13 if from_me else 0,
             rng.choice(MESSAGES), int(t.timestamp() * 1000)))
    # group chat with a location share
    conn.execute(
        "INSERT INTO message (chat_row_id,from_me,key_id,sender_jid_row_id,"
        "status,message_type,text_data,timestamp,starred,recipient_count,"
        "latitude,longitude) VALUES (?,0,'KEYLOC',2,0,5,'Live location',"
        "?,0,4,18.9410,72.9330)",
        (gchat, int(times[120].timestamp() * 1000)))
    conn.commit()
    for i, text in enumerate(DELETED_MESSAGES[:4]):
        t = times[80] + timedelta(minutes=i * 17)
        conn.execute(
            "INSERT INTO message (chat_row_id,from_me,key_id,sender_jid_row_id,"
            "status,message_type,text_data,timestamp,starred,recipient_count)"
            " VALUES (?,0,'DELKEY',2,0,0,?,?,0,0)",
            (gchat, text, int(t.timestamp() * 1000)))
    conn.commit()
    conn.execute("DELETE FROM message WHERE key_id = 'DELKEY'")
    conn.execute("DELETE FROM message WHERE _id % 13 = 0")
    conn.commit()

    for t in times[:40]:
        conn.execute("INSERT INTO call_log (jid_row_id,from_me,call_id,"
                     "timestamp,video_call,duration,call_result,"
                     "is_joinable_group_call) VALUES (?,?,?,?,?,?,5,0)",
                     (rng.randint(1, len(CONTACTS)), rng.randint(0, 1),
                      f"CALL{rng.randint(10**6,10**7)}",
                      int(t.timestamp() * 1000), rng.randint(0, 1),
                      rng.randint(5, 1200)))
    conn.commit(); conn.close()
    stats["whatsapp"] = 150

    # wa.db contact list
    p = root / "data/data/com.whatsapp/databases/wa.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY
        AUTOINCREMENT, jid TEXT, is_whatsapp_user INTEGER, status TEXT,
        number TEXT, display_name TEXT, wa_name TEXT, given_name TEXT)""")
    for name, number in CONTACTS:
        conn.execute("INSERT INTO wa_contacts (jid,is_whatsapp_user,status,"
                     "number,display_name,wa_name,given_name) VALUES "
                     "(?,1,'Available',?,?,?,?)",
                     (f"{number.lstrip('+')}@s.whatsapp.net", number, name,
                      name, name.split()[0]))
    conn.commit(); conn.close()

    # ---------------- Chrome history --------------------------------------
    p = root / "data/data/com.android.chrome/app_chrome/Default/History"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url
            LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0, last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0);
        CREATE TABLE visits (id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER
            NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER,
            transition INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path
            LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes
            INTEGER NOT NULL, total_bytes INTEGER NOT NULL, mime_type TEXT,
            referrer VARCHAR, tab_url VARCHAR, danger_type INTEGER DEFAULT 0);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,
            url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL,
            lower_term LONGVARCHAR NOT NULL);
    """)
    rng = random.Random(13)
    for i, (url, title) in enumerate(URLS, 1):
        t = times[rng.randint(0, len(times) - 1)]
        webkit = int((t.timestamp() + 11_644_473_600) * 1_000_000)
        conn.execute("INSERT INTO urls (url,title,visit_count,typed_count,"
                     "last_visit_time,hidden) VALUES (?,?,?,?,?,0)",
                     (url, title, rng.randint(1, 25), rng.randint(0, 4), webkit))
        conn.execute("INSERT INTO visits (url,visit_time,from_visit,transition)"
                     " VALUES (?,?,0,?)", (i, webkit, rng.choice([0, 1, 5, 7])))
        if "search?q=" in url:
            term = url.split("q=")[1].replace("+", " ")
            conn.execute("INSERT INTO keyword_search_terms VALUES (2,?,?,?)",
                         (i, term, term.lower()))
    conn.execute("INSERT INTO downloads (id,target_path,start_time,"
                 "received_bytes,total_bytes,mime_type,referrer,tab_url,"
                 "danger_type) VALUES (1,'/sdcard/Download/manifest.pdf',?,"
                 "184320,184320,'application/pdf','','https://www.portofmumbai.in/schedules',0)",
                 (int((times[70].timestamp() + 11_644_473_600) * 1_000_000),))
    conn.commit()
    conn.execute("DELETE FROM urls WHERE id = 1")     # cleared a search
    conn.commit(); conn.close()

    # ---------------- system files ----------------------------------------
    (root / "system").mkdir(parents=True, exist_ok=True)
    (root / "system/build.prop").write_text("\n".join([
        "ro.product.manufacturer=Samsung",
        "ro.product.model=SM-G991B",
        "ro.product.brand=samsung",
        "ro.build.version.release=13",
        "ro.build.version.security_patch=2024-11-01",
        "ro.build.id=TP1A.220624.014",
        "ro.build.fingerprint=samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXU5DWA1:user/release-keys",
        "ro.serialno=RF8N90ABCDE",
        "ro.board.platform=exynos2100",
        "ro.crypto.state=encrypted",
    ]), encoding="utf-8")

    (root / "data/system").mkdir(parents=True, exist_ok=True)
    (root / "data/system/packages.list").write_text("\n".join([
        "com.whatsapp 10123 0 /data/user/0/com.whatsapp default 3003,1028",
        "com.instagram.android 10188 0 /data/user/0/com.instagram.android default 3003",
        "com.android.chrome 10099 0 /data/user/0/com.android.chrome default 3003",
        "org.telegram.messenger 10201 0 /data/user/0/org.telegram.messenger default 3003",
        "com.snapchat.android 10233 0 /data/user/0/com.snapchat.android default 3003",
        "com.google.android.gm 10077 0 /data/user/0/com.google.android.gm default 3003",
    ]), encoding="utf-8")

    (root / "data/misc/wifi").mkdir(parents=True, exist_ok=True)
    (root / "data/misc/wifi/wpa_supplicant.conf").write_text("""
network={
    ssid="PortAuthority-Guest"
    key_mgmt=WPA-PSK
}
network={
    ssid="Warehouse4-5G"
    key_mgmt=WPA-PSK
}
network={
    ssid="HomeNet_2G"
    key_mgmt=WPA-PSK
}
""".strip(), encoding="utf-8")

    p = root / "data/system/users/0/accounts.db"
    conn = _connect(p)
    conn.execute("CREATE TABLE accounts (_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                 " name TEXT, type TEXT, password TEXT, previous_name TEXT)")
    conn.executemany("INSERT INTO accounts (name,type,password,previous_name)"
                     " VALUES (?,?,'',NULL)",
                     [("owner@example.com", "com.google"),
                      ("+919111222333", "com.whatsapp"),
                      ("dockside_ops", "com.instagram.android")])
    conn.commit(); conn.close()

    # ---------------- media -----------------------------------------------
    media = [
        ("sdcard/DCIM/Camera/IMG_20260612_224511.jpg", 640, 480, 18.9401, 72.9350),
        ("sdcard/DCIM/Camera/IMG_20260615_101233.jpg", 640, 480, 19.0760, 72.8777),
        ("sdcard/DCIM/Camera/IMG_20260701_020417.jpg", 640, 480, 18.9388, 72.9401),
        ("sdcard/Pictures/Screenshots/Screenshot_20260620_143002.png", 480, 800, None, None),
        ("sdcard/WhatsApp/Media/WhatsApp Images/IMG-20260618-WA0007.jpg", 512, 384, None, None),
        ("sdcard/Download/berth_layout.jpg", 800, 600, 18.9415, 72.9333),
    ]
    for i, (rel, w, h, lat, lon) in enumerate(media):
        target = root / rel
        taken = times[40 + i * 12]
        if rel.endswith(".png"):
            from PIL import Image
            target.parent.mkdir(parents=True, exist_ok=True)
            Image.new("RGB", (w, h), (28, 34, 44)).save(target, "PNG")
            os.utime(target, (taken.timestamp(), taken.timestamp()))
        else:
            make_jpeg(target, w, h, taken, lat, lon, seed=i)
    stats["media"] = len(media)

    # A file whose extension lies about its content — the kind of concealment
    # an extension-trusting tool would miss entirely.
    disguised = root / "sdcard/Download/invoice_2026.txt"
    make_jpeg(disguised, 320, 240, times[95], seed=99)
    stats["disguised"] = 1

    # ---------------- anti-forensic artifacts ------------------------------
    # Planted deliberately so the anti-forensics detectors can be tested
    # against ground truth rather than assumed to work.
    from exif_writer import write_jpeg_with_exif
    from PIL import Image

    # 1. A vault app's concealed media: a real JPEG renamed to hide it.
    vault_dir = root / "sdcard/.gallery_lock"
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / ".nomedia").write_bytes(b"")
    img = Image.new("RGB", (400, 300))
    px = img.load()
    for y in range(300):
        for x in range(400):
            px[x, y] = ((x * 3) % 256, (y * 5) % 256, 120)
    write_jpeg_with_exif(vault_dir / "IMG_4471.hid", img, times[60],
                         latitude=18.9422, longitude=72.9311)
    stats["vault_media"] = 1

    # 2. Thumbnail cache: concatenated JPEGs, as Android writes them. Two of
    #    the three source photos are NOT in the tree, so recovering them from
    #    here is a genuine recovery of otherwise-lost images.
    thumbs = bytearray()
    for i in range(3):
        t = Image.new("RGB", (96, 96))
        tp = t.load()
        for y in range(96):
            for x in range(96):
                tp[x, y] = ((x * 2 + i * 40) % 256, (y * 2) % 256, 90 + i * 40)
        buf = io.BytesIO()
        t.save(buf, "JPEG", quality=70)
        thumbs += buf.getvalue()
        thumbs += b"\x00" * 64          # inter-thumbnail padding
    tdir = root / "sdcard/DCIM/.thumbnails"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / ".thumbdata3--1967290299").write_bytes(bytes(thumbs))
    stats["thumbnails"] = 3

    # 3. WhatsApp encrypted backup — must be reported as encrypted, not empty.
    crypt = root / "sdcard/WhatsApp/Databases"
    crypt.mkdir(parents=True, exist_ok=True)
    rng2 = random.Random(77)
    (crypt / "msgstore.db.crypt14").write_bytes(
        bytes(rng2.getrandbits(8) for _ in range(8192)))
    stats["encrypted_backup"] = 1

    # 4. A SQLCipher-style encrypted database: high entropy, page-aligned.
    sig = root / "data/data/org.thoughtcrime.securesms/databases"
    sig.mkdir(parents=True, exist_ok=True)
    (sig / "signal.db").write_bytes(
        bytes(rng2.getrandbits(8) for _ in range(4096 * 6)))
    stats["encrypted_db"] = 1

    # 5. Residue for an app that is no longer installed (not in packages.list).
    gone = root / "data/data/com.gallery.vault/shared_prefs"
    gone.mkdir(parents=True, exist_ok=True)
    (gone / "vault_prefs.xml").write_text(
        '<?xml version="1.0"?><map><int name="pin_set" value="1" />'
        '<string name="hidden_count">14</string></map>', encoding="utf-8")
    stats["uninstalled_residue"] = 1

    # 6. Vault and wiper apps present in the installed list.
    packages = root / "data/system/packages.list"
    packages.write_text(packages.read_text() + "\n" + "\n".join([
        "com.domobile.applock 10301 0 /data/user/0/com.domobile.applock default 3003",
        "com.piriform.ccleaner 10302 0 /data/user/0/com.piriform.ccleaner default 3003",
        "org.thoughtcrime.securesms 10303 0 /data/user/0/org.thoughtcrime.securesms default 3003",
        "com.topjohnwu.magisk 10304 0 /data/user/0/com.topjohnwu.magisk default 3003",
        "org.telegram.messenger 10305 0 /data/user/0/org.telegram.messenger default 3003",
        "com.facebook.orca 10306 0 /data/user/0/com.facebook.orca default 3003",
        "com.viber.voip 10307 0 /data/user/0/com.viber.voip default 3003",
        "net.one97.paytm 10308 0 /data/user/0/net.one97.paytm default 3003",
        "com.google.android.apps.maps 10309 0 /data/user/0/com.google.android.apps.maps default 3003",
    ]), encoding="utf-8")
    stats["suspect_apps"] = 4

    # ---------------- social / messaging apps ------------------------------
    # Real schemas, so the app parsers are exercised for real rather than
    # against a shape invented to suit them.
    rng3 = random.Random(31)

    def _pbuf(*parts):
        """Minimal protobuf encoder, for Telegram/Snapchat blob payloads."""
        out = b""
        for num, val in parts:
            if isinstance(val, str):
                raw = val.encode()
                out += _varint((num << 3) | 2) + _varint(len(raw)) + raw
            else:
                out += _varint((num << 3) | 0) + _varint(val)
        return out

    def _varint(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out

    # --- Telegram: message text lives in a serialised blob, not a column
    p = root / "data/data/org.telegram.messenger/files/cache4.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, data BLOB);
        CREATE TABLE messages_v2 (mid INTEGER PRIMARY KEY AUTOINCREMENT,
            uid INTEGER, read_state INTEGER, send_state INTEGER, date INTEGER,
            data BLOB, out INTEGER, ttl INTEGER);
    """)
    TELEGRAM = [
        "The consignment clears customs on Thursday.",
        "Use this account from now on, not the old one.",
        "Delete the photos after you have seen them.",
        "He is asking questions. Say nothing.",
        "Wallet is 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa if you need it.",
    ]
    TELEGRAM_DELETED = [
        "Burn the manifest once it is signed.",
        "Two hundred thousand, cash, at the jetty.",
    ]
    for i, (name, number) in enumerate(CONTACTS[:5], 100):
        conn.execute("INSERT INTO users (uid,name,data) VALUES (?,?,?)",
                     (i, name.replace(" ", ";;;"),
                      _pbuf((1, name), (2, number.lstrip("+")))))
    for i, text in enumerate(TELEGRAM):
        t = times[70 + i * 6]
        conn.execute("INSERT INTO messages_v2 (uid,read_state,send_state,date,"
                     "data,out,ttl) VALUES (?,1,0,?,?,?,0)",
                     (100 + (i % 5), int(t.timestamp()),
                      _pbuf((1, text), (2, int(t.timestamp()))), i % 2))
    conn.commit()
    for i, text in enumerate(TELEGRAM_DELETED):
        t = times[95 + i * 3]
        conn.execute("INSERT INTO messages_v2 (uid,read_state,send_state,date,"
                     "data,out,ttl) VALUES (999,1,0,?,?,0,0)",
                     (int(t.timestamp()), _pbuf((1, text), (2, int(t.timestamp())))))
    conn.commit()
    conn.execute("DELETE FROM messages_v2 WHERE uid = 999")
    conn.commit(); conn.close()
    stats["telegram"] = len(TELEGRAM)
    stats["telegram_deleted"] = len(TELEGRAM_DELETED)

    # --- Instagram: text column plus JSON payload fallback
    p = root / "data/data/com.instagram.android/databases/direct.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE messages (_id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id TEXT, user_id TEXT, text TEXT, message BLOB,
        timestamp INTEGER, item_type TEXT)""")
    INSTAGRAM = [
        "did you see the story I posted",
        "meet at the usual place, 9pm",
        "sending the address now",
    ]
    for i, text in enumerate(INSTAGRAM):
        t = times[60 + i * 9]
        conn.execute("INSERT INTO messages (thread_id,user_id,text,timestamp,"
                     "item_type) VALUES (?,?,?,?,'text')",
                     (f"thread_{i%2}", f"ig_user_{i}", text,
                      int(t.timestamp() * 1000)))
    # One message whose text is only in the JSON payload
    t = times[88]
    conn.execute("INSERT INTO messages (thread_id,user_id,text,message,"
                 "timestamp,item_type) VALUES ('thread_0','ig_user_9',NULL,?,?,"
                 "'text')",
                 (json.dumps({"text": "payload only: bring the second phone",
                              "item_id": "x1"}).encode(),
                  int(t.timestamp() * 1000)))
    conn.commit(); conn.close()
    stats["instagram"] = len(INSTAGRAM) + 1

    # --- Snapchat: metadata survives, content usually does not
    p = root / "data/data/com.snapchat.android/databases/tcspahn.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE Friend (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, displayName TEXT);
        CREATE TABLE Chat (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT, content TEXT, content_type TEXT,
            timestamp INTEGER);
    """)
    for name, _num in CONTACTS[:4]:
        conn.execute("INSERT INTO Friend (username,displayName) VALUES (?,?)",
                     (name.lower().replace(" ", "_"), name))
    for i in range(6):
        t = times[50 + i * 8]
        has_text = i % 3 == 0
        conn.execute("INSERT INTO Chat (sender_id,content,content_type,timestamp)"
                     " VALUES (?,?,?,?)",
                     (CONTACTS[i % 4][0].lower().replace(" ", "_"),
                      "check this before it disappears" if has_text else None,
                      "text" if has_text else "snap",
                      int(t.timestamp() * 1000)))
    conn.commit(); conn.close()
    stats["snapchat"] = 6

    # --- Facebook Messenger
    p = root / "data/data/com.facebook.orca/databases/threads_db2"
    conn = _connect(p)
    conn.execute("""CREATE TABLE messages (_id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_key TEXT, sender TEXT, text TEXT, timestamp_ms INTEGER,
        attachments TEXT)""")
    MESSENGER = ["are we still on for friday",
                 "he replied, said yes",
                 "call me, do not write it here"]
    for i, text in enumerate(MESSENGER):
        t = times[65 + i * 11]
        conn.execute("INSERT INTO messages (thread_key,sender,text,timestamp_ms,"
                     "attachments) VALUES (?,?,?,?,?)",
                     (f"ONE_TO_ONE:{i}",
                      json.dumps({"user_key": f"FACEBOOK:1000{i}",
                                  "name": CONTACTS[i][0]}),
                      text, int(t.timestamp() * 1000),
                      json.dumps([{"filename": "doc.pdf",
                                   "mimeType": "application/pdf"}])
                      if i == 1 else None))
    conn.commit(); conn.close()
    stats["messenger"] = len(MESSENGER)

    # --- Viber
    p = root / "data/data/com.viber.voip/databases/viber_messages"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE participants_info (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT, display_name TEXT, contact_name TEXT);
        CREATE TABLE messages (_id INTEGER PRIMARY KEY AUTOINCREMENT,
            participant_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
    """)
    for name, number in CONTACTS[:3]:
        conn.execute("INSERT INTO participants_info (number,display_name,"
                     "contact_name) VALUES (?,?,?)", (number, name, name))
    for i, text in enumerate(["viber test one", "the van is loaded",
                              "confirmed for tonight"]):
        t = times[72 + i * 7]
        conn.execute("INSERT INTO messages (participant_id,body,date,send_type)"
                     " VALUES (?,?,?,?)",
                     (1 + i % 3, text, int(t.timestamp() * 1000), i % 2))
    conn.commit(); conn.close()
    stats["viber"] = 3

    # --- Notification history: previews content from encrypted apps
    p = root / "data/data/com.android.systemui/databases/notification_log.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE notifications (_id INTEGER PRIMARY KEY
        AUTOINCREMENT, pkg TEXT, title TEXT, text TEXT, post_time INTEGER,
        key TEXT)""")
    NOTIFS = [
        ("org.thoughtcrime.securesms", "Kabir Shah",
         "the second handset is clean, use that"),
        ("org.thoughtcrime.securesms", "Kabir Shah",
         "do not reply on this number again"),
        ("com.whatsapp", "Priya Nair", "are we still on for tomorrow?"),
        ("org.telegram.messenger", "Unknown", "manifest attached, delete after"),
        ("com.google.android.gm", "Dockyard Office", "Vessel schedule revised"),
    ]
    for i, (pkg, title, text) in enumerate(NOTIFS):
        t = times[80 + i * 4]
        conn.execute("INSERT INTO notifications (pkg,title,text,post_time,key)"
                     " VALUES (?,?,?,?,?)",
                     (pkg, title, text, int(t.timestamp() * 1000), f"key{i}"))
    conn.commit(); conn.close()
    stats["notifications"] = len(NOTIFS)
    stats["notifications_from_encrypted"] = sum(
        1 for pkg, _, _ in NOTIFS
        if pkg in ("org.thoughtcrime.securesms", "org.telegram.messenger"))

    # --- Gmail
    p = root / "data/data/com.google.android.gm/databases/mailstore.owner.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE messages (_id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject TEXT, snippet TEXT, fromAddress TEXT, toAddresses TEXT,
        dateSentMs INTEGER)""")
    for i, (subj, snip) in enumerate([
            ("Vessel schedule revised", "Berth 4 moved to 23:00 Tuesday"),
            ("Invoice 4471", "Please find the invoice attached"),
            ("Re: customs", "It has been handled, do not call")]):
        t = times[58 + i * 13]
        conn.execute("INSERT INTO messages (subject,snippet,fromAddress,"
                     "toAddresses,dateSentMs) VALUES (?,?,?,?,?)",
                     (subj, snip, f"sender{i}@example.com",
                      "owner@example.com", int(t.timestamp() * 1000)))
    conn.commit(); conn.close()
    stats["gmail"] = 3

    # --- Payment app
    p = root / "data/data/net.one97.paytm/databases/transactions.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE transactions (_id INTEGER PRIMARY KEY
        AUTOINCREMENT, amount REAL, payee TEXT, type TEXT, status TEXT,
        txn_id TEXT, remarks TEXT, timestamp INTEGER)""")
    PAYMENTS = [
        (200000.0, "dockyard.ops@okaxis", "DEBIT", "SUCCESS", "for the container"),
        (15000.0, "kabir.shah@okhdfc", "DEBIT", "SUCCESS", ""),
        (5000.0, "priya.nair@okicici", "CREDIT", "SUCCESS", "refund"),
    ]
    for i, (amt, payee, kind, status, note) in enumerate(PAYMENTS):
        t = times[62 + i * 15]
        conn.execute("INSERT INTO transactions (amount,payee,type,status,txn_id,"
                     "remarks,timestamp) VALUES (?,?,?,?,?,?,?)",
                     (amt, payee, kind, status, f"UTR{100000+i}", note,
                      int(t.timestamp() * 1000)))
    conn.commit(); conn.close()
    stats["payments"] = len(PAYMENTS)

    # --- Google Maps history
    p = root / "data/data/com.google.android.apps.maps/databases/gmm_storage.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE destinations (_id INTEGER PRIMARY KEY
        AUTOINCREMENT, destination TEXT, latitude REAL, longitude REAL,
        time INTEGER)""")
    MAPS = [("Mumbai Port Trust berth 4", 18.9412, 72.9338),
            ("Old jetty Sewri", 18.9955, 72.8608),
            ("Warehouse Bhiwandi", 19.2969, 73.0629)]
    for i, (label, lat, lon) in enumerate(MAPS):
        t = times[68 + i * 12]
        conn.execute("INSERT INTO destinations (destination,latitude,longitude,"
                     "time) VALUES (?,?,?,?)",
                     (label, lat, lon, int(t.timestamp() * 1000)))
    conn.commit(); conn.close()
    stats["maps"] = len(MAPS)

    # --- usagestats: places a person at the device
    usage_dir = root / "data/system/usagestats/0/daily"
    usage_dir.mkdir(parents=True, exist_ok=True)
    base_ms = int(times[75].timestamp() * 1000)
    events = []
    for i, pkg in enumerate(["com.whatsapp", "org.telegram.messenger",
                             "com.android.chrome", "net.one97.paytm",
                             "com.whatsapp", "org.thoughtcrime.securesms"]):
        events.append(f'  <event package="{pkg}" class="MainActivity" '
                      f'time="{i * 180000}" type="{1 if i % 2 == 0 else 2}" />')
    (usage_dir / "usagestats_daily.xml").write_text(
        f'<?xml version="1.0"?>\n<usagestats beginTime="{base_ms}">\n'
        + "\n".join(events) + "\n</usagestats>", encoding="utf-8")
    stats["usage_events"] = len(events)

    return stats




# ---------------------------------------------------------------------- iOS
def build_ios(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    stats = {}
    times = rand_times(240, seed=21)
    rng = random.Random(17)

    # ---------------- call history ----------------------------------------
    p = root / "HomeDomain/Library/CallHistoryDB/CallHistory.storedata"
    conn = _connect(p)
    conn.execute("""CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY,
        Z_ENT INTEGER, Z_OPT INTEGER, ZANSWERED INTEGER, ZCALLTYPE INTEGER,
        ZORIGINATED INTEGER, ZREAD INTEGER, ZDURATION FLOAT, ZDATE FLOAT,
        ZADDRESS VARCHAR, ZISO_COUNTRY_CODE VARCHAR, ZLOCATION VARCHAR,
        ZSERVICE_PROVIDER VARCHAR)""")
    for i, t in enumerate(times[:110], 1):
        name, number = rng.choice(CONTACTS)
        originated = rng.random() < 0.5
        answered = rng.random() < 0.75
        conn.execute("INSERT INTO ZCALLRECORD VALUES (?,7,1,?,1,?,1,?,?,?,'in',"
                     "'Mumbai','com.apple.Telephony')",
                     (i, int(answered), int(originated),
                      float(rng.randint(0, 850) if answered else 0),
                      us_to_apple(t), number))
    conn.commit()
    conn.execute("DELETE FROM ZCALLRECORD WHERE Z_PK % 9 = 0")
    conn.commit(); conn.close()
    stats["calls"] = 110

    # ---------------- Messages --------------------------------------------
    p = root / "HomeDomain/Library/SMS/sms.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT
            NOT NULL, country TEXT, service TEXT NOT NULL, uncanonicalized_id TEXT);
        CREATE TABLE chat (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT
            NOT NULL, chat_identifier TEXT, service_name TEXT, display_name TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT
            NOT NULL, text TEXT, handle_id INTEGER DEFAULT 0, service TEXT,
            date INTEGER, date_read INTEGER, date_delivered INTEGER,
            is_from_me INTEGER DEFAULT 0, is_read INTEGER DEFAULT 0,
            is_sent INTEGER DEFAULT 0, is_delivered INTEGER DEFAULT 0,
            country TEXT, associated_message_type INTEGER DEFAULT 0,
            expressive_send_style_id TEXT, attributedBody BLOB);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER,
            message_date INTEGER);
        CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);
        CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT NOT NULL, filename TEXT, mime_type TEXT,
            total_bytes INTEGER DEFAULT 0, transfer_name TEXT);
        CREATE TABLE message_attachment_join (message_id INTEGER,
            attachment_id INTEGER);
    """)
    for i, (name, number) in enumerate(CONTACTS, 1):
        conn.execute("INSERT INTO handle (id,country,service) VALUES (?,'in',"
                     "'iMessage')", (number,))
        conn.execute("INSERT INTO chat (guid,chat_identifier,service_name,"
                     "display_name) VALUES (?,?,'iMessage','')",
                     (f"iMessage;-;{number}", number))
        conn.execute("INSERT INTO chat_handle_join VALUES (?,?)", (i, i))

    # a group thread
    conn.execute("INSERT INTO chat (guid,chat_identifier,service_name,"
                 "display_name) VALUES ('iMessage;+;chat9911','chat9911',"
                 "'iMessage','Berth Crew')")
    gchat = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for h in (1, 2, 4):
        conn.execute("INSERT INTO chat_handle_join VALUES (?,?)", (gchat, h))

    apple_ns = lambda t: int(us_to_apple(t) * 1_000_000_000)
    for i, t in enumerate(times[:180], 1):
        handle = rng.randint(1, len(CONTACTS))
        from_me = rng.random() < 0.45
        conn.execute(
            "INSERT INTO message (guid,text,handle_id,service,date,date_read,"
            "date_delivered,is_from_me,is_read,is_sent,is_delivered,country,"
            "associated_message_type) VALUES (?,?,?,'iMessage',?,?,?,?,1,?,?,"
            "'in',0)",
            (f"MSG-{i:05d}", rng.choice(MESSAGES), handle, apple_ns(t),
             apple_ns(t + timedelta(seconds=30)),
             apple_ns(t + timedelta(seconds=2)),
             int(from_me), int(from_me), int(from_me)))
        mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO chat_message_join VALUES (?,?,?)",
                     (handle, mid, apple_ns(t)))

    # a message whose text lives only in attributedBody (iOS 16+ behaviour)
    attributed = (b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01\x40\x84\x84\x84"
                  b"\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92"
                  b"\x84\x84\x84\x08NSString\x01\x94\x84\x01\x2b\x2b"
                  b"The container will be moved before the audit.\x86")
    conn.execute(
        "INSERT INTO message (guid,text,handle_id,service,date,is_from_me,"
        "is_read,attributedBody) VALUES ('MSG-ATTR',NULL,2,'iMessage',?,0,1,?)",
        (apple_ns(times[130]), attributed))

    conn.commit()
    for i, text in enumerate(DELETED_MESSAGES):
        t = times[70] + timedelta(minutes=i * 13)
        conn.execute(
            "INSERT INTO message (guid,text,handle_id,service,date,is_from_me,"
            "is_read,country) VALUES (?,?,3,'iMessage',?,0,1,'in')",
            (f"DEL-{i}", text, apple_ns(t)))
    conn.commit()
    conn.execute("DELETE FROM message WHERE guid LIKE 'DEL-%'")
    conn.execute("DELETE FROM message WHERE ROWID % 12 = 0")
    conn.commit()

    conn.execute("INSERT INTO attachment (guid,filename,mime_type,total_bytes,"
                 "transfer_name) VALUES ('ATT-1','~/Library/SMS/Attachments/"
                 "aa/00/berth.jpg','image/jpeg',284512,'berth.jpg')")
    conn.execute("INSERT INTO message_attachment_join VALUES (5,1)")
    conn.commit(); conn.close()
    stats["messages"] = 180
    stats["deleted_messages"] = len(DELETED_MESSAGES)

    # ---------------- AddressBook ------------------------------------------
    p = root / "HomeDomain/Library/AddressBook/AddressBook.sqlitedb"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
            First TEXT, Last TEXT, Middle TEXT, Organization TEXT,
            JobTitle TEXT, Department TEXT, Note TEXT, Nickname TEXT,
            Birthday REAL, CreationDate REAL, ModificationDate REAL);
        CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER, property INTEGER, label INTEGER, value TEXT);
    """)
    for i, (name, number) in enumerate(CONTACTS, 1):
        first, _, last = name.partition(" ")
        conn.execute("INSERT INTO ABPerson (First,Last,Middle,Organization,"
                     "JobTitle,Department,Note,Nickname,Birthday,CreationDate,"
                     "ModificationDate) VALUES (?,?,'','','','','','',NULL,?,?)",
                     (first, last, us_to_apple(times[0]),
                      us_to_apple(times[-1])))
        conn.execute("INSERT INTO ABMultiValue (record_id,property,label,value)"
                     " VALUES (?,3,1,?)", (i, number))
        conn.execute("INSERT INTO ABMultiValue (record_id,property,label,value)"
                     " VALUES (?,4,1,?)",
                     (i, name.lower().replace(" ", ".") + "@example.com"))
    conn.commit()
    conn.execute("INSERT INTO ABPerson (First,Last,Organization,CreationDate,"
                 "ModificationDate) VALUES ('Deleted','Associate','',?,?)",
                 (us_to_apple(times[5]), us_to_apple(times[5])))
    rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO ABMultiValue (record_id,property,label,value)"
                 " VALUES (?,3,1,'+919555000111')", (rid,))
    conn.commit()
    conn.execute("DELETE FROM ABPerson WHERE ROWID = ?", (rid,))
    conn.execute("DELETE FROM ABMultiValue WHERE record_id = ?", (rid,))
    conn.commit(); conn.close()
    stats["contacts"] = len(CONTACTS)

    # ---------------- Safari history ---------------------------------------
    p = root / "HomeDomain/Library/Safari/History.db"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE, domain_expansion TEXT, visit_count
            INTEGER NOT NULL, daily_visit_counts BLOB, visit_time REAL);
        CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_item INTEGER NOT NULL, visit_time REAL NOT NULL,
            title TEXT, load_successful BOOLEAN DEFAULT 1);
    """)
    for i, (url, title) in enumerate(URLS, 1):
        t = times[rng.randint(0, len(times) - 1)]
        conn.execute("INSERT INTO history_items (url,domain_expansion,"
                     "visit_count,visit_time) VALUES (?,?,?,?)",
                     (url, url.split("/")[2], rng.randint(1, 18),
                      us_to_apple(t)))
        conn.execute("INSERT INTO history_visits (history_item,visit_time,"
                     "title,load_successful) VALUES (?,?,?,1)",
                     (i, us_to_apple(t), title))
    conn.commit()
    conn.execute("DELETE FROM history_items WHERE id = 1")
    conn.commit(); conn.close()

    # ---------------- location cache ---------------------------------------
    p = root / "RootDomain/Library/Caches/locationd/cache_encryptedA.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE ZRTCLLOCATIONMO (Z_PK INTEGER PRIMARY KEY,
        Z_ENT INTEGER, Z_OPT INTEGER, ZLATITUDE FLOAT, ZLONGITUDE FLOAT,
        ZHORIZONTALACCURACY FLOAT, ZALTITUDE FLOAT, ZSPEED FLOAT,
        ZCOURSE FLOAT, ZTIMESTAMP FLOAT)""")
    base_lat, base_lon = 18.9400, 72.9340
    for i, t in enumerate(times[::4][:50], 1):
        conn.execute("INSERT INTO ZRTCLLOCATIONMO VALUES (?,5,1,?,?,?,?,?,?,?)",
                     (i, base_lat + rng.uniform(-0.09, 0.09),
                      base_lon + rng.uniform(-0.09, 0.09),
                      rng.uniform(5, 65), rng.uniform(0, 30),
                      rng.uniform(0, 14), rng.uniform(0, 360), us_to_apple(t)))
    conn.commit(); conn.close()
    stats["locations"] = 50

    # ---------------- Notes -------------------------------------------------
    p = root / "AppDomainGroup-group.com.apple.notes/NoteStore.sqlite"
    conn = _connect(p)
    conn.executescript("""
        CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER PRIMARY KEY,
            ZTITLE1 TEXT, ZISPINNED INTEGER, ZMARKEDFORDELETION INTEGER,
            ZISPASSWORDPROTECTED INTEGER, ZCREATIONDATE1 FLOAT,
            ZMODIFICATIONDATE1 FLOAT);
        CREATE TABLE ZICNOTEDATA (Z_PK INTEGER PRIMARY KEY, ZNOTE INTEGER,
            ZDATA BLOB);
    """)
    notes = [
        ("Berth schedule", "Berth 4 — 23:00 Tuesday\nBerth 7 — 04:00 Thursday\n"
                           "Contact: Dockyard Office"),
        ("Shopping", "milk\nbread\nbatteries"),
        ("Reminders", "Renew passport\nPay warehouse rent\nDelete old messages"),
    ]
    for i, (title, body) in enumerate(notes, 1):
        blob = zlib.compress(body.encode("utf-8"))
        # gzip-style wrapper so the inflate fallback path is exercised
        conn.execute("INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES (?,?,?,?,0,?,?)",
                     (i, title, int(i == 1), int(i == 3),
                      us_to_apple(times[10 * i]), us_to_apple(times[10 * i + 5])))
        conn.execute("INSERT INTO ZICNOTEDATA VALUES (?,?,?)", (i, i, blob))
    conn.commit(); conn.close()
    stats["notes"] = len(notes)

    # ---------------- media -------------------------------------------------
    media = [
        ("CameraRollDomain/Media/DCIM/100APPLE/IMG_0431.JPG", 640, 480, 18.9401, 72.9350),
        ("CameraRollDomain/Media/DCIM/100APPLE/IMG_0432.JPG", 640, 480, 19.0760, 72.8777),
        ("CameraRollDomain/Media/DCIM/100APPLE/IMG_0433.JPG", 640, 480, None, None),
        ("MediaDomain/Library/SMS/Attachments/aa/00/berth.jpg", 800, 600, 18.9415, 72.9333),
    ]
    for i, (rel, w, h, lat, lon) in enumerate(media):
        make_jpeg(root / rel, w, h, times[50 + i * 15], lat, lon, seed=40 + i)
    stats["media"] = len(media)

    # ---------------- KnowledgeC: the device-usage timeline -----------------
    # iOS's own analytics store. Records app focus, lock state and screen
    # events with start/end times — evidence that a person was holding the
    # handset, not merely that it was powered on.
    p = root / "AppDomainGroup-group.com.apple.CoreDuet/Knowledge/KnowledgeC.db"
    conn = _connect(p)
    conn.execute("""CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER,
        Z_OPT INTEGER, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR,
        ZSTARTDATE FLOAT, ZENDDATE FLOAT, ZCREATIONDATE FLOAT)""")
    KC_APPS = ["net.whatsapp.WhatsApp", "ph.telegra.Telegraph",
               "com.apple.MobileSMS", "com.apple.mobilesafari",
               "org.whispersystems.signal", "com.burbn.instagram"]
    pk = 1
    kc_events = 0
    for i, t in enumerate(times[::5][:40]):
        bundle = KC_APPS[i % len(KC_APPS)]
        dur = 30 + (i % 12) * 45
        conn.execute("INSERT INTO ZOBJECT VALUES (?,6,1,'/app/inFocus',?,?,?,?)",
                     (pk, bundle, us_to_apple(t),
                      us_to_apple(t + timedelta(seconds=dur)), us_to_apple(t)))
        pk += 1; kc_events += 1
        # Lock/unlock transitions bracket the app usage.
        conn.execute("INSERT INTO ZOBJECT VALUES (?,7,1,'/device/isLocked',?,?,?,?)",
                     (pk, "0" if i % 2 == 0 else "1",
                      us_to_apple(t - timedelta(seconds=5)),
                      us_to_apple(t - timedelta(seconds=4)),
                      us_to_apple(t)))
        pk += 1; kc_events += 1
        if i % 4 == 0:
            conn.execute("INSERT INTO ZOBJECT VALUES (?,8,1,'/display/isBacklit',"
                         "'1',?,?,?)",
                         (pk, us_to_apple(t - timedelta(seconds=6)),
                          us_to_apple(t + timedelta(seconds=dur)),
                          us_to_apple(t)))
            pk += 1; kc_events += 1
    conn.commit(); conn.close()
    stats["knowledgec_events"] = kc_events
    stats["knowledgec_apps"] = len(KC_APPS)

    # ---------------- PowerLog: independent corroboration -------------------
    p = root / "RootDomain/Library/BatteryLife/CurrentPowerlog.PLSQL"
    conn = _connect(p)
    conn.execute("""CREATE TABLE PLApplicationAgent_EventNone_AppRunTime (
        ID INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER,
        BundleID TEXT, Duration REAL)""")
    pl = 0
    for i, t in enumerate(times[::9][:20]):
        conn.execute("INSERT INTO PLApplicationAgent_EventNone_AppRunTime "
                     "(timestamp,BundleID,Duration) VALUES (?,?,?)",
                     (int(t.timestamp()), KC_APPS[i % len(KC_APPS)],
                      float(20 + i * 7)))
        pl += 1
    conn.commit(); conn.close()
    stats["powerlog_events"] = pl

    return stats



# --------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", choices=["android", "ios", "both"],
                    default="both")
    ap.add_argument("--out", default="./evidence")
    # A bare path is what everyone types, and rejecting it teaches nothing —
    # the error names the flag but not the fix, so the obvious next move is to
    # run the identical command again. Accept both spellings.
    ap.add_argument("out_positional", nargs="?", metavar="OUT",
                    help="output directory (same as --out)")
    args = ap.parse_args()
    if args.out_positional:
        args.out = args.out_positional

    out = Path(args.out)
    results = {}
    if args.platform in ("android", "both"):
        target = out / "android" if args.platform == "both" else out
        results["android"] = build_android(target)
        print(f"Android device tree written to {target}")
        for k, v in results["android"].items():
            print(f"  {k:16s} {v}")
    if args.platform in ("ios", "both"):
        target = out / "ios" if args.platform == "both" else out
        results["ios"] = build_ios(target)
        print(f"iOS backup tree written to {target}")
        for k, v in results["ios"].items():
            print(f"  {k:16s} {v}")
    print("\nNext:")
    print(f"  argus case new --dir ./cases --investigator 'A. Sharma'")
    print(f"  argus exhibit add ./cases/<CASE> EXH-001 --make Samsung "
          f"--model 'Galaxy S21 5G' --isolation 'Faraday pouch'")
    print(f"  argus acquire ./cases/<CASE> --exhibit EXH-001 "
          f"--operator 'A. Sharma' --method import --source {out}/android")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
