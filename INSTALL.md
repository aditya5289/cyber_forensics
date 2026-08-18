# ARGUS Forensics 1.0.0 — install and first run

Build `5a7167f06ae50682` · 392 tests passing · validation 18/18

---

## 1. Check the download arrived intact

Windows PowerShell:

```powershell
Get-FileHash .\argus-1.0.0.zip -Algorithm SHA256
```

The result must match:

```
97cf739d04fe4869c9aaec59f2b7ce777ffadac5f3d488f6e875a71676810c91
```

macOS or Linux:

```bash
shasum -a 256 -c argus-1.0.0.sha256
```

If it does not match, stop — the archive is damaged or has been altered. Do not
use it on evidence.

## 2. Unpack

Put it on a local disk rather than a network drive. Windows treats network
paths as the internet zone permanently, so files there keep re-blocking
themselves.

```powershell
Expand-Archive .\argus-1.0.0.zip -DestinationPath C:\
cd C:\argus-1.0.0
Get-ChildItem -Recurse | Unblock-File
```

That last line clears Mark-of-the-Web. Windows applies it to everything that
arrives from a browser, and without clearing it the launcher is blocked.

## 3. Verify the installation before touching evidence

```powershell
python -m argus.cli selfcheck
```

Expected:

```
  ✓ 83 shipped files match the release manifest.
```

This is what lets you answer, later, *which* build produced an exhibit and how
you know it had not been altered. Record the version and build ID in your case
notes — a validation certificate is issued against a specific build, so if the
files drift the certificate stops describing what is installed.

The command exits non-zero on a mismatch, so it can gate a script.

## 3a. Delete old copies

If you have extracted ARGUS more than once, remove the older folders. Several
copies on different drives are indistinguishable once running, and it is easy to
troubleshoot a fixed problem in a stale one for a long time before noticing.

The running build is now shown in the app header and in the footer, so you can
always confirm which copy you are looking at. It should read `5a7167f06ae5`.

The build ID covers the `argus` package — the tool itself. Sample generators and
test fixtures live outside it, so a change to those alters the archive checksum
without changing the build ID. That is deliberate: the ID answers "which code
produced this exhibit", and sample data never touches an exhibit.

## 4. Run it

```powershell
.\ARGUS.bat
```

or, if the launcher is blocked for any reason:

```powershell
python argus_app.py
```

A browser opens on `http://127.0.0.1:8765/`. It binds to localhost only.

---

## Requirements

**Python 3.10 or newer** is the only hard requirement. Everything else is
optional and degrades rather than fails:

| Optional | Gives you | Without it |
|---|---|---|
| Pillow | EXIF, GPS, perceptual image matching | Media is still hashed and catalogued, just not decoded or compared |
| adb | Live acquisition from a connected Android handset | Import of an existing extraction works normally |

| libimobiledevice | Live acquisition from a connected iPhone | Import of an existing iTunes backup works normally |

No pip install, no network, no build step. The whole tool is standard library.
This is deliberate: a forensic workstation is frequently air-gapped, and a tool
that needs to reach the internet to start is a tool that does not work where it
matters.

## No device connected? That is the normal case

Neither adb nor libimobiledevice is needed to work from an extraction that
already exists on disk. On the **Support** step, continue past the "no device
detected" panel and choose **Import** on the next screen. It accepts:

- a folder pulled from a device (`adb pull`, or a mounted image)
- an iTunes backup folder
- Cellebrite `.ufdr`
- `.tar`, `.tar.gz`, `.zip` archives
- a raw `dd` image
- a monolithic SIM dump

Live acquisition is the only thing those two tools unlock.

### If you do want adb

Unzip [platform-tools](https://dl.google.com/android/repository/platform-tools-latest-windows.zip)
to `C:\platform-tools`. You do not need to touch PATH — ARGUS checks that
location and the other standard install paths directly.

Avoid `winget install Google.PlatformTools`: it frequently installs without
adding adb to PATH, and its manifest hash goes stale when Google republishes the
archive, producing "Installer hash does not match". Do not bypass that hash
check on a machine that will handle evidence — the error cannot distinguish a
stale manifest from a tampered download.

If you install adb while ARGUS is already running, **restart it**. A process
reads PATH once at start-up, so "Scan again" cannot see an environment change
made afterwards.

---

## Trying it without evidence

The repository ships a synthetic device generator, so you can exercise the whole
pipeline end to end without touching a real handset:

```powershell
python samples\make_device.py --out C:\temp\evidence
```

Then Import that folder. It contains planted ground truth — deleted SMS, a
media vault, thumbnails that survived their originals, encrypted app stores,
notifications previewing encrypted apps — so you can see what recovery actually
looks like and check the tool against a known answer.

All sample data is invented.

## Proving it works

```powershell
python -m unittest discover -s tests    # 392 tests
python -m argus.cli validate            # measured recall and precision
```

Two of those suites deliberately attack the tool rather than confirm it:
`test_robustness.py` runs ~1,000 parses of corrupted evidence asserting no crash
and no fabricated content, and `test_schema_variants.py` plants the same
conversation in six different app schemas to catch a parser that only
understands the generation it was written against.

The validation harness is a NIST CFTT-style known-answer test. It reports its
own limitations alongside its figures, including the ones that are unflattering
— for example, that most deleted rows in a busy SQLite table are physically
destroyed by page compaction and are unrecoverable by any tool, not just this
one.

## A handset you can browse but not debug

If the phone appears in the file manager (`This PC → <handset>`) but adb sees
nothing, you do not need USB debugging at all:

```powershell
python -m argus.cli mtp list
python -m argus.cli mtp acquire "OPPO F11" --out C:\evidence\oppo-f11
```

Dragging the folder out in Explorer does the same copy, but produces no hashes,
no record of what was taken, and — the dangerous one — no record of what was
**missed**. MTP transfers fail individually and quietly: a file locked by the
handset, a name the host filesystem rejects, an entry the media provider lists
but will not serve. Copy 4,000 files, receive 3,960, and nothing tells you.

So ARGUS lists the device first, copies, then reconciles. Every arrival is
hashed; every listed file that did not arrive is named in
`argus-mtp-manifest.json`. A file missing from the copy means the transfer
failed — **not** that the handset lacked it, and the manifest says so.

What MTP reaches: shared storage, camera media, downloads, documents, and app
folders under `Android/media` including WhatsApp media. What it cannot reach:
`/data/data` — message databases, call logs, and the unallocated space where
deleted records live. That needs adb or a physical extraction.

This is a copy served by the handset's own media provider, not an image of its
storage, and reading a file over MTP may update its access time on the device.
Both facts are recorded in the manifest.

## What is actually attached

```powershell
python -m argus.cli bus
```

adb and libimobiledevice only see handsets that cooperate. A phone in MTP mode,
one whose driver never bound, one in fastboot, one where USB debugging was never
enabled — all are physically present and invisible to both.

`bus` asks the **operating system** instead, so a device that is plugged in is
reported whether or not any forensic tool can talk to it. It identifies handset
manufacturers by USB vendor ID — assigned by USB-IF and stable, so a match is a
fact about the hardware rather than a guess from a product string.

That single fact changes the diagnosis. If USB reports Oppo hardware, **the
cable and port are working**, and the remaining causes are USB debugging, the
connection mode, or the driver. "Check your cable" is the standard advice and it
is wrong whenever the device is enumerating.

It also names the modes that matter — Qualcomm EDL (`05c6:9008`) and MediaTek
BootROM (`0e8d:0003`), where physical acquisition becomes possible and adb
cannot see either. Note the **product** ID: a vendor ID alone identifies no
mode. MediaTek's `0e8d` covers the preloader, the BootROM, and perfectly
ordinary MTP and ADB interfaces, so keying on the vendor announced "BootROM" for
a phone that was simply browsable in Explorer.

A handset in **MTP mode** is flagged as exactly that, with the point an examiner
needs: its shared storage can be copied off and imported with no adb, no
debugging toggle and no vendor tooling. And it lists mounted volumes carrying `DCIM`, `Android` or `LOST.DIR`,
which can be imported immediately with no adb at all.

## Several handsets at once

The scan reports **every** device on the bus, whatever state each is in, and
they are rarely all in the same one. A ready handset is selectable; one that is
unauthorised, offline or blocked by the OS is shown greyed with its state and
the specific fix, rather than omitted.

That last point was a real defect. A phone that is plugged in and enumerating
but not yet authorised was being discarded and reported as "no device detected"
— sending the examiner to check a cable that was working perfectly.

Register each handset as its own exhibit. Analysis runs across exhibits, so
shared correspondents and a merged timeline come out of the case, not out of one
device.

## A handset that will not connect

```powershell
python -m argus.cli diagnose
python -m argus.cli diagnose --make oppo
```

Or press **Why not?** on the Support step.

This runs adb, reads the state it reports, and names the specific cause. The
states mean different things and need different responses:

| State | Cause | Fix |
|---|---|---|
| `unauthorized` | Not trusted this computer | Unlock the screen and accept the RSA prompt |
| `offline` | Enumerated but unresponsive | Switch USB mode to File transfer; `adb kill-server` |
| `no permissions` | OS is blocking the USB device | udev rule on Linux; wrong driver on Windows |
| `recovery` / `bootloader` | Wrong boot mode | Reboot to system |
| *(empty list)* | Nothing on the bus | Charge-only cable is the usual culprit |

**Vendor skins hide extra switches**, and the symptom looks like a hardware
fault. ColorOS (Oppo, realme, recent OnePlus) has a **Disable permission
monitoring** toggle in Developer options that must also be on — without it adb
connects but is refused, and the device shows as `unauthorized` however many
times you accept the prompt. MIUI needs **USB debugging (Security settings)**
plus a signed-in Mi account. The diagnostic detects the vendor from the model
string and shows the relevant notes.

---

## Vendor containers you cannot open

```powershell
python -m argus.cli triage <file>
python -m argus.cli triage <file> --carve --out C:\temp\carved
```

MSAB `.xry` / `.xrycase` and Cellebrite `.ufd` are proprietary and ARGUS does
not decode them. Guessing at an undocumented container structure produces
records that look authoritative and are wrong, which is worse than a refusal.

Triage instead tells you what the bytes actually are — a zip wearing a vendor
extension, a compressed stream, or something with real file signatures buried in
it — and whether an independent read is even possible. Where files *are*
embedded, `--carve` recovers them by signature and ARGUS parses them normally,
carving their unallocated space in turn.

Two things it will tell you that matter:

- **A small `.xrycase` is a case index, not the extraction.** The device data
  lives in the companion `.xry`. Examiners lose time on this one.
- **High entropy means carving cannot work.** Above ~7.5 bits/byte the contents
  are compressed or encrypted and no signature survives. An empty carve there
  means this route cannot reach the data — not that the device held none.

For a complete read, export from the tool that made the container: in XAMN,
Report/Export → **Files** (the extracted file system, which ARGUS parses and
carves independently) or **Extended XML** (the decoded report).

Reading an XRY export back through ARGUS is not redundant. XRY gives you its
decode; ARGUS carves unallocated space independently and cites source file,
table and row for every record. Two tools agreeing from the same bytes is a
stronger position than one, and where they disagree is worth chasing.

---

## What it covers

```powershell
python -m argus.cli platforms
```

127 handsets across 24 manufacturers, plus SIM cards, KaiOS, Windows Phone,
feature phones, SD cards and wearables. For a handset that is not catalogued,
`argus manual show "<model>" --chipset "<soc>" --os Android --os-version 13`
derives a profile from the chipset family and OS release, clearly marked as
inferred and never scored as highly as a tested entry.

---

## Legal

For use only on devices you own or are lawfully authorised to examine. Mobile
device examination is regulated in most jurisdictions. All bundled sample data
is synthetic.
