# ARGUS Field Tool — method statement and limitations

**Version** 1.1.0-field
**File** `ARGUS.bat`, 192,884 bytes
**SHA-256** `e268e0d36fad0c7d4426f71e6d1c74de0ebd376de814b04d6d1c3c9752073e0a`

This document exists to be read alongside anything the tool produces. Verify
the hash before use:

```powershell
Get-FileHash .\ARGUS.bat -Algorithm SHA256
```

If it does not match, the file is not this version and nothing below describes
what you are running.

---

## 1. What it is

A single-file Windows tool for acquiring and triaging mobile handsets. It runs
without installation, without administrator rights, without network access, and
without leaving anything on the machine beyond the evidence folder it is told
to write to.

It is not a substitute for XRY, Cellebrite, or GrayKey. It reaches a strict
subset of what those tools reach, and section 4 states exactly which subset.

---

## 2. Method

### 2.1 Device identification

Four independent enumerators are queried and each reports its own status
separately: PnP (`Get-PnpDevice`), WMI (`Win32_PnPEntity`), the raw
`HKLM\SYSTEM\CurrentControlSet\Enum\USB` registry keys, and the Windows shell
namespace. A device is treated as a handset when **any** of the following
holds, and which one fired is recorded:

| Basis | Confidence |
|---|---|
| USB-IF vendor ID in the table | vendor ID |
| Windows device class `WPD` | device class |
| Driver service is the MTP or ADB driver | driver |
| Product name matches a handset pattern | name only |

Devices matching none of these are counted and their VID/PID printed, so a
vendor absent from the table appears as a visible gap rather than as silence.

Modes (Qualcomm EDL, MediaTek BootROM, Apple DFU, Samsung Download, and others)
are keyed on **vendor and product ID together**. A vendor ID alone identifies no
mode.

Connection stability is measured, not assumed: the bus is enumerated twice, 900
ms apart, and any device that appears or disappears between the two passes is
reported as an unstable connection.

### 2.2 Acquisition

Two routes, both following the same discipline:

**MTP** — for a handset mounted in *This PC*. Requires no USB debugging.
**adb logical** — for a handset with USB debugging authorised. Also captures
`getprop` and the installed package list.

Both:

1. **Inventory the device first.** The listing is what makes a shortfall
   detectable; without it a partial transfer is indistinguishable from a
   handset that held less.
2. **Check free space** against the listed size plus 5% and refuse upfront if
   short.
3. **Copy.**
4. **Reconcile** what arrived against what was listed.
5. **SHA-256 every file that arrived.**
6. **Name every file that did not**, with the reason.
7. Write `argus-mtp-manifest.json` (or `argus-adb-manifest.json`) and append to
   a hash-chained `argus-custody.jsonl`.

The acquisition is resumable: re-running retries only what is missing.

### 2.3 Analysis

Operates on the acquired folder, never on the handset.

- File inventory with content type determined by **header bytes, not
  extension**.
- EXIF read from the JPEG APP1 segment by a hand-written parser: make, model,
  `DateTimeOriginal`, and GPS converted to decimal degrees.
- Video metadata from the ISO base media box tree: `mvhd` creation time (epoch
  1904 UTC) and duration, `udta/©xyz` ISO 6709 location.
- Exact duplicate detection by size collision then SHA-256.
- Application media folders, `.nomedia` markers, timestamp anomalies,
  thumbnails without originals.
- Output: HTML report plus CSV inventories, written beside the evidence.

EXIF and video metadata are parsed by hand rather than through `System.Drawing`
or a media framework. An image decoder is a large attack surface aimed directly
at untrusted input, and evidence is untrusted input by definition. Every offset
is bounds-checked.

### 2.4 Verification

`Verify` re-hashes the acquisition against its manifest and reports
**unchanged**, **altered**, **missing** and **added** separately. It also walks
the custody chain, in which each entry carries the hash of the one before it.

---

## 3. What it reaches

- Shared storage: camera media, downloads, documents, screenshots
- App media folders under `Android/media`, including WhatsApp media
- Device properties and installed package list (adb route only)
- Mounted volumes and removable cards carrying handset directories

---

## 4. What it does NOT reach — read this before relying on any output

**These are limitations of method, not defects. They cannot be worked around
by re-running the tool.**

### 4.1 `/data/data` is out of scope

Message databases, call logs, contacts, app private storage, and the
unallocated database space where deleted records survive are **not reached by
either route**. MTP cannot see them at all. adb cannot without root.

**A file absent from an ARGUS exhibit is not thereby absent from the handset.**
Every manifest states this. It is the single most important limitation here.

### 4.2 No deleted-record recovery

The tool does not parse SQLite, does not read freelist or freeblock space, and
does not carve unallocated space. Nothing it produces speaks to deleted data.

### 4.3 MTP is a media-provider copy, not an image

It returns what the handset's media provider chooses to expose. It is not a
bit-for-bit image of storage, and it cannot be used to compute a hash of the
device. Reading a file over MTP may update its access time **on the handset**.

### 4.4 Timestamps

Filesystem times in the exhibit are those of the **copy**, not the handset. Use
EXIF capture time or video `mvhd` time where present — those were written by
the recording device. Any handset clock may be wrong or set deliberately.

### 4.5 GPS

A GPS tag records where the camera *believed* it was. It is written by the
handset, can be absent, stale or edited, and its absence is not evidence the
device lacked location data — tagging is off by default on many builds and is
stripped by most messengers.

### 4.6 Inferences deliberately not drawn

The tool reports the following as observations and explicitly refuses to state
the conclusion they suggest:

| Observed | NOT concluded |
|---|---|
| Thumbnail with no original | the photograph was deleted |
| `.nomedia` in a media folder | concealment |
| Byte-identical duplicates | which copy came first, or direction |
| Modified before created | tampering (normal on any copy) |
| Empty carve of a high-entropy container | the device held nothing |

### 4.7 Proprietary containers

`.xry`, `.xrycase` and `.ufd` are not decoded. Triage reports what the bytes
are and whether an independent read is possible; it does not interpret the
container. Guessing at an undocumented structure produces records that look
authoritative and are wrong.

---

## 5. Validation performed

### 5.1 Known-answer tests

Two byte-exact fixtures with known correct values are embedded in the tool and
asserted by `Self-test`:

| Fixture | Asserted |
|---|---|
| JPEG | Make `ARGUS`, Model `TESTCAM-1`, taken `2024:03:15 14:22:07`, lat `51.477500`, lon `-0.001500` |
| MP4 | recorded `2021-06-01 09:30:00Z`, duration `12.5 s`, lat `48.858200`, lon `2.294500` |

Coordinates are asserted to six decimal places. The negative longitude is
deliberate: a reader that ignores the `W` reference places the point in the
wrong hemisphere, and the error looks entirely plausible in a report.

### 5.2 Negative controls

Corrupt JPEG yields no GPS. Non-JPEG yields no EXIF. A truncated MP4 declaring
a 2 GB box inside a 24-byte file returns in under three seconds and fabricates
no location. An edited custody-log entry is detected.

### 5.3 Structural verification

Every build is checked for balanced brackets, quotes and here-strings; invalid
`$name:` variable references; and string-interpolation errors. The launcher
additionally parses the script with PowerShell's own
`System.Management.Automation.Language.Parser` **before running it**, and
refuses to proceed on any syntax error.

### 5.4 Defects found during validation, and fixed

Recorded because a validation record that lists no failures is not a validation
record.

| Defect | Consequence had it shipped |
|---|---|
| Video `udta` decoded as ASCII | Byte `0xA9` in the `©xyz` atom became `?`; **every GPS-tagged video silently returned no location** |
| Vendor whitelist discarded unknown IDs | A connected, mounted handset reported as "no hardware on the bus" |
| Low-level modes keyed on vendor alone | An MTP handset reported as being in MediaTek BootROM |
| Swallowed enumerator failure | An empty result reported as an absence |
| `"$n:"` variable reference | Script would not load at all |
| Self-test had only negative controls | A parser returning null for everything would have passed |

### 5.5 What has NOT been validated

**The tool has not been run end-to-end against a real handset.** All validation
above is against synthetic fixtures and static analysis. Until an acquisition
of a physical device has been completed and checked, treat the first run as
part of validation rather than as evidence collection.

---

## 6. Reproducibility

Every operation appends to `argus-custody.jsonl` beside the evidence: operator,
workstation, timestamp, action, counts, and the hash of the previous entry.
`Verify` re-checks the chain.

The chain makes casual alteration detectable. It does **not** make the log
tamper-proof — anyone able to rewrite the file can recompute every hash. It
means the log can be checked rather than merely asserted.

---

## 7. Suggested wording for a report

> Shared storage was acquired from the handset over MTP using ARGUS Field Tool
> 1.1.0 (SHA-256 `e268e0d3…`). The acquisition inventoried the device before
> copying, reconciled the copy against that inventory, and recorded a SHA-256
> for every file received. [N] files were listed and [M] received; any
> shortfall is itemised in `argus-mtp-manifest.json`.
>
> This method reaches shared storage only. Message databases, call logs and
> deleted records reside in `/data/data`, which is not accessible by this
> method. **No conclusion about the absence of any item can be drawn from this
> exhibit.**

---

## 8. Legal

For use only on devices you own or are lawfully authorised to examine. Mobile
device examination is regulated in most jurisdictions. All bundled test
fixtures are synthetic and contain no real personal data.
