# Lab manual → ARGUS implementation map

Every numbered step in *Practical Exercise — Mobile Device Forensic Acquisition
and Analysis using MSAB XRY & XAMN*, and where it lives in this codebase.

---

## Part A — Data acquisition (§5)

### §5.1 Verify device support — Steps 1–2

| Step | Manual | ARGUS |
|---|---|---|
| 1 | Open the XRY Device Manual, search for the model | `argus manual search "iPhone 12"` → `argus/devices/manual.py::DeviceManual.search` |
| 2 | Select the model; view Device Overview and Capability overview | `argus manual show "iPhone 12 mini"` → `DeviceManual.overview` |

The capability overview is a real matrix of **lock state → available method**,
not a static list. Unlocked / AFU / BFU / locked each expose a different set,
and each cell carries its risk level, prerequisites and caveats — for example
that BFU on a modern iPhone reaches only SIM-resident data because handset
content is still encrypted at rest.

`DeviceManual.assert_supported()` is called by the acquisition engine before any
device method runs. An unsupported combination raises `DeviceNotSupportedError`
and the extraction never starts, implementing precaution 1 of §7 as an
enforced gate rather than a warning.

Device *selection* uses a stricter score threshold than device *browsing*, so a
fuzzy near-miss cannot silently resolve an unknown handset to a real profile —
which would otherwise let the matrix authorise a method the real device does
not support.

### §5.2 Create a new case — Steps 3–5

| Step | Manual | ARGUS |
|---|---|---|
| 3 | Enter a unique Case ID (timestamp default, editable) | `Case.create(case_id=...)`; `generate_case_id()` produces `CASE-YYYYMMDD-HHMMSS` |
| 4 | Specify "Save at location"; optionally password-protect | `--dir`, `--password` (PBKDF2-HMAC-SHA256, 600 000 iterations, verifier only — the password is never stored) |
| 5 | Click Create Case | `argus case new` |

### §5.3 Case Overview

`argus case show <case>` → `Case.overview()`. Lists exhibits, every extraction
with its device, method, artifact count, size and status, plus the case-level
audit chain state.

### §5.4 Connect and detect the device — Steps 6–7

`argus devices` → `argus/devices/detect.py`. Enumerates Android over `adb`
(build properties, IMEI, battery, root and encryption state) and iOS over
`libimobiledevice` (ProductType, version, serial, IMEI, ICCID, pairing state).

If nothing is found, it reports *why* — missing toolchain, unauthorised USB
debugging prompt, untrusted pairing, or a charge-only cable — rather than an
unqualified "no device", which sends an examiner looking in the wrong place.

### §5.5 Choose the extraction action — Step 8

`--method logical | filesystem | backup | import`.

`logical` queries content providers, matching the manual's "Logical (Full read)
— requests data from the device operating system within the permissions
granted". It returns allocated records only; deleted material is already gone
at that layer. `filesystem` pulls the database files **with their `-wal` and
`-journal` sidecars**, which is what makes deleted-record recovery possible.

### §5.6 Specify time span — Step 9

`--span all | 24h | 7d | 30d | 365d | YYYY-MM-DD..YYYY-MM-DD` →
`argus/parsers/timestamps.py::span_to_range`. Applied during decoding via
`ParseContext.in_span`, so excluded artifacts are never written into the
container at all.

### §5.7 Specify artifact categories — Step 10

`--categories Calls,Contacts,Messages,...` (16 categories, `all` by default) →
`ParseContext.wants`. Excluding a category reduces extraction time exactly as
the manual describes.

### §5.8 Enter case and exhibit details — Step 11

`--operator` and `--exhibit` are **required**; the engine refuses to run without
them, because they are the chain-of-custody record. Case ID and save location
carry over from the case. The container filename is generated automatically as
`<EXHIBIT>_<method>_<timestamp>.afc`, with a collision counter so two
extractions started in the same second cannot clash.

### §5.9 Run and complete the extraction — Steps 12–13

Step 12's live log — module, status, timestamp, message — is emitted to the
console *and* persisted to `extraction.log.jsonl` inside the container, and is
replayable later in the UI's Extraction log view.

Step 13's completed file with size, decode version and status is the sealed
`.afc` container. `EvidenceContainer.seal()` computes a Merkle root over every
blob plus a digest of the artifact database, records the seal in the custody
chain, and switches the container to read-only.

> The engine never discards a partial extraction. If a module fails halfway,
> what was already acquired stays in the container and the failure is recorded
> in the log, the manifest and the returned report.

---

## Part B — Data analysis (§6)

### §6.1 Open the case in XAMN — Step 14

`argus analyze <container>` → `AnalysisSession.overview()`. Shows case info
(creation date, seal state, Case ID, operator), device identity, and category-
wise artifact counts including per-application counts.

Containers are **verified on open**. If a seal does not match, the session
still opens — an examiner must be able to look at damaged evidence — but every
response carries the integrity failure so it cannot be reported as sound.

### §6.2 Review pictures and videos — Step 15

Gallery view, filterable by time, location and source application →
`AnalysisSession.gallery()`. Thumbnails are served from the content-addressed
blob store. Files carrying GPS are badged; files whose extension disagrees with
their magic bytes are badged separately.

### §6.3 Review call records — Step 16

`AnalysisSession.list_view("Calls")` — chronological, with caller identity,
duration and direction, plus presentation code (why a number is absent:
restricted, unknown, payphone), SIM slot and geocoded location where present.

### §6.4 Connection / link analysis — Step 17

`argus graph --scope calls` or the UI's Connection view →
`argus/analyze/graph.py`. A force-directed graph where edge weight is the
artifact count per link, exactly as the manual describes.

Identity resolution is the hard part and is handled conservatively: phone-like
identifiers normalise to their last ten digits and JIDs to their local part, so
`+91 98765 43210`, `09876543210` and `919876543210@s.whatsapp.net` are one
node — but two numbers differing in those ten digits are never merged. Display
names come from the contact list first, then from a majority vote across
artifacts.

Beyond the manual: degree, Brandes betweenness centrality (who bridges
otherwise separate clusters), reciprocity per edge, and one-way link detection.

### §6.5 Review application artifacts — Step 18

`AnalysisSession.application("Instagram")` — per-app artifacts with file path,
dimensions and hash values. Applications with no dedicated parser are still
surveyed generically rather than silently omitted.

### §6.6 Message connection analysis — Step 19

`argus graph --scope messages` — the same graph restricted to messaging
artifacts across all applications.

### §6.7 Review contacts — Step 20

`AnalysisSession.column_view("Contacts")` — flat tabular projection with
participant identity and source application/device, matching the manual's
Column view.

### §6.8 Generate the forensic report — Step 21

`argus report --scope all|filtered|selected --formats html,pdf,xlsx,docx,xml,json,csv`

Scope maps directly onto the manual's All / Filtered / Selected. Filtered takes
an AQL expression. Every format carries the integrity statement **before** the
findings, and deleted records are visually distinguished throughout.

---

## §7 Precautions

| # | Precaution | Implementation |
|---|---|---|
| 1 | Verify device support before extraction | `assert_supported()` gates the engine; unsupported combinations abort before the device is touched |
| 2 | Airplane mode / Faraday pouch | `Exhibit.isolation` is a recorded field; `argus exhibit add` warns when it is left blank |
| 3 | Do not disconnect during extraction | Battery below 20% raises a warning before a long extraction; the live log makes progress visible so the operator knows when it is safe |
| 4 | Record Case ID, Operator, Exhibit ID | Required arguments; written into the manifest and the hash-chained custody log |
| 5 | Verify hash values after extraction and before analysis | Triple hashing (MD5/SHA-1/SHA-256) on ingest; `argus verify` re-hashes every blob; verification runs automatically when a container is opened for analysis |
| 6 | Handle personal data confidentially | Containers are local files; the analysis server binds to 127.0.0.1 with no upload surface and no write path to sealed evidence |

---

## §8 Viva-voce questions

The tool answers each of these operationally, not just conceptually.

**1. Difference between logical, file-system and physical extraction?**
See `argus/devices/manual.py::METHOD_INFO` — each method carries a
description, risk level, whether it yields deleted data, and typical duration.
Logical returns allocated records via OS APIs; file-system copies the databases
including WAL sidecars, enabling deleted-record recovery; physical images the
flash including unallocated space. Run `argus manual show <device>` to see which
are available for a given handset and lock state.

**2. Why check device support before extraction?**
Because an unsupported method can brick the device or destroy data, and because
the available methods depend on lock state. ARGUS enforces this: the engine
refuses to start an unsupported combination.

**3. Purpose of a Faraday pouch?**
To prevent remote wipe or lock commands reaching the device between seizure and
acquisition. Recorded per exhibit in `Exhibit.isolation`; its absence is warned
about at registration.

**4. Difference between XRY and XAMN?**
XRY acquires, XAMN analyses. Here: `argus.acquire` versus `argus.analyze`, with
the `.afc` container as the handover format — the same split, and the same
reason for it: acquisition happens once under time pressure at the device;
analysis happens repeatedly, later, and must never mutate the evidence.

**5. What should be recorded for chain of custody?**
Case ID, exhibit ID, operator, seizure details, isolation method, extraction
method and time span, and every subsequent access. All of it lands in
`audit.jsonl`, hash-chained so that any later edit is detectable —
`argus verify` will name the broken entry.

**6. What is a connection graph used for?**
To turn a pile of messages into a statement about relationships: who
communicated with whom, how often, through which application, in which
direction, and who bridges otherwise separate groups. In the bundled sample
case it surfaces a deleted contact as a one-way link carrying only recovered
deleted messages — a finding no chronological list would make obvious.

**7. Why does a locked device (AFU/BFU) support fewer options?**
Because file-level encryption keys are only in memory after the user has
unlocked the device once. Before first unlock the data is encrypted at rest and
there is nothing to read. The matrix in `manual.py` encodes exactly this: BFU
on a modern handset offers only SIM extraction and photographic documentation.

---

## §9 Result

The bundled sample case reproduces the manual's conclusion end to end. From a
generated Android tree:

```
Artifacts            522
Deleted recovered     39
Categories           Messages 327, Calls 151, Contacts 16, Web 8,
                     Files & Media 7, Applications 6, Accounts 3,
                     Networks 3, Device info 1
Integrity            VERIFIED
```

Including a JPEG concealed as `invoice_2026.txt` (identified by content), six
deliberately deleted SMS messages recovered from freelist pages, four deleted
WhatsApp messages recovered from page slack, and a deleted contact that appears
in the connection graph as a one-way link.

---

## Beyond the manual

Capabilities added because their absence would be a real gap in casework:

- **Deleted-record carving** across freeblocks, page slack, freelist pages, WAL
  frames and rollback journals, with a three-pass strategy and explicit
  confidence scoring.
- **Content-based file typing** so renamed files are still found and flagged.
- **Cross-platform timestamp normalisation** across eight epochs, with
  implausible conversions refused rather than guessed.
- **AQL**, a parameterised boolean query language over all artifacts.
- **Behavioural analytics** — activity histograms, burst detection, long-silence
  detection, and timestamp-anomaly detection that flags likely clock tampering.
- **Tamper-evident custody** via a hash-chained log and a Merkle-sealed
  container, with all four tamper vectors covered by tests.
- **`attributedBody` recovery** for iOS 16+ messages whose visible text is not
  in the `text` column.
