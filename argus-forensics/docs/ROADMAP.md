# Build state — "god level" upgrade

**Status: all items complete (12–22). 157/157 tests pass, no import failures.**
24,600 lines of Python, 37 registered parsers, 12 finding rules, 21 findings on
the reference case.

Everything below is implemented, tested and wired into the CLI, the Workbench
app and the report builder. `ARGUS.bat` works exactly as before, with two new
steps in the app.

---

## Delivered

### Foundations (item 12)

| Module | What it does | Measured |
|---|---|---|
| `parsers/protobuf.py` | Schema-less protobuf decoder for app blobs (Signal, Telegram, Maps, KnowledgeC, Apple Notes). Recovers structure and values; never invents field names. | Nested messages round-trip; plain strings are not shredded into fake field trees |
| `parsers/filecarver.py` | Signature carving with **structural validation** — JPEG segments walked to real EOI, PNG chunks by declared length, MP4 boxes by size, SQLite by header consistency. | **12/12 planted files at exact offset and exact byte size, 0 false positives** |
| `core/streaming.py` | Split-segment images, LRU block cache, single-pass hash+scan, progress/ETA. Refuses E01/AFF/QCOW2 rather than misreading them. | Split reassembly and boundary-spanning reads byte-correct |

### Intelligence (items 13, 14)

| Module | What it does | Measured |
|---|---|---|
| `intel/entities.py` | Extracts and **checksum-validates** phones, emails, URLs, Tor addresses, BTC (Base58Check + bech32), ETH, XMR, IBAN (mod-97), payment cards (Luhn **plus** issuer IIN ranges), UPI, IMEI, coordinates, vehicle registrations, tracking numbers. Span-conflict resolution stops one real finding becoming three wrong ones. | **15/15 known-answer checks correct**; no cross-type false positives |
| `intel/findings.py` | 10 auditable rules producing ranked findings. Every finding cites its artifacts, says why it matters, and states the caveat that would make it wrong. | Produces the correct primary lead on the sample case |
| `intel/correlate.py` | Cross-exhibit identity linking on exact shared identifiers; byte-identical media matching; label-propagation community detection with Newman modularity. | Deterministic across runs; two-cluster graph separated correctly at Q=0.63 |

### Anti-forensics (item 16)

Vault/hider app catalogue (38 packages), encrypted-store detection (SQLCipher
by entropy + page alignment, WhatsApp `.crypt14/15`), thumbnail-cache carving,
uninstalled-app residue, factory-reset estimation, and an **empirical**
recovery-limitation assessment.

All planted ground truth detected. Two real correctness bugs found and fixed:

- System providers (`com.android.providers.*`) were being reported as
  "uninstalled apps", burying the one entry that mattered.
- `PRAGMA secure_delete` was being read as a property of the evidence. It is
  not — it reports the *reading* connection's setting and its default varies by
  build. The assessment now inspects the file's actual free space and reports
  whether residual data is present, which is the only thing observable from a
  file.

### Court-readiness (item 17)

`validate/harness.py` — 18 known-answer tests over a generated reference corpus
where ground truth is exact by construction. Reports recall, precision and
per-capability false-negative/false-positive rates.

```
tests 18/18 · overall recall 1.000 · precision 1.000 · 434 items · 0 missed · 0 spurious

Anti-forensics detection   1.000 / 1.000      File carving        1.000 / 1.000
Deleted-record recovery    1.000 / 1.000      Parsing (msg/call/contact)  1.000
Entity extraction          1.000 / 1.000      Evidence integrity  1.000 / 1.000
Entity validation          1.000 / 1.000      Repeatability       1.000 / 1.000
```

**The harness earned its keep immediately.** It first reported deleted-record
recall of **0.25**, far below what ad-hoc testing suggested. Investigation
showed 6 of 8 deleted rows were *physically absent* from the file — SQLite
compacts pages when freeing cells and overwrites content outright. The carver
had recovered both survivors, i.e. 100% of what was recoverable.

The test was wrong, not the carver: it measured against an impossible standard.
Recall is now measured against records whose bytes still exist, with the
destroyed count reported separately. Measuring against the deleted count would
have understated the tool — which misleads just as surely as exaggeration, only
in the other direction.

`validate/certificate.py` — a self-contained JSON integrity statement holding
every digest, the container seal, the custody-chain tip and the validated error
rates at the time of examination. Verifiable **without ARGUS**: the five steps in
`how_to_verify` need only a SHA-256 implementation. Optional HMAC seal, with the
certificate stating plainly that a keyed seal is *not* a digital signature and
does not prove authorship.

### Integration (item 18)

- **Workbench** gains a **Findings** step between Analyse and Report, showing
  the ranked lead sheet, high-value entities, cross-exhibit correlation and
  community structure — each finding with its confidence and caveat.
- **Reports** gain the lead sheet as **section 2**, before the artifact tables.
  A reader who reaches 30 000 rows before being told what matters has been given
  data, not a report.
- **New endpoints**: `/api/intelligence`, `/api/validate`, `/api/certificate`
  (the last two as background jobs with live logs).
- **New CLI**: `argus intel`, `argus validate`, `argus certificate issue|verify`.

---

## What it finds on the sample case, unprompted

```
[CRITICAL] Entire conversation with +919555000111 was deleted
[CRITICAL] 2 shared contacts deleted on one device but not another
[HIGH]     53 deleted communications recovered across 9 correspondents
[HIGH]     1 file disguised by extension (invoice_2026.txt is a JPEG)
[HIGH]     16 parties appear on multiple exhibits
[HIGH]     Short-lived intensive contact, never saved to contacts
[HIGH]     51 messages discuss deletion or evasion
[MEDIUM]   3 locations recorded on multiple exhibits
[MEDIUM]   22% of communications between 01:00 and 05:00
[MEDIUM]   1 correspondent with one-directional traffic
```

Every one cites its artifacts. Every one carries a caveat.

---

### Expanded parser suite (item 15)

13 new first-class parsers, all verified against planted ground truth:

| Source | Recovers | Notable |
|---|---|---|
| Telegram | messages, users, calls | Text lives in a serialised TL **blob**, not a column |
| Instagram | direct messages | Falls back to the JSON payload when `text` is NULL |
| Snapchat | chats, friends | Reports **metadata-only** records honestly where content was never retained |
| Messenger | threads, attachments | Disambiguated from Instagram by schema, not filename |
| Viber, Discord | messages, participants | Runtime column resolution |
| Signal | registration metadata | Store is SQLCipher; identified, not decoded |
| Gmail | headers, snippets | States that full bodies remain server-side |
| Payment apps | UPI/wallet transactions | Amount, counterparty, direction, reference |
| Google Maps | searches, destinations | Distinguishes *intent to travel* from *recorded presence* |
| Android usagestats | foreground/interaction events | Places a person at the device |
| Android notifications | every posted notification | **Previews content from encrypted apps** |
| iOS KnowledgeC | app focus, lock, screen, Siri | Richest behavioural source on an iPhone |
| iOS PowerLog | app runtime | Independent corroboration of KnowledgeC |

Every parser resolves its tables and columns **at runtime** and records which
schema variant it matched. These apps ship fortnightly and rename columns
freely; a parser hard-coded to one version returns nothing against the next,
which reads as an empty chat rather than a broken parser.

### Two new cross-source finding rules

**`crosssource.notification_leak`** — the most valuable inference the tool
makes. Signal and Telegram keep their stores encrypted, so their content is
unavailable. But the OS writes a *preview* of each incoming message into its own
unencrypted notification store. Content unreadable in the app is therefore often
perfectly readable a few tables away. An examiner working app-by-app will not
see this: it requires noticing that one source is encrypted *and* that another
contains its content.

**`activity.device_in_use`** — foreground, screen and unlock telemetry. Message
records show what a handset sent; usage telemetry shows whether someone was
*holding it*. That distinction is what allows activity to be attributed to a
person rather than a phone, and it is usually the contested point.

### A real carver limitation, fixed properly

Telegram's deleted rows would not carve. Investigation showed why: when SQLite
frees a compact row it stamps four bytes over the start of the cell, which
erases the payload length, the rowid, the header length **and the first serial
type**. An exact-column parse can then never succeed, so the row looked
unrecoverable.

It was not. The remaining types and the whole body survive. **Partial-record
recovery** now parses `ncols - n` types and shifts the values right,
reconstructing every column except the destroyed leading one(s) — which are
reported as unknown and the record flagged `partial`.

The destroyed column is almost always the rowid alias, an integer of no
evidential interest, while the survivors hold the message text, the timestamp
and the correspondent. Refusing to report the row to protect a technicality
would have discarded the actual evidence. Result on the reference corpus:

```
Telegram deleted row recovered: "Burn the manifest once it is signed."
   origin=unallocated  PARTIAL(-1 column)  confidence=0.9
```

Validation confirmed no regression: still 18/18, recall 1.000, **zero spurious
records** — the more permissive pass did not buy recall with false positives.

---

## Beyond the roadmap (items 19–22)

Four capabilities that add investigative power rather than surface area.

### Perceptual image matching (`parsers/media/perceptual.py`)

SHA-256 answers *"is this the same file?"*. It cannot answer *"is this the same
photograph?"* — and in mobile forensics those are different questions. A picture
sent through WhatsApp, saved, screenshotted and forwarded becomes four files with
four unrelated digests, and a tool relying on cryptographic hashing alone treats
them as four unrelated pictures.

Three algorithms (aHash, dHash, and a DCT pHash written out rather than pulling
in SciPy), because each fails differently and agreement between them is what
earns confidence. Measured on identical source images:

| Transformation | dHash | aHash | pHash | Verdict |
|---|---|---|---|---|
| Recompressed q95 → q35 | 0 | 0 | 0 | identical |
| Resized to 50% | 2 | 2 | 0 | near-duplicate |
| Brightness +28 | 3 | 1 | 2 | near-duplicate |
| **A different photograph** | **52** | **47** | **38** | **no match** |

Hashes are computed at ingest and sealed into the container, so matching later
costs nothing and does not depend on re-reading a copy years afterwards. Images
below 16 px are refused rather than hashed — at that size a perceptual hash
carries no information and would match almost anything.

### Hash-set filtering (`core/hashsets.py`)

NSRL-style known-good suppression and known-bad flagging, accepting NSRL RDS CSV,
HashKeeper, plain digest lists and ARGUS JSON. Three decisions worth noting:

- **Known-bad always beats known-good.** A file appearing in both lists is
  flagged, never suppressed.
- **Matching is per algorithm.** A set of MD5s never appears to "not match"
  because the caller led with SHA-256.
- **Known-good is a filter, never a deletion.** Suppressed files remain in the
  container and in every export, and the count is reported. A system file that
  had been *modified* would not match and so would not be suppressed — which is
  the point.

Every set records where it came from and when it was loaded, because a hit
against an unattributed list proves nothing.

### Conversation reconstruction (`analyze/conversations.py`)

Every tool in this space presents messages as a flat table. That is the wrong
shape for the question an examiner actually asks. Threading produces turn-taking,
reply latency measured *across a direction change* (so a burst of consecutive
messages is not scored as instant replies), silences inside a thread, and — most
usefully — **where the deleted messages sit**. A deleted message between two
surviving ones is far more informative than the same message in isolation.

```
argus thread <container> --who "9555000111"

2026-06-25T17:56:49  9555000111: The customs officer has been paid.   [RECOVERED FROM DELETED SPACE]
2026-06-25T18:07:49  9555000111: Move the container tonight, not tomorrow.  [RECOVERED …]
2026-06-25T18:18:49  9555000111: Nobody can trace this handset to me.  [RECOVERED …]
2026-06-25T18:29:49  9555000111: Meet at the old jetty, 02:00, come alone.  [RECOVERED …]
2026-06-25T18:40:49  9555000111: I told you to stop putting this in writing.  [RECOVERED …]
```

Voice channels are excluded from "channel switching" — counting a phone call as
another messaging app made almost every contact look like channel-switching and
buried the handful of real cases.

### Event fusion and attribution (`intel/fusion.py`)

The capability that answers the question which actually decides contested cases:
**was somebody holding the handset when it happened?**

A message artifact cannot separate "the phone sent this" from "the owner sent
this". But the handset records — in stores entirely independent of the messaging
app — whether the screen was lit, whether it was unlocked, and which app was in
front. Fusing those gives each act an attribution verdict with named
corroboration:

```
2026-06-14T21:50:00  [attributed]  strength=0.98
  Are we still on for tomorrow?
    + usage    0.0s  KnowledgeC: WhatsApp in foreground (30s)
    + usage   -0.9s  PowerLog: WhatsApp running (20s)
    + lock    -5.0s  KnowledgeC: device unlocked
```

On the reference case: 90 attributed, 11 probable, 4 unattributed, **730
unknown**. That distribution is the important part. Most handsets retain usage
telemetry for days, not months, so most acts *cannot* be attributed — and the
module reports them as `unknown`, never as "not the owner". Conflating "we cannot
tell" with "it wasn't them" would be the single most dangerous error here, so a
low-coverage finding fires explicitly whenever coverage is under 15%.

Attribution is always to *a person at the device*, never to a named individual:
anyone holding the unlocked handset produces an identical record, and every
attributed event says so.

---

### Co-location — same place, *same time* (`intel/colocation.py`)

Shared-location correlation reported that two exhibits both recorded positions
in the same 1 km cell. It could not say *when*, and its own caveat told the
examiner to compare the timelines by hand. That comparison is now done:
positions are matched within 500 m and 15 minutes, merged into **encounters**,
and reported with when, where, how close, how many independent point pairs
supported them, and which record types placed each device there.

The analysis is defined as much by what it refuses. Three kinds of coordinate
look exactly like a position and are none:

| Coordinate | Why it is excluded |
|---|---|
| Maps searched destination | Intent to travel. Two people looking up the same address did not meet at it. |
| **Received** location message | The *sender's* position. Counting it makes every shared pin look like both parties stood there — precisely backwards. |
| Downloaded or forwarded photo | The original photographer's position. Only camera originals (in `DCIM`, carrying maker EXIF) place *this* handset. |

A fix whose stated accuracy is worse than the match radius is dropped rather
than matched loosely — a cell-tower fix good to 3 km cannot support a claim
about a 500 m meeting, and quietly widening the radius would turn the weakest
evidence into the most productive.

Encounters split on a gap in **either** time or space, so an hour of fixes
beside another handset is one encounter rather than twelve, and two meetings
ten minutes apart at different places are not merged into one meeting at a
centroid where neither device ever was. Confidence scales with tightness in
space and time, corroboration by several point pairs, and the weight of the
record type; a carved row weighs less than a live one.

Eight or more encounters across five or more days is reported as the handsets
**travelling together** — one person carrying both, or two people sharing a
home or vehicle — rather than as a series of meetings, because that is the
likelier explanation and calling it "meetings" would be wrong.

---

## Honest limitations

- Validation figures describe **this build on this platform** against a
  **synthetic** corpus. It reproduces documented schemas, not every version
  variant in a real caseload; recall against an unseen variant may be lower.
- Encrypted evidence is **identified, never decoded**. No decryption capability
  is claimed.
- Community detection describes graph structure, not intent. On a single
  handset the graph is hub-and-spoke and the tool now says "no community
  structure" rather than overclaiming.
- Cross-exhibit phone matching uses the last ten digits. Two different
  international numbers sharing those digits would collide.
- Factory-reset estimation can be confounded by an acquisition that normalises
  file timestamps. The finding says so.
- Blob-recovered text (Telegram, Snapchat) is extracted from undocumented
  serialisation formats. It is marked with its extraction method and carries a
  reduced confidence, because it is a strings sweep over a structure ARGUS does
  not fully parse rather than a clean column read.
- Partial records are missing their leading column(s) by construction. They are
  flagged `partial` with a count of unrecoverable columns.
- Notification previews are truncated copies written by the OS. They may be cut
  short, may show a display name rather than an account, and say nothing about
  what was sent in the other direction.
- Usage telemetry shows the device was operated, not *who* operated it.
- Perceptual matching identifies the same *image*, not the same *file*.
  Thumbnails, stock graphics, memes and app assets legitimately recur across
  unrelated devices.
- A reconstructed conversation is only as complete as the evidence. Where
  messages were destroyed rather than recovered the thread has holes that cannot
  be seen, so "no gap detected" is not "nothing was deleted".
- Fusion coverage on a real handset is typically low. The attributed subset must
  not be mistaken for the whole picture.
- A known-bad hash hit is only as strong as the provenance of the set.
- Co-location places *devices* together, never named people: whoever was
  carrying each handset produces an identical record. Device clocks drift
  and may sit in different zones, so a genuine meeting can be missed and a
  near miss can be matched. In a station or a shopping centre, being
  within 500 m is not being together. Finding no encounter is not evidence
  the devices were apart — location retention differs between handsets and
  is usually sparse.
