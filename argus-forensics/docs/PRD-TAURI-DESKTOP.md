# ARGUS Forensics — Product Requirements Document

## Tauri Desktop Migration (Windows Executable)

| Field | Value |
|-------|-------|
| **Document** | PRD-TAURI-DESKTOP v1.0 |
| **Product** | ARGUS Forensics Desktop |
| **Current version** | 1.0.0 (Python + localhost web workbench) |
| **Target platform (v1)** | Windows 10/11 x64 |
| **Target framework** | [Tauri 2.x](https://v2.tauri.app/) (Rust host + embedded WebView2) |
| **Parity requirement** | **100%** — every workflow, API, file format, and CLI capability preserved |
| **Status** | Draft for engineering kickoff |

---

## 1. Executive summary

ARGUS Forensics today is a **Python forensic engine** served over **localhost HTTP** and rendered in the user's default browser. Examiners launch it via `ARGUS.bat`, `Start ARGUS.vbs`, or `python argus_app.py`. The workbench (`workbench.html`), analyst (`analyst.html`), and legacy XAMN view (`xamn.html`) talk to **50+ REST endpoints** on port 8742.

This PRD defines migration to a **single Windows executable** built with **Rust + Tauri**, packaging:

- A native desktop shell (no external browser, no visible localhost URL)
- Embedded WebView2 UI (reuse existing HTML/CSS/JS with minimal changes)
- A **Python sidecar** for the forensic engine (phase 1 — fastest path to 100% parity)
- Native Windows integrations (folder dialogs, MTP, process spawning, single-instance, auto-update hooks)

**Strategic decision:** Reimplementing acquisition, carving, parsers, and reporting in Rust would take 12–24 months and risk subtle parity bugs. **Phase 1 bundles the proven Python engine as a managed sidecar.** Phase 2+ may port hot paths to Rust incrementally.

---

## 2. Goals

| ID | Goal |
|----|------|
| G1 | Ship **one double-click `.exe`** — no Python install, no browser tab, no port conflicts |
| G2 | **100% feature parity** with current workbench + CLI + all acquisition/analysis/report paths |
| G3 | **Byte-compatible** `.afc` containers, `case.json`, audit chains, and report outputs |
| G4 | Preserve **air-gap operability** — no CDN, no cloud dependency, offline-first |
| G5 | **Windows-native UX** — system tray, file associations, proper window chrome, MSI/NSIS installer |
| G6 | Maintain **court-defensible integrity** — selfcheck manifest, installation ID, tamper-evident logs |
| G7 | Keep **existing pytest suite** as acceptance gate (run against sidecar in CI) |

## 3. Non-goals (v1 desktop)

| ID | Non-goal |
|----|----------|
| NG1 | Rewriting parsers/acquisition in Rust (deferred to phase 2+) |
| NG2 | macOS/Linux Tauri builds (Windows first; share Rust shell later) |
| NG3 | Cloud case sync, multi-user server, or web SaaS deployment |
| NG4 | Changing the `.afc` on-disk format or AQL query language |
| NG5 | Removing or deprecating the CLI (`argus.exe` wrapper still supported) |

---

## 4. Current state architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Examiner                                                    │
│    ARGUS.bat / Start ARGUS.vbs / python argus_app.py        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Python ThreadingHTTPServer (127.0.0.1:8742)                │
│    argus/server/workbench.py                                │
│    • Token auth (session token in URL hash)                 │
│    • 50+ GET/POST /api/* routes                             │
│    • /blob/{sha256} content serving                         │
│    • JobRunner (daemon threads, resumable logs)             │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  Static UI (no build)     │    │  Python forensic engine      │
│  workbench.html          │    │  acquire · parsers · analyze │
│  analyst.html (iframe)   │    │  intel · report · validate   │
│  xamn.html               │    │  devices · core (.afc)       │
└──────────────────────────┘    └─────────────────────────────┘
                                           │
                                           ▼
                              ┌─────────────────────────────┐
                              │  External tools (spawned)    │
                              │  adb · idevice* · ewfexport  │
                              │  affconvert · PowerShell/MTP │
                              └─────────────────────────────┘
```

### 4.1 Entry points today

| Entry | Path | Must remain |
|-------|------|-------------|
| GUI | `argus_app.py` → `workbench.serve()` | Replaced by Tauri `main.rs` |
| CLI | `argus` (30+ subcommands) | `argus-cli.exe` or `argus.exe --cli` |
| Windows launchers | `ARGUS.bat`, `Start ARGUS.vbs` | Replaced by `ARGUS Forensics.exe` shortcut |

### 4.2 Evidence formats (immutable contract)

```
Case/
  case.json
  audit.jsonl          # hash-chained custody
  exhibits/<EXH-ID>/
    EXH-001_20260729T110402.afc/
      manifest.json
      artifacts.db     # SQLite
      audit.jsonl
      extraction.log.jsonl
      blobs/ab/cd/<sha256>
      raw/
```

**Requirement:** Desktop app must read/write containers produced by CLI/web and vice versa.

---

## 5. Target state architecture

```
┌─────────────────────────────────────────────────────────────┐
│  ARGUS Forensics.exe (Tauri 2 + Rust)                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  WebView2 — workbench.html / analyst.html / xamn.html │  │
│  │  (existing JS, adapted fetch → Tauri IPC optional)    │  │
│  └───────────────────────┬───────────────────────────────┘  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  Rust shell layer                                      │  │
│  │  • Window/tray/menus                                   │  │
│  │  • Native folder/file dialogs                          │  │
│  │  • Sidecar lifecycle (start/stop/health/restart)       │  │
│  │  • Optional: reverse proxy localhost → tauri://        │  │
│  │  • Single-instance lock                                │  │
│  │  • Logging (examiner-safe, no evidence in logs)        │  │
│  │  • Update channel (future)                             │  │
│  └───────────────────────┬───────────────────────────────┘  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  Python sidecar (embedded, PyOxidizer or embeddable   │  │
│  │  python + argus package)                               │  │
│  │  argus-sidecar.exe → workbench.serve(127.0.0.1:dynamic)│  │
│  └───────────────────────┬───────────────────────────────┘  │
└──────────────────────────┼──────────────────────────────────┘
                           ▼
              External: adb, idevice*, PowerShell, ewfexport…
```

### 5.1 Recommended integration pattern (Phase 1)

**Option A — Localhost proxy (lowest risk, fastest):**

1. Tauri starts embedded Python sidecar on **ephemeral port** (not fixed 8742).
2. Rust injects `token` + `port` into WebView via `window.__ARGUS__` bootstrap.
3. Existing `fetch("/api/...")` continues unchanged (Tauri allows localhost).
4. No rewrites to 50+ API handlers in v1.

**Option B — Tauri commands (phase 2):**

Gradually replace HTTP with `invoke()` for hot paths (browse, job poll, env). Keep sidecar for long jobs.

**Decision for v1:** **Option A** — mandatory for 100% parity on schedule.

### 5.2 Repository layout (proposed)

```
argus-forensics/
  argus/                    # unchanged Python engine
  argus_app.py              # sidecar entry (also used standalone)
  src-tauri/
    Cargo.toml
    tauri.conf.json
    src/
      main.rs               # Tauri bootstrap
      sidecar.rs            # spawn/monitor Python
      proxy.rs              # optional port discovery
      dialogs.rs            # native path picker
    icons/
  ui/                       # moved from argus/ui/ (or symlink)
    workbench.html
    analyst.html
    xamn.html
  docs/
    PRD-TAURI-DESKTOP.md    # this document
  scripts/
    bundle-python.ps1       # embed CPython + argus into resources
```

---

## 6. Feature parity matrix (100%)

Every row is **MUST** for v1 release unless marked *Phase 2*.

### 6.1 Workbench workflow (8 steps)

| Step | Feature | Current | Desktop requirement |
|------|---------|---------|---------------------|
| 1 | Create/open case, password protection | ✓ | Native folder picker for case dir |
| 2 | Case overview, health, activity, jobs | ✓ | Same API |
| 3 | Register exhibit, isolation warnings | ✓ | Same |
| 4 | Device scan (adb/iOS/MTP), deep scan, auto-scan | ✓ | USB permissions; MTP via PS |
| 4 | Device manual search + capability matrix | ✓ | Same |
| 4 | USB watch (2 min), diagnose | ✓ | Same |
| 4 | Batch extract selected / all connected | ✓ | Same |
| 5 | Extraction methods: import, logical, filesystem, backup, comprehensive, mtp, turbo | ✓ | Same |
| 5 | Pre-flight preview (`acquire/preview`) | ✓ | Same |
| 5 | Live job log, progress, ETA, phases, cancel | ✓ | Poll `/api/job`; reconnect on focus |
| 5 | Resume incomplete extraction | ✓ | Same |
| 5 | Import classifier (UFDR, XRY, folder, .ab, iOS backup) | ✓ | Native browse |
| 6 | Analyse (iframe → analyst.html) | ✓ | Embed in WebView or navigate |
| 7 | Findings, entities, correlation, hash-set screening | ✓ | Same |
| 8 | Report HTML/PDF/XLSX/DOCX/XML/JSON/CSV | ✓ | Optional deps bundled |
| 8 | Validation harness, certificate, court bundle | ✓ | Same |

### 6.2 Analysis UI (`analyst.html`)

| Feature | Requirement |
|---------|-------------|
| AQL search, facets, saved query state | ✓ |
| Overview, Messages, Calls, Contacts, Conversations | ✓ |
| Gallery, Connections graph, Timeline + scrubber | ✓ |
| Places / map clusters, Deleted view | ✓ |
| Fusion, Media matching, Entities, Apps, Analytics | ✓ |
| Extraction log, Integrity, Audit | ✓ |
| Artifact detail pane, blob inline display | ✓ `/blob/` |
| Tagging (`POST /api/tag`) | ✓ |

### 6.3 CLI parity (`argus` — 30+ commands)

| Command group | Desktop delivery |
|---------------|------------------|
| `case`, `exhibit`, `acquire`, `acquire-batch` | `argus.exe` CLI subcommand OR bundled `argus-cli.exe` |
| `analyze`, `query`, `report`, `intel`, … | Same |
| `mtp`, `devices`, `diagnose`, `watch` | Same |
| `selfcheck`, `validate`, `certificate` | Same |

**Requirement:** CLI must work when invoked from `cmd.exe` beside the installed app (for lab automation).

### 6.4 Acquisition engine

| Method | Modules | Windows notes |
|--------|---------|---------------|
| logical | `android_adb.py` | Requires `adb` on PATH or well-known paths |
| filesystem | `android_adb.py` | Parallel pulls, turbo mode |
| comprehensive | `engine.py` + `android_apps.py` | Multi-pass |
| backup | `android_backup.py`, `ios_backup.py` | Optional pycryptodome |
| import | `adapters.py`, `msab.py`, `opaque.py`, `e01.py`, `aff.py` | Path-based |
| mtp | `mtp.py` | **Windows only** — PowerShell + Shell.Application |
| batch | `batch.py` | Serial queue, retry failed |

### 6.5 External dependencies

| Tool | Required for | Bundle strategy |
|------|--------------|-----------------|
| **WebView2** | UI | Tauri prerequisite (Evergreen runtime or fixed) |
| **Embedded Python 3.10+** | Engine | Ship in `resources/python/` |
| **adb** | Android | Do not bundle (license/size); discover + installer hint |
| **libimobiledevice** | iOS | Same |
| **ewfexport / affconvert** | E01/AFF import | Optional; detect at runtime |
| **PowerShell 5.1+** | MTP, USB bus | Present on Windows 10+ |

### 6.6 Non-functional requirements

| NFR | Target |
|-----|--------|
| Cold start | < 8 s to workbench on typical lab PC (SSD, 16 GB RAM) |
| Sidecar health | Auto-restart on crash; examiner sees toast, not silent failure |
| Single instance | Second launch focuses existing window |
| Memory | Sidecar + WebView < 1 GB idle; acquisition bounded by device |
| Disk | Install size ≤ 250 MB (Python embed + UI + Rust); evidence external |
| Logging | `%LOCALAPPDATA%\ARGUS\logs\` — no artifact bodies |
| Uninstall | MSI removes app; never deletes case workspace |
| Security | localhost only; token per session; CSP in WebView |
| Offline | Zero network calls in core path |

---

## 7. Tauri / Rust component specification

### 7.1 `main.rs` responsibilities

- Initialize Tauri 2 app with single main window (1280×800 min).
- Load `workbench.html` from bundled assets (`tauri://localhost` or `dist/`).
- On `setup`:
  1. Resolve workspace dir (`%USERPROFILE%\ARGUS` or last-used from registry).
  2. Start Python sidecar with `--port 0 --token <uuid> --workspace <path>`.
  3. Wait for `/api/ping` (timeout 30 s, splash screen).
  4. Inject bootstrap: `{ token, port, version, build }`.
- Register window events: close → graceful sidecar shutdown (30 s acquire warning).
- System tray: Show / Hide, Open workspace folder, Exit.

### 7.2 `sidecar.rs`

```rust
// Pseudocode contract
struct SidecarConfig {
    python_exe: PathBuf,      // resources/python/python.exe
    script: PathBuf,          // resources/argus_sidecar.py
    workspace: PathBuf,
    port: u16,                // 0 = ephemeral
    token: String,
}

async fn start(config) -> Result<SidecarHandle>;
async fn health(handle) -> bool;  // GET /api/ping
async fn stop(handle, graceful: bool);
```

Sidecar entry script wraps `argus.server.workbench.serve()` with CLI args (no browser open).

### 7.3 Native dialogs (`tauri-plugin-dialog`)

Replace JS modal folder browser for:

- Case save location
- Import source picker (files + folders)
- Report output directory
- Hash-set file picker

Keep server `browse` API as fallback for power users.

### 7.4 Shell permissions (`tauri-plugin-shell`)

Allow spawn (sidecar only in v1):

- `adb`, `idevice_id`, `ideviceinfo`, `idevicebackup2`
- `powershell.exe` (MTP scripts)
- `ewfexport`, `affconvert` if on PATH

**Scope:** Sidecar runs child processes; Tauri shell plugin is backup for Rust-native tooling later.

### 7.5 File associations (Windows)

| Extension | Action |
|-----------|--------|
| `.afc` | Open in ARGUS (analysis mode, container path) |
| `.argus-case` (optional alias) | Open case folder |

### 7.6 Installer

- **NSIS** or **WiX MSI** via `tauri build`
- Install to `Program Files\ARGUS Forensics\`
- Desktop + Start Menu shortcuts
- Optional: bundle WebView2 bootstrapper
- Code signing (production requirement — certificate TBD)

---

## 8. Frontend migration plan

### 8.1 Minimal changes (Phase 1)

| Change | File | Detail |
|--------|------|--------|
| Bootstrap | `workbench.html` | Read `window.__ARGUS__` for token/port instead of URL hash only |
| API base | `api()` helper | `const BASE = __ARGUS__.apiBase \|\| ""` |
| Remove browser assumptions | all UIs | Drop "open in browser" messaging |
| iframe | workbench → analyst | Works in WebView2; test CSP |
| Deep links | — | `argus://open?case=...` → Rust command → load case |

### 8.2 Token auth migration

**Current:** Token in `sessionStorage` + URL hash from launcher.

**Desktop:**

1. Rust generates UUID token per app session.
2. Injected before any UI script runs.
3. Sidecar validates same token (unchanged server code).
4. No token in disk or registry.

### 8.3 Progress / jobs

No change — polling `GET /api/job?id=&since=` remains. Tauri `onWindowFocus` triggers catch-up poll (already implemented in JS).

---

## 9. Python bundling strategy

### 9.1 Options evaluated

| Approach | Pros | Cons |
|----------|------|------|
| **Embeddable Python zip** | Simple, debuggable | ~30 MB |
| **PyOxidizer / PyInstaller onefile** | Single artifact | Harder to patch argus package |
| **Require system Python** | Small installer | Violates G1 |

**Recommendation:** **Embeddable CPython 3.12** + copy `argus/` package into `resources/site-packages/`. Sidecar script sets `PYTHONPATH`.

### 9.2 Optional dependencies

Bundle in installer "full" profile:

```
pillow, openpyxl, python-docx, reportlab, pycryptodome
```

Or lazy-download optional pack (air-gap: ship full MSI only).

### 9.3 Build pipeline

```powershell
# scripts/build-desktop.ps1 (proposed)
1. python tools/build_release.py          # stage argus
2. Download/embed CPython embeddable
3. pip install -e . --target resources/site-packages
4. cargo tauri build --target x86_64-pc-windows-msvc
5. Run pytest against installed sidecar
6. Sign ARGUS_Forensics_x64.msi
```

---

## 10. API inventory (must remain callable)

Full list for regression tests. Sidecar exposes identical routes.

### GET `/api/*`

`env`, `browse`, `classify`, `diagnose`, `devices`, `watch`, `hashsets`, `manual/search`, `manual/show`, `cases`, `case`, `case/summary`, `case/activity`, `case/incomplete`, `containers`, `job`, `jobs`, `verify`, `overview`, `search`, `artifact`, `gallery`, `connections`, `applications`, `application`, `column`, `timeline`, `statistics`, `places`, `places/clusters`, `timeline/buckets`, `analytics`, `intel`, `findings`, `entities`, `communities`, `facets`, `deleted`, `log`, `audit`, `integrity`, `intelligence`, `conversations`, `fusion`, `media_matching`

### POST `/api/*`

`case/new`, `case/close`, `exhibit/add`, `acquire`, `acquire/preview`, `acquire/batch`, `validate`, `certificate`, `bundle`, `hashset/load`, `job/cancel`, `report`, `tag`

### Static

`/`, `/workbench.html`, `/analyst.html`, `/xamn.html`, `/blob/{sha256}`, `/api/ping`

---

## 11. Testing & acceptance criteria

### 11.1 Automated

| Suite | Gate |
|-------|------|
| `tests/test_argus.py` (400+ tests) | 100% pass against bundled sidecar |
| `tests/test_mtp.py` | Pass on Windows CI agent |
| `tests/test_batch.py`, `tests/test_progress.py` | Pass |
| New: `tests/test_tauri_sidecar.py` | Port discovery, token auth, ping |
| New: `tests/e2e/desktop_smoke.ps1` | Launch exe, create case, import sample, analyse |

### 11.2 Manual acceptance (examiner script)

1. Install MSI on clean Windows 11 VM.
2. Connect Android handset → scan → comprehensive extract → seal container.
3. Connect MTP-only device (no USB debugging) → MTP extract with live progress.
4. Run findings + generate PDF report + court bundle.
5. Verify container opens in CLI `argus verify` on second machine.
6. Kill app mid-extraction → resume incomplete.
7. `argus selfcheck` shows installation ID matching MSI build.

### 11.3 Parity sign-off

Product owner signs checklist in **Appendix A** (all rows green).

---

## 12. Phased delivery plan

### Phase 0 — Foundation (2–3 weeks)

- [ ] `src-tauri/` scaffold, WebView loads `workbench.html`
- [ ] Sidecar spawn + health check + ephemeral port
- [ ] Token injection bootstrap
- [ ] Dev workflow: `cargo tauri dev` + live Python

### Phase 1 — MVP desktop (4–6 weeks)

- [ ] Embedded Python bundling script
- [ ] All 3 HTML surfaces load and function
- [ ] Native folder dialogs for case/import/report
- [ ] Single-instance + tray
- [ ] Graceful shutdown with active job warning
- [ ] MSI installer (unsigned dev builds)
- [ ] pytest CI against sidecar

### Phase 2 — Production hardening (3–4 weeks)

- [ ] Code signing
- [ ] WebView2 bootstrapper / minimum runtime check
- [ ] `.afc` file association
- [ ] CLI wrapper `argus.exe` in install dir
- [ ] Crash telemetry (local only, opt-in)
- [ ] Update mechanism design (offline MSI updates)

### Phase 3 — Optimization (ongoing)

- [ ] Replace `browse` with Rust native dialog only
- [ ] Tauri events for job progress (reduce polling)
- [ ] Port MTP orchestration to Rust (retain PS scripts)
- [ ] Optional: Rust parser for hot SQLite paths

---

## 13. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Python embed size | Large installer | Compress; optional slim build without office deps |
| WebView2 missing | App won't start | Pre-install check + link to Evergreen |
| MTP COM failures in sidecar | Android MTP broken | Same PS scripts; test on Win10/11 |
| Port conflict | Rare with ephemeral | Always port 0 |
| Long path / spaces in workspace | Import fails | Document + test `D:\Cases` |
| Antivirus false positive | MSI blocked | Code signing; submit to AV vendors |
| Sidecar zombie on crash | Port leak | Parent watchdog; kill tree on exit |
| iframe CSP in WebView2 | Analyse broken | Tauri CSP config per docs |

---

## 14. Open questions

| # | Question | Owner | Default if unresolved |
|---|----------|-------|------------------------|
| 1 | Bundle adb platform-tools in installer? | Product | No — link to install guide |
| 2 | MSI vs portable ZIP for air-gap labs? | Product | Both |
| 3 | Code signing certificate provider? | Legal/IT | Deferred to Phase 2 |
| 4 | App name in shell: "ARGUS Forensics" vs "ARGUS"? | Product | ARGUS Forensics |
| 5 | Auto-update via Tauri updater? | Product | No in v1 |
| 6 | Migrate UI to React/Svelte later? | Engineering | No — keep vanilla HTML v1 |

---

## 15. Success metrics

| Metric | Target |
|--------|--------|
| Feature parity | 100% Appendix A checklist |
| Test pass rate | 100% existing pytest on release branch |
| Examiner install steps | 1 (double-click MSI) |
| Support tickets: "Python not found" | 0 |
| Container interoperability | CLI ↔ Desktop round-trip verified |
| Cold start P95 | < 10 s |

---

## Appendix A — Parity checklist (sign-off)

### Workflow
- [ ] Case create/open/close/password
- [ ] Exhibit register + warnings
- [ ] Device scan/deep/auto/batch
- [ ] Manual search + capability matrix
- [ ] USB watch + diagnose
- [ ] All 7 extraction methods + preview + resume
- [ ] Live progress (phases, ETA, bytes, cancel)
- [ ] Analyse all views
- [ ] Findings + hash sets
- [ ] All report formats + bundle + certificate + validate

### CLI
- [ ] All 30+ subcommands operational from install dir

### Formats
- [ ] `.afc` seal/verify/deep-verify
- [ ] Audit chain verify
- [ ] MSAB/XRY/UFDR import
- [ ] E01/AFF import (when tools present)

### Windows
- [ ] MTP full copy + reconciliation
- [ ] adb/iOS detection paths
- [ ] Drive-root folder picker (A:–Z:)

---

## Appendix B — `tauri.conf.json` sketch

```json
{
  "productName": "ARGUS Forensics",
  "version": "1.1.0",
  "identifier": "forensics.argus.desktop",
  "build": {
    "frontendDist": "../argus/ui",
    "devUrl": "http://localhost:8742"
  },
  "app": {
    "windows": [{
      "title": "ARGUS Forensics",
      "width": 1400,
      "height": 900,
      "minWidth": 1024,
      "minHeight": 700
    }],
    "security": {
      "csp": "default-src 'self'; connect-src 'self' http://127.0.0.1:* ipc:; img-src 'self' blob: http://127.0.0.1:*; style-src 'self' 'unsafe-inline'"
    }
  },
  "bundle": {
    "targets": ["msi", "nsis"],
    "resources": ["resources/python/**", "resources/argus/**"],
    "windows": {
      "webviewInstallMode": { "type": "downloadBootstrapper" }
    }
  }
}
```

---

## Appendix C — Sidecar CLI contract

```text
argus-sidecar.exe \
  --workspace "%USERPROFILE%\ARGUS" \
  --port 0 \
  --token "<uuid>" \
  --no-browser \
  --quiet
```

Stdout (JSON line when ready):

```json
{"event":"ready","port":49152,"token":"<uuid>","version":"1.1.0","build":"<installation_id>"}
```

---

*End of PRD — ARGUS Forensics Tauri Desktop v1.0*
