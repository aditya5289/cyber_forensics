"""Acquisition engine — the orchestrator for lab manual §5.5 – §5.9.

Runs the whole XRY-side workflow as one auditable transaction:

    Step 8  choose extraction action, gated by the device capability matrix
    Step 9  apply the time span
    Step 10 apply the artifact category filter
    Step 11 record operator and exhibit details
    Step 12 execute, emitting a live module/status/timestamp/message log
    Step 13 seal the container and report completion status

Design rule: **the engine never throws away a partial extraction.**  If a
module fails halfway, whatever was already acquired stays in the container and
the failure is recorded in the log and the manifest.  Discarding partial
evidence because of a late error would be the single worst behaviour a tool
like this could have.
"""

from __future__ import annotations

import shutil
import tempfile
import time
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..core.case import Case
from ..core.container import EvidenceContainer, ExtractionMeta
from ..core.errors import AcquisitionError, DeviceNotSupportedError
from ..core.models import Category
from ..devices.detect import DetectedDevice, require_device
from ..devices.manual import DeviceManual
from ..parsers.registry import ParseContext, dispatch, load_all
from ..parsers.timestamps import span_to_range
from . import android_adb, android_backup, ios_backup
from .filesystem import ingest_tree
from .progress import ProgressMeter

ALL_CATEGORIES = [c.value for c in Category]


@dataclass
class AcquisitionPlan:
    """Everything Steps 8–11 collect, in one reviewable object."""

    method: str = "logical"                 # logical|filesystem|backup|import|comprehensive|mtp
    time_span: str = "all"                  # Step 9
    categories: List[str] = field(default_factory=lambda: list(ALL_CATEGORIES))
    operator: str = ""                      # Step 11
    exhibit_id: str = ""
    lock_state: str = "unlocked"
    device_name: str = ""
    serial: Optional[str] = None
    source_path: Optional[Path] = None      # for import/backup methods
    backup_password: Optional[str] = None
    whatsapp_recovery_key: Optional[str] = None
    whatsapp_passphrase: Optional[str] = None
    recover_deleted: bool = True
    carve_confidence: float = 0.45
    owner_identifiers: List[str] = field(default_factory=list)
    owner_name: str = "Device owner"
    notes: str = ""
    keep_raw: bool = True
    resume: bool = False
    resume_container: Optional[str] = None
    turbo: bool = False
    verify_pulls: bool = True
    parallel_pulls: int = 1
    skip_app_discovery: bool = False
    skip_device_report: bool = False
    skip_perceptual_hash: bool = False
    skip_blob_store: bool = False
    skip_content_sniff: bool = False
    ingest_workers: Optional[int] = None
    fast_seal: bool = False

    def validate(self) -> None:
        if not self.operator:
            raise AcquisitionError(
                "Operator name is required (manual Step 11 — chain of custody)")
        if not self.exhibit_id:
            raise AcquisitionError("Exhibit ID is required (manual Step 11)")
        bad = [c for c in self.categories if c not in ALL_CATEGORIES]
        if bad:
            raise AcquisitionError(
                f"unknown categories {bad}; valid: {ALL_CATEGORIES}")
        span_to_range(self.time_span)       # raises on malformed span


@dataclass
class AcquisitionReport:
    container: str = ""
    method: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    files_acquired: int = 0
    bytes_acquired: int = 0
    artifacts: int = 0
    deleted_recovered: int = 0
    categories: Dict[str, int] = field(default_factory=dict)
    applications: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    integrity_failures: List[str] = field(default_factory=list)
    status: str = "Completed"
    seal: Dict[str, Any] = field(default_factory=dict)
    export_zip: str = ""
    files_seen: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    decode_coverage_pct: float = 0.0
    decode_by_parser: Dict[str, int] = field(default_factory=dict)
    audit_warnings: List[Dict[str, Any]] = field(default_factory=list)
    acquisition_summary: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


from ..core.resume import INCOMPLETE_MARKER, find_incomplete, open_for_resume


def apply_performance_settings(plan: AcquisitionPlan) -> None:
    """Baseline parallelism applied to every extraction."""
    import os
    cpu = os.cpu_count() or 4
    if plan.ingest_workers is None:
        plan.ingest_workers = max(8, min(24, cpu * 2))
    plan.parallel_pulls = max(plan.parallel_pulls, min(16, cpu * 2))


def apply_turbo_settings(plan: AcquisitionPlan) -> None:
    """Apply the fastest-safe extraction preset.

    Turbo trades forensic depth for speed: parallel pulls, no per-file hash
    verification during transfer, no deleted-record carving, no perceptual
    hashing, and no blob duplication into the container.  MTP and ADB paths
    each have dedicated fast lanes inside their modules.
    """
    if plan.method == "turbo":
        plan.turbo = True
    if not plan.turbo:
        return
    import os
    cpu = os.cpu_count() or 4
    if plan.method in ("comprehensive", "turbo"):
        plan.method = "filesystem"
    # mtp keeps method=mtp — turbo only disables hashing and enables fast copy
    plan.recover_deleted = False
    plan.verify_pulls = False
    plan.skip_app_discovery = True
    plan.skip_device_report = True
    plan.skip_perceptual_hash = True
    plan.skip_blob_store = True
    plan.skip_content_sniff = True
    plan.fast_seal = True
    plan.parallel_pulls = max(plan.parallel_pulls, min(24, cpu * 3))
    if plan.ingest_workers is None:
        plan.ingest_workers = max(12, min(32, cpu * 3))
    else:
        plan.ingest_workers = max(plan.ingest_workers, max(12, min(32, cpu * 3)))


def _write_incomplete(container: EvidenceContainer, plan: AcquisitionPlan,
                      device: Optional[DetectedDevice]) -> None:
    if plan.method == "import":
        return
    payload = {
        "format": "argus-incomplete/1",
        "exhibit_id": plan.exhibit_id,
        "method": plan.method,
        "operator": plan.operator,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "device": device.name if device else plan.device_name,
        "serial": device.serial if device else (plan.serial or ""),
        "warning": ("This acquisition has NOT completed. The container is not "
                    "an exhibit. Re-run extraction for this exhibit to resume; "
                    "this file is removed only when acquisition finishes cleanly."),
    }
    target = container.path / INCOMPLETE_MARKER
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _clear_incomplete(container: EvidenceContainer) -> None:
    target = container.path / INCOMPLETE_MARKER
    if target.exists():
        target.unlink()


class AcquisitionEngine:
    """Execute an :class:`AcquisitionPlan` against a case."""

    def __init__(self, case: Case, manual: Optional[DeviceManual] = None,
                 progress: Optional[Callable[[Dict[str, Any]], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.case = case
        self.manual = manual or DeviceManual()
        self.progress = progress
        self.cancel_check = cancel_check
        self._meter: Optional[ProgressMeter] = None
        self._monitor: Optional[Any] = None
        load_all()

    def _check_cancelled(self, container: EvidenceContainer,
                         stage: str) -> None:
        if self.cancel_check and self.cancel_check():
            self._log(container, "engine", "cancelled",
                      f"Extraction cancelled by operator during {stage}",
                      level="warning")
            raise AcquisitionError("Extraction cancelled by operator")

    # ------------------------------------------------------------------ Step 8
    def check_support(self, plan: AcquisitionPlan) -> Dict[str, Any]:
        """Gate the extraction against the device manual before touching data."""
        from .ios_live import looks_like_apple
        if looks_like_apple(plan.device_name):
            return {
                "method": "backup",
                "label": "iOS logical backup",
                "risk": "low",
                "note": ("Apple device — logical backup / Camera Roll copy. "
                         "Keep the handset unlocked and trusted."),
            }
        if plan.method == "comprehensive":
            for method in ("logical", "filesystem"):
                try:
                    cap = self.manual.assert_supported(
                        plan.device_name, plan.lock_state, method)
                    out = cap.as_dict()
                    out["method"] = "comprehensive"
                    out["label"] = "Comprehensive (god-level)"
                    out["note"] = (
                        "4-pass acquisition: logical query, app DB discovery, "
                        "filesystem pull, dumpsys & Vivo/BBK backup exports.")
                    return out
                except DeviceNotSupportedError:
                    continue
            raise DeviceNotSupportedError(
                f"{plan.device_name} does not support comprehensive extraction "
                f"in lock state '{plan.lock_state}' — neither logical nor "
                "filesystem is available")
        if plan.method == "mtp":
            mtp_tail = " MTP copies shared storage only — not /data/data."
            if not plan.device_name.strip():
                return {"method": "mtp", "label": "MTP (file transfer)",
                        "note": "Device not verified against manual." + mtp_tail}
            try:
                cap = self.manual.assert_supported(
                    plan.device_name, plan.lock_state, "logical")
                note = cap.as_dict()
            except DeviceNotSupportedError:
                note = {
                    "method": "mtp",
                    "label": "MTP (file transfer)",
                    "note": (f"'{plan.device_name}' is not in the device "
                             "manual — MTP will still copy shared storage; "
                             "verify the handset manually (manual §7)."),
                }
            note["note"] = (note.get("note") or "") + mtp_tail
            return note
        method = "filesystem" if plan.method == "turbo" else plan.method
        cap = self.manual.assert_supported(
            plan.device_name, plan.lock_state, method)
        return cap.as_dict()

    # ------------------------------------------------------------------- run
    def run(self, plan: AcquisitionPlan,
            device: Optional[DetectedDevice] = None) -> AcquisitionReport:
        plan.validate()
        apply_performance_settings(plan)
        apply_turbo_settings(plan)

        if (plan.method == "import" and plan.source_path
                and self._is_argus_container_import(plan.source_path)):
            return self._import_existing_container(plan)

        self._meter = ProgressMeter()
        started = time.time()
        report = AcquisitionReport(
            method=plan.method,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

        # The capability matrix gates *device* actions only. An import replays
        # bytes that were already lawfully acquired, so there is no device to
        # damage and nothing to gate — but the device is still recorded so the
        # container states what the evidence came from.
        capability: Dict[str, Any] = {}
        if plan.device_name and plan.method != "import":
            try:
                capability = self.check_support(plan)
            except DeviceNotSupportedError as exc:
                raise AcquisitionError(
                    f"Refusing to start: {exc} "
                    f"(manual §7 precaution 1 — verify device support first)"
                ) from exc

        meta = ExtractionMeta(
            exhibit_id=plan.exhibit_id, operator=plan.operator,
            method=plan.method, time_span=plan.time_span,
            categories=list(plan.categories),
            lock_state=plan.lock_state,
            started_at=report.started_at, notes=plan.notes,
            tool_version=_version(),
        )
        if device:
            meta.device_make = device.make
            meta.device_model = device.marketing_name or device.model
            meta.device_os = f"{device.os_family} {device.os_version}".strip()
            meta.device_serial = device.serial
            meta.imei = device.imei
            meta.iccid = device.iccid
            meta.phone_number = device.phone_number
        elif plan.device_name:
            parts = plan.device_name.split(" ", 1)
            meta.device_make = parts[0]
            meta.device_model = parts[1] if len(parts) > 1 else ""

        container: EvidenceContainer
        resumed = False
        resume_path = plan.resume_container
        if plan.method != "import":
            if not resume_path and plan.resume:
                hits = find_incomplete(self.case, plan.exhibit_id, plan.method)
                if hits:
                    resume_path = hits[0]["path"]
            if resume_path:
                container = open_for_resume(self.case, resume_path,
                                            operator=plan.operator)
                report.container = str(container.path)
                resumed = True
                self._log(container, "engine", "resume",
                          f"Resuming incomplete extraction in "
                          f"{container.path.name} — partial data is preserved")
                from ..core.custody import append_entry as field_custody
                field_custody(container.path, "extraction.resume", {
                    "method": plan.method,
                    "operator": plan.operator,
                }, operator=plan.operator)
            else:
                container = self.case.new_container(plan.exhibit_id, meta,
                                                    label=plan.method)
                report.container = str(container.path)
                from ..core.custody import append_entry as field_custody
                _write_incomplete(container, plan, device)
                field_custody(container.path, "extraction.start", {
                    "exhibit_id": plan.exhibit_id,
                    "method": plan.method,
                    "operator": plan.operator,
                    "device": device.name if device else plan.device_name,
                }, operator=plan.operator)
        else:
            container = self.case.new_container(plan.exhibit_id, meta,
                                                label=plan.method)
            report.container = str(container.path)

        self._log(container, "engine", "start",
                  f"Extraction started — method={plan.method}"
                  f"{' (turbo)' if plan.turbo else ''}, "
                  f"span={plan.time_span}, "
                  f"categories={len(plan.categories)}/{len(ALL_CATEGORIES)}",
                  phase="prepare")
        if plan.categories and len(plan.categories) < len(ALL_CATEGORIES):
            preview = ", ".join(plan.categories[:8])
            if len(plan.categories) > 8:
                preview += f" (+{len(plan.categories) - 8} more)"
            self._log(container, "engine", "note",
                      f"Targeting data types: {preview}")
        if capability:
            self._log(container, "device.manual", "ok",
                      f"Capability confirmed: {capability.get('label')} "
                      f"({capability.get('risk')} risk)"
                      + (f" — {capability['note']}" if capability.get("note") else ""))

        staging = Path(tempfile.mkdtemp(prefix="argus-acq-"))
        monitor_serial = device.serial if device else (plan.serial or "")
        if monitor_serial and plan.method not in ("import", "mtp"):
            from .monitor import ExtractionMonitor
            self._monitor = ExtractionMonitor(
                monitor_serial, log=lambda *a, **k: self._log(container, *a, **k),
                cancel_check=self.cancel_check)
            self._monitor.start()
        try:
            self._check_cancelled(container, "prepare")
            raw_root = self._acquire(plan, container, staging, device, report,
                                     resumed=resumed)
            self._check_cancelled(container, "acquire")
            from .summary import build_acquisition_summary, write_acquisition_summary
            write_acquisition_summary(raw_root, method=plan.method)
            report.acquisition_summary = build_acquisition_summary(
                raw_root, method=plan.method)
            container.update_extraction(acquisition_summary=report.acquisition_summary)
            if report.acquisition_summary.get("comms_row_total"):
                self._log(container, "engine", "ok",
                          f"Communications acquired — "
                          f"{report.acquisition_summary['comms_row_total']:,} "
                          f"provider row(s) across "
                          f"{len(report.acquisition_summary.get('comms_providers') or [])} "
                          f"source(s)")
            from .preprocess import preprocess_raw_tree
            preprocess = preprocess_raw_tree(
                raw_root, log=lambda *a, **k: self._log(container, *a, **k),
                whatsapp_recovery_key=plan.whatsapp_recovery_key or "",
                whatsapp_passphrase=(plan.whatsapp_passphrase
                                     or plan.backup_password or ""))
            container.update_extraction(preprocess_summary=preprocess)
            self._decode(plan, container, raw_root, report, resumed=resumed)
        except AcquisitionError as exc:
            report.status = "Failed"
            report.warnings.append(str(exc))
            self._log(container, "engine", "error", str(exc), level="error")
        except Exception as exc:                              # pragma: no cover
            report.status = "Failed"
            report.warnings.append(f"unexpected error: {exc}")
            self._log(container, "engine", "error", f"unexpected: {exc}",
                      level="error")
        finally:
            stats = container.refresh_statistics()
            report.artifacts = int(stats.get("artifacts", 0))
            report.categories = stats.get("categories", {})
            report.applications = stats.get("applications", {})
            rec = stats.get("recovery", {})
            report.deleted_recovered = sum(
                v for k, v in rec.items() if k != "allocated")
            report.finished_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds")
            report.duration_seconds = round(time.time() - started, 2)
            container.update_extraction(finished_at=report.finished_at)

            if report.status != "Failed":
                report.status = ("Completed" if not report.integrity_failures
                                 else "Completed with integrity warnings")
                _clear_incomplete(container)
                if plan.method != "import":
                    from ..core.custody import append_entry as field_custody
                    field_custody(container.path, "extraction.complete", {
                        "status": report.status,
                        "artifacts": report.artifacts,
                        "duration_seconds": report.duration_seconds,
                    }, operator=plan.operator)
            self._log(container, "engine", report.status.lower().split()[0],
                      f"Extraction {report.status.lower()} — "
                      f"{report.artifacts} artifacts "
                      f"({report.deleted_recovered} recovered from deleted "
                      f"space) in {report.duration_seconds}s")
            try:
                report.seal = container.seal(fast=plan.fast_seal)
                self._log(container, "engine", "sealed",
                          f"Container sealed: "
                          f"{report.seal['container_seal'][:32]}…")
            except Exception as exc:
                report.warnings.append(f"seal failed: {exc}")
            if report.status != "Failed":
                try:
                    from ..core.container import default_zip_path
                    zip_dest = default_zip_path(container.path)
                    zip_out = container.export_zip(zip_dest)
                    report.export_zip = str(zip_out)
                    self._log(container, "engine", "exported",
                              f"Portable ZIP saved: {zip_out.name} "
                              f"({_human(zip_out.stat().st_size)})")
                except Exception as exc:
                    report.warnings.append(f"ZIP export failed: {exc}")
            container.close()
            self.case.audit.record("extraction.complete", {
                "container": Path(report.container).name,
                "status": report.status,
                "artifacts": report.artifacts,
                "deleted_recovered": report.deleted_recovered,
                "duration_seconds": report.duration_seconds,
                "seal": (report.seal or {}).get("container_seal", "")[:32],
            })
            shutil.rmtree(staging, ignore_errors=True)
            self._meter = None
            if self._monitor:
                self._monitor.stop()
                self._monitor = None
        return report

    @staticmethod
    def _is_argus_container_import(source: Path | str) -> bool:
        from ..core.container import is_argus_container_archive
        return is_argus_container_archive(Path(source))

    def _import_existing_container(self, plan: AcquisitionPlan) -> AcquisitionReport:
        """Attach a portable ``.afc`` / ``.afc.zip`` without re-decoding."""
        from ..core.container import EvidenceContainer, import_container_archive

        started = time.time()
        report = AcquisitionReport(
            method="import",
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        try:
            dest = import_container_archive(
                self.case, plan.exhibit_id, plan.source_path or "")
            report.container = str(dest)
            with EvidenceContainer(dest, mode="r") as container:
                stats = container.refresh_statistics()
                report.artifacts = int(stats.get("artifacts", 0))
                report.categories = stats.get("categories", {})
                report.applications = stats.get("applications", {})
                rec = stats.get("recovery", {})
                report.deleted_recovered = sum(
                    v for k, v in rec.items() if k != "allocated")
                report.seal = container.manifest.get("seal", {})
            report.notes.append(
                "ARGUS container attached — artifacts are ready for analysis "
                "(no re-decode needed).")
            report.status = "Completed"
        except Exception as exc:
            report.status = "Failed"
            report.warnings.append(str(exc))
        report.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report.duration_seconds = round(time.time() - started, 2)
        self.case.audit.record("extraction.import", {
            "container": Path(report.container).name if report.container else "",
            "status": report.status,
            "artifacts": report.artifacts,
            "source": str(plan.source_path or ""),
        })
        return report

    # -------------------------------------------------------------- acquire
    def _acquire(self, plan: AcquisitionPlan, container: EvidenceContainer,
                 staging: Path, device: Optional[DetectedDevice],
                 report: AcquisitionReport,
                 resumed: bool = False) -> Path:
        """Get bytes off the device (or off disk) into a staging tree."""
        raw_root = (container.path / "raw") if plan.keep_raw else staging
        raw_root.mkdir(parents=True, exist_ok=True)
        log = lambda *a, **k: self._log(container, *a, **k)

        if plan.method == "import":
            src = Path(plan.source_path or "")
            if not src.exists():
                raise AcquisitionError(f"import source not found: {src}")

            # Format detection is delegated to the adapter registry, so ARGUS
            # accepts another tool's extraction as readily as its own. Most
            # evidence an examiner receives was not acquired by the tool they
            # are using.
            from . import adapters
            described = adapters.describe(src)
            if not described.get("ok"):
                raise AcquisitionError(
                    f"{described.get('reason')} — supported sources: "
                    + ", ".join(a.label for a in adapters.adapters()))
            log("import", "start",
                f"Identified as {described['label']}: {src}")

            staged = adapters.stage(src, raw_root, plan)
            report.files_acquired += staged.files
            report.bytes_acquired += staged.bytes_staged
            report.warnings.extend(staged.warnings[:80])
            report.notes.extend(staged.notes[:40])

            container.update_extraction(
                source_format=staged.source_format,
                import_adapter=staged.adapter)
            if staged.device:
                container.update_extraction(**_device_fields(staged.device))
            if staged.foreign_decoded:
                # Another tool's decoded output is recorded as provenance, never
                # adopted as an ARGUS finding — the examiner must be able to see
                # which tool decoded what.
                container.manifest.setdefault(
                    "foreign_provenance", staged.foreign_decoded)
                container._write_manifest()
                log("import", "note",
                    f"Recorded {len(staged.foreign_decoded)} decoded model "
                    f"group(s) from the originating tool as foreign "
                    f"provenance (attributed to it, not to ARGUS)")
            for note in staged.notes[:6]:
                log("import", "note", note)
            log("import", "ok",
                f"{staged.source_format}: {staged.files} file(s), "
                f"{_human(staged.bytes_staged)}"
                + (f", platform {staged.platform}" if staged.platform else ""))
            if staged.platform:
                self._staged_platform = staged.platform
            return raw_root

        # ------------------------------------------------ live device methods
        dev = device or require_device(plan.serial)
        from ..devices.identity import snapshot_from_detected, write_identity
        identity = snapshot_from_detected(dev)
        write_identity(raw_root, identity)
        log("device", "ok",
            f"Device identified: {dev.name} "
            f"({dev.os_family} {dev.os_version or 'OS unknown'}, "
            f"{dev.transport}, serial {dev.serial[:48]})")
        usb_bits = [identity.get("usb_vendor"), identity.get("usb_vid"),
                    identity.get("usb_pid"), identity.get("usb_mode")]
        if any(usb_bits):
            log("device", "ok",
                "USB identity: "
                + " ".join(filter(None, [
                    identity.get("usb_vendor"),
                    f"VID_{identity.get('usb_vid', '').upper()}"
                    if identity.get("usb_vid") else "",
                    f"PID_{identity.get('usb_pid', '').upper()}"
                    if identity.get("usb_pid") else "",
                    identity.get("usb_mode"),
                ])))
        if identity.get("volumes"):
            log("device", "ok",
                "Storage volumes: " + ", ".join(identity["volumes"]))
        if not container.extraction.get("device_make") and identity.get("make"):
            container.update_extraction(
                device_make=identity.get("make", ""),
                device_model=identity.get("marketing_name")
                or identity.get("model", ""),
                device_os=f"{identity.get('os_family', '')} "
                          f"{identity.get('os_version', '')}".strip(),
                device_serial=identity.get("usb_instance_serial")
                or identity.get("serial", ""),
            )
        if dev.battery is not None and dev.battery < 20:
            log("device", "warning",
                f"Battery at {dev.battery}% — connect a charger before a long "
                f"extraction. Do not disconnect during extraction (manual §7).",
                level="warning")

        if dev.os_family == "Android":
            if dev.transport == "mtp" and plan.method != "mtp":
                log("device", "note",
                    "Handset is in file-transfer (MTP) mode, not USB debugging — "
                    "switching acquisition to MTP.",
                    level="warning")
                plan.method = "mtp"

            if plan.method == "mtp" or dev.transport == "mtp":
                from . import mtp
                from .monitor import MtpExtractionMonitor
                label = ((dev.raw or {}).get("mtp_name")
                         or dev.marketing_name or dev.name or dev.model)
                if not mtp.available():
                    kind = mtp.backend()
                    raise AcquisitionError(
                        "No MTP backend on this host. On Windows use File "
                        "transfer. On Linux install gvfs-mtp/libmtp and unlock "
                        "the phone. On macOS open Android File Transfer. Or "
                        "enable USB debugging for ADB."
                        + (f" (backend={kind})" if kind else ""))
                if self._monitor:
                    self._monitor.stop()
                self._monitor = MtpExtractionMonitor(
                    label, raw_root, log=log, cancel_check=self.cancel_check)
                self._monitor.start()
                mtp_result = mtp.acquire(
                    label, raw_root,
                    progress=lambda msg, **extra: log(
                        "mtp", "progress", msg, **extra),
                    hash_files=plan.verify_pulls and not plan.turbo,
                    resume=resumed,
                    turbo=plan.turbo)
                report.files_acquired += mtp_result.files_copied
                report.bytes_acquired += mtp_result.bytes_copied
                report.warnings.extend(mtp_result.warnings[:80])
                if mtp_result.missing:
                    report.warnings.append(
                        f"MTP: {len(mtp_result.missing)} listed file(s) did "
                        f"not copy — see argus-mtp-manifest.json")
                mtp.write_manifest(mtp_result,
                                   raw_root / "argus-mtp-manifest.json")
                if mtp_result.volumes:
                    identity["volumes"] = mtp_result.volumes
                    write_identity(raw_root, identity)
                    log("mtp", "ok",
                        "Copied volumes: " + ", ".join(mtp_result.volumes))
                comm = mtp.scan_communication_artifacts(raw_root)
                counts = comm.get("counts", {})
                total_comm = sum(counts.values())
                if total_comm:
                    log("mtp", "ok",
                        "Communications material on shared storage — "
                        f"{counts.get('databases', 0)} database(s), "
                        f"{counts.get('backups', 0)} backup XML, "
                        f"{counts.get('vcards', 0)} vCard(s), "
                        f"{counts.get('whatsapp', 0)} WhatsApp DB(s) "
                        f"(decode will parse these)")
                else:
                    log("mtp", "note",
                        "No SMS/call/contact databases found on shared storage. "
                        "Live calls, contacts and messages require USB debugging "
                        "(enable Developer options → USB debugging, then re-run "
                        "with ADB) or an on-device backup app export.",
                        level="warning")
                adb_res = android_adb.acquire_communications(
                    raw_root, categories=plan.categories, log=log,
                    # 180s was routinely too tight for an examiner enabling
                    # Developer options and USB debugging for the first time
                    # on a phone they don't own — finding the toggle alone
                    # can eat most of that window.
                    wait_seconds=300, force_comms=True)
                if adb_res.pulled:
                    report.files_acquired += len(adb_res.pulled)
                    report.bytes_acquired += adb_res.bytes_total
                    log("adb.comms", "ok",
                        f"Pulled {len(adb_res.pulled)} communication source(s) "
                        f"({_human(adb_res.bytes_total)})")
                log("mtp", "ok",
                    f"Copied {mtp_result.files_copied} of "
                    f"{mtp_result.files_listed} listed file(s), "
                    f"{_human(mtp_result.bytes_copied)}")
                return raw_root

            session = android_adb.AdbSession(dev.serial)
            from . import android_vendor
            make = (identity.get("make") or dev.make or "").strip()
            model = (identity.get("model") or dev.model or dev.name or "").strip()
            vendor_fs = android_vendor.expand_fs_paths(make, model)
            vendor_comm = android_vendor.expand_comm_paths(make, model)
            vendor_providers = android_vendor.extra_providers(make)
            if vendor_fs or vendor_comm:
                log("device", "note",
                    f"Vendor paths for {make or 'unknown'} — "
                    f"{len(vendor_fs)} FS + {len(vendor_comm)} export target(s)")
            android_adb.ensure_device_ready(session, log=log)
            awake = False
            if not plan.turbo:
                awake = android_adb.enable_keep_awake(session, log=log)
            try:
                android_adb.device_report(
                    session, raw_root, lite=bool(plan.skip_device_report or plan.turbo))
                if plan.skip_device_report or plan.turbo:
                    log("device", "note",
                        "Turbo identity capture — skipped package/account dumps")
                pull_kw = dict(
                    categories=plan.categories, log=log,
                    skip_existing=resumed or plan.turbo,
                    verify=plan.verify_pulls,
                    parallel=plan.parallel_pulls,
                    vendor_paths=vendor_fs,
                )
                if plan.method == "logical":
                    res = android_adb.logical_query(
                        session, raw_root, plan.categories, log,
                        skip_existing=resumed or plan.turbo,
                        extra_providers=vendor_providers)
                elif plan.method in ("filesystem", "turbo"):
                    res = android_adb.pull_filesystem(session, raw_root, **pull_kw)
                elif plan.method == "comprehensive":
                    res = android_adb.comprehensive_acquire(
                        session, raw_root, plan.categories, log,
                        skip_existing=resumed or plan.turbo,
                        verify=plan.verify_pulls,
                        parallel=plan.parallel_pulls,
                        skip_app_discovery=plan.skip_app_discovery,
                        vendor_fs=vendor_fs, vendor_comm=vendor_comm,
                        vendor_providers=vendor_providers)
                elif plan.method == "backup":
                    ab = android_adb.create_backup(session, staging,
                                                   plan.backup_password or "", log)
                    if not ab:
                        raise AcquisitionError(
                            "adb backup returned no data (Android 12+ restricts it; "
                            "try the filesystem or comprehensive method)")
                    n, warns = android_backup.extract(ab, raw_root,
                                                      plan.backup_password)
                    report.files_acquired += n
                    report.warnings.extend(warns)
                    res = android_adb.PullResult(pulled=[str(ab)],
                                                 bytes_total=ab.stat().st_size)
                else:
                    raise AcquisitionError(
                        f"method '{plan.method}' is not implemented for Android")
                report.files_acquired += len(res.pulled)
                report.bytes_acquired += res.bytes_total
                report.integrity_failures.extend(res.integrity_failures)
                report.warnings.extend(res.failed)
                log("engine", "ok",
                    f"ADB acquire — {len(res.pulled)} pulled, "
                    f"{len(res.skipped)} skipped, {len(res.failed)} failed, "
                    f"{_human(res.bytes_total)}")
                android_adb.write_adb_manifest(
                    raw_root, res, method=plan.method, serial=dev.serial)
                self._validate_acquire(container, report, plan, res, log)
                if plan.method in ("logical", "filesystem", "turbo"):
                    comms = android_adb.acquire_comms_supplement(
                        session, raw_root, categories=plan.categories, log=log,
                        vendor_comm_paths=vendor_comm,
                        vendor_providers=vendor_providers,
                        skip_existing=resumed or plan.turbo)
                    if comms.pulled:
                        report.files_acquired += len(comms.pulled)
                        report.bytes_acquired += comms.bytes_total
                        log("adb.comms", "ok",
                            f"Communications supplement — {len(comms.pulled)} "
                            f"source(s), {_human(comms.bytes_total)}")
            finally:
                if awake:
                    android_adb.disable_keep_awake(session)
            return raw_root

        from .ios_live import acquire_ios, looks_like_apple
        if dev.os_family == "iOS" or looks_like_apple(
                dev.name, dev.os_family, dev.transport):
            evidence, route = acquire_ios(
                dev.serial, raw_root,
                display_name=dev.marketing_name or dev.name or dev.model,
                password=plan.backup_password or None,
                turbo=plan.turbo,
                log=log)
            if route in ("idevicebackup2", "itunes"):
                self._ios_backup(evidence, raw_root, container, report, plan)
            else:
                report.files_acquired += sum(
                    1 for p in evidence.rglob("*") if p.is_file())
                log("ios.media", "ok",
                    f"iOS media copy via {route} — decode will treat this as "
                    "an iOS Camera Roll / DCIM tree")
            return raw_root

        raise AcquisitionError(f"unsupported platform: {dev.os_family}")

    def _ios_backup(self, src: Path, raw_root: Path,
                    container: EvidenceContainer, report: AcquisitionReport,
                    plan: AcquisitionPlan) -> None:
        backup = ios_backup.IOSBackup(src)
        info = backup.device_info()
        container.update_extraction(
            device_make="Apple",
            device_model=info.get("product_type", ""),
            device_os=f"iOS {info.get('product_version','')}".strip(),
            device_serial=info.get("serial_number", ""),
            imei=info.get("imei", ""), iccid=info.get("iccid", ""),
            phone_number=info.get("phone_number", ""))
        self._log(container, "ios.backup", "ok",
                  f"Backup identified: {info.get('device_name')} "
                  f"{info.get('product_type')} iOS {info.get('product_version')}")
        if backup.encrypted:
            raise AcquisitionError(
                "iOS backup is encrypted. Supply the backup password, or "
                "produce an unencrypted backup with "
                "`idevicebackup2 encryption off <password>`.")
        written, total, warns = backup.rebuild(
            raw_root, progress=lambda n, b, p: self._log(
                container, "ios.backup", "progress",
                f"{n} files rebuilt ({_human(b)}) — {p}"))
        report.files_acquired += written
        report.bytes_acquired += total
        report.warnings.extend(warns[:50])
        self._log(container, "ios.backup", "ok",
                  f"Logical tree rebuilt: {written} files, {_human(total)}")

    # --------------------------------------------------------------- decode
    def _decode(self, plan: AcquisitionPlan, container: EvidenceContainer,
                raw_root: Path, report: AcquisitionReport,
                resumed: bool = False) -> None:
        """Step 13's "Decode" action: turn raw bytes into artifacts."""
        self._check_cancelled(container, "decode")
        lo, hi = span_to_range(plan.time_span)
        # An adapter that read a source's own metadata knows the platform more
        # reliably than a heuristic over directory names.
        platform = getattr(self, "_staged_platform", "") or _guess_platform(
            raw_root)
        self._log(container, "decode", "start",
                  f"Decoding {platform or 'unknown platform'} evidence tree"
                  + (f" (time span {plan.time_span})" if lo else ""),
                  phase="decode",
                  progress_current=0, progress_total=1, progress_pct=0)

        ctx = ParseContext(
            evidence_root=raw_root, platform=platform,
            owner_identifiers=plan.owner_identifiers,
            owner_name=plan.owner_name,
            recover_deleted=plan.recover_deleted,
            carve_confidence=plan.carve_confidence,
            store_blob=(None if plan.skip_blob_store else
                        lambda p, rel: container.store_file(p, rel).sha256),
            log=lambda *a, **k: self._log(container, *a, **k),
            time_lo=lo, time_hi=hi, categories=plan.categories,
            skip_perceptual_hash=plan.skip_perceptual_hash,
            skip_content_sniff=plan.skip_content_sniff,
            skip_file_hash=plan.turbo,
        )
        skip_sources: Optional[set] = None
        if resumed or plan.resume:
            prior = {s["path"] for s in container.db.sources()}
            if prior:
                skip_sources = prior
                self._log(container, "decode", "note",
                          f"Resume — skipping {len(prior):,} source(s) "
                          f"already decoded in this container")
        result = ingest_tree(raw_root, ctx, container,
                             workers=plan.ingest_workers,
                             progress_every=500 if plan.turbo else 750,
                             batch_size=2000 if plan.turbo else 1000,
                             skip_sources=skip_sources)
        report.warnings.extend(result.warnings[:200])
        report.notes.extend(result.notes[:200])
        report.files_seen = result.files_seen
        report.files_parsed = result.files_parsed
        report.files_skipped = result.files_skipped
        report.decode_by_parser = dict(result.by_parser)
        if result.files_seen:
            report.decode_coverage_pct = round(
                100.0 * result.files_parsed / result.files_seen, 1)
        if not report.files_acquired:
            report.files_acquired = result.files_seen
            report.bytes_acquired = result.bytes_seen
        container.update_extraction(
            decode_files_seen=result.files_seen,
            decode_files_parsed=result.files_parsed,
            decode_files_skipped=result.files_skipped,
            decode_coverage_pct=report.decode_coverage_pct,
            decode_by_parser=report.decode_by_parser,
        )
        self._log(container, "decode", "ok",
                  f"Decoded {len(result.artifacts)} artifacts from "
                  f"{result.files_parsed} of {result.files_seen} files",
                  phase="decode", progress_current=1, progress_total=1,
                  progress_pct=100)
        self._post_decode_audit(container, report, plan, result)
        self._warn_missing_communications(container, report, plan)

    def _enrich_progress(self, module: str, status: str,
                         extra: Dict[str, Any]) -> Dict[str, Any]:
        """Attach phase, rate, and ETA to progress-bearing log lines."""
        if not self._meter:
            return extra
        module_l = (module or "").lower()
        if "phase" not in extra:
            if module_l in ("decode", "ingest"):
                extra["phase"] = "decode"
            elif module_l.startswith("adb"):
                extra["phase"] = "transfer"
                if module_l == "adb.comprehensive" and status == "progress":
                    extra.setdefault("phase", "transfer")
            elif module_l == "engine" and status == "start":
                extra["phase"] = "prepare"
        if "progress_current" in extra and "progress_total" in extra:
            try:
                cur = int(extra["progress_current"])
                tot = int(extra["progress_total"])
                if extra.get("phase"):
                    self._meter.set_phase(str(extra["phase"]))
                snap = self._meter.snapshot(
                    current=cur, total=tot,
                    bytes_current=int(extra.get("bytes_current", 0)),
                    bytes_total=int(extra.get("bytes_total", 0)),
                )
                snap.pop("message", None)
                for key, value in snap.items():
                    extra.setdefault(key, value)
            except (TypeError, ValueError):
                pass
        return extra

    def _post_decode_audit(self, container: EvidenceContainer,
                           report: AcquisitionReport,
                           plan: AcquisitionPlan,
                           ingest: Any) -> None:
        """Structured god-level decode audit — surfaced in UI and dashboard."""
        stats = container.refresh_statistics().get("categories", {})
        decoded_cats = {k: int(v) for k, v in stats.items() if v}
        wanted = [c for c in (plan.categories or []) if c in ALL_CATEGORIES]
        gaps = [c for c in wanted if c not in decoded_cats]
        audits: List[Dict[str, Any]] = []

        if report.files_seen and report.decode_coverage_pct < 35:
            msg = (f"Low decode coverage — only {report.decode_coverage_pct:.0f}% "
                   f"of files ({report.files_parsed:,}/{report.files_seen:,}) "
                   f"produced artifacts. Check extraction warnings and parser logs.")
            audits.append({"severity": "action_required", "code": "low_decode_coverage",
                           "message": msg})
            report.warnings.append(msg)

        if gaps:
            preview = ", ".join(gaps[:6])
            if len(gaps) > 6:
                preview += f" (+{len(gaps) - 6} more)"
            audits.append({
                "severity": "info", "code": "category_gaps",
                "message": f"No artifacts in requested categories: {preview}",
            })

        method = (plan.method or "").lower()
        if method == "mtp":
            try:
                mtp_manifest = container.path / "raw" / "argus-mtp-manifest.json"
                if mtp_manifest.is_file():
                    raw_root_manifest = json.loads(
                        mtp_manifest.read_text(encoding="utf-8"))
                    missing = raw_root_manifest.get("missing") or []
                    if missing:
                        audits.append({
                            "severity": "action_required",
                            "code": "mtp_incomplete",
                            "message": (f"MTP copy incomplete — {len(missing):,} "
                                        f"listed file(s) did not land on disk."),
                        })
            except (OSError, json.JSONDecodeError, TypeError):
                pass

        enc = [s for s in container.db.sources()
               if "encrypted" in (s.get("notes") or "").lower()]
        if enc:
            audits.append({
                "severity": "critical", "code": "encrypted_stores",
                "message": (f"{len(enc)} encrypted store(s) present — content "
                            "not included in artifact totals."),
            })

        report.audit_warnings = audits
        if audits:
            container.update_extraction(decode_audit=audits)

    def _validate_acquire(self, container: EvidenceContainer,
                          report: AcquisitionReport,
                          plan: AcquisitionPlan,
                          pull: Any,
                          log: Callable[..., None]) -> None:
        """Pre-decode acquisition quality checks."""
        wanted_comms = {c for c in (plan.categories or [])
                        if c in ("Messages", "Contacts", "Calls", "Chats")}
        if not wanted_comms:
            return
        stats = getattr(pull, "provider_stats", None) or []
        comm_keys = {"sms", "sms_inbox", "sms_sent", "mms", "threads",
                     "contacts", "contacts_all", "calls", "mms_part",
                     "vivo_sms", "bbk_sms", "sec_calls"}
        comm_providers = [s for s in stats if s.get("key") in comm_keys]
        if comm_providers:
            empty = [s["key"] for s in comm_providers
                     if int(s.get("rows") or 0) == 0 and not s.get("skipped")]
            if empty and len(empty) == len(comm_providers):
                msg = (
                    f"All {len(empty)} communication provider(s) returned 0 rows "
                    f"({', '.join(empty[:5])}). Dumpsys and export passes may "
                    f"still recover data — check raw/ after decode.")
                report.warnings.append(msg)
                report.audit_warnings.append({
                    "severity": "action_required",
                    "code": "providers_empty", "message": msg})
                log("engine", "warning", msg, level="warning")
        if pull.failed and len(pull.failed) > len(pull.pulled):
            msg = (f"More paths failed ({len(pull.failed)}) than succeeded "
                   f"({len(pull.pulled)}) — device may need root or USB "
                   f"debugging (Security settings) on Vivo/MIUI.")
            if msg not in report.warnings:
                report.warnings.append(msg)
                log("engine", "warning", msg, level="warning")

    def _warn_missing_communications(self, container: EvidenceContainer,
                                     report: AcquisitionReport,
                                     plan: AcquisitionPlan) -> None:
        """Tell the examiner when Messages/Contacts/Calls decoded to zero."""
        wanted = {c for c in (plan.categories or [])
                  if c in ("Messages", "Contacts", "Calls", "Chats")}
        if not wanted:
            return
        stats = container.refresh_statistics().get("categories", {})
        msgs = int(stats.get("Messages", 0)) + int(stats.get("Chats", 0))
        contacts = int(stats.get("Contacts", 0))
        calls = int(stats.get("Calls", 0))
        gaps: List[str] = []
        if "Messages" in wanted or "Chats" in wanted:
            if msgs == 0:
                gaps.append("Messages")
        if "Contacts" in wanted and contacts == 0:
            gaps.append("Contacts")
        if "Calls" in wanted and calls == 0:
            gaps.append("Calls")
        if not gaps:
            self._log(container, "decode", "ok",
                      f"Communications decoded — {msgs:,} message(s), "
                      f"{contacts:,} contact(s), {calls:,} call(s)")
            self._warn_missing_gps(container, report, plan)
            return
        method = (container.extraction.get("method") or plan.method or "").lower()
        if method in ("comprehensive", "logical", "filesystem", "turbo"):
            note = (
                f"No {' / '.join(gaps)} decoded despite {method} extraction. "
                f"On non-root Vivo handsets, contacts/calls often return 0 from "
                f"content providers — check Messages via ADB logical dumps in raw/content/. "
                f"For deeper recovery: export SMS Backup+ / vCard on-phone, or root.")
        elif method == "mtp":
            note = (
                f"No {' / '.join(gaps)} in this extraction. MTP copies shared storage "
                f"only. Enable USB debugging and re-run Comprehensive, or export "
                f"SMS Backup+ / vCard to Download/ before MTP.")
        else:
            note = (
                f"No {' / '.join(gaps)} in this extraction.")
        report.warnings.append(note)
        report.audit_warnings.append({
            "severity": "action_required", "code": "comms_gap", "message": note})
        self._log(container, "decode", "warning", note, level="warning")
        self._warn_missing_gps(container, report, plan)

    def _warn_missing_gps(self, container: EvidenceContainer,
                          report: AcquisitionReport,
                          plan: AcquisitionPlan) -> None:
        """Warn when no geolocation decoded but media was expected."""
        wanted = plan.categories or []
        if wanted and "Places" not in wanted and "Locations" not in wanted:
            return
        stats = container.refresh_statistics().get("categories", {})
        places = int(stats.get("Places", 0)) + int(stats.get("Locations", 0))
        media = int(stats.get("Files & Media", 0))
        if places > 0 or media < 5:
            return
        note = (
            "No GPS coordinates decoded. Geolocation usually comes from photo EXIF "
            "(DCIM/Camera) or Google Maps history. Ensure DCIM copied fully during "
            "MTP, or enable USB debugging for dumpsys location.")
        if note not in report.warnings:
            report.warnings.append(note)
        self._log(container, "decode", "warning", note, level="warning")

    # ------------------------------------------------------------------- log
    def _log(self, container: EvidenceContainer, module: str, status: str,
             message: str, level: str = "info", **extra: Any) -> None:
        extra = self._enrich_progress(module, status, dict(extra))
        entry = container.log(module, status, message, level=level, **extra)
        if self.progress:
            try:
                self.progress(entry)
            except Exception:                                 # pragma: no cover
                pass


def _device_fields(device: Dict[str, Any]) -> Dict[str, str]:
    """Map an adapter's device dictionary onto container metadata fields.

    Source tools use wildly different key names for the same facts, so this maps
    a generous set of aliases rather than requiring one spelling.
    """
    aliases = {
        "device_make": ("make", "manufacturer", "vendor", "Device Make",
                        "Manufacturer"),
        "device_model": ("model", "product_type", "Device Model", "Model",
                         "device_name", "Device Name", "device"),
        "device_os": ("os", "os_version", "product_version", "OS Version",
                      "Operating System", "software_version"),
        "device_serial": ("serial", "serial_number", "Serial Number", "udid",
                          "unique_identifier"),
        "imei": ("imei", "IMEI", "imei1"),
        "iccid": ("iccid", "ICCID"),
        "phone_number": ("phone_number", "msisdn", "Phone Number"),
    }
    lowered = {str(k).strip().lower(): str(v) for k, v in device.items()}
    out: Dict[str, str] = {}
    for field_name, keys in aliases.items():
        for key in keys:
            value = lowered.get(key.strip().lower())
            if value:
                out[field_name] = value[:200]
                break
    return out


def _guess_platform(root: Path) -> str:
    markers_android = ["data/data", "sdcard", "build.prop", "packages.list",
                       "apps/", "mmssms.db", "contacts2.db"]
    markers_ios = ["HomeDomain", "CameraRollDomain", "Manifest.db", "sms.db",
                   "AddressBook.sqlitedb", "Library/SMS", "100APPLE",
                   "ios_backup", "ios_media"]
    blob = " ".join(p.as_posix() for p in list(root.rglob("*"))[:4000]).lower()
    a = sum(1 for m in markers_android if m.lower() in blob)
    i = sum(1 for m in markers_ios if m.lower() in blob)
    if a > i:
        return "android"
    if i > a:
        return "ios"
    return ""


def _copy_tree(src: Path, dest: Path) -> tuple[int, int]:
    n = total = 0
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(src)
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(p, target)
            n += 1
            total += target.stat().st_size
        except OSError:
            continue
    return n, total


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _version() -> str:
    from .. import __version__
    return __version__
