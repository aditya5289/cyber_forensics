"""Batch acquisition — extract many handsets in one supervised run.

Large raids and lab intake days can involve dozens of devices. Running each
extraction manually — register exhibit, pick method, wait, repeat — does not
scale and invites mistakes (wrong exhibit ID, skipped handset).

This module queues one acquisition per device and runs them **serially**. USB
stability and chain-of-custody both favour one live extraction at a time on a
single workstation; parallelism is achieved by queuing, not by hammering the
bus with concurrent pulls.

Each device gets its own exhibit (auto-registered when needed) and its own
``.afc`` container. Failures are recorded and the queue continues unless
``stop_on_error`` is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..core.case import Case, Exhibit
from ..core.errors import AcquisitionError
from ..devices.detect import DetectedDevice, detect_all, resolve_device
from ..devices.manual import DeviceManual
from .engine import ALL_CATEGORIES, AcquisitionEngine, AcquisitionPlan
from .progress import ProgressMeter


ProgressFn = Callable[[Dict[str, Any]], None]


@dataclass
class BatchDeviceSpec:
    """One handset in a batch queue."""

    serial: str
    exhibit_id: str = ""
    device_name: str = ""
    lock_state: str = "unlocked"
    method: str = "comprehensive"
    resume: bool = False
    notes: str = ""
    make: str = ""
    model: str = ""
    imei: str = ""
    transport: str = ""
    mtp_name: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BatchAcquisitionPlan:
    """Operator + queue of devices to extract."""

    operator: str
    devices: List[BatchDeviceSpec]
    time_span: str = "all"
    categories: List[str] = field(default_factory=lambda: list(ALL_CATEGORIES))
    stop_on_error: bool = False
    auto_register_exhibits: bool = True
    exhibit_prefix: str = "EXH"
    recover_deleted: bool = True
    carve_confidence: float = 0.45
    owner_identifiers: List[str] = field(default_factory=list)
    owner_name: str = "Device owner"
    turbo: bool = False

    def validate(self) -> None:
        if not self.operator:
            raise AcquisitionError("operator is required for batch extraction")
        if not self.devices:
            raise AcquisitionError("batch queue is empty — no devices to extract")


@dataclass
class BatchDeviceResult:
    serial: str = ""
    exhibit_id: str = ""
    device_name: str = ""
    status: str = "pending"          # pending|running|completed|failed|skipped
    container: str = ""
    error: str = ""
    artifacts: int = 0
    duration_seconds: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BatchAcquisitionReport:
    started_at: str = ""
    finished_at: str = ""
    total: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[BatchDeviceResult] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "skipped": self.skipped,
            "results": [r.as_dict() for r in self.results],
        }


def next_exhibit_id(case: Case, prefix: str = "EXH") -> str:
    """Allocate the next unused exhibit ID in a case."""
    existing = {e.exhibit_id for e in case.exhibits()}
    for n in range(1, 10_000):
        eid = f"{prefix}-{n:03d}"
        if eid not in existing:
            return eid
    raise AcquisitionError("could not allocate exhibit ID — case is full")


def ensure_exhibit(case: Case, spec: BatchDeviceSpec,
                   device: Optional[DetectedDevice] = None) -> str:
    """Register an exhibit if needed; return exhibit_id."""
    eid = spec.exhibit_id.strip() if spec.exhibit_id else ""
    if eid and eid in case.data.get("exhibits", {}):
        return eid
    if not eid:
        eid = next_exhibit_id(case)
    dev = device
    make = spec.make or (dev.make if dev else "")
    model = spec.model or (dev.marketing_name or dev.model if dev else "")
    imei = spec.imei or (dev.imei if dev else "")
    serial = spec.serial or (dev.serial if dev else "")
    case.add_exhibit(Exhibit(
        exhibit_id=eid,
        description=f"Batch intake — {spec.device_name or make or serial}",
        make=make,
        model=model,
        imei=imei,
        serial=serial,
        seized_by=case.data.get("investigator", ""),
    ))
    return eid


def build_specs_from_connected(method: str = "comprehensive",
                               prefix: str = "EXH") -> List[BatchDeviceSpec]:
    """Build a batch queue from every handset currently connected."""
    raw_devices = detect_all().get("devices", [])
    specs: List[BatchDeviceSpec] = []
    index = 0
    for dev in raw_devices:
        if isinstance(dev, DetectedDevice):
            d = dev.as_dict()
        else:
            d = dev
        if d.get("raw", {}).get("ready") is False:
            continue
        index += 1
        rec = d.get("raw", {}).get("recommended_method", "")
        dev_method = rec or ("mtp" if d.get("transport") == "mtp" else method)
        specs.append(BatchDeviceSpec(
            serial=d.get("serial", ""),
            exhibit_id=f"{prefix}-{index:03d}",
            device_name=d.get("name") or d.get("model", ""),
            method=dev_method,
            make=d.get("make", ""),
            model=d.get("marketing_name") or d.get("model", ""),
            imei=d.get("imei", ""),
            transport=d.get("transport", ""),
            mtp_name=d.get("name") or d.get("model", ""),
        ))
    return specs


class BatchAcquisitionEngine:
    """Run a :class:`BatchAcquisitionPlan` against a case."""

    def __init__(self, case: Case, manual: Optional[DeviceManual] = None,
                 progress: Optional[ProgressFn] = None):
        self.case = case
        self.manual = manual or DeviceManual()
        self.progress = progress

    def _emit(self, module: str, status: str, message: str,
              level: str = "info", meter: Optional[ProgressMeter] = None,
              **extra: Any) -> None:
        entry = {
            "module": module, "status": status, "level": level,
            "message": message, **extra,
        }
        if meter and "batch_current" in extra and "batch_total" in extra:
            try:
                cur = int(extra["batch_current"])
                tot = int(extra["batch_total"])
                device_frac = float(extra.get("device_frac", 0.0))
                overall = int(round(((cur - 1) + device_frac) * 100 / tot))
                entry["batch_pct"] = min(100.0, max(0.0, overall))
                snap = meter.snapshot(
                    current=cur, total=tot, message=message)
                snap.pop("message", None)
                entry.setdefault("phase", snap.get("phase", "transfer"))
                if snap.get("eta_seconds"):
                    entry.setdefault("eta_seconds", snap["eta_seconds"])
                if snap.get("rate"):
                    entry.setdefault("rate", snap["rate"])
                    entry.setdefault("rate_unit", snap.get("rate_unit", "devices/s"))
            except (TypeError, ValueError):
                pass
        if self.progress:
            try:
                self.progress(entry)
            except Exception:                                 # pragma: no cover
                pass

    def run(self, plan: BatchAcquisitionPlan) -> BatchAcquisitionReport:
        plan.validate()
        report = BatchAcquisitionReport(
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            total=len(plan.devices),
        )
        meter = ProgressMeter()
        meter.set_phase("transfer")
        device_durations: List[float] = []
        self._emit("batch", "start",
                   f"Batch extraction queued — {len(plan.devices)} device(s)",
                   batch_total=len(plan.devices), batch_current=0,
                   batch_pct=0.0, phase="prepare", meter=meter)

        for index, spec in enumerate(plan.devices, start=1):
            result = BatchDeviceResult(
                serial=spec.serial,
                exhibit_id=spec.exhibit_id,
                device_name=spec.device_name,
                status="running",
            )
            report.results.append(result)

            device_started = datetime.now(timezone.utc)
            self._emit("batch", "device",
                       f"Device {index}/{len(plan.devices)}: "
                       f"{spec.device_name or spec.serial}",
                       batch_current=index, batch_total=len(plan.devices),
                       device_frac=0.0, meter=meter)

            try:
                device = resolve_device(
                    spec.serial,
                    transport=spec.transport,
                    mtp_name=spec.mtp_name,
                    device_name=spec.device_name,
                )
                if plan.auto_register_exhibits:
                    eid = ensure_exhibit(self.case, spec, device)
                    spec.exhibit_id = eid
                    result.exhibit_id = eid

                method = "turbo" if plan.turbo else spec.method
                acq = AcquisitionPlan(
                    method=method,
                    time_span=plan.time_span,
                    categories=list(plan.categories),
                    operator=plan.operator,
                    exhibit_id=spec.exhibit_id,
                    lock_state=spec.lock_state,
                    device_name=spec.device_name or device.name,
                    serial=device.serial,
                    recover_deleted=plan.recover_deleted,
                    carve_confidence=plan.carve_confidence,
                    owner_identifiers=list(plan.owner_identifiers),
                    owner_name=plan.owner_name,
                    notes=spec.notes,
                    resume=spec.resume,
                    turbo=plan.turbo,
                )

                def device_progress(entry: Dict[str, Any]) -> None:
                    merged = dict(entry)
                    merged["batch_current"] = index
                    merged["batch_total"] = len(plan.devices)
                    try:
                        device_frac = float(entry.get("progress_pct", 0)) / 100.0
                    except (TypeError, ValueError):
                        device_frac = 0.0
                    merged["batch_pct"] = round(
                        ((index - 1) + device_frac) * 100 / len(plan.devices), 1)
                    if device_durations:
                        avg = sum(device_durations) / len(device_durations)
                        remain = (len(plan.devices) - index) + (1.0 - device_frac)
                        merged["eta_seconds"] = int(avg * remain)
                    if self.progress:
                        try:
                            self.progress(merged)
                        except Exception:                         # pragma: no cover
                            pass

                engine = AcquisitionEngine(self.case, manual=self.manual,
                                           progress=device_progress)
                acq_report = engine.run(acq, device=device)

                result.status = acq_report.status
                result.container = acq_report.container
                result.artifacts = acq_report.artifacts
                result.duration_seconds = acq_report.duration_seconds
                if acq_report.status.lower().startswith("fail"):
                    result.status = "failed"
                    result.error = "; ".join(acq_report.warnings[:3]) or "failed"
                    report.failed += 1
                    if plan.stop_on_error:
                        self._emit("batch", "error",
                                   f"Stopping batch after failure on "
                                   f"{spec.serial}", level="error")
                        break
                else:
                    result.status = "completed"
                    report.completed += 1
                    finished = datetime.now(timezone.utc)
                    device_durations.append(
                        (finished - device_started).total_seconds())
                    meter._touch_anchor(index)
                    self._emit("batch", "ok",
                               f"Completed {spec.exhibit_id} — "
                               f"{acq_report.artifacts} artifacts",
                               batch_current=index,
                               batch_total=len(plan.devices),
                               device_frac=1.0, meter=meter)

            except Exception as exc:
                result.status = "failed"
                result.error = str(exc)
                report.failed += 1
                self._emit("batch", "error",
                           f"{spec.serial}: {exc}", level="error",
                           batch_current=index, batch_total=len(plan.devices),
                           meter=meter)
                if plan.stop_on_error:
                    break

        report.finished_at = datetime.now(timezone.utc).isoformat(
            timespec="seconds")
        report.skipped = report.total - report.completed - report.failed
        meter.set_phase("verify")
        self._emit("batch", "done",
                   f"Batch complete — {report.completed} succeeded, "
                   f"{report.failed} failed",
                   batch_current=report.total, batch_total=report.total,
                   device_frac=1.0, batch_pct=100.0, phase="verify",
                   meter=meter)
        return report
