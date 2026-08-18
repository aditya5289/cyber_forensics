"""Background job runner for long operations.

An extraction can run for minutes or hours. The manual is explicit that the
operator must be able to watch progress — module, status, timestamp, message —
and must not disconnect the device mid-run. A browser request that simply
blocks for an hour gives the operator nothing to watch and times out long
before the work finishes.

So acquisitions run in a worker thread and the UI polls. Every log line the
engine emits is appended to the job's buffer with a monotonic sequence number,
and the UI asks for "everything after N". That makes the stream resumable: a
refreshed page, a closed laptop lid or a flaky localhost connection cannot lose
log lines, which matters because that log is part of the record of what was
done to the evidence.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Job:
    """One background operation with a resumable log."""

    def __init__(self, kind: str, label: str = ""):
        self.id = uuid.uuid4().hex[:16]
        self.kind = kind
        self.label = label
        self.status = "queued"           # queued|running|done|failed|cancelled
        self.created_at = _utc()
        self.started_at = ""
        self.finished_at = ""
        self.result: Any = None
        self.error: str = ""
        self.traceback: str = ""
        self.progress: float = 0.0
        self.phase: str = ""
        self.eta_seconds: int = 0
        self.bytes_current: int = 0
        self.bytes_total: int = 0
        self.rate: float = 0.0
        self.rate_unit: str = ""
        self._log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ log
    def emit(self, module: str, status: str, message: str,
             level: str = "info", **extra: Any) -> None:
        with self._lock:
            if "progress_pct" in extra:
                try:
                    self.progress = max(
                        self.progress, float(extra["progress_pct"]) / 100.0)
                except (TypeError, ValueError):
                    pass
            for key in ("phase", "eta_seconds", "bytes_current", "bytes_total",
                        "rate", "rate_unit"):
                if key in extra:
                    setattr(self, key, extra[key])
            self._log.append({
                "seq": len(self._log) + 1,
                "ts": _utc(),
                "module": module,
                "status": status,
                "level": level,
                "message": message,
                **extra,
            })

    def log_since(self, seq: int = 0, limit: int = 2000) -> List[Dict[str, Any]]:
        with self._lock:
            return self._log[seq:seq + limit]

    @property
    def log_length(self) -> int:
        with self._lock:
            return len(self._log)

    # --------------------------------------------------------------- control
    def request_cancel(self) -> None:
        self._cancel.set()
        self.emit("job", "cancelling",
                  "Cancellation requested — the current module will finish "
                  "first so partial evidence is not left inconsistent.",
                  level="warning")

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ---------------------------------------------------------------- status
    def snapshot(self, since: int = 0) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": self.progress,
            "phase": self.phase,
            "eta_seconds": self.eta_seconds,
            "bytes_current": self.bytes_current,
            "bytes_total": self.bytes_total,
            "rate": self.rate,
            "rate_unit": self.rate_unit,
            "error": self.error,
            "traceback": self.traceback if self.status == "failed" else "",
            "result": self.result,
            "log": self.log_since(since),
            "log_length": self.log_length,
        }


class JobRunner:
    """Holds jobs for the life of the process."""

    def __init__(self, max_retained: int = 200):
        self.jobs: Dict[str, Job] = {}
        self.order: List[str] = []
        self.max_retained = max_retained
        self._lock = threading.Lock()

    def submit(self, kind: str, fn: Callable[[Job], Any],
               label: str = "") -> Job:
        job = Job(kind, label)
        with self._lock:
            self.jobs[job.id] = job
            self.order.append(job.id)
            while len(self.order) > self.max_retained:
                stale = self.order.pop(0)
                self.jobs.pop(stale, None)

        def runner() -> None:
            job.status = "running"
            job.started_at = _utc()
            try:
                job.result = fn(job)
                job.status = "cancelled" if job.cancelled else "done"
            except Exception as exc:
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.traceback = traceback.format_exc()
                job.emit("job", "error", job.error, level="error")
            finally:
                job.finished_at = _utc()
                job.progress = 1.0

        threading.Thread(target=runner, daemon=True,
                         name=f"argus-job-{job.id}").start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            ids = list(reversed(self.order))[:limit]
        return [{
            "id": j.id, "kind": j.kind, "label": j.label, "status": j.status,
            "created_at": j.created_at, "finished_at": j.finished_at,
            "error": j.error,
        } for j in (self.jobs[i] for i in ids if i in self.jobs)]
