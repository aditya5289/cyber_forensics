"""Live acquisition progress telemetry — rate, ETA, bytes, phase.

Every long-running acquisition path reports through here so the workbench
can show one consistent god-level progress panel instead of ad-hoc counts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ProgressMeter:
    """Tracks throughput and estimates time remaining."""

    started_at: float = field(default_factory=time.time)
    anchor_at: float = 0.0
    anchor_cur: int = 0
    phase: str = "prepare"

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        self.anchor_at = 0.0
        self.anchor_cur = 0

    def _touch_anchor(self, current: int) -> None:
        now = time.time()
        if self.anchor_at <= 0 or current >= self.anchor_cur + max(10, self.anchor_cur // 20):
            self.anchor_at = now
            self.anchor_cur = current

    def rate(self, current: int) -> float:
        """Units per second since the last anchor."""
        if self.anchor_at <= 0:
            return 0.0
        elapsed = time.time() - self.anchor_at
        if elapsed < 3:
            return 0.0
        done = max(0, current - self.anchor_cur)
        return done / elapsed if done else 0.0

    def eta_seconds(self, current: int, total: int) -> float:
        if total <= 0 or current <= 0 or current >= total:
            return 0.0
        self._touch_anchor(current)
        rate = self.rate(current)
        if rate <= 0:
            return 0.0
        return (total - current) / rate

    def snapshot(self, *, current: int, total: int,
                 bytes_current: int = 0, bytes_total: int = 0,
                 message: str = "") -> Dict[str, Any]:
        """Build log/progress extra fields for job.emit."""
        pct = round(current * 100 / total, 1) if total else 0.0
        eta = self.eta_seconds(current, total)
        rate = self.rate(current)
        extras: Dict[str, Any] = {
            "phase": self.phase,
            "progress_current": current,
            "progress_total": total,
            "progress_pct": pct,
            "bytes_current": bytes_current,
            "bytes_total": bytes_total,
            "eta_seconds": int(round(eta)) if eta else 0,
            "rate": round(rate, 2),
            "rate_unit": "files/s",
        }
        if bytes_total > 0 and bytes_current > 0:
            byte_rate = 0.0
            if self.anchor_at > 0:
                elapsed = max(3.0, time.time() - self.anchor_at)
                byte_rate = bytes_current / elapsed
            extras["byte_rate"] = int(byte_rate)
            if byte_rate > 0 and bytes_current < bytes_total:
                extras["eta_seconds"] = int(
                    round((bytes_total - bytes_current) / byte_rate))
        if message:
            extras["message"] = message
        return extras


def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    return f"{n / (1024 ** 3):.2f} GB"
