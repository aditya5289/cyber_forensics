"""Live USB bus watcher — detect connect and disconnect transitions.

A one-shot scan answers "is anything there now", which is the wrong question
while the handset is still in the examiner's hand. Watching reports the moment
a device enumerates or disappears.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .detect import detect_all


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class WatchEvent:
    kind: str                    # connected | disconnected | mtp | diagnostic
    message: str
    device: Dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_utc)

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "message": self.message,
                "device": self.device, "ts": self.ts}


class DeviceWatcher:
    """Poll ``detect_all()`` and emit transition events."""

    def __init__(self, history_limit: int = 100):
        self._lock = threading.Lock()
        self._seen: Set[str] = set()
        self._events: List[WatchEvent] = []
        self._history_limit = history_limit
        self._last_poll = ""
        self._bootstrapped = False

    def _key(self, device: Dict[str, Any]) -> str:
        transport = device.get("transport", "")
        serial = device.get("serial", "") or device.get("name", "")
        return f"{transport}:{serial}"

    def poll(self) -> Dict[str, Any]:
        snap = detect_all()
        devices = snap.get("devices", [])
        keys = {self._key(d) for d in devices}
        new_events: List[WatchEvent] = []

        with self._lock:
            if not self._bootstrapped:
                self._seen = set(keys)
                self._bootstrapped = True
                if devices:
                    new_events.append(WatchEvent(
                        "diagnostic", f"{len(devices)} device(s) already connected"))
            else:
                for device in devices:
                    key = self._key(device)
                    if key not in self._seen:
                        label = device.get("name") or device.get("model") or key
                        transport = device.get("transport", "")
                        kind = "mtp" if transport == "mtp" else "connected"
                        new_events.append(WatchEvent(
                            kind, f"Handset connected: {label} ({transport})",
                            device=device))
                for key in list(self._seen):
                    if key not in keys:
                        new_events.append(WatchEvent(
                            "disconnected", f"Handset removed: {key}"))

            self._seen = keys
            self._events.extend(new_events)
            if len(self._events) > self._history_limit:
                self._events = self._events[-self._history_limit:]
            self._last_poll = _utc()

            return {
                "devices": devices,
                "count": len(devices),
                "diagnostics": snap.get("diagnostics", []),
                "toolchain": snap.get("toolchain", {}),
                "events": [e.as_dict() for e in new_events],
                "history": [e.as_dict() for e in self._events[-40:]],
                "polled_at": self._last_poll,
            }

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()
            self._events.clear()
            self._bootstrapped = False
