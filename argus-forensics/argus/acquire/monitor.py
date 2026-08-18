"""Live device health monitoring during long extractions."""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Callable, Optional


class ExtractionMonitor:
    """Poll ADB battery and connection state while extraction runs."""

    def __init__(self, serial: Optional[str],
                 log: Optional[Callable[..., None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None,
                 interval: int = 120):
        self.serial = serial
        self.log = log
        self.cancel_check = cancel_check
        self.interval = max(60, interval)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._low_battery_warned = False
        self._disconnect_warned = False

    def start(self) -> None:
        if not self.serial or self._thread:
            return
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-extraction-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        from .android_adb import AdbSession, ensure_device_ready, get_device_state

        while not self._stop.wait(self.interval):
            if self.cancel_check and self.cancel_check():
                return
            state = get_device_state(self.serial or "")
            if state != "device":
                if not self._disconnect_warned and self.log:
                    self.log("device", "warning",
                             f"Handset went {state} during extraction — "
                             f"keep USB connected and screen unlocked",
                             level="warning")
                    self._disconnect_warned = True
                ensure_device_ready(AdbSession(self.serial or ""), self.log,
                                    restart=True, timeout=30)
                if get_device_state(self.serial or "") == "device":
                    self._disconnect_warned = False
                    if self.log:
                        self.log("device", "ok", "ADB connection restored")
                    try:
                        from .android_adb import enable_keep_awake
                        enable_keep_awake(AdbSession(self.serial or ""), self.log)
                    except Exception:
                        pass
                continue
            self._disconnect_warned = False
            try:
                session = AdbSession(self.serial or "")
                raw = session.shell("dumpsys battery", timeout=30)
                m = re.search(r"level:\s*(\d+)", raw)
                if not m:
                    continue
                level = int(m.group(1))
                charging = "status=2" in raw or "AC powered: true" in raw
                if level < 15 and not charging and not self._low_battery_warned:
                    self._low_battery_warned = True
                    if self.log:
                        self.log("device", "warning",
                                 f"Battery at {level}% and not charging — "
                                 f"connect power to avoid interruption",
                                 level="warning")
                elif level >= 25:
                    self._low_battery_warned = False
                elif self.log and level % 20 == 0:
                    self.log("device", "note",
                             f"Battery {level}%"
                             + (" (charging)" if charging else ""),
                             level="info")
                try:
                    df = session.shell("df /data /sdcard 2>/dev/null | tail -n +2",
                                       timeout=20)
                    low = False
                    for line in df.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[-1].rstrip("%").isdigit():
                            if int(parts[-1].rstrip("%")) >= 92:
                                low = True
                                break
                    if low and self.log:
                        self.log("device", "warning",
                                 "Device storage nearly full — large pulls may fail",
                                 level="warning")
                except Exception:
                    pass
            except Exception:
                pass


class MtpExtractionMonitor:
    """Poll MTP handset visibility and copy stall during file-transfer runs."""

    def __init__(self, device_name: str,
                 destination: Optional[Path | str] = None,
                 log: Optional[Callable[..., None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None,
                 interval: int = 45):
        self.device_name = device_name
        self.destination = Path(destination) if destination else None
        self.log = log
        self.cancel_check = cancel_check
        self.interval = max(30, interval)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._disconnect_warned = False
        self._stall_warned = False
        self._last_files = -1
        self._last_growth = time.time()

    def start(self) -> None:
        if not self.device_name or self._thread:
            return
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-mtp-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _device_present(self) -> bool:
        from . import mtp

        if not mtp.available():
            return True
        want = self.device_name.lower()
        for dev in mtp.devices():
            name = dev.name.lower()
            if name == want or want in name or name in want:
                return True
        return False

    def _file_count(self) -> int:
        if not self.destination:
            return 0
        from .mtp import _count_files, _load_checkpoint

        ck = _load_checkpoint(self.destination, self.device_name)
        if ck and ck.get("files_on_disk") is not None:
            return int(ck["files_on_disk"])
        return _count_files(self.destination)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            if self.cancel_check and self.cancel_check():
                return
            if not self._device_present():
                if not self._disconnect_warned and self.log:
                    self.log("mtp.session", "warning",
                             "Handset disappeared from MTP — keep USB on File "
                             "transfer, screen unlocked, cable seated",
                             level="warning")
                    self._disconnect_warned = True
                continue
            if self._disconnect_warned and self.log:
                self.log("mtp.session", "ok", "MTP handset visible again")
                self._disconnect_warned = False

            try:
                files = self._file_count()
            except Exception:
                continue
            if files > self._last_files:
                self._last_files = files
                self._last_growth = time.time()
                self._stall_warned = False
            elif files == self._last_files and files > 0:
                stall = time.time() - self._last_growth
                if stall >= 120 and not self._stall_warned and self.log:
                    self.log("mtp.session", "warning",
                             f"Copy may be stalled ({files:,} files on disk, "
                             f"no growth for {int(stall)}s) — keep screen unlocked",
                             level="warning")
                    self._stall_warned = True
