"""God-level device scanning — parallel, unified, and actionable.

A forensic workstation may have adb, MTP, iOS, and raw USB bus entries all
describing the same physical handset. Showing four cards for one phone sends the
examiner down the wrong path; hiding MTP because adb is ``unauthorized`` hides
the only acquisition route that works right now.

This module runs every detector in parallel, merges duplicates into one
physical-device view, attaches vendor-specific guidance, and recommends the
best acquisition method for each handset's *current* state.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .detect import (
    DetectedDevice,
    _detect_mtp_devices,
    _normalize_serial_key,
    _serial_usb_fragment,
    detect_android,
    detect_ios,
    toolchain_status,
)
from .diagnose import STATE_MEANING, vendor_guidance_for


@dataclass
class ScanStage:
    """One step in a scan, with timing for the UI."""

    name: str
    label: str
    status: str = "pending"          # pending | running | done | skipped | error
    elapsed_ms: int = 0
    count: int = 0
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "count": self.count,
            "detail": self.detail,
        }


@dataclass
class _Timed:
    """A detector's result alongside how long that detector itself took."""

    value: Any = None
    elapsed_ms: int = 0
    error: Optional[BaseException] = None


def _timed(fn: Any, *args: Any) -> _Timed:
    """Run *fn*, timing the call itself.

    Timing a parallel stage from the main thread measures when its result was
    collected, not how long it ran: whichever detector was read second had
    already finished and was reported as taking ~0 ms. The clock belongs
    inside the worker.
    """
    start = time.perf_counter()
    try:
        value, error = fn(*args), None
    except Exception as exc:                              # pragma: no cover
        value, error = None, exc
    return _Timed(value=value,
                  elapsed_ms=int((time.perf_counter() - start) * 1000),
                  error=error)


def _instance_id(serial: str) -> str:
    """USB instance id shared between adb serial and MTP shell paths."""
    frag = _serial_usb_fragment(serial)
    if frag.startswith("usb#"):
        parts = frag.split("#")
        if len(parts) >= 3:
            return parts[2].lower()
    key = _normalize_serial_key(serial)
    if key and not key.startswith("::") and "usb#vid_" not in key:
        return key
    return ""


def _physical_key(device: DetectedDevice) -> str:
    """Stable key for merging adb + MTP views of the same handset."""
    for candidate in (
        device.serial,
        (device.raw or {}).get("mtp_path", ""),
    ):
        inst = _instance_id(candidate)
        if inst:
            return f"inst:{inst}"
    frag = _serial_usb_fragment(device.serial)
    if frag:
        return f"usb:{frag.lower()}"
    make = (device.make or "").strip().lower()
    model = (device.model or device.marketing_name or "").strip().lower()
    if model and len(model) > 2:
        return f"name:{make}:{model}"
    return f"solo:{device.transport}:{_normalize_serial_key(device.serial)}"


def _rank_device(device: DetectedDevice) -> Tuple[int, int]:
    """Lower is better — prefer ready adb, then ready mtp, then blocked adb."""
    ready = bool((device.raw or {}).get("ready", True))
    transport_rank = {"adb": 0, "usbmux": 1, "mtp": 2}.get(device.transport, 9)
    if device.transport == "adb" and ready:
        return (0, transport_rank)
    if device.transport == "mtp" and ready:
        return (1, transport_rank)
    if device.transport == "adb":
        return (2, transport_rank)
    if ready:
        return (3, transport_rank)
    return (4, transport_rank)


def _merge_group(group: List[DetectedDevice]) -> DetectedDevice:
    """Collapse multiple transport views into one examiner-facing card."""
    if len(group) == 1:
        return group[0]

    ordered = sorted(group, key=_rank_device)
    primary = ordered[0]
    raw = dict(primary.raw or {})
    alternates: List[Dict[str, Any]] = []

    for other in ordered[1:]:
        alternates.append({
            "transport": other.transport,
            "serial": other.serial,
            "ready": (other.raw or {}).get("ready", True),
            "adb_state": (other.raw or {}).get("adb_state", ""),
            "mtp_name": (other.raw or {}).get("mtp_name", ""),
        })
        if other.transport == "adb" and not raw.get("adb_state"):
            raw["adb_state"] = (other.raw or {}).get("adb_state", "")
            raw["meaning"] = (other.raw or {}).get("meaning", "")
            raw["hint"] = (other.raw or {}).get("hint", "")
        if other.transport == "mtp":
            raw.setdefault("mtp_path", (other.raw or {}).get("mtp_path", ""))
            raw.setdefault("mtp_name", (other.raw or {}).get("mtp_name", ""))

    raw["alternate_transports"] = alternates
    raw["merged_count"] = len(group)
    raw["transports"] = [d.transport for d in ordered]

    return DetectedDevice(
        transport=primary.transport,
        serial=primary.serial,
        make=primary.make or next((d.make for d in ordered if d.make), ""),
        model=primary.model or next((d.model for d in ordered if d.model), ""),
        marketing_name=primary.marketing_name or next(
            (d.marketing_name for d in ordered if d.marketing_name), ""),
        os_family=primary.os_family,
        os_version=primary.os_version or next(
            (d.os_version for d in ordered if d.os_version), ""),
        build_id=primary.build_id,
        chipset=primary.chipset,
        imei=primary.imei or next((d.imei for d in ordered if d.imei), ""),
        iccid=primary.iccid,
        phone_number=primary.phone_number,
        lock_state=primary.lock_state,
        trusted=primary.trusted,
        rooted=primary.rooted,
        encrypted=primary.encrypted,
        battery=primary.battery if primary.battery is not None else next(
            (d.battery for d in ordered if d.battery is not None), None),
        raw=raw,
    )


def _merge_devices(devices: List[DetectedDevice]) -> List[DetectedDevice]:
    buckets: Dict[str, List[DetectedDevice]] = {}
    for device in devices:
        buckets.setdefault(_physical_key(device), []).append(device)
    merged = [_merge_group(g) for g in buckets.values()]
    merged.sort(key=lambda d: (_rank_device(d), d.name.lower()))
    return merged


def _recommend(device: DetectedDevice) -> None:
    """Attach acquisition guidance to device.raw."""
    raw = device.raw
    transport = device.transport
    ready = raw.get("ready", True)
    adb_state = raw.get("adb_state", "")
    alternates = raw.get("alternate_transports") or []
    has_ready_adb = (
        transport == "adb" and ready
    ) or any(a.get("transport") == "adb" and a.get("ready") for a in alternates)
    has_mtp = transport == "mtp" or any(
        a.get("transport") == "mtp" for a in alternates)

    if device.os_family == "iOS" or (device.make or "").lower() == "apple":
        raw["recommended_method"] = "backup"
        raw["recommended_action"] = (
            "Apple device — logical iTunes-style backup (messages, calls, "
            "app data that allows backup). Keep the handset unlocked and tap "
            "Trust. If libimobiledevice is missing, ARGUS will copy Camera "
            "Roll via This PC or reuse an existing iTunes backup.")
        raw["scan_tier"] = "full" if device.os_version else "quick"
        return

    if has_ready_adb:
        raw["recommended_method"] = "comprehensive"
        raw["recommended_action"] = (
            "USB debugging authorised — Comprehensive is the fullest live "
            "extraction (logical, app DBs, filesystem, APKs). Use Physical "
            "if the handset has a root shell.")
        raw["scan_tier"] = "full"
        return

    if has_mtp and ready:
        raw["recommended_method"] = "mtp"
        raw["recommended_action"] = (
            "File-transfer (MTP) mode — copies every volume the phone exposes "
            "(Internal storage, SD card). Enable USB debugging for app "
            "databases under /data/data.")
        raw["scan_tier"] = "quick" if not device.os_version else "full"
        return

    if adb_state == "unauthorized":
        raw["recommended_method"] = "sim"
        raw["recommended_action"] = (
            "Handset connected but not trusted — unlock screen and accept "
            "the USB debugging prompt. Tick 'Always allow'. If the phone "
            "is BFU and will not unlock, import a SIM/USIM dump "
            "(Messages → SIM dump) for card-resident SMS and contacts.")
        meaning, fix = STATE_MEANING.get("unauthorized", ("", ""))
        raw.setdefault("meaning", meaning)
        raw.setdefault("hint", fix)
        raw["scan_tier"] = "blocked"
        return

    if adb_state == "offline":
        raw["recommended_method"] = has_mtp and "mtp" or ""
        raw["recommended_action"] = (
            "adb offline — switch USB mode to File transfer (MTP) from the "
            "notification shade, then replug.")
        raw["scan_tier"] = "blocked"
        return

    if not ready:
        raw["recommended_method"] = "sim"
        raw["recommended_action"] = (
            "Handset is not ready for a live extraction. If the case is BFU "
            "or the phone is destroyed, import a SIM/USIM reader dump "
            "(Messages → SIM dump). Screenshot documentation remains available "
            "as photographs imported as evidence.")
        raw["scan_tier"] = "blocked"
        return

    raw["recommended_method"] = transport or ""
    raw["recommended_action"] = "Ready for acquisition."
    raw["scan_tier"] = "full"


def _attach_vendor_hints(device: DetectedDevice) -> None:
    hints = vendor_guidance_for(device.make or device.name)
    if hints:
        device.raw["vendor_hints"] = hints


def _enrich_from_bus(devices: List[DetectedDevice],
                     bus: List[Any]) -> None:
    """Stamp USB VID/PID facts onto MTP cards that only had a display name."""
    from .identity import parse_usb_ids, vendor_for_vid, mode_for_pid

    by_vidpid: Dict[Tuple[str, str], Any] = {}
    for item in bus:
        vid = (getattr(item, "vendor_id", "") or "").lower()
        pid = (getattr(item, "product_id", "") or "").lower()
        if vid and pid:
            by_vidpid[(vid, pid)] = item

    for device in devices:
        raw = device.raw
        vid = (raw.get("usb_vid") or "").lower()
        pid = (raw.get("usb_pid") or "").lower()
        if not vid:
            vid, pid = parse_usb_ids(device.serial or raw.get("mtp_path", ""))
            if vid:
                raw["usb_vid"] = vid
                raw["usb_pid"] = pid
                raw["usb_vendor"] = vendor_for_vid(vid)
                raw["usb_mode"] = mode_for_pid(pid)
        hit = by_vidpid.get((vid, pid))
        if hit is None:
            continue
        raw["usb_description"] = getattr(hit, "description", "")
        raw["usb_mode_name"] = getattr(hit, "mode_name", "") or raw.get("usb_mode", "")
        if getattr(hit, "mode_note", ""):
            raw["usb_mode_note"] = hit.mode_note
        if not device.make and getattr(hit, "vendor", ""):
            device.make = hit.vendor.split("/")[0].strip()
            raw["usb_vendor"] = hit.vendor
        raw["confidence"] = "usb+bus" if device.transport == "mtp" else raw.get(
            "confidence", "full")


def _bus_diagnostics(on_bus: Optional[List[Any]] = None
                     ) -> Tuple[List[str], int]:
    """USB bus facts when no forensic tool answered.

    *on_bus* is the enumeration the scan already performed. Re-querying it
    here meant a second full ``Get-PnpDevice`` sweep on exactly the path where
    nothing was found — the one where the examiner is already waiting.
    """
    diagnostics: List[str] = []
    bus_count = 0
    try:
        from .bus import fastboot_devices, mobile_devices_on_bus, volumes
        if on_bus is None:
            on_bus = mobile_devices_on_bus()
        bus_count = len(on_bus)
        in_fastboot = fastboot_devices()
        evidence_volumes = [v for v in volumes() if v.looks_like_evidence]

        if on_bus:
            names = ", ".join(sorted({d.vendor for d in on_bus}))
            diagnostics.append(
                f"USB reports hardware from {names} attached to this machine, "
                f"so the cable and port are working. The handset is present "
                f"but not answering — the problem is USB debugging, the "
                f"connection mode, or the driver, not the physical link.")
            for device in on_bus:
                if device.mode_note:
                    diagnostics.append(f"{device.vendor}: {device.mode_note}")

        if in_fastboot:
            diagnostics.append(
                f"{len(in_fastboot)} handset(s) are in bootloader/fastboot "
                f"mode, where adb does not operate. Reboot to the system for a "
                f"logical acquisition.")

        if evidence_volumes:
            paths = ", ".join(v.path for v in evidence_volumes[:4])
            diagnostics.append(
                f"Mounted volume(s) containing handset or memory-card "
                f"directories: {paths}. These can be imported directly with no "
                f"adb involved.")
    except Exception:                                     # pragma: no cover
        pass
    return diagnostics, bus_count


def _toolchain_diagnostics(tools: Dict[str, Any]) -> List[str]:
    missing = [name for name in ("adb", "libimobiledevice")
               if not tools[name]["available"]]
    diagnostics: List[str] = []
    for name in missing:
        family = "Android" if name == "adb" else "iOS"
        diagnostics.append(
            f"{name} is not installed, so a connected {family} handset "
            f"cannot be detected. To install: "
            f"{tools[name]['install_hint']}")
    if len(missing) < 2:
        diagnostics.append(
            "Toolchain present but no handset responded. Check the data "
            "cable (a charge-only cable will not enumerate), confirm USB "
            "debugging / pairing, and confirm the device is powered on.")
    diagnostics.append(
        "Neither tool is required to import an extraction that already "
        "exists on disk — a folder pulled from the device, an iTunes "
        "backup, a UFDR, a .tar or a .zip. Choose Import on the next step. "
        "Live acquisition is the only thing they unlock.")
    return diagnostics


def scan_devices(*, deep: bool = True, refresh_adb: bool = False) -> Dict[str, Any]:
    """Parallel multi-transport scan with merge, timing, and recommendations."""
    t0 = time.perf_counter()
    stages: List[ScanStage] = []

    if refresh_adb:
        from .detect import find_tool, _run
        adb = find_tool("adb")
        if adb:
            _run([adb, "kill-server"], timeout=5)
            _run([adb, "start-server"], timeout=10)

    tools = toolchain_status()
    stage_tools = ScanStage(name="toolchain", label="Toolchain",
                            status="done", count=int(tools["adb"]["available"])
                            + int(tools["libimobiledevice"]["available"]))
    stages.append(stage_tools)

    android: List[DetectedDevice] = []
    ios: List[DetectedDevice] = []
    mtp: List[DetectedDevice] = []
    bus_hardware: List[Any] = []

    def _scan_bus() -> List[Any]:
        from .bus import mobile_devices_on_bus
        return mobile_devices_on_bus()

    def _stage(name: str, label: str, outcome: _Timed) -> ScanStage:
        """Build a stage from a worker's own timing, not the collection order."""
        stage = ScanStage(name=name, label=label,
                          elapsed_ms=outcome.elapsed_ms)
        if outcome.error is not None:                     # pragma: no cover
            stage.status = "error"
            stage.detail = str(outcome.error)
        else:
            stage.status = "done"
            stage.count = len(outcome.value or [])
        return stage

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_android = pool.submit(_timed, detect_android, deep)
        f_ios = pool.submit(_timed, detect_ios)
        # The bus query takes no input from the other detectors and is a
        # read-only OS enumeration, so it has no reason to wait behind them —
        # it used to run last, on its own, after everything else had finished.
        f_bus = pool.submit(_timed, _scan_bus)

        android_out, ios_out = f_android.result(), f_ios.result()
        android = android_out.value or []
        ios = ios_out.value or []
        stages.append(_stage("android", "Android (adb)", android_out))
        stages.append(_stage("ios", "iOS (usbmux)", ios_out))

        # MTP keys off what adb and usbmux already claimed, so it cannot start
        # until those land. Running it here keeps it overlapped with the bus
        # query still in flight rather than serialised after it.
        mtp_out = _timed(_detect_mtp_devices, android + ios)
        mtp = mtp_out.value or []
        stages.append(_stage("mtp", "MTP (file transfer)", mtp_out))

        bus_out = f_bus.result()
        bus_hardware = bus_out.value or []
        stages.append(_stage("bus", "USB bus", bus_out))
    # An empty list means the bus was read and held nothing; a failed read
    # means we do not know, and the diagnostics below should ask again rather
    # than report "no hardware attached" on the strength of an exception.
    bus_known = bus_out.error is None

    t_merge = time.perf_counter()
    combined = android + ios + mtp
    _enrich_from_bus(combined, bus_hardware)
    merged = _merge_devices(combined)
    for device in merged:
        _recommend(device)
        _attach_vendor_hints(device)
    merge_stage = ScanStage(name="merge", label="Unify & recommend",
                            status="done", count=len(merged),
                            elapsed_ms=int((time.perf_counter() - t_merge) * 1000))
    stages.append(merge_stage)

    ready = [d for d in merged if (d.raw or {}).get("ready", True)]
    blocked = [d for d in merged if not (d.raw or {}).get("ready", True)]

    diagnostics: List[str] = []
    if not merged:
        bus_diag, _bus_count = _bus_diagnostics(
            bus_hardware if bus_known else None)
        diagnostics.extend(bus_diag)
        diagnostics.extend(_toolchain_diagnostics(tools))
    elif bus_hardware and not any(d.transport == "mtp" for d in merged):
        for item in bus_hardware:
            if getattr(item, "mode_note", ""):
                diagnostics.append(f"{item.vendor}: {item.mode_note}")

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    by_transport: Dict[str, int] = {}
    for d in merged:
        for t in (d.raw or {}).get("transports", [d.transport]):
            by_transport[t] = by_transport.get(t, 0) + 1

    return {
        "devices": [d.as_dict() for d in merged],
        "count": len(merged),
        "ready_count": len(ready),
        "blocked_count": len(blocked),
        "toolchain": tools,
        "diagnostics": diagnostics,
        "scan": {
            "deep": deep,
            "refresh_adb": refresh_adb,
            "elapsed_ms": elapsed_ms,
            "stages": [s.as_dict() for s in stages],
            "by_transport": by_transport,
            "merged_from": len(combined),
            "physical_devices": len(merged),
            "usb_hardware": [d.as_dict() if hasattr(d, "as_dict") else d
                             for d in bus_hardware],
        },
    }
