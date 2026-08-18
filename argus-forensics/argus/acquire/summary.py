"""Build structured acquisition summaries from on-disk manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def build_acquisition_summary(raw_root: Path,
                              method: str = "") -> Dict[str, Any]:
    """Summarise what was acquired before decode — for UI and audit."""
    summary: Dict[str, Any] = {
        "method": method,
        "adb": {},
        "mtp": {},
        "comms_providers": [],
        "comms_row_total": 0,
        "sources_pulled": 0,
        "sources_failed": 0,
        "data_types": {},
    }

    adb_path = raw_root / "argus-adb-manifest.json"
    adb = _read_json(adb_path)
    if adb:
        sm = adb.get("summary") or {}
        summary["adb"] = {
            "passes": adb.get("passes") or [],
            "pulled": sm.get("pulled", 0),
            "skipped": sm.get("skipped", 0),
            "failed": sm.get("failed", 0),
            "bytes": sm.get("bytes", 0),
        }
        summary["sources_pulled"] += int(sm.get("pulled") or 0)
        summary["sources_failed"] += int(sm.get("failed") or 0)
        providers = adb.get("providers") or []
        summary["comms_providers"] = providers
        summary["comms_row_total"] = sum(
            int(p.get("rows") or 0) for p in providers)

    mtp_path = raw_root / "argus-mtp-manifest.json"
    mtp = _read_json(mtp_path)
    if mtp:
        summary["mtp"] = {
            "files_listed": mtp.get("files_listed", 0),
            "files_copied": mtp.get("files_copied", 0),
            "bytes_copied": mtp.get("bytes_copied", 0),
            "missing": len(mtp.get("missing") or []),
            "volumes": mtp.get("volumes") or [],
        }
        summary["sources_pulled"] += int(mtp.get("files_copied") or 0)

    # Count logical dump files on disk
    content_dir = raw_root / "logical" / "content"
    comms_logical = raw_root / "comms_logical" / "content"
    for base in (content_dir, comms_logical):
        if not base.is_dir():
            continue
        for dump in base.glob("*.txt"):
            try:
                text = dump.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rows = text.count("Row:")
            if rows:
                key = dump.stem
                summary["data_types"][key] = rows

    contacts_export = raw_root / "contacts_export"
    if contacts_export.is_dir():
        for dump in contacts_export.glob("*.txt"):
            try:
                rows = dump.read_text(encoding="utf-8", errors="replace").count("Row:")
            except OSError:
                rows = 0
            if rows:
                summary["data_types"][f"export_{dump.stem}"] = rows

    db_dir = raw_root / "databases"
    if db_dir.is_dir():
        dbs = [p for p in db_dir.rglob("*") if p.is_file()]
        summary["data_types"]["databases"] = len(dbs)

    dumpsys_dir = raw_root / "dumpsys"
    if dumpsys_dir.is_dir():
        summary["data_types"]["dumpsys_files"] = sum(
            1 for p in dumpsys_dir.glob("*.txt") if p.stat().st_size > 40)

    return summary


def write_acquisition_summary(raw_root: Path, method: str = "") -> Path:
    """Persist summary next to raw evidence."""
    summary = build_acquisition_summary(raw_root, method=method)
    target = raw_root / "argus-acquisition-summary.json"
    target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return target
