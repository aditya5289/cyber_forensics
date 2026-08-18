"""Field-tool chain of custody — PS1-compatible ``argus-custody.jsonl``.

The PowerShell field tool and the Python workbench can both touch the same
exhibit. This module speaks the field format so custody is one narrative, not
two unrelated logs an examiner has to reconcile in court.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import __version__

CUSTODY_FILE = "argus-custody.jsonl"
GENESIS = "0" * 64


def _now_field() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")


def _body_without_hash(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in entry.items() if k != "hash"}


def _hash_entry(entry: Dict[str, Any]) -> str:
    body = json.dumps(_body_without_hash(entry), ensure_ascii=False,
                      separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def append_entry(root: Path | str, action: str,
                 detail: Optional[Dict[str, Any]] = None,
                 operator: str = "",
                 tool: str = "") -> Dict[str, Any]:
    """Append one hash-chained entry compatible with ``ARGUS.ps1``."""
    root = Path(root)
    log_path = root / CUSTODY_FILE
    prev = GENESIS
    seq = 0
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    last = json.loads(line)
                    prev = str(last.get("hash", GENESIS))
                    seq = int(last.get("seq", 0))
                except json.JSONDecodeError:
                    continue

    entry: Dict[str, Any] = {
        "seq": seq + 1,
        "at": _now_field(),
        "operator": operator or getpass.getuser(),
        "host": socket.gethostname(),
        "tool": tool or f"ARGUS Workbench {__version__}",
        "action": action,
        "detail": detail or {},
        "prev_hash": prev,
    }
    entry["hash"] = _hash_entry(entry)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_chain(root: Path | str) -> Dict[str, Any]:
    """Verify a field custody log. Returns ``ok``, ``entries``, ``problems``."""
    log_path = Path(root) / CUSTODY_FILE
    if not log_path.exists():
        return {"ok": True, "entries": 0, "problems": [],
                "note": "no field custody log present"}

    problems: List[str] = []
    prev = GENESIS
    count = 0
    for index, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {index}: invalid JSON")
            continue
        if entry.get("prev_hash") != prev:
            problems.append(f"entry {index}: previous hash mismatch")
        stated = entry.get("hash", "")
        expected = _hash_entry(entry)
        if stated != expected:
            problems.append(f"entry {index}: hash does not match body")
        prev = stated or prev

    return {"ok": not problems, "entries": count, "problems": problems,
            "path": str(log_path)}


def read_entries(root: Path | str, limit: int = 200) -> List[Dict[str, Any]]:
    log_path = Path(root) / CUSTODY_FILE
    if not log_path.exists():
        return []
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    out: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def find_in_tree(root: Path) -> Optional[Path]:
    """Locate a field custody log under an imported folder."""
    direct = root / CUSTODY_FILE
    if direct.exists():
        return direct
    for candidate in root.rglob(CUSTODY_FILE):
        if candidate.is_file():
            return candidate
    return None


def import_field_log(source: Path, dest: Path) -> Tuple[Optional[Path], Dict[str, Any]]:
    """Copy and verify a field custody log found during import."""
    found = find_in_tree(source)
    if not found:
        return None, {"imported": False}
    target = dest / CUSTODY_FILE
    if not target.exists():
        target.write_text(found.read_text(encoding="utf-8"), encoding="utf-8")
    report = verify_chain(dest)
    report["imported"] = True
    report["source"] = str(found)
    return target, report
