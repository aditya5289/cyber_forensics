"""Resume interrupted live acquisitions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .container import EvidenceContainer

INCOMPLETE_MARKER = "argus-INCOMPLETE.json"


def read_marker(container_path: Path) -> Optional[Dict[str, Any]]:
    marker = Path(container_path) / INCOMPLETE_MARKER
    if not marker.exists():
        return None
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"format": "argus-incomplete/1", "warning": "corrupt marker"}


def find_incomplete(case, exhibit_id: str,
                    method: str = "") -> List[Dict[str, Any]]:
    """Return incomplete containers for an exhibit, newest first."""
    from .case import Case

    if not isinstance(case, Case):
        raise TypeError("case must be a Case instance")
    hits: List[Dict[str, Any]] = []
    for path in case.containers(exhibit_id):
        marker = read_marker(path)
        if not marker:
            continue
        if method and marker.get("method") not in ("", method):
            continue
        if EvidenceContainer(path, mode="r").sealed:
            continue
        hits.append({
            "path": str(path),
            "name": path.name,
            "marker": marker,
            "method": marker.get("method", ""),
            "started_at": marker.get("started_at", ""),
            "operator": marker.get("operator", ""),
            "device": marker.get("device", ""),
        })
    hits.sort(key=lambda h: h.get("started_at", ""), reverse=True)
    return hits


def open_for_resume(case, container_path: Path | str,
                    operator: str = "") -> EvidenceContainer:
    """Re-open an incomplete container for append-mode acquisition."""
    path = Path(container_path)
    marker = read_marker(path)
    if not marker:
        raise ValueError(f"container is not marked incomplete: {path}")
    container = case.open_container(path, mode="a")
    if container.sealed:
        raise ValueError(f"container is sealed and cannot be resumed: {path}")
    return container
