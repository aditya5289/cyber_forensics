"""Case management (lab manual §5.2 – §5.3).

A *case* is the top-level unit of work: an identifier, an investigating
officer, a set of exhibits, and one or more extractions per exhibit.  It
corresponds to XRY's "Let's get started" screen and Case Overview.

On disk::

    <root>/<CASE-ID>/
        case.json
        audit.jsonl                 case-level chain of custody
        exhibits/<EXHIBIT-ID>/      one folder per seized item
            <EXHIBIT>_<stamp>.afc/  extraction containers
        reports/
        notes/

Optional password protection (manual Step 4) derives a key with PBKDF2-HMAC-
SHA256 (600 000 iterations) and stores only the verifier — never the password.
It gates *access through the tool*; it is deliberately not presented as
encryption-at-rest, because pretending a passphrase check is crypto would be
worse than not having it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import AuditLog
from .container import EvidenceContainer, ExtractionMeta
from .errors import CaseError

CASE_FILE = "case.json"
KDF_ITERATIONS = 600_000
ID_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def generate_case_id(prefix: str = "CASE") -> str:
    """Timestamp-based ID, matching XRY's auto-generated default (Step 3)."""
    return f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def safe_id(value: str) -> str:
    cleaned = ID_SAFE.sub("-", (value or "").strip()).strip("-")
    if not cleaned:
        raise CaseError("identifier is empty after sanitisation")
    return cleaned[:96]


@dataclass
class Exhibit:
    """A seized item under examination (manual Step 11: Exhibit ID)."""

    exhibit_id: str
    description: str = ""
    make: str = ""
    model: str = ""
    imei: str = ""
    serial: str = ""
    phone_number: str = ""
    seized_at: str = ""
    seized_by: str = ""
    seized_from: str = ""
    condition: str = ""
    isolation: str = ""            # "Faraday pouch" / "Airplane mode" / "None"
    created_at: str = field(default_factory=lambda:
                            datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Case:
    """Create, open and manage a forensic case."""

    def __init__(self, root: Path | str, data: Dict[str, Any], actor: str = ""):
        self.root = Path(root)
        self.data = data
        self.audit = AuditLog(self.root / "audit.jsonl", actor=actor or None)

    # -------------------------------------------------------------- lifecycle
    @classmethod
    def create(cls, base_dir: Path | str, case_id: Optional[str] = None,
               investigator: str = "", organisation: str = "",
               description: str = "", password: Optional[str] = None,
               actor: str = "") -> "Case":
        """Manual Steps 3–5: enter Case ID, choose location, create case."""
        case_id = safe_id(case_id or generate_case_id())
        root = Path(base_dir) / case_id
        if root.exists():
            raise CaseError(f"case already exists at {root}")
        for sub in ("exhibits", "reports", "notes"):
            (root / sub).mkdir(parents=True, exist_ok=True)

        data: Dict[str, Any] = {
            "case_id": case_id,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "investigator": investigator,
            "organisation": organisation,
            "description": description,
            "status": "open",
            "exhibits": {},
            "protection": None,
            "schema": 2,
        }
        if password:
            data["protection"] = cls._make_verifier(password)

        case = cls(root, data, actor=actor)
        case.save()
        case.audit.record("case.create", {
            "case_id": case_id, "investigator": investigator,
            "organisation": organisation, "protected": bool(password),
            "location": str(root),
        })
        return case

    @classmethod
    def open(cls, path: Path | str, password: Optional[str] = None,
             actor: str = "") -> "Case":
        root = Path(path)
        if root.is_file() and root.name == CASE_FILE:
            root = root.parent
        cf = root / CASE_FILE
        if not cf.exists():
            raise CaseError(f"no case found at {root}")
        data = json.loads(cf.read_text(encoding="utf-8"))
        protection = data.get("protection")
        if protection:
            if password is None:
                raise CaseError(f"case {data['case_id']} is password protected")
            if not cls._check_verifier(protection, password):
                raise CaseError("incorrect case password")
        case = cls(root, data, actor=actor)
        case.audit.record("case.open", {"case_id": data.get("case_id")})
        return case

    def save(self) -> None:
        (self.root / CASE_FILE).write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8")

    # -------------------------------------------------------------- protection
    @staticmethod
    def _make_verifier(password: str) -> Dict[str, Any]:
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 KDF_ITERATIONS)
        return {
            "kdf": "pbkdf2-hmac-sha256",
            "iterations": KDF_ITERATIONS,
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(dk).decode(),
        }

    @staticmethod
    def _check_verifier(protection: Dict[str, Any], password: str) -> bool:
        salt = base64.b64decode(protection["salt"])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 int(protection.get("iterations", KDF_ITERATIONS)))
        return secrets.compare_digest(
            base64.b64encode(dk).decode(), protection["verifier"])

    # ---------------------------------------------------------------- exhibits
    def add_exhibit(self, exhibit: Exhibit) -> Exhibit:
        eid = safe_id(exhibit.exhibit_id)
        exhibit.exhibit_id = eid
        if eid in self.data["exhibits"]:
            raise CaseError(f"exhibit {eid} already registered in this case")
        (self.root / "exhibits" / eid).mkdir(parents=True, exist_ok=True)
        self.data["exhibits"][eid] = exhibit.as_dict()
        self.save()
        self.audit.record("exhibit.register", exhibit.as_dict())
        return exhibit

    def get_exhibit(self, exhibit_id: str) -> Exhibit:
        d = self.data["exhibits"].get(safe_id(exhibit_id))
        if not d:
            raise CaseError(f"no such exhibit: {exhibit_id}")
        return Exhibit(**d)

    def exhibits(self) -> List[Exhibit]:
        return [Exhibit(**d) for d in self.data["exhibits"].values()]

    def exhibit_dir(self, exhibit_id: str) -> Path:
        return self.root / "exhibits" / safe_id(exhibit_id)

    # ------------------------------------------------------------- extractions
    def new_container(self, exhibit_id: str, meta: ExtractionMeta,
                      label: str = "") -> EvidenceContainer:
        """Allocate a fresh, uniquely-named container for an extraction."""
        eid = safe_id(exhibit_id)
        if eid not in self.data["exhibits"]:
            raise CaseError(f"exhibit {eid} is not registered; add it first")
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        prefix = f"{eid}_{safe_id(label) + '_' if label else ''}{stamp}"
        name = f"{prefix}.afc"
        # Two extractions started inside the same second must not collide —
        # the second one would otherwise fail outright and the operator would
        # have to redo the acquisition.
        counter = 2
        while (self.exhibit_dir(eid) / name).exists():
            name = f"{prefix}-{counter}.afc"
            counter += 1
        meta.case_id = self.case_id
        meta.exhibit_id = eid
        container = EvidenceContainer(self.exhibit_dir(eid) / name, mode="w",
                                      meta=meta, actor=self.audit.actor)
        self.audit.record("extraction.begin", {
            "exhibit_id": eid, "container": name,
            "method": meta.method, "operator": meta.operator,
            "time_span": meta.time_span, "categories": meta.categories,
        })
        return container

    def containers(self, exhibit_id: Optional[str] = None) -> List[Path]:
        base = (self.exhibit_dir(exhibit_id) if exhibit_id
                else self.root / "exhibits")
        if not base.exists():
            return []
        return sorted(p for p in base.rglob("*.afc") if p.is_dir())

    def incomplete_extractions(self, exhibit_id: Optional[str] = None,
                               method: str = "") -> List[Dict[str, Any]]:
        from .resume import find_incomplete
        if exhibit_id:
            return find_incomplete(self, exhibit_id, method)
        out: List[Dict[str, Any]] = []
        for ex in self.data.get("exhibits", {}):
            out.extend(find_incomplete(self, ex, method))
        return out

    def open_container(self, path: Path | str,
                       mode: str = "r") -> EvidenceContainer:
        return EvidenceContainer(path, mode=mode, actor=self.audit.actor)

    # ----------------------------------------------------------------- summary
    def overview(self) -> Dict[str, Any]:
        """Case Overview screen data (manual §5.3 / Fig. 5.11)."""
        items = []
        total = 0
        for path in self.containers():
            try:
                manifest = json.loads(
                    (path / "manifest.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            stats = manifest.get("statistics", {}) or {}
            total += int(stats.get("artifacts", 0) or 0)
            from .container import default_zip_path
            zip_p = default_zip_path(path)
            incomplete = (path / "argus-INCOMPLETE.json").exists()
            custody_entries = 0
            custody_path = path / "argus-custody.jsonl"
            if custody_path.exists():
                from .custody import read_entries
                custody_entries = len(read_entries(path))
            items.append({
                "name": path.name,
                "path": str(path),
                "zip_path": str(zip_p) if zip_p.is_file() else "",
                "exhibit_id": manifest.get("extraction", {}).get("exhibit_id", ""),
                "method": manifest.get("extraction", {}).get("method", ""),
                "operator": manifest.get("extraction", {}).get("operator", ""),
                "device": " ".join(filter(None, [
                    manifest.get("extraction", {}).get("device_make", ""),
                    manifest.get("extraction", {}).get("device_model", "")])),
                "created_at": manifest.get("created_at", ""),
                "sealed": manifest.get("sealed", False),
                "incomplete": incomplete,
                "field_custody_entries": custody_entries,
                "status": ("INCOMPLETE" if incomplete
                           else ("Completed" if manifest.get("sealed")
                                 else "In progress")),
                "artifacts": stats.get("artifacts", 0),
                "size_bytes": _dir_size(path),
                "categories": stats.get("categories", {}),
            })
        audit_ok, audit_problems = self.audit.verify()
        return {
            "case_id": self.case_id,
            "created_at": self.data.get("created_at"),
            "investigator": self.data.get("investigator", ""),
            "organisation": self.data.get("organisation", ""),
            "description": self.data.get("description", ""),
            "status": self.data.get("status", "open"),
            "protected": bool(self.data.get("protection")),
            "location": str(self.root),
            "exhibits": [e.as_dict() for e in self.exhibits()],
            "extractions": items,
            "total_artifacts": total,
            "audit_entries": len(self.audit),
            "audit_chain_valid": audit_ok,
            "audit_problems": audit_problems,
        }

    def close_case(self, conclusion: str = "") -> None:
        self.data["status"] = "closed"
        self.data["closed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.data["conclusion"] = conclusion
        self.save()
        self.audit.record("case.close", {"conclusion": conclusion[:500]})

    @property
    def case_id(self) -> str:
        return self.data["case_id"]

    def __repr__(self) -> str:                                # pragma: no cover
        return f"<Case {self.case_id} exhibits={len(self.data['exhibits'])}>"


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def discover_cases(base_dir: Path | str) -> List[Dict[str, Any]]:
    """List every case under a directory without opening protected ones."""
    base = Path(base_dir)
    out: List[Dict[str, Any]] = []
    if not base.exists():
        return out
    for cf in sorted(base.glob(f"*/{CASE_FILE}")):
        try:
            d = json.loads(cf.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({
            "case_id": d.get("case_id"),
            "path": str(cf.parent),
            "created_at": d.get("created_at"),
            "investigator": d.get("investigator", ""),
            "status": d.get("status", "open"),
            "protected": bool(d.get("protection")),
            "exhibits": len(d.get("exhibits", {})),
        })
    return out
