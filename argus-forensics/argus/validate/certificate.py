"""Evidence certificate — a self-contained, verifiable integrity statement.

The problem this solves: an examiner hands over a report and a copy of the
evidence. Six months later, in a hearing, someone asks whether the evidence
still matches what was examined. Answering that should not require the original
workstation, the original software, or trust in either.

A certificate is a single JSON document containing every digest, the container
seal, the custody-chain tip and the tool's validated error rates at the time of
examination. :func:`verify_certificate` re-checks it against evidence on disk
using nothing but the standard library, so an opposing expert can confirm or
refute it independently.

On signing: the certificate is sealed with an HMAC-SHA256 over its canonical
form. This detects alteration by anyone without the key. It is **not** a
digital signature and does not prove authorship to a third party who lacks the
key — asymmetric signing would be needed for that. The distinction is stated in
the certificate itself rather than left for a reader to assume, because
overstating what a seal proves is exactly the kind of claim that collapses
under cross-examination.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__

CERTIFICATE_VERSION = "1.0"


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ExaminerNote:
    """A recorded observation, attributable and timestamped."""

    author: str
    text: str
    created_at: str = field(default_factory=_utc)
    artifact_ids: List[str] = field(default_factory=list)
    kind: str = "observation"        # observation | conclusion | review

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_certificate(container_paths: Sequence[Path | str],
                      examiner: str = "",
                      organisation: str = "",
                      reference: str = "",
                      notes: Optional[Sequence[ExaminerNote]] = None,
                      validation: Optional[Dict[str, Any]] = None,
                      peer_reviewer: str = "",
                      key: Optional[bytes] = None) -> Dict[str, Any]:
    """Produce a certificate for one or more sealed containers."""
    from ..core.container import EvidenceContainer
    from ..core.hashing import hash_file

    containers: List[Dict[str, Any]] = []
    for raw_path in container_paths:
        path = Path(raw_path)
        container = EvidenceContainer(path, mode="r")
        try:
            verification = container.verify(deep=True)
            manifest = container.manifest
            seal = manifest.get("seal") or {}
            extraction = manifest.get("extraction") or {}
            stats = manifest.get("statistics") or {}
            audit_ok, audit_problems = container.audit.verify()

            blob_digests = sorted(p.name for p in container.iter_blobs())
            containers.append({
                "name": path.name,
                "path": str(path),
                "sealed": manifest.get("sealed", False),
                "sealed_at": manifest.get("sealed_at", ""),
                "case_id": extraction.get("case_id", ""),
                "exhibit_id": extraction.get("exhibit_id", ""),
                "operator": extraction.get("operator", ""),
                "method": extraction.get("method", ""),
                "device": {k: extraction.get(k, "") for k in
                           ("device_make", "device_model", "device_os",
                            "device_serial", "imei", "iccid")},
                "artifact_count": stats.get("artifacts", 0),
                "categories": stats.get("categories", {}),
                "recovery": stats.get("recovery", {}),
                "seal": {
                    "container_seal": seal.get("container_seal", ""),
                    "blob_merkle_root": seal.get("blob_merkle_root", ""),
                    "blob_count": seal.get("blob_count", 0),
                    "artifacts_db_sha256": seal.get("artifacts_db_sha256", ""),
                    "artifacts_db_size": seal.get("artifacts_db_size", 0),
                },
                "manifest_sha256": hash_file(path / "manifest.json").sha256,
                "audit": {
                    "entries": len(container.audit),
                    "tip": container.audit.tip,
                    "chain_valid": audit_ok,
                    "problems": audit_problems,
                },
                "verification_at_issue": {
                    "ok": verification["ok"],
                    "blobs_checked": verification["blobs_checked"],
                    "problems": verification["problems"],
                },
                "blob_digests_sha256": blob_digests,
            })
        finally:
            container.close()

    body: Dict[str, Any] = {
        "certificate_version": CERTIFICATE_VERSION,
        "issued_at": _utc(),
        "tool": {
            "name": "ARGUS Forensics",
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "host": platform.node(),
        },
        "examination": {
            "examiner": examiner,
            "organisation": organisation,
            "reference": reference,
            "peer_reviewer": peer_reviewer,
            "peer_reviewed": bool(peer_reviewer),
        },
        "containers": containers,
        "all_containers_verified": all(
            c["verification_at_issue"]["ok"] for c in containers),
        "examiner_notes": [n.as_dict() for n in (notes or ())],
        "validation": _validation_extract(validation),
        "attestation": ATTESTATION,
        "how_to_verify": HOW_TO_VERIFY,
    }

    body["certificate_sha256"] = hashlib.sha256(_canonical(body)).hexdigest()
    if key:
        body["seal"] = {
            "algorithm": "HMAC-SHA256",
            "value": hmac.new(key, _canonical(
                {k: v for k, v in body.items() if k != "seal"}),
                hashlib.sha256).hexdigest(),
            "meaning": (
                "Detects any alteration to this certificate by a party without "
                "the key. This is a keyed integrity seal, NOT a digital "
                "signature: it does not prove authorship to anyone who does "
                "not hold the same key."),
        }
    return body


def _validation_extract(validation: Optional[Dict[str, Any]]
                        ) -> Dict[str, Any]:
    if not validation:
        return {
            "performed": False,
            "note": ("No validation run was attached to this certificate. Run "
                     "`argus validate` and attach the result to state the "
                     "tool's measured error rates at the time of examination."),
        }
    return {
        "performed": True,
        "generated_at": validation.get("generated_at", ""),
        "tool_version": validation.get("version", ""),
        "summary": validation.get("summary", {}),
        "by_capability": validation.get("by_capability", {}),
        "limitations": validation.get("limitations", []),
        "method": validation.get("method", ""),
    }


ATTESTATION = [
    "Every artifact in the referenced containers records the source file, "
    "source table and row identifier it was derived from, so any individual "
    "finding can be re-derived from the original evidence.",
    "Evidence was opened read-only throughout. Source files were copied and "
    "hashed before any parsing, and the copies were verified against the "
    "originals.",
    "Records recovered from deleted or unallocated space are flagged as such "
    "with an individual confidence value, and are visually distinguished in "
    "every report format.",
    "The chain-of-custody log is hash-chained: each entry embeds the digest of "
    "its predecessor, so removing or altering any entry invalidates every "
    "entry after it.",
    "This certificate states what was verified at the time of issue. It does "
    "not and cannot attest to the handling of the evidence before acquisition "
    "or after issue.",
]

HOW_TO_VERIFY = [
    "1. Recompute the SHA-256 of each container's manifest.json and compare it "
    "to manifest_sha256 in this certificate.",
    "2. Recompute the SHA-256 of each file under blobs/ — the filename IS the "
    "expected digest — and confirm the set matches blob_digests_sha256.",
    "3. Recompute the SHA-256 of artifacts.db and compare it to "
    "seal.artifacts_db_sha256.",
    "4. Re-walk audit.jsonl: each entry's hash must equal SHA-256 of that "
    "entry with the hash field removed, and its prev field must equal the "
    "previous entry's hash. The final hash must equal audit.tip.",
    "5. Or run: argus certificate verify <certificate.json>",
    "Steps 1–4 need only a SHA-256 implementation. They do not require ARGUS, "
    "and they do not require trusting it.",
]


def write_certificate(certificate: Dict[str, Any], path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(certificate, indent=2, ensure_ascii=False,
                               default=str), encoding="utf-8")
    return path


def verify_certificate(path: Path | str, key: Optional[bytes] = None,
                       recheck_evidence: bool = True) -> Dict[str, Any]:
    """Re-verify a certificate, and optionally the evidence it describes."""
    path = Path(path)
    certificate = json.loads(path.read_text(encoding="utf-8"))
    problems: List[str] = []
    checks: List[Dict[str, Any]] = []

    # --- the certificate's own integrity
    stated = certificate.get("certificate_sha256", "")
    body = {k: v for k, v in certificate.items()
            if k not in ("certificate_sha256", "seal")}
    recomputed = hashlib.sha256(_canonical(body)).hexdigest()
    self_ok = bool(stated) and stated == recomputed
    if not self_ok:
        problems.append(
            f"certificate digest mismatch: states {stated[:16]}…, recomputed "
            f"{recomputed[:16]}… — this document has been altered")
    checks.append({"check": "certificate self-digest", "ok": self_ok})

    seal = certificate.get("seal")
    if seal and key:
        expected = hmac.new(key, _canonical(
            {k: v for k, v in certificate.items() if k != "seal"}),
            hashlib.sha256).hexdigest()
        seal_ok = hmac.compare_digest(expected, seal.get("value", ""))
        if not seal_ok:
            problems.append("HMAC seal does not verify with the supplied key")
        checks.append({"check": "HMAC seal", "ok": seal_ok})
    elif seal:
        checks.append({"check": "HMAC seal", "ok": None,
                       "note": "sealed, but no key supplied to verify it"})

    # --- the evidence itself
    if recheck_evidence:
        from ..core.hashing import hash_file
        for entry in certificate.get("containers", []):
            container_path = Path(entry["path"])
            name = entry["name"]
            if not container_path.exists():
                problems.append(f"{name}: container not found at recorded path")
                checks.append({"check": f"{name} present", "ok": False})
                continue

            manifest = container_path / "manifest.json"
            if manifest.exists():
                actual = hash_file(manifest).sha256
                ok = actual == entry.get("manifest_sha256")
                if not ok:
                    problems.append(f"{name}: manifest.json has changed")
                checks.append({"check": f"{name} manifest digest", "ok": ok})

            db = container_path / "artifacts.db"
            expected_db = entry.get("seal", {}).get("artifacts_db_sha256", "")
            if db.exists() and expected_db:
                ok = hash_file(db).sha256 == expected_db
                if not ok:
                    problems.append(f"{name}: artifacts.db has changed")
                checks.append({"check": f"{name} artifact database digest",
                               "ok": ok})

            expected_blobs = set(entry.get("blob_digests_sha256", []))
            blob_root = container_path / "blobs"
            actual_blobs: set[str] = set()
            bad: List[str] = []
            if blob_root.exists():
                for blob in blob_root.rglob("*"):
                    if not blob.is_file() or blob.name.endswith(".partial"):
                        continue
                    actual_blobs.add(blob.name)
                    if hash_file(blob).sha256 != blob.name:
                        bad.append(blob.name)
            missing = expected_blobs - actual_blobs
            added = actual_blobs - expected_blobs
            if bad:
                problems.append(f"{name}: {len(bad)} blob(s) do not match "
                                f"their own digest")
            if missing:
                problems.append(f"{name}: {len(missing)} blob(s) are missing")
            if added:
                problems.append(f"{name}: {len(added)} blob(s) were added "
                                f"after the certificate was issued")
            checks.append({
                "check": f"{name} blob store",
                "ok": not (bad or missing or added),
                "expected": len(expected_blobs), "found": len(actual_blobs),
            })

            audit = container_path / "audit.jsonl"
            if audit.exists():
                from ..core.audit import AuditLog
                log = AuditLog(audit)
                chain_ok, chain_problems = log.verify()
                tip_ok = log.tip == entry.get("audit", {}).get("tip", log.tip)
                if not chain_ok:
                    problems.extend(f"{name}: audit {p}"
                                    for p in chain_problems[:5])
                if not tip_ok:
                    problems.append(f"{name}: custody log has changed since the "
                                    f"certificate was issued")
                checks.append({"check": f"{name} custody chain",
                               "ok": chain_ok and tip_ok})

    return {
        "certificate": str(path),
        "verified_at": _utc(),
        "issued_at": certificate.get("issued_at", ""),
        "examiner": certificate.get("examination", {}).get("examiner", ""),
        "tool_version_at_issue": certificate.get("tool", {}).get("version", ""),
        "evidence_rechecked": recheck_evidence,
        "checks": checks,
        "ok": not problems,
        "problems": problems,
        "conclusion": (
            "VERIFIED — this certificate is intact and the evidence it "
            "describes matches the digests recorded at the time of examination."
            if not problems else
            "FAILED — see problems. The evidence or the certificate has "
            "changed since issue and must not be relied upon until the "
            "discrepancy is explained."),
    }


def generate_key() -> bytes:
    """A fresh 256-bit sealing key. Store it separately from the certificate."""
    return secrets.token_bytes(32)
