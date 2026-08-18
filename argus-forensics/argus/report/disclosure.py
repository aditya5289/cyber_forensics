"""Court disclosure bundle — one folder with everything an examiner needs to hand over."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..analyze.session import AnalysisSession
from ..core.container import EvidenceContainer
from ..report.builder import ReportBuilder, ReportOptions


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_disclosure_bundle(
    containers: List[Path],
    out_dir: Path,
    *,
    examiner: str = "",
    organisation: str = "",
    reference: str = "",
    conclusion: str = "",
    owner_identifiers: Optional[List[str]] = None,
    emit: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    """Assemble report, certificate, validation summary, and manifest."""
    out_dir = Path(out_dir)
    bundle_root = out_dir / f"disclosure_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    bundle_root.mkdir(parents=True, exist_ok=True)

    def log(module: str, status: str, message: str, **extra: Any) -> None:
        if emit:
            emit(module, status, message, **extra)

    log("bundle", "start", f"Building disclosure package in {bundle_root.name}")

    verification: List[Dict[str, Any]] = []
    for path in containers:
        container = EvidenceContainer(path, mode="r")
        try:
            result = container.verify(deep=True)
            verification.append({"container": path.name, **result})
            log("bundle", "verify",
                f"{path.name}: {'OK' if result['ok'] else 'FAILED'}")
        finally:
            container.close()

    validation_path = ""
    validation_data = None
    try:
        from ..validate.harness import run_validation
        validation = run_validation()
        validation_data = validation.as_dict()
        validation_path = str(bundle_root / "validation.json")
        Path(validation_path).write_text(
            json.dumps(validation_data, indent=2), encoding="utf-8")
        log("bundle", "ok", "Validation harness report attached")
    except Exception as exc:
        log("bundle", "warning", f"Validation harness skipped: {exc}",
            level="warning")

    report_files: List[Path] = []
    with AnalysisSession(containers, deep_verify=True) as session:
        opts = ReportOptions(
            title="Mobile Device Forensic Examination Report",
            formats=["html", "json"],
            include_intelligence=True,
            include_deleted=True,
            include_graph=True,
            include_timeline=True,
            include_log=True,
            include_audit=True,
            examiner=examiner,
            organisation=organisation,
            reference=reference,
            conclusion=conclusion,
            owner_identifiers=owner_identifiers or [],
        )
        builder = ReportBuilder(session, opts)
        report_files = builder.write(bundle_root / "report", "forensic_report")
        for path in report_files:
            log("bundle", "ok", f"Report: {path.name}")

        from ..validate.certificate import build_certificate, write_certificate
        cert = build_certificate(
            containers, examiner=examiner, organisation=organisation,
            reference=reference, validation=validation_data)
        cert_path = write_certificate(cert, bundle_root / "certificate.json")
        log("bundle", "ok", f"Certificate: {cert_path.name}")

    manifest_files: List[Dict[str, Any]] = []
    for path in bundle_root.rglob("*"):
        if path.is_file() and path.name != "manifest.json":
            manifest_files.append({
                "path": path.relative_to(bundle_root).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            })

    manifest = {
        "format": "argus-disclosure-bundle/1",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "examiner": examiner,
        "organisation": organisation,
        "reference": reference,
        "containers": [str(c) for c in containers],
        "verification": verification,
        "all_verified": all(v.get("ok") for v in verification),
        "files": manifest_files,
    }
    manifest_path = bundle_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    log("bundle", "ok",
        f"Disclosure bundle complete — {len(manifest_files)} file(s)")

    return {
        "bundle_dir": str(bundle_root),
        "manifest": str(manifest_path),
        "report_files": [str(p) for p in report_files],
        "certificate": str(bundle_root / "certificate.json"),
        "validation": validation_path,
        "all_verified": manifest["all_verified"],
        "file_count": len(manifest_files),
    }
