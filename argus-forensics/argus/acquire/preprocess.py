"""Pre-decode preparation — antiforensics sweep and encrypted-store recovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


def _installed_packages(raw_root: Path) -> Set[str]:
    packages: Set[str] = set()
    for pattern in ("**/packages.list", "**/installed_packages.txt"):
        for path in raw_root.glob(pattern):
            try:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if parts:
                        packages.add(parts[-1])
            except OSError:
                continue
    return packages


def preprocess_raw_tree(raw_root: Path,
                        log: Optional[Callable[..., None]] = None,
                        *,
                        whatsapp_recovery_key: str = "",
                        whatsapp_passphrase: str = "",
                        output_root: Optional[Path] = None) -> Dict[str, Any]:
    """Run antiforensics scan and WhatsApp crypt decryption before decode."""
    root = Path(raw_root)
    summary: Dict[str, Any] = {
        "antiforensics": {},
        "whatsapp_decrypt": {},
    }

    from ..parsers.antiforensics import scan_tree
    from ..parsers.android.whatsapp_crypt import (as_dict as wa_as_dict,
                                                   decrypt_whatsapp_backups)

    packages = _installed_packages(root)
    report = scan_tree(root, installed_packages=packages or None)
    af_path = root / "argus-antiforensics.json"
    try:
        payload = {
            "format": "argus-antiforensics/1",
            "suspect_apps": report.suspect_apps[:40],
            "vault_directories": report.vault_directories[:40],
            "encrypted_stores": report.encrypted_stores[:40],
            "uninstalled_residue": report.uninstalled_residue[:20],
            "limited_recovery": report.limited_recovery[:20],
            "thumbnail_caches": report.thumbnail_caches[:20],
            "reset_estimate": report.reset_estimate,
            "indicator_count": report.indicator_count,
        }
        af_path.write_text(json.dumps(payload, indent=1, ensure_ascii=False),
                           encoding="utf-8")
        summary["antiforensics"] = payload
        if log and report.indicator_count:
            log("preprocess", "ok",
                f"Antiforensics sweep — {report.indicator_count} indicator(s): "
                f"{len(report.encrypted_stores)} encrypted, "
                f"{len(report.suspect_apps)} suspect app(s), "
                f"{len(report.vault_directories)} vault path(s)")
    except OSError:
        pass

    wa = decrypt_whatsapp_backups(
        root, log=log,
        recovery_key=whatsapp_recovery_key,
        passphrase=whatsapp_passphrase,
        output_root=output_root)
    summary["whatsapp_decrypt"] = wa_as_dict(wa)
    if wa.decrypted and log:
        log("preprocess", "ok",
            f"WhatsApp decrypt — {wa.decrypted}/{wa.attempted} backup(s) opened")
    return summary
