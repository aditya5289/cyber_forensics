"""Ranked examination next-steps — ties acquisition, decode, and intelligence."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def build_recommendations(session: Any,
                          intel: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Priority-ordered actions for the examiner."""
    out: List[Dict[str, Any]] = []
    try:
        dash = session.dashboard_visuals()
    except Exception:
        return out

    ext = dash.get("extraction") or {}
    cq = dash.get("comms_quality") or {}
    decoded = cq.get("decoded") or {}
    method = (ext.get("method") or "").lower()
    gaps = cq.get("gaps") or []

    if gaps:
        for g in gaps[:2]:
            out.append({
                "id": g.get("code", "gap"),
                "title": "Communications gap detected",
                "detail": g.get("message", ""),
                "severity": "high",
                "view": "messages",
            })

    if cq.get("is_vivo") and decoded.get("messages", 0) > 0:
        if decoded.get("contacts", 0) == 0 and decoded.get("calls", 0) == 0:
            out.append({
                "id": "vivo_fallback",
                "title": "Vivo pattern — review fallback sources",
                "detail": ("Contacts/calls often return 0 from live providers on "
                           "Funtouch. Review dumpsys/, logical/content/, and "
                           ".vivobackup exports in Files view."),
                "severity": "medium",
                "view": "files",
            })

    if method == "mtp" and (decoded.get("messages", 0) == 0):
        out.append({
            "id": "mtp_to_comprehensive",
            "title": "Re-run with USB debugging",
            "detail": ("MTP copies shared storage only. Enable Developer options "
                       "→ USB debugging (Security settings) and run Comprehensive."),
            "severity": "high",
            "view": "extract",
        })

    cov = float(ext.get("decode_coverage_pct") or 0)
    if cov and cov < 35:
        out.append({
            "id": "low_decode",
            "title": "Low decode coverage",
            "detail": f"Only {cov:.0f}% of files produced artifacts — check warnings.",
            "severity": "medium",
            "view": "dashboard",
        })

    if ext.get("mtp_completeness"):
        detail = ext["mtp_completeness"]
        missing = ext.get("mtp_missing_folders") or []
        if missing:
            detail += " — gaps: " + ", ".join(missing[:4])
        out.append({
            "id": "mtp_incomplete",
            "title": "MTP copy incomplete",
            "detail": detail,
            "severity": "high",
            "view": "extract",
        })

    intel_ran = bool(intel and intel.get("findings"))
    preprocess = ext.get("preprocess_summary") or {}
    wa = preprocess.get("whatsapp_decrypt") or {}
    if wa.get("attempted") and not wa.get("decrypted"):
        out.append({
            "id": "whatsapp_crypt",
            "title": "WhatsApp backup encrypted",
            "detail": ("Encrypted WhatsApp backup found without a matching key. "
                       "Re-run Comprehensive with USB debugging to pull the key file."),
            "severity": "high",
            "view": "extract",
        })
    elif wa.get("decrypted"):
        out.append({
            "id": "whatsapp_decrypted",
            "title": f"WhatsApp — {wa['decrypted']} backup(s) decrypted",
            "detail": "Decrypted msgstore databases are ready for decode and analysis.",
            "severity": "medium",
            "view": "messages",
        })

    af = preprocess.get("antiforensics") or {}
    if int(af.get("indicator_count") or 0) > 0:
        enc_n = len(af.get("encrypted_stores") or [])
        vaults = len(af.get("vault_directories") or [])
        if enc_n or vaults:
            out.append({
                "id": "antiforensics",
                "title": "Antiforensics indicators on acquisition",
                "detail": (f"{enc_n} encrypted store(s), {vaults} vault path(s) — "
                           "review findings and argus-antiforensics.json."),
                "severity": "high" if enc_n else "medium",
                "view": "findings",
            })

    owners = dash.get("owner_suggestions") or []
    if owners and not intel_ran:
        out.append({
            "id": "run_intel",
            "title": "Run intelligence with owner identity",
            "detail": f"Detected identifiers: {', '.join(owners[:3])}. "
                      f"Set owner in Findings for attribution rules.",
            "severity": "medium",
            "view": "findings",
        })
    elif not intel_ran:
        out.append({
            "id": "run_intel",
            "title": "Run intelligence",
            "detail": "Generate ranked findings from decoded artifacts.",
            "severity": "low",
            "view": "findings",
        })

    findings = (intel or {}).get("findings") or {}
    crit = int((findings.get("by_severity") or {}).get("critical") or 0)
    high = int((findings.get("by_severity") or {}).get("high") or 0)
    if crit or high:
        out.append({
            "id": "review_findings",
            "title": f"Review {crit + high} high-priority finding(s)",
            "detail": "Open the lead sheet and verify evidence citations.",
            "severity": "high" if crit else "medium",
            "view": "findings",
        })

    triage = dash.get("triage") or {}
    enc = triage.get("encrypted_stores") or []
    if enc:
        out.append({
            "id": "encrypted",
            "title": f"{len(enc)} encrypted store(s)",
            "detail": ("Content not included in artifact totals — re-run "
                       "Comprehensive with USB debugging to pull WhatsApp key "
                       "or document limitation in report."),
            "severity": "critical",
            "view": "dashboard",
        })

    return out[:10]
