"""The examiner's folio — a complete-sentence assessment of the exhibit.

A dashboard of numbers is not an examination. The first thing a master
examiner writes is what they actually have, what they do not have, and
what they will do next. ARGUS writes that page so the human does not
have to reconstruct it from KPIs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def compose_folio(overview: Dict[str, Any],
                  triage: Optional[Dict[str, Any]] = None,
                  provenance: Optional[Dict[str, Any]] = None,
                  comms: Optional[Dict[str, Any]] = None
                  ) -> Dict[str, Any]:
    """Return a court-ready brief. Every field is meant to be read aloud."""
    ov = overview or {}
    tri = triage or {}
    prov = provenance or ov.get("provenance") or {}
    comms = comms or {}
    device = ov.get("device") or {}
    name = " ".join(p for p in (
        device.get("make"), device.get("model")) if p).strip() or "the handset"
    method = (ov.get("method") or prov.get("method") or "extraction").strip()
    total = int(ov.get("total_artifacts") or tri.get("total_artifacts") or 0)
    deleted = int(ov.get("deleted_recovered") or tri.get("deleted_recovered") or 0)
    sealed = "seal" in (ov.get("encryption_level") or "").lower() or bool(
        prov.get("sealed"))
    integ_ok = True
    integ = ov.get("integrity") or tri.get("integrity") or {}
    if isinstance(integ, dict):
        integ_ok = bool(integ.get("ok", True))

    decoded = (comms.get("decoded") or {})
    messages = int(decoded.get("messages") or 0)
    calls = int(decoded.get("calls") or 0)
    contacts = int(decoded.get("contacts") or 0)
    cats = ov.get("categories") or tri.get("categories") or {}
    if not messages:
        messages = int(cats.get("Messages") or 0) + int(cats.get("Chats") or 0)
    if not calls:
        calls = int(cats.get("Calls") or 0)
    if not contacts:
        contacts = int(cats.get("Contacts") or 0)

    acq = prov.get("acquisition_summary") or {}
    physical = prov.get("physical") or acq.get("physical") or {}
    caveats = list(prov.get("caveats") or acq.get("caveats") or [])
    mtp_hint = str(prov.get("mtp_completeness") or "")
    encrypted = list(tri.get("encrypted_stores") or [])

    strengths: List[str] = []
    gaps: List[str] = []
    if integ_ok and sealed:
        strengths.append("The container is sealed and independent verification "
                         "reproduces the manifest hash.")
    elif integ_ok:
        strengths.append("Integrity verification succeeded; seal the container "
                         "before the exhibit leaves this workstation.")
    else:
        gaps.append("Integrity verification failed. Do not treat this as "
                    "sealed evidence until the problems are resolved.")

    if messages:
        strengths.append(f"{messages:,} message or chat record(s) were decoded.")
    if contacts:
        strengths.append(f"{contacts:,} contact record(s) were decoded.")
    if calls:
        strengths.append(f"{calls:,} call record(s) were decoded.")
    if deleted:
        strengths.append(
            f"{deleted:,} record(s) were recovered from deleted or unallocated "
            "space and were not visible to the device user.")
    dumped = physical.get("dumped") or []
    if dumped:
        strengths.append(
            "Physical images were taken of " + ", ".join(str(n) for n in dumped[:8])
            + ".")
    passes = (acq.get("adb") or {}).get("passes") or []
    if passes:
        strengths.append("ADB acquisition completed passes: "
                         + ", ".join(str(p) for p in passes) + ".")

    if method.lower() == "mtp" and not messages and not contacts and not calls:
        gaps.append(
            "This was an MTP copy of shared storage. Live SMS, contacts and "
            "calls were not queried. Enable USB debugging and run Comprehensive.")
    if mtp_hint:
        gaps.append("MTP copy was incomplete: " + mtp_hint + ".")
    crypto = str(physical.get("crypto") or "").lower()
    if crypto in ("file", "fbe") or "encrypt" in crypto:
        gaps.append(
            "Userdata is file-based encrypted. Partition images are a valid "
            "exhibit; file contents stay ciphertext until keys are applied.")
    if encrypted:
        gaps.append(
            f"{len(encrypted)} encrypted store(s) were identified and not opened "
            "(ARGUS names ciphertext; it does not brute-force it).")
    if not total:
        gaps.append("No artifacts have been decoded yet.")
    for note in caveats[:3]:
        if note and note not in gaps:
            gaps.append(str(note))

    if not integ_ok:
        verdict = ("This examination cannot yet be presented as sealed evidence.")
        next_action = {
            "label": "Resolve integrity failures",
            "reason": "A report that leads with findings after a failed seal "
                      "misleads the reader.",
        }
    elif method.lower() == "mtp" and not messages:
        verdict = (f"{name} was copied over MTP. Shared storage is in the "
                   "container; communications that live under /data/data are not.")
        next_action = {
            "label": "Run Comprehensive with USB debugging",
            "reason": "Logical providers and app databases require an authorised "
                      "ADB session.",
        }
    elif encrypted and messages == 0:
        verdict = (f"{name} yielded {total:,} artifact(s), but encrypted stores "
                   "still hold content that has not been read.")
        next_action = {
            "label": "Supply the WhatsApp key or backup passphrase",
            "reason": "crypt12/14 need the device key file; crypt15 needs the "
                      "recovery key. ARGUS will not guess it.",
        }
    elif total:
        verdict = (f"{name} was examined by {method}. {total:,} artifact(s) "
                   "are in the sealed container"
                   + (f", including {deleted:,} recovered from deleted space"
                      if deleted else "")
                   + ".")
        next_action = {
            "label": "Open Findings, then generate the court report",
            "reason": "Ranked leads cite the artifacts they rest on; the report "
                      "must be generated from the sealed container.",
        }
    else:
        verdict = f"The container for {name} is present, but decode has not produced artifacts."
        next_action = {
            "label": "Open Analyse and wait for ingest to finish",
            "reason": "MTP media copies often decode after the copy returns.",
        }

    paragraphs: List[str] = [verdict]
    if ov.get("first_activity") or ov.get("last_activity"):
        paragraphs.append(
            "Observed activity spans "
            f"{ov.get('first_activity') or 'an unknown start'} to "
            f"{ov.get('last_activity') or 'an unknown end'} (UTC).")
    if ov.get("operator"):
        paragraphs.append(
            f"The recorded operator is {ov.get('operator')}.")

    return {
        "title": "Examiner's folio",
        "device": name,
        "method": method,
        "verdict": verdict,
        "paragraphs": paragraphs,
        "strengths": strengths[:8],
        "gaps": gaps[:8],
        "next_action": next_action,
        "integrity_ok": integ_ok,
        "artifact_count": total,
        "deleted_recovered": deleted,
    }
