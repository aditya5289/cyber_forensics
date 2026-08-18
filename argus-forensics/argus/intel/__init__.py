"""Investigative intelligence — turning artifacts into leads.

``entities``   validated extraction of phones, wallets, accounts, IDs, URLs
``findings``   auditable rules producing ranked, evidence-cited findings
``correlate``  cross-exhibit identity linking and community detection

The single entry point most callers want is :func:`analyse`, which runs the
whole layer over an analysis session and returns everything at once, with
findings from every source merged into one prioritised list — an examiner
should read one ranked lead sheet, not four separate ones.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..core.models import Artifact, Category
from .correlate import CrossExhibitCorrelator, detect_communities
from .entities import EntityExtractor
from .findings import Finding, FindingsEngine

__all__ = ["analyse", "EntityExtractor", "FindingsEngine", "Finding",
           "CrossExhibitCorrelator", "detect_communities"]

_ARTIFACT_BATCH = 8000


def _load_artifacts(session: Any,
                    progress: Optional[Callable[[str], None]] = None
                    ) -> tuple[List[tuple], List[Artifact]]:
    """Load artifacts exhibit-by-exhibit in bounded batches."""
    per_exhibit: List[tuple] = []
    artifacts: List[Artifact] = []
    loaded = list(session.loaded)
    totals = [lc.db.count() for lc in loaded]
    grand = sum(totals)
    seen = 0
    for lc, total in zip(loaded, totals):
        label = (lc.container.extraction.get("exhibit_id")
                 or lc.container.path.name)
        arts: List[Artifact] = []
        batch: List[Artifact] = []
        for art in lc.db.iter_artifacts():
            batch.append(art)
            if len(batch) >= _ARTIFACT_BATCH:
                arts.extend(batch)
                seen += len(batch)
                if progress:
                    progress(f"Loading artifacts… {seen:,}/{grand:,}")
                batch = []
        if batch:
            arts.extend(batch)
            seen += len(batch)
        if progress and total:
            progress(f"Loaded {label}: {len(arts):,} artifact(s)")
        per_exhibit.append((label, arts))
        artifacts.extend(arts)
    return per_exhibit, artifacts


def analyse(session: Any, owner_name: str = "Device owner",
            owner_identifiers: Optional[Iterable[str]] = None,
            include_correlation: bool = True,
            include_media_matching: bool = True,
            include_fusion: bool = True,
            include_conversations: bool = True,
            hashset_registry: Any = None,
            progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Run the full intelligence layer over an :class:`AnalysisSession`."""
    from ..analyze.conversations import (build_conversations,
                                         conversation_findings)
    from ..analyze.graph import ConnectionGraph
    from .correlate import community_findings, correlation_findings
    from .fusion import fuse_session, fusion_findings

    owner_identifiers = list(owner_identifiers or ())

    if progress:
        progress("Loading artifacts from sealed containers…")
    per_exhibit, artifacts = _load_artifacts(session, progress)

    contacts = [a for a in artifacts if a.category == Category.CONTACT]

    if progress:
        progress(f"Extracting entities from {len(artifacts):,} artifact(s)…")
    extractor = EntityExtractor()
    extractor.set_owner_identifiers(owner_identifiers)
    extractor.set_known_contacts(
        p.normalised() for a in contacts for p in a.participants)
    extractor.scan_artifacts(artifacts)

    graph = ConnectionGraph(owner_label=owner_name)
    graph.learn_contacts(contacts)
    graph.add(artifacts)
    graph.finalise()

    if progress:
        progress("Running investigative rules…")
    communities = detect_communities(graph)

    engine = FindingsEngine()
    from .findings import CaseContext
    ctx = CaseContext(artifacts=artifacts, owner_name=owner_name,
                      owner_keys=set(owner_identifiers), entities=extractor,
                      graph=graph)
    findings: List[Finding] = engine.run(ctx, progress=progress)

    findings.extend(community_findings(communities))
    findings.extend(_antiforensic_findings(artifacts))

    # --- conversation reconstruction
    conversations: Dict[str, Any] = {}
    if include_conversations:
        if progress:
            progress("Reconstructing conversations…")
        try:
            builder = build_conversations(session, owner_name=owner_name)
            conversations = builder.summary()
            findings.extend(conversation_findings(builder))
        except Exception as exc:
            conversations = {"error": f"{type(exc).__name__}: {exc}"}

    # --- event fusion / attribution
    fusion: Dict[str, Any] = {}
    if include_fusion:
        if progress:
            progress("Fusing timeline events…")
        try:
            fuser = fuse_session(session, owner_name=owner_name)
            fusion = fuser.summary()
            findings.extend(fusion_findings(fuser))
        except Exception as exc:
            fusion = {"error": f"{type(exc).__name__}: {exc}"}

    # --- perceptual media matching
    media_matching: Dict[str, Any] = {}
    if include_media_matching:
        if progress:
            progress("Matching perceptual media hashes…")
        try:
            from ..parsers.media.perceptual import (build_index,
                                                    perceptual_findings)
            index = build_index(session)
            media_matching = index.summary()
            findings.extend(perceptual_findings(index))
        except Exception as exc:
            media_matching = {"error": f"{type(exc).__name__}: {exc}"}

    # --- hash-set screening
    hashsets: Dict[str, Any] = {}
    if hashset_registry is not None:
        if progress:
            progress("Screening against hash sets…")
        try:
            from ..core.hashsets import hashset_findings, screen_session
            hashsets = screen_session(session, hashset_registry)
            findings.extend(hashset_findings(hashsets))
        except Exception as exc:
            hashsets = {"error": f"{type(exc).__name__}: {exc}"}

    correlation: Dict[str, Any] = {}
    if include_correlation and len(per_exhibit) > 1:
        if progress:
            progress("Correlating across exhibits…")
        correlator = CrossExhibitCorrelator(owner_keys=owner_identifiers)
        for label, arts in per_exhibit:
            correlator.add_exhibit(label, arts)
        correlation = correlator.summary()
        findings.extend(correlation_findings(correlator))

    findings.sort(key=lambda f: (-f.score, f.rule_id))
    by_sev = Counter(f.severity for f in findings)

    if progress:
        progress(f"Complete — {len(findings):,} finding(s) from "
                 f"{len(artifacts):,} artifact(s)")

    from .recommendations import build_recommendations
    recommendations = build_recommendations(session, {
        "findings": {
            "by_severity": {s: by_sev.get(s, 0) for s in
                            ("critical", "high", "medium", "low", "info")},
            "total": len(findings),
        },
    })

    return {
        "findings": {
            "findings": [f.as_dict() for f in findings],
            "count": len(findings),
            "by_severity": {s: by_sev.get(s, 0) for s in
                            ("critical", "high", "medium", "low", "info")},
            "by_category": dict(Counter(f.category for f in findings)),
            "top": [f.as_dict() for f in findings[:12]],
            "artifacts_analysed": len(artifacts),
            "rules_run": len(engine.rules),
        },
        "entities": extractor.summary(),
        "entity_detail": [h.as_dict() for h in extractor.results()][:400],
        "communities": communities,
        "correlation": correlation,
        "conversations": conversations,
        "fusion": fusion,
        "media_matching": media_matching,
        "hashsets": hashsets,
        "exhibits": [label for label, _ in per_exhibit],
        "artifacts_analysed": len(artifacts),
        "recommendations": recommendations,
    }


def _antiforensic_findings(artifacts: List[Artifact]) -> List[Finding]:
    """Derive anti-forensics findings from artifacts already in the container.

    The acquisition-time detectors record their observations as artifacts, so
    the lead sheet can be rebuilt from a sealed container long afterwards
    without re-reading the original device.
    """
    encrypted = [a for a in artifacts if a.attributes.get("encrypted")]
    concealed = [a for a in artifacts if a.attributes.get("concealed")]
    thumbs = [a for a in artifacts
              if "thumbnail" in (a.subtype or "").lower()]
    out: List[Finding] = []
    if encrypted:
        out.append(Finding(
            rule_id="antiforensics.encrypted_artifacts",
            title=f"{len(encrypted)} encrypted store(s) present but not decoded",
            detail=("Content in these files is NOT counted in this "
                    "extraction's artifact totals: "
                    + "; ".join(str(a.attributes.get("filename") or a.body)
                                for a in encrypted[:6])),
            severity="critical", confidence=0.9, category="antiforensics",
            artifact_ids=[a.artifact_id for a in encrypted],
            evidence=[str(a.attributes.get("explanation", ""))[:170]
                      for a in encrypted[:4]],
            metrics={"count": len(encrypted)},
            why_it_matters=("Any conclusion about what is absent from this "
                            "handset must account for these files."),
            caveat=("Identification only — ARGUS does not attempt decryption "
                    "and claims no capability to do so."),
        ))
    if concealed:
        out.append(Finding(
            rule_id="antiforensics.concealed_artifacts",
            title=f"{len(concealed)} media file(s) concealed by a vault app",
            detail=("Media renamed so the gallery will not index it. The file "
                    "content is unmodified and has been recovered: "
                    + "; ".join(str(a.attributes.get("filename") or a.body)
                                for a in concealed[:6])),
            severity="high", confidence=0.85, category="antiforensics",
            artifact_ids=[a.artifact_id for a in concealed],
            metrics={"count": len(concealed)},
            why_it_matters=("Deliberate concealment — and most consumer vaults "
                            "only rename rather than encrypt, so the hidden "
                            "content is available."),
            caveat="Vault applications are also used for ordinary privacy.",
        ))
    if thumbs:
        out.append(Finding(
            rule_id="antiforensics.thumbnail_recovery",
            title=f"{len(thumbs)} image(s) recovered from thumbnail cache",
            detail=("Android retains thumbnails after the source photograph is "
                    "deleted, so these may be the only surviving copies of "
                    "images the user removed."),
            severity="medium", confidence=0.9, category="antiforensics",
            artifact_ids=[a.artifact_id for a in thumbs],
            metrics={"count": len(thumbs)},
            why_it_matters=("Establishes that an image existed even when the "
                            "full-resolution original is unrecoverable."),
            caveat=("Thumbnails are low resolution and carry no EXIF, so they "
                    "cannot establish where or when a photo was taken."),
        ))
    return out
