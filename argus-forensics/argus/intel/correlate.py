"""Cross-exhibit correlation and community detection.

Two questions come up in every multi-device case and neither is answerable by
looking at one handset at a time:

1. **Is this the same person on both phones?** The same individual appears as a
   phone number on one device, a WhatsApp JID on another and an email address
   in a third. Answering by eye across two 800-artifact exhibits is not
   feasible.

2. **Who groups with whom?** A communication graph with fifty parties has
   structure in it — clusters that talk to each other far more than to the rest
   of the network. Those clusters are frequently the organisational units in a
   case.

Both are done here with explicit, conservative methods.

On identity: correlation is only asserted on a **shared identifier**, never on a
similar display name. "Rahul M." on one handset and "Rahul Mehta" on another
are *not* merged — name similarity is reported as a weaker, separate signal for
a human to adjudicate. Wrongly merging two people invents a relationship that
does not exist, which is a far worse error than failing to spot one that does.

On communities: label propagation (Raghavan et al., 2007) rather than Louvain.
It is near-linear, needs no resolution parameter to tune, and — importantly for
a forensic tool — is run with a fixed seed so the same evidence always produces
the same communities. A tool that returns different structure on each run
cannot be relied on in a report.
"""

from __future__ import annotations

import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..core.models import Artifact, Category, Recovery
from ..parsers.timestamps import to_iso

US = 1_000_000


# ═══════════════════════════════════════════════════ community detection
def label_propagation(adjacency: Dict[str, Dict[str, float]],
                      iterations: int = 40,
                      seed: int = 20260729) -> Dict[str, int]:
    """Weighted label propagation. Deterministic for a given graph and seed.

    Each node adopts the label carried by the greatest total edge weight among
    its neighbours; ties are broken by the lowest label so the outcome does not
    depend on dictionary ordering. Node visit order is shuffled with a fixed
    seed, which is what makes repeated runs reproducible — a requirement for
    anything that goes into a report.
    """
    nodes = sorted(adjacency)
    labels = {n: i for i, n in enumerate(nodes)}
    if not nodes:
        return {}
    rng = random.Random(seed)

    for _ in range(iterations):
        order = nodes[:]
        rng.shuffle(order)
        changed = 0
        for node in order:
            neighbours = adjacency.get(node) or {}
            if not neighbours:
                continue
            weights: Dict[int, float] = defaultdict(float)
            for other, weight in neighbours.items():
                if other in labels:
                    weights[labels[other]] += weight
            if not weights:
                continue
            best = max(weights.values())
            # Lowest label among the tied maxima: deterministic tie-break.
            winner = min(lbl for lbl, w in weights.items() if w == best)
            if labels[node] != winner:
                labels[node] = winner
                changed += 1
        if not changed:
            break

    # Renumber communities by descending size so IDs are stable and readable.
    sizes = Counter(labels.values())
    ranking = {old: new for new, (old, _) in
               enumerate(sorted(sizes.items(), key=lambda kv: (-kv[1], kv[0])))}
    return {node: ranking[lbl] for node, lbl in labels.items()}


def modularity(adjacency: Dict[str, Dict[str, float]],
               communities: Dict[str, int]) -> float:
    """Newman modularity Q — how much better than chance the split is.

    Q near 0 means the "communities" are no better than random; above ~0.3
    indicates real structure. Reporting it stops a meaningless partition being
    presented as a finding.
    """
    total = sum(sum(n.values()) for n in adjacency.values()) / 2.0
    if total <= 0:
        return 0.0
    degree = {n: sum(nb.values()) for n, nb in adjacency.items()}
    q = 0.0
    for i, neighbours in adjacency.items():
        for j, weight in neighbours.items():
            if communities.get(i) == communities.get(j):
                q += weight - (degree[i] * degree[j]) / (2.0 * total)
    return round(q / (2.0 * total), 4)


@dataclass
class Community:
    community_id: int
    members: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    internal_weight: float = 0.0
    external_weight: float = 0.0
    apps: Dict[str, int] = field(default_factory=dict)
    contains_owner: bool = False
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def cohesion(self) -> float:
        """Share of this group's traffic that stays inside it."""
        total = self.internal_weight + self.external_weight
        return round(self.internal_weight / total, 3) if total else 0.0

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.update(size=self.size, cohesion=self.cohesion,
                 first_seen_iso=to_iso(self.first_seen) if self.first_seen else "",
                 last_seen_iso=to_iso(self.last_seen) if self.last_seen else "")
        return d


def detect_communities(graph: Any, min_size: int = 2) -> Dict[str, Any]:
    """Find communities in a :class:`~argus.analyze.graph.ConnectionGraph`."""
    adjacency: Dict[str, Dict[str, float]] = defaultdict(dict)
    for (a, b), edge in graph.edges.items():
        weight = float(edge.artifact_count)
        adjacency[a][b] = weight
        adjacency[b][a] = weight
    for node in graph.nodes:
        adjacency.setdefault(node, {})

    assignment = label_propagation(dict(adjacency))
    q = modularity(dict(adjacency), assignment)

    grouped: Dict[int, Community] = {}
    for node, cid in assignment.items():
        comm = grouped.setdefault(cid, Community(community_id=cid))
        comm.members.append(node)
        gnode = graph.nodes.get(node)
        if gnode is not None:
            comm.labels.append(gnode.label)
            if gnode.is_owner:
                comm.contains_owner = True
            for app, count in (gnode.apps or {}).items():
                comm.apps[app] = comm.apps.get(app, 0) + count
            if gnode.first_seen:
                comm.first_seen = (gnode.first_seen if comm.first_seen is None
                                   else min(comm.first_seen, gnode.first_seen))
            if gnode.last_seen:
                comm.last_seen = (gnode.last_seen if comm.last_seen is None
                                  else max(comm.last_seen, gnode.last_seen))

    for (a, b), edge in graph.edges.items():
        ca, cb = assignment.get(a), assignment.get(b)
        if ca is None or cb is None:
            continue
        if ca == cb:
            grouped[ca].internal_weight += edge.artifact_count
        else:
            grouped[ca].external_weight += edge.artifact_count
            grouped[cb].external_weight += edge.artifact_count

    communities = [c for c in grouped.values() if c.size >= min_size]
    communities.sort(key=lambda c: (-c.size, c.community_id))

    # Modularity alone is not enough. A single hub-and-spoke community around
    # the device owner scores respectably while telling us nothing — a
    # partition needs at least two real groups before it describes structure.
    meaningful = q >= 0.3 and len(communities) >= 2
    if meaningful:
        interpretation = (
            f"Clear community structure: {len(communities)} groups with "
            f"modularity {q}. These groupings reflect real differences in who "
            f"talks to whom.")
    elif len(communities) < 2:
        interpretation = (
            "No community structure — the network resolves to a single group "
            "centred on the device owner. This is the expected shape for one "
            "handset, where every correspondent connects through the owner and "
            "rarely to each other. Add a second exhibit, or interpret the "
            "graph by volume rather than by grouping.")
    else:
        interpretation = (
            f"Weak community structure (modularity {q}, below the 0.3 "
            f"threshold). The groupings are not clearly better than chance and "
            f"should not be relied upon.")

    return {
        "communities": [c.as_dict() for c in communities],
        "count": len(communities),
        "modularity": q,
        "structure_is_meaningful": meaningful,
        "interpretation": interpretation,
        "assignment": assignment,
        "singletons": sum(1 for c in grouped.values() if c.size < min_size),
    }


# ═══════════════════════════════════════════════════════ identity linking
_JID_SUFFIX = re.compile(r"@(s\.whatsapp\.net|c\.us|g\.us|broadcast)$", re.I)


def identity_keys(artifact: Artifact) -> Set[str]:
    """Every identifier on an artifact, normalised for comparison."""
    keys: Set[str] = set()
    for p in artifact.participants:
        key = p.normalised()
        if key:
            keys.add(key)
    for field_name in ("phone_numbers", "emails", "im_handles"):
        value = artifact.attributes.get(field_name)
        if isinstance(value, list):
            for item in value:
                norm = normalise_identifier(str(item))
                if norm:
                    keys.add(norm)
    for field_name in ("jid", "chat_jid", "phone_number", "account_name"):
        value = artifact.attributes.get(field_name)
        if isinstance(value, str) and value:
            norm = normalise_identifier(value)
            if norm:
                keys.add(norm)
    return keys


def normalise_identifier(raw: str) -> str:
    """Reduce an identifier to a comparison key.

    Phone-like values collapse to their last ten digits, which is country-code
    agnostic without being so loose that different numbers collide. JIDs reduce
    to their local part. Everything else is lowercased verbatim.
    """
    value = (raw or "").strip()
    if not value:
        return ""
    value = _JID_SUFFIX.sub("", value)
    if "@" in value:
        return value.split("/")[0].lower()
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 7:
        return digits[-10:]
    return value.lower()


@dataclass
class SharedIdentity:
    """One party present on more than one exhibit."""

    key: str
    labels: List[str] = field(default_factory=list)
    exhibits: Dict[str, int] = field(default_factory=dict)   # exhibit -> count
    apps: Set[str] = field(default_factory=set)
    deleted_on: List[str] = field(default_factory=list)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    basis: str = "shared identifier"
    confidence: float = 0.95
    artifact_ids: List[str] = field(default_factory=list)

    @property
    def exhibit_count(self) -> int:
        return len(self.exhibits)

    @property
    def best_label(self) -> str:
        named = [l for l in self.labels if l and not l.replace("+", "").isdigit()]
        return Counter(named).most_common(1)[0][0] if named else self.key

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["artifact_ids"] = self.artifact_ids[:200]
        d.update(apps=sorted(self.apps), exhibit_count=self.exhibit_count,
                 best_label=self.best_label,
                 first_seen_iso=to_iso(self.first_seen) if self.first_seen else "",
                 last_seen_iso=to_iso(self.last_seen) if self.last_seen else "")
        return d


@dataclass
class NameSimilarity:
    """A weaker signal: similar names with *different* identifiers."""

    label_a: str
    label_b: str
    exhibit_a: str
    exhibit_b: str
    key_a: str
    key_b: str
    ratio: float
    note: str = ("Names are similar but the identifiers differ. This is NOT "
                 "asserted as the same person — it requires human review.")

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CrossExhibitCorrelator:
    """Correlate parties, media and locations across several exhibits."""

    def __init__(self, owner_keys: Optional[Iterable[str]] = None):
        self.owner_keys = {normalise_identifier(k) for k in (owner_keys or ())}
        self.owner_keys.discard("")
        self._parties: Dict[str, SharedIdentity] = {}
        self._blobs: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"exhibits": defaultdict(int), "names": set(),
                     "size": 0, "mime": ""})
        self._cells: Dict[Tuple[float, float], Dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self._cell_artifacts: Dict[Tuple[float, float], List[str]] = defaultdict(list)
        self._labels_by_exhibit: Dict[str, Dict[str, str]] = defaultdict(dict)
        # label -> every identifier seen under that label, per exhibit. Needed
        # so a person already matched on their phone number is not *also*
        # reported as a "similar name" because their email is a different key.
        self._keys_by_label: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set))
        self.exhibits: List[str] = []

    # -------------------------------------------------------------- ingest
    def add_exhibit(self, name: str, artifacts: Iterable[Artifact]) -> None:
        if name not in self.exhibits:
            self.exhibits.append(name)
        for art in artifacts:
            self._ingest_parties(name, art)
            self._ingest_blob(name, art)
            self._ingest_location(name, art)

    def _ingest_parties(self, exhibit: str, art: Artifact) -> None:
        if art.category not in (Category.MESSAGE, Category.CALL,
                                Category.CHAT, Category.CONTACT):
            return
        for p in art.participants:
            if p.is_owner:
                continue
            key = p.normalised()
            if not key or key in self.owner_keys:
                continue
            entry = self._parties.get(key)
            if entry is None:
                entry = SharedIdentity(key=key)
                self._parties[key] = entry
            entry.exhibits[exhibit] = entry.exhibits.get(exhibit, 0) + 1
            label = p.label()
            if label:
                entry.labels.append(label)
                if not label.replace("+", "").isdigit():
                    self._labels_by_exhibit[exhibit][key] = label
                    self._keys_by_label[exhibit][label.lower()].add(key)
            if art.app:
                entry.apps.add(art.app)
            if len(entry.artifact_ids) < 300:
                entry.artifact_ids.append(art.artifact_id)
            if art.recovery != Recovery.ALLOCATED and exhibit not in entry.deleted_on:
                entry.deleted_on.append(exhibit)
            if art.timestamp:
                entry.first_seen = (art.timestamp if entry.first_seen is None
                                    else min(entry.first_seen, art.timestamp))
                entry.last_seen = (art.timestamp if entry.last_seen is None
                                   else max(entry.last_seen, art.timestamp))

    def _ingest_blob(self, exhibit: str, art: Artifact) -> None:
        sha = art.blob_sha256
        if not sha:
            return
        entry = self._blobs[sha]
        entry["exhibits"][exhibit] += 1
        entry.setdefault("artifact_ids", []).append(art.artifact_id)
        name = art.attributes.get("filename") or art.body
        if name:
            entry["names"].add(str(name)[:120])
        entry["size"] = art.attributes.get("size_bytes") or entry["size"]
        entry["mime"] = art.attributes.get("mime_type") or entry["mime"]

    def _ingest_location(self, exhibit: str, art: Artifact) -> None:
        if art.latitude is None or art.longitude is None:
            return
        cell = (round(art.latitude, 2), round(art.longitude, 2))
        self._cells[cell][exhibit] += 1
        self._cell_artifacts[cell].append(art.artifact_id)

    # -------------------------------------------------------------- results
    def shared_parties(self) -> List[SharedIdentity]:
        """Parties appearing on two or more exhibits, by shared identifier."""
        out = [e for e in self._parties.values() if e.exhibit_count >= 2]
        return sorted(out, key=lambda e: (-e.exhibit_count,
                                          -sum(e.exhibits.values())))

    def name_similarities(self, threshold: float = 0.86
                          ) -> List[NameSimilarity]:
        """Similar names on different exhibits with *different* identifiers.

        Deliberately reported separately from :meth:`shared_parties`. These are
        candidates for human review, not conclusions.
        """
        out: List[NameSimilarity] = []
        seen: Set[Tuple[str, str, str, str]] = set()
        pairs = [(ea, eb) for i, ea in enumerate(self.exhibits)
                 for eb in self.exhibits[i + 1:]]
        for ea, eb in pairs:
            for key_a, label_a in self._labels_by_exhibit[ea].items():
                for key_b, label_b in self._labels_by_exhibit[eb].items():
                    if key_a == key_b:
                        continue                      # already a hard match
                    # If these two labels share *any* identifier across the two
                    # exhibits, they are the same person by the strong test and
                    # must not be re-reported as a weak name guess.
                    if self._keys_by_label[ea][label_a.lower()] & \
                            self._keys_by_label[eb][label_b.lower()]:
                        continue
                    ratio = SequenceMatcher(None, label_a.lower(),
                                            label_b.lower()).ratio()
                    if ratio < threshold:
                        continue
                    fingerprint = (ea, eb, label_a.lower(), label_b.lower())
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    out.append(NameSimilarity(
                        label_a=label_a, label_b=label_b,
                        exhibit_a=ea, exhibit_b=eb,
                        key_a=key_a, key_b=key_b, ratio=round(ratio, 3)))
        return sorted(out, key=lambda n: -n.ratio)[:40]

    def shared_media(self) -> List[Dict[str, Any]]:
        """Byte-identical files present on more than one exhibit.

        A matching SHA-256 is proof the *same file* existed on both devices —
        one of the strongest links available, because it survives renaming and
        cannot occur by chance.
        """
        out = []
        for sha, entry in self._blobs.items():
            if len(entry["exhibits"]) >= 2:
                out.append({
                    "sha256": sha,
                    "exhibits": dict(entry["exhibits"]),
                    "exhibit_count": len(entry["exhibits"]),
                    "filenames": sorted(entry["names"])[:6],
                    "size": entry["size"], "mime": entry["mime"],
                    "artifact_ids": entry.get("artifact_ids", [])[:50],
                })
        return sorted(out, key=lambda e: -e["exhibit_count"])

    def shared_locations(self) -> List[Dict[str, Any]]:
        out = []
        for cell, exhibits in self._cells.items():
            if len(exhibits) >= 2:
                out.append({
                    "latitude": cell[0], "longitude": cell[1],
                    "exhibits": dict(exhibits),
                    "exhibit_count": len(exhibits),
                    "total_points": sum(exhibits.values()),
                    "map_url": (f"https://www.openstreetmap.org/?mlat={cell[0]}"
                                f"&mlon={cell[1]}#map=14/{cell[0]}/{cell[1]}"),
                    "artifact_ids": self._cell_artifacts[cell][:60],
                })
        return sorted(out, key=lambda e: (-e["exhibit_count"],
                                          -e["total_points"]))

    def summary(self) -> Dict[str, Any]:
        parties = self.shared_parties()
        media = self.shared_media()
        places = self.shared_locations()
        similar = self.name_similarities()
        return {
            "exhibits": self.exhibits,
            "exhibit_count": len(self.exhibits),
            "shared_parties": [p.as_dict() for p in parties],
            "shared_party_count": len(parties),
            "shared_media": media[:100],
            "shared_media_count": len(media),
            "shared_locations": places[:60],
            "shared_location_count": len(places),
            "name_similarities": [n.as_dict() for n in similar],
            "note": ("Shared parties, media and locations are asserted only on "
                     "an exact identifier or an exact SHA-256 match. Similar "
                     "names are listed separately and are not treated as the "
                     "same person."),
        }


# ═══════════════════════════════════════════════════════ finding generation
def correlation_findings(correlator: CrossExhibitCorrelator) -> List[Any]:
    """Turn correlation results into :class:`~argus.intel.findings.Finding`s."""
    from .findings import Finding

    out: List[Finding] = []
    if len(correlator.exhibits) < 2:
        return out

    parties = correlator.shared_parties()
    if parties:
        top = parties[:8]
        out.append(Finding(
            rule_id="correlate.shared_parties",
            title=f"{len(parties)} party/parties appear on multiple exhibits",
            detail=("The same identifier appears on more than one device: "
                    + "; ".join(f"{p.best_label} ({p.exhibit_count} exhibits, "
                                f"{sum(p.exhibits.values())} artifacts)"
                                for p in top)),
            severity="high", confidence=0.9, category="correlation",
            parties=[p.best_label for p in top],
            artifact_ids=[aid for p in parties for aid in p.artifact_ids][:300],
            first_seen=min((p.first_seen for p in parties if p.first_seen),
                           default=None),
            last_seen=max((p.last_seen for p in parties if p.last_seen),
                          default=None),
            metrics={"count": len(parties),
                     "exhibits": correlator.exhibits,
                     "detail": [p.as_dict() for p in top]},
            why_it_matters=("A correspondent common to several seized devices "
                            "links those devices to each other through a "
                            "specific person."),
            caveat=("Matching is on the last ten digits of a phone number, so "
                    "two genuinely different international numbers sharing "
                    "those digits would collide. Verify the full number."),
        ))

    deleted_on_one = [p for p in parties
                      if p.deleted_on and len(p.deleted_on) < p.exhibit_count]
    if deleted_on_one:
        out.append(Finding(
            rule_id="correlate.asymmetric_deletion",
            title=(f"{len(deleted_on_one)} shared contact(s) deleted on one "
                   f"device but not another"),
            detail=("These parties survive as live records on one exhibit while "
                    "on another they exist only in deleted space: "
                    + "; ".join(f"{p.best_label} (deleted on "
                                f"{', '.join(p.deleted_on)})"
                                for p in deleted_on_one[:6])),
            severity="critical", confidence=0.8, category="correlation",
            parties=[p.best_label for p in deleted_on_one[:8]],
            artifact_ids=[aid for p in deleted_on_one
                          for aid in p.artifact_ids][:300],
            metrics={"count": len(deleted_on_one),
                     "detail": [p.as_dict() for p in deleted_on_one[:8]]},
            why_it_matters=("The device where the thread was removed shows an "
                            "intent the other device did not act on — and the "
                            "surviving copy may contain the original content."),
            caveat=("Different retention settings or storage pressure between "
                    "devices can produce the same asymmetry."),
        ))

    media = correlator.shared_media()
    if media:
        out.append(Finding(
            rule_id="correlate.shared_media",
            title=f"{len(media)} byte-identical file(s) on multiple exhibits",
            detail=("Files with matching SHA-256 digests are present on more "
                    "than one device: "
                    + "; ".join(f"{(m['filenames'] or ['(unnamed)'])[0]} "
                                f"({m['exhibit_count']} exhibits)"
                                for m in media[:6])),
            severity="high", confidence=0.99, category="correlation",
            artifact_ids=[aid for m in media
                          for aid in m.get("artifact_ids", [])][:300],
            metrics={"count": len(media), "detail": media[:10]},
            why_it_matters=("An identical cryptographic digest is conclusive "
                            "that the same file existed on both devices — it "
                            "survives renaming and cannot arise by chance."),
            caveat=("Widely-circulated media (forwards, stock images, app "
                    "assets) will match across unrelated devices. Check what "
                    "the file actually is."),
        ))

    places = correlator.shared_locations()
    if places:
        out.append(Finding(
            rule_id="correlate.shared_locations",
            title=f"{len(places)} location(s) recorded on multiple exhibits",
            detail=("Both devices recorded positions in these approximately "
                    "1 km cells: "
                    + "; ".join(f"{p['latitude']:.2f}, {p['longitude']:.2f} "
                                f"({p['total_points']} points)"
                                for p in places[:5])),
            severity="medium", confidence=0.7, category="correlation",
            artifact_ids=[aid for p in places
                          for aid in p.get("artifact_ids", [])][:300],
            metrics={"count": len(places), "detail": places[:10]},
            why_it_matters=("Devices recording the same locations may have "
                            "been carried together, or their users met there."),
            caveat=("A 1 km cell is coarse and public places produce "
                    "coincidental overlap. Co-location requires matching times "
                    "as well as places — compare the timelines before "
                    "concluding anything."),
        ))

    similar = correlator.name_similarities()
    if similar:
        out.append(Finding(
            rule_id="correlate.name_similarity",
            title=f"{len(similar)} similar name(s) across exhibits — review needed",
            detail=("These contacts have similar names but different "
                    "identifiers, so they were NOT merged: "
                    + "; ".join(f"'{n.label_a}' ({n.exhibit_a}) ~ "
                                f"'{n.label_b}' ({n.exhibit_b}) "
                                f"[{n.ratio:.0%}]" for n in similar[:6])),
            severity="low", confidence=0.4, category="correlation",
            metrics={"count": len(similar),
                     "detail": [n.as_dict() for n in similar[:12]]},
            why_it_matters=("One person using two numbers is common and worth "
                            "checking, but must be confirmed by a human."),
            caveat=("Name similarity is weak evidence. Common given names "
                    "produce many spurious matches; this is a prompt to look, "
                    "not a conclusion."),
        ))

    return out


def community_findings(community_result: Dict[str, Any]) -> List[Any]:
    """Turn community structure into findings, honestly caveated."""
    from .findings import Finding

    out: List[Finding] = []
    if not community_result.get("structure_is_meaningful"):
        return out
    communities = community_result.get("communities", [])
    interesting = [c for c in communities
                   if c["size"] >= 3 and not c["contains_owner"]]
    if not interesting:
        return out
    out.append(Finding(
        rule_id="graph.communities",
        title=(f"{len(interesting)} distinct group(s) detected in the "
               f"communication network"),
        detail=("Label propagation found clusters that communicate internally "
                "far more than with the rest of the network "
                f"(modularity {community_result['modularity']}). Groups: "
                + "; ".join(f"[{', '.join(c['labels'][:4])}"
                            + (f" +{c['size']-4} more" if c["size"] > 4 else "")
                            + f"] cohesion {c['cohesion']:.0%}"
                            for c in interesting[:4])),
        severity="medium", confidence=0.65, category="graph",
        parties=[l for c in interesting[:3] for l in c["labels"][:4]],
        metrics={"count": len(interesting),
                 "modularity": community_result["modularity"],
                 "detail": interesting[:6]},
        why_it_matters=("Groups that talk mostly among themselves, and not to "
                        "the device owner's wider network, often correspond to "
                        "a distinct activity or organisational unit."),
        caveat=("Community detection describes graph structure, not intent. "
                "Family, colleagues and a sports club all form cohesive "
                "clusters. Modularity below 0.3 would make this meaningless."),
    ))
    return out
