"""Connection / link analysis (lab manual Steps 17 and 19, §6.4 and §6.6).

Builds the communication graph: who spoke to whom, how often, through which
application, and when.  This is the view that turns a pile of messages into an
argument about a relationship, which is why the manual asks for it twice — once
for calls and once for messages.

Identity resolution
-------------------
The hard part is not drawing the graph, it is deciding that
``+91 98765 43210``, ``09876543210`` and ``919876543210@s.whatsapp.net`` are
one person.  :meth:`ConnectionGraph._key` normalises phone-like identifiers to
their last ten digits and JIDs to their local part, then a display name is
chosen by majority vote across every artifact that names that identity.
Getting this wrong in either direction is bad: over-merging invents a contact
who never existed, under-merging hides a pattern of contact.  The chosen rule
is conservative — it never merges two identifiers that differ in their last ten
digits.

Metrics
-------
* ``artifact_count``  edge weight, as in the manual's "artifact count per link"
* ``degree``          how many distinct parties a node communicated with
* ``betweenness``     Brandes' algorithm — who sits between otherwise separate
                      clusters; a broker in a network is evidentially
                      interesting in a way a high-volume contact is not
* ``reciprocity``     ratio of two-way to one-way contact on an edge
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..core.db import ArtifactDB
from ..core.models import Artifact, Category, Direction

OWNER_KEY = "__owner__"


@dataclass
class Node:
    key: str
    label: str = ""
    identifiers: Set[str] = field(default_factory=set)
    is_owner: bool = False
    artifact_count: int = 0
    calls: int = 0
    messages: int = 0
    incoming: int = 0
    outgoing: int = 0
    apps: Counter = field(default_factory=Counter)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    total_call_seconds: int = 0
    degree: int = 0
    betweenness: float = 0.0

    def touch(self, ts: Optional[int]) -> None:
        if ts is None:
            return
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["identifiers"] = sorted(self.identifiers)
        d["apps"] = dict(self.apps.most_common())
        return d


@dataclass
class Edge:
    source: str
    target: str
    artifact_count: int = 0
    calls: int = 0
    messages: int = 0
    source_to_target: int = 0
    target_to_source: int = 0
    apps: Counter = field(default_factory=Counter)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    total_call_seconds: int = 0
    samples: List[str] = field(default_factory=list)
    artifact_ids: List[str] = field(default_factory=list)

    @property
    def reciprocity(self) -> float:
        a, b = self.source_to_target, self.target_to_source
        if a + b == 0:
            return 0.0
        return round(min(a, b) / max(a, b), 3) if max(a, b) else 0.0

    def touch(self, ts: Optional[int]) -> None:
        if ts is None:
            return
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["apps"] = dict(self.apps.most_common())
        d["reciprocity"] = self.reciprocity
        return d


class ConnectionGraph:
    """Communication graph over a set of artifacts."""

    COMMUNICATION = {Category.CALL, Category.MESSAGE, Category.CHAT}

    def __init__(self, owner_label: str = "Device owner"):
        self.owner_label = owner_label
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str], Edge] = {}
        self._name_votes: Dict[str, Counter] = defaultdict(Counter)
        self._contact_names: Dict[str, str] = {}

    # ------------------------------------------------------------- building
    @staticmethod
    def _key(identifier: str, is_owner: bool) -> str:
        if is_owner:
            return OWNER_KEY
        raw = (identifier or "").strip()
        if not raw:
            return ""
        if "@" in raw:
            local, _, domain = raw.partition("@")
            if domain in ("s.whatsapp.net", "c.us") and local.isdigit():
                return local[-10:] if len(local) >= 10 else local
            return raw.split("/")[0].lower()
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) >= 7:
            return digits[-10:]
        return raw.lower()

    def learn_contacts(self, artifacts: Iterable[Artifact]) -> None:
        """Pre-load the contact list so graph nodes carry real names.

        Run this over Category.CONTACT artifacts before adding communications,
        otherwise the graph shows a wall of phone numbers and the analyst has
        to resolve identities by hand.
        """
        for art in artifacts:
            if art.category != Category.CONTACT:
                continue
            name = (art.attributes.get("display_name")
                    or art.body or "").strip()
            if not name:
                continue
            for p in art.participants:
                k = self._key(p.identifier, False)
                if k:
                    self._contact_names.setdefault(k, name)

    def add(self, artifacts: Iterable[Artifact]) -> "ConnectionGraph":
        for art in artifacts:
            if art.category not in self.COMMUNICATION:
                continue
            parties = []
            for p in art.participants:
                k = self._key(p.identifier, p.is_owner)
                if not k:
                    continue
                parties.append((k, p))
                if p.display_name and not p.is_owner:
                    self._name_votes[k][p.display_name.strip()] += 1

            keys = list(dict.fromkeys(k for k, _ in parties))
            if not keys:
                continue
            if OWNER_KEY not in keys:
                keys.insert(0, OWNER_KEY)

            duration = int(art.attributes.get("duration_seconds") or 0)

            for k, p in parties:
                node = self._node(k, p.display_name, p.is_owner)
                node.artifact_count += 1
                node.touch(art.timestamp)
                if art.app:
                    node.apps[art.app] += 1
                if art.category == Category.CALL:
                    node.calls += 1
                    node.total_call_seconds += duration
                else:
                    node.messages += 1
                if art.direction == Direction.INCOMING:
                    node.incoming += 1
                elif art.direction == Direction.OUTGOING:
                    node.outgoing += 1
            if OWNER_KEY not in {k for k, _ in parties}:
                self._node(OWNER_KEY, self.owner_label, True).artifact_count += 1

            # Edges: every unordered pair on the artifact
            for i, a in enumerate(keys):
                for b in keys[i + 1:]:
                    if a == b:
                        continue
                    self._edge(a, b, art, duration)
        return self

    def _node(self, key: str, label: str, is_owner: bool) -> Node:
        node = self.nodes.get(key)
        if node is None:
            node = Node(key=key, is_owner=is_owner,
                        label=self.owner_label if is_owner else (label or key))
            self.nodes[key] = node
        if label and not is_owner:
            node.identifiers.add(label if "@" in label else label)
        return node

    def _edge(self, a: str, b: str, art: Artifact, duration: int) -> Edge:
        src, tgt = (a, b) if a <= b else (b, a)
        edge = self.edges.get((src, tgt))
        if edge is None:
            edge = Edge(source=src, target=tgt)
            self.edges[(src, tgt)] = edge
        edge.artifact_count += 1
        edge.touch(art.timestamp)
        if art.app:
            edge.apps[art.app] += 1
        if art.category == Category.CALL:
            edge.calls += 1
            edge.total_call_seconds += duration
        else:
            edge.messages += 1
        if art.direction == Direction.OUTGOING:
            edge.source_to_target += 1
        elif art.direction == Direction.INCOMING:
            edge.target_to_source += 1
        if len(edge.samples) < 5 and art.body:
            edge.samples.append(art.summary(90))
        if len(edge.artifact_ids) < 200:
            edge.artifact_ids.append(art.artifact_id)
        return edge

    # -------------------------------------------------------------- metrics
    def finalise(self) -> "ConnectionGraph":
        """Resolve display names and compute structural metrics."""
        for key, node in self.nodes.items():
            if node.is_owner:
                node.label = self.owner_label
                continue
            named = self._contact_names.get(key)
            if not named and self._name_votes.get(key):
                named = self._name_votes[key].most_common(1)[0][0]
            if named:
                node.label = named
            elif node.identifiers:
                node.label = sorted(node.identifiers, key=len)[-1]
            else:
                node.label = key

        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for (a, b) in self.edges:
            adjacency[a].add(b)
            adjacency[b].add(a)
        for key, node in self.nodes.items():
            node.degree = len(adjacency.get(key, ()))

        self._betweenness(adjacency)
        return self

    def _betweenness(self, adjacency: Dict[str, Set[str]]) -> None:
        """Brandes' betweenness centrality on the unweighted graph."""
        nodes = list(self.nodes)
        if len(nodes) > 3000:              # keep the UI responsive
            return
        scores = {n: 0.0 for n in nodes}
        for s in nodes:
            stack: List[str] = []
            preds: Dict[str, List[str]] = {n: [] for n in nodes}
            sigma = {n: 0.0 for n in nodes}
            dist = {n: -1 for n in nodes}
            sigma[s], dist[s] = 1.0, 0
            queue = deque([s])
            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in adjacency.get(v, ()):
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        preds[w].append(v)
            delta = {n: 0.0 for n in nodes}
            while stack:
                w = stack.pop()
                for v in preds[w]:
                    if sigma[w]:
                        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    scores[w] += delta[w]
        n = len(nodes)
        norm = ((n - 1) * (n - 2) / 2.0) if n > 2 else 1.0
        for key, node in self.nodes.items():
            node.betweenness = round(scores.get(key, 0.0) / norm, 5) if norm else 0.0

    # -------------------------------------------------------------- queries
    def top_contacts(self, limit: int = 20) -> List[Dict[str, Any]]:
        ranked = sorted((n for n in self.nodes.values() if not n.is_owner),
                        key=lambda n: (-n.artifact_count, n.label))
        return [n.as_dict() for n in ranked[:limit]]

    def brokers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Nodes that bridge otherwise-disconnected parts of the network."""
        ranked = sorted((n for n in self.nodes.values()
                         if not n.is_owner and n.betweenness > 0),
                        key=lambda n: -n.betweenness)
        return [n.as_dict() for n in ranked[:limit]]

    def one_way_contacts(self, min_artifacts: int = 3) -> List[Dict[str, Any]]:
        """Edges with traffic in only one direction — often bots or blocked."""
        out = []
        for edge in self.edges.values():
            if edge.artifact_count < min_artifacts:
                continue
            if edge.source_to_target == 0 or edge.target_to_source == 0:
                out.append(edge.as_dict())
        return sorted(out, key=lambda e: -e["artifact_count"])

    def components(self) -> List[List[str]]:
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for (a, b) in self.edges:
            adjacency[a].add(b)
            adjacency[b].add(a)
        seen: Set[str] = set()
        out: List[List[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            comp, queue = [], deque([start])
            seen.add(start)
            while queue:
                v = queue.popleft()
                comp.append(v)
                for w in adjacency.get(v, ()):
                    if w not in seen:
                        seen.add(w)
                        queue.append(w)
            out.append(sorted(comp))
        return sorted(out, key=len, reverse=True)

    # ---------------------------------------------------------------- export
    def to_dict(self, min_weight: int = 1, max_nodes: int = 400) -> Dict[str, Any]:
        edges = [e for e in self.edges.values() if e.artifact_count >= min_weight]
        edges.sort(key=lambda e: -e.artifact_count)
        keep: Set[str] = {OWNER_KEY}
        for e in edges:
            if len(keep) >= max_nodes:
                break
            keep.add(e.source)
            keep.add(e.target)
        edges = [e for e in edges if e.source in keep and e.target in keep]
        return {
            "nodes": [self.nodes[k].as_dict() for k in keep if k in self.nodes],
            "edges": [e.as_dict() for e in edges],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "shown_nodes": len(keep),
                "shown_edges": len(edges),
                "components": len(self.components()),
                "min_weight": min_weight,
            },
        }

    def to_graphml(self) -> str:
        """Export for Gephi / yEd, for analysts who want a bigger canvas."""
        def esc(s: str) -> str:
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="count" for="node" attr.name="artifacts" attr.type="int"/>',
            '  <key id="owner" for="node" attr.name="is_owner" attr.type="boolean"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>',
            '  <graph id="ARGUS" edgedefault="undirected">',
        ]
        for key, node in self.nodes.items():
            lines.append(f'    <node id="{esc(key)}">')
            lines.append(f'      <data key="label">{esc(node.label)}</data>')
            lines.append(f'      <data key="count">{node.artifact_count}</data>')
            lines.append(f'      <data key="owner">{str(node.is_owner).lower()}</data>')
            lines.append('    </node>')
        for i, edge in enumerate(self.edges.values()):
            lines.append(
                f'    <edge id="e{i}" source="{esc(edge.source)}" '
                f'target="{esc(edge.target)}">')
            lines.append(f'      <data key="weight">{edge.artifact_count}</data>')
            lines.append('    </edge>')
        lines += ['  </graph>', '</graphml>']
        return "\n".join(lines)


def build_graph(db: ArtifactDB, owner_label: str = "Device owner",
                where: str = "", params: tuple = ()) -> ConnectionGraph:
    """Convenience: build and finalise a graph straight from a container DB."""
    graph = ConnectionGraph(owner_label=owner_label)
    graph.learn_contacts(db.iter_artifacts("category = ?", (Category.CONTACT.value,)))
    graph.add(db.iter_artifacts(where, params))
    return graph.finalise()
