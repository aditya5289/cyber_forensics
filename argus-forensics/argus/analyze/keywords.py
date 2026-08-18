"""Keyword-list search over sealed evidence.

Examiners arrive with a list of names, numbers, and phrases — not a single
AQL query. This module runs each term against the same FTS index the Analyst
search box uses, then ranks hits so a 400-term list does not bury the one
that actually matched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Sequence


def parse_keyword_text(text: str) -> List[str]:
    """Split a keyword file or pasted list into unique search terms.

    Accepts one term per line, optional ``#`` comments, quoted phrases, and
    comma-separated values on a single line. Empty lines are ignored.
    """
    seen = set()
    out: List[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        chunks = _split_line(line)
        for term in chunks:
            key = term.casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(term)
    return out


def parse_keyword_file(path: Path | str) -> List[str]:
    return parse_keyword_text(Path(path).read_text(encoding="utf-8", errors="replace"))


def _split_line(line: str) -> List[str]:
    if "," in line and not (line.startswith('"') and line.endswith('"')):
        parts = [p.strip() for p in line.split(",")]
        return [p.strip('"').strip("'") for p in parts if p.strip()]
    if (line.startswith('"') and line.endswith('"')) or (
            line.startswith("'") and line.endswith("'")):
        inner = line[1:-1].strip()
        return [inner] if inner else []
    return [line]


def aql_for_term(term: str) -> str:
    """Quote a term so AQL treats it as a phrase, not a field:value pair."""
    cleaned = (term or "").replace('"', "").strip()
    if not cleaned:
        return ""
    return f'"{cleaned}"'


def scan_keywords(session, terms: Sequence[str], *,
                  per_term: int = 25) -> dict:
    """Run each term and return ranked hit counts plus sample artifacts."""
    hits = []
    for term in terms:
        q = aql_for_term(term)
        if not q:
            continue
        result = session.query(q, limit=per_term, order="timestamp DESC")
        samples = []
        for art in result.get("artifacts") or []:
            samples.append({
                "artifact_id": art.get("artifact_id"),
                "timestamp_iso": art.get("timestamp_iso"),
                "category": art.get("category"),
                "subtype": art.get("subtype"),
                "app": art.get("app"),
                "body": (art.get("body") or "")[:240],
                "recovery": art.get("recovery"),
            })
        hits.append({
            "term": term,
            "query": q,
            "total": int(result.get("total") or 0),
            "samples": samples,
        })
    hits.sort(key=lambda h: (-int(h["total"]), h["term"].lower()))
    matched = [h for h in hits if h["total"]]
    return {
        "terms": len(hits),
        "matched": len(matched),
        "unmatched": len(hits) - len(matched),
        "hits": hits,
    }


def load_terms(terms: Iterable[str] = (), text: str = "",
               path: str = "") -> List[str]:
    collected: List[str] = []
    if path:
        collected.extend(parse_keyword_file(path))
    if text:
        collected.extend(parse_keyword_text(text))
    collected.extend(t.strip() for t in terms if str(t).strip())
    return parse_keyword_text("\n".join(collected))
