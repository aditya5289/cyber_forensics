#!/usr/bin/env python3
"""Faithful text extraction from the GAT-MADRL Elsevier PDF.

The point of this file is that the reformatted paper must contain the
author's words and nobody else's. Two extraction faults stand in the way, and
both silently corrupt text rather than failing:

  1. LIGATURES. The PDF embeds fi, fl, ff, ffi and ffl as single glyphs with
     no Unicode mapping. pypdf drops them outright - "defined" becomes
     "dened", "traffic" becomes "trac" - which is invisible damage that reads
     almost like a typo. pdfplumber preserves them as (cid:NN) codes, which
     can be mapped back exactly. Every code was identified from its own
     context in the document rather than assumed from a font table.

  2. HYPHENATION. LaTeX breaks words across lines with a hyphen. Joining every
     "X- Y" would also destroy genuine compounds like "topology-aware". So
     extraction is line-aware: only a hyphen at the END of a line is a break
     hyphen, and only those are rejoined.

Nothing here rewrites, summarises or generates. It recovers what was typeset.
"""
from __future__ import annotations

import json
import re
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
import pdfplumber  # noqa: E402

# Every code below was pinned by reading its surrounding text in this exact
# document. The comment on each line is the evidence.
CID_MAP = {
    28:  "fi",    # "the(cid:28)rst time"        -> first
    29:  "fl",    # "mice (cid:29)ows"           -> flows
    30:  "ffi",   # "Tra(cid:30)c engineering"   -> Traffic
    31:  "ffl",   # "enumerated o(cid:31)ine"    -> offline
    27:  "ff",    # "bu(cid:27)er capacity"      -> buffer
    21:  "–",  # "31(cid:21)45%"            -> en dash
    22:  "—",  # "actions (cid:22) about"   -> em dash
    136: "•",  # itemize bullet
    80:  "\\sum",   # display summation
    88:  "\\sum",   # display summation
    2:   "[",     # large bracket, E[...]
    3:   "]",
    104: "[",     # large bracket, E[...]
    105: "]",
    16:  "(",     # large paren
    17:  ")",
    237: "í",  # "Ver(cid:237)ssimo"        -> Veríssimo
    242: "ò",  # "Li(cid:242) P"            -> Liò
}

CID_RE = re.compile(r"\(cid:(\d+)\)")


def repair(text: str) -> str:
    """Replace CID codes with the glyphs they stand for."""
    def sub(m):
        code = int(m.group(1))
        if code not in CID_MAP:
            # Loud rather than silent. An unmapped glyph is missing text.
            raise KeyError(f"unmapped glyph (cid:{code})")
        return CID_MAP[code]
    return CID_RE.sub(sub, text)


def page_lines(page, y_tol: float = 2.0):
    """Group words into visual lines, so line-end hyphens are identifiable."""
    # x_tolerance matters more than it looks. At the default of 3 the
    # justified body text loses its word gaps entirely - whole clauses come
    # back as "Software-definednetworking(SDN)separatesthecontrol". At 1.5
    # the gaps are recovered without splitting words that belong together;
    # both failure modes are asserted against in main().
    words = page.extract_words(x_tolerance=1.5, use_text_flow=True,
                               keep_blank_chars=False)
    lines, current, last_top = [], [], None
    for w in words:
        top = round(w["top"], 1)
        if last_top is None or abs(top - last_top) <= y_tol:
            current.append(w)
        else:
            lines.append(current)
            current = [w]
        last_top = top if last_top is None else (last_top if abs(top - last_top) <= y_tol else top)
    if current:
        lines.append(current)
    return [" ".join(repair(w["text"]) for w in ln) for ln in lines]


def extract(pdf_path: Path):
    all_lines, per_page = [], []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for i, page in enumerate(pdf.pages, 1):
            lines = page_lines(page)
            per_page.append(lines)
            all_lines.extend(lines)
    return all_lines, per_page


def dehyphenate(lines):
    """Rejoin words split by a hyphen at end of line, and only those."""
    out, joined = [], 0
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.search(r"(\w{2,})-$", line)
        if m and i + 1 < len(lines):
            nxt = lines[i + 1].lstrip()
            nm = re.match(r"([A-Za-z]+)(.*)", nxt, re.S)
            # Only join when the continuation begins with lowercase letters.
            # "topology-\nAware" would be a genuine compound at a break.
            if nm and nm.group(1)[:1].islower():
                line = line[: m.start(1)] + m.group(1) + nm.group(1)
                lines[i + 1] = nm.group(2).lstrip()
                joined += 1
                out.append(line)
                i += 1
                continue
        out.append(line)
        i += 1
    return out, joined


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "GAT-MADRL_Elsevier_preview.pdf")
    lines, per_page = extract(src)
    print(f"pages          : {len(per_page)}")
    print(f"raw lines      : {len(lines)}")

    lines, joined = dehyphenate(lines)
    print(f"hyphens rejoined: {joined}")

    text = "\n".join(lines)
    leftover = CID_RE.findall(text)
    print(f"unmapped glyphs : {len(leftover)}  {'OK' if not leftover else set(leftover)}")

    Path("/tmp/gat_clean.txt").write_text(text, encoding="utf-8")
    Path("/tmp/gat_pages.json").write_text(
        json.dumps(per_page, ensure_ascii=False), encoding="utf-8")

    # Prove the repairs landed: words that were broken must now be whole.
    print("\nligature repair check:")
    for w in ["defined", "flatten", "first", "traffic", "flow", "buffer",
              "offline", "efficient", "configuration", "significant"]:
        n = len(re.findall(r"\b" + w, text, re.I))
        print(f"  {w:<14} {n:>4} occurrence(s)")

    # Word-boundary sanity, both directions.
    runon = re.findall(r"\b[a-z]{16,}\b", text)
    print(f"\nrun-on words (>=16 lowercase chars): {len(runon)}  {runon[:5]}")
    frag = re.findall(r"(?<![A-Za-z])[a-z]{1}(?= [a-z]{1} )", text)
    print(f"suspicious single-letter runs         : {len(frag)}")
    for phrase in ["Software-defined networking",
                   "congestion control possible for the first time",
                   "centralized training with decentralized execution"]:
        print(f"  intact: {phrase!r} -> {phrase in text}")

    print("\nresidue check (damaged forms that must NOT appear):")
    for bad in [r"\bdened\b", r"\batten\b", r"\btrac\b", r"\bbuer\b",
                r"\bcongurat", r"\bspecic\b", r"\bsignicant\b"]:
        n = len(re.findall(bad, text, re.I))
        flag = "OK" if n == 0 else "*** STILL DAMAGED ***"
        print(f"  {bad:<18} {n:>3}  {flag}")

    print(f"\nclean text -> /tmp/gat_clean.txt  ({len(text):,} chars)")


if __name__ == "__main__":
    main()
