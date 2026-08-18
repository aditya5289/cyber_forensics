#!/usr/bin/env python3
"""Structure-aware extraction: lines plus the geometry needed to rebuild them.

Plain text loses two things a reformatter needs and cannot guess:

  PARAGRAPH BREAKS. Once lines are joined, "...end of sentence. Next sentence
  begins" is indistinguishable from a new paragraph. The PDF encodes it
  geometrically - a paragraph's first line is indented. Recording each line's
  left edge recovers it exactly, rather than inferring it from punctuation and
  getting it wrong at every sentence that happens to end a line.

  TABLE GRIDS. The linear text stream interleaves table cells with the
  surrounding prose, so a table read that way can silently attach a number to
  the wrong row. Cells are recovered from x/y positions instead.

Output is JSON: every line with its page, left edge, top, and text.
"""
from __future__ import annotations

import json
import re
import statistics
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
import pdfplumber  # noqa: E402

from extract_paper import CID_MAP, CID_RE, repair  # same glyph table, one source


def page_records(page, page_no, y_tol=2.0):
    words = page.extract_words(x_tolerance=1.5, use_text_flow=True,
                               keep_blank_chars=False)
    rows = {}
    for w in words:
        top = round(w["top"], 1)
        key = None
        for k in rows:
            if abs(k - top) <= y_tol:
                key = k
                break
        rows.setdefault(key if key is not None else top, []).append(w)

    out = []
    for top in sorted(rows):
        ws = sorted(rows[top], key=lambda w: w["x0"])
        out.append({
            "page": page_no,
            "top": top,
            "x0": round(ws[0]["x0"], 1),
            "x1": round(ws[-1]["x1"], 1),
            "size": round(statistics.median(
                [w.get("bottom", 0) - w.get("top", 0) for w in ws]), 2),
            "text": " ".join(repair(w["text"]) for w in ws),
        })
    return out


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "GAT-MADRL_Elsevier_preview.pdf")
    recs = []
    with pdfplumber.open(str(src)) as pdf:
        for i, page in enumerate(pdf.pages, 1):
            recs.extend(page_records(page, i))

    # The body's left margin is the most common left edge; an indent sits a
    # few points right of it and marks a paragraph opening.
    edges = [r["x0"] for r in recs]
    margin = statistics.mode([round(e) for e in edges])
    indents = sorted({round(e) for e in edges if margin < e < margin + 30})
    print(f"lines            : {len(recs)}")
    print(f"body left margin : {margin} pt")
    print(f"indent edges seen: {indents[:8]}")

    para_starts = 0
    for r in recs:
        r["indented"] = bool(margin + 2 < r["x0"] < margin + 30)
        para_starts += r["indented"]
    print(f"indented lines   : {para_starts}  (paragraph openings)")

    Path("/tmp/gat_lines.json").write_text(
        json.dumps(recs, ensure_ascii=False), encoding="utf-8")
    print("wrote /tmp/gat_lines.json")

    print("\nsample - indent flag against text:")
    for r in recs[41:53]:
        flag = "PARA" if r["indented"] else "    "
        print(f"  p{r['page']:>2} x0={r['x0']:>6} {flag}  {r['text'][:72]}")


if __name__ == "__main__":
    main()
