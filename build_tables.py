#!/usr/bin/env python3
"""Rebuild the nine tables from glyph coordinates, and show the working.

Reading a table out of the linear text stream is the one operation here that
can corrupt a result without looking wrong. Cells arrive interleaved with the
surrounding prose and with each other, so a standard deviation from one row
can attach itself to the value above it and the table still reads plausibly.
In a results table that is a fabricated number.

So cells are placed by their x/y position on the page instead, and every
table is also written out as a plain-text dump beside the LaTeX. The dump is
there so the author can check nine tables in about a minute rather than
trusting the reconstruction.

Booktabs rules are emitted because the source uses them; no vertical rules,
per IEEE house style.
"""
from __future__ import annotations

import re
import statistics
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
import pdfplumber  # noqa: E402

from extract_paper import repair  # one glyph table for the whole pipeline

ESC = [("&", r"\&"), ("%", r"\%"), ("$", r"\$"), ("#", r"\#"), ("_", r"\_")]
UNI = [("–", "--"), ("—", "---"), ("±", r"$\pm$"), ("≈", r"$\approx$"),
       ("≥", r"$\geq$"), ("≤", r"$\leq$"), ("×", r"$\times$"), ("−", "-")]


def tex(s):
    for a, b in ESC:
        s = s.replace(a, b)
    for a, b in UNI:
        s = s.replace(a, b)
    return s


def rows_of(page, y_tol=3.0):
    words = [{"t": repair(w["text"]), "x0": w["x0"], "x1": w["x1"],
              "y": round(w["top"], 1)}
             for w in page.extract_words(x_tolerance=1.5, use_text_flow=False)]
    rows = {}
    for w in words:
        key = next((k for k in rows if abs(k - w["y"]) <= y_tol), w["y"])
        rows.setdefault(key, []).append(w)
    return [(y, sorted(rows[y], key=lambda w: w["x0"])) for y in sorted(rows)]


def column_edges(band):
    """Infer column boundaries from the gaps between words across all rows."""
    starts = sorted(w["x0"] for _, ws in band for w in ws)
    if not starts:
        return []
    edges, run = [starts[0]], [starts[0]]
    for s in starts[1:]:
        if s - run[-1] > 8:          # a real column gap, not inter-word space
            edges.append(s)
            run = [s]
        else:
            run.append(s)
    # Merge edges that are within a few points of each other.
    merged = [edges[0]]
    for e in edges[1:]:
        if e - merged[-1] > 12:
            merged.append(e)
    return merged


def table_band(rows, cap_y, max_rows=26):
    """The rows immediately above a 'Table N.' caption are the table body."""
    band = []
    for y, ws in rows:
        if y >= cap_y:
            break
        band.append((y, ws))
    return band[-max_rows:]


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "GAT-MADRL_Elsevier_preview.pdf")
    outdir = Path("/tmp/tables")
    outdir.mkdir(exist_ok=True)
    dump = []

    with pdfplumber.open(str(src)) as pdf:
        for pno, page in enumerate(pdf.pages, 1):
            rows = rows_of(page)
            for y, ws in rows:
                line = " ".join(w["t"] for w in ws)
                m = re.match(r"^Table\s+(\d+)\.", line)
                if not m:
                    continue
                n = int(m.group(1))
                band = table_band(rows, y)
                # Trim to where the table actually starts: walk up while rows
                # still look tabular (3+ cells or short numeric content).
                keep = []
                for by, bws in reversed(band):
                    txt = " ".join(w["t"] for w in bws)
                    if len(bws) >= 3 or re.fullmatch(r"[\d\.\(\)\s—–%-]+", txt):
                        keep.append((by, bws))
                    elif keep:
                        break
                keep.reverse()
                if not keep:
                    continue

                edges = column_edges(keep)
                ncol = max(1, len(edges))
                grid = []
                for by, bws in keep:
                    cells = [""] * ncol
                    for w in bws:
                        ci = max(0, sum(1 for e in edges if w["x0"] >= e - 4) - 1)
                        cells[ci] = (cells[ci] + " " + w["t"]).strip()
                    grid.append(cells)

                dump.append(f"===== TABLE {n}  (page {pno}, {len(grid)} rows, "
                            f"{ncol} cols) =====")
                dump.append(f"caption: {line}")
                for cells in grid:
                    dump.append("  | " + " | ".join(c or "" for c in cells))
                dump.append("")

                body = ["\\begin{tabular}{@{}l" + "r" * (ncol - 1) + "@{}}",
                        "\\toprule"]
                for i, cells in enumerate(grid):
                    body.append(" & ".join(tex(c) for c in cells) + r" \\")
                    if i == 0:
                        body.append("\\midrule")
                body.append("\\bottomrule")
                body.append("\\end{tabular}")
                (outdir / f"table{n}.tex").write_text("\n".join(body), encoding="utf-8")
                print(f"  table{n}.tex  page {pno:>2}  {len(grid)} rows x {ncol} cols")

    Path("/tmp/tables_raw.txt").write_text("\n".join(dump), encoding="utf-8")
    print(f"\nraw dump -> /tmp/tables_raw.txt  ({len(dump)} lines)")
    print("CHECK the dump against the source PDF before submitting.")


if __name__ == "__main__":
    main()
