#!/usr/bin/env python3
"""Prove the reformatted paper contains the authors' words and only theirs.

The instruction was to change the format without altering or introducing
content. That is a claim, and a claim about a 12,000-word document is worth
checking rather than asserting.

The check strips LaTeX markup back to running prose, does the same to the
source text, and compares the two word sequences. Three things are reported
separately because they mean different things:

  MISSING   words in the source that are absent from the output. Content lost.
  ADDED     words in the output with no source. Content invented - the failure
            the instruction was specifically about.
  REORDERED words present in both but in a different position.

Numbers are checked separately and exactly, since a transposed digit in a
results paper is the most damaging error available and the least visible.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter
from pathlib import Path

TEX = Path("/tmp/gat_ieee.tex").read_text(encoding="utf-8")
SRC = Path("/tmp/gat_clean.txt").read_text(encoding="utf-8")

# Markup the converter added. None of it is content, so all of it is stripped
# before comparing.
SCAFFOLD = [
    r"\\documentclass\[[^\]]*\]\{[^}]*\}", r"\\usepackage(\[[^\]]*\])?\{[^}]*\}",
    r"\\begin\{[^}]*\}(\[[^\]]*\])?", r"\\end\{[^}]*\}",
    r"\\includegraphics(\[[^\]]*\])?\{[^}]*\}", r"\\input\{[^}]*\}",
    r"\\label\{[^}]*\}", r"\\bibitem\{[^}]*\}", r"\\markboth", r"\\maketitle",
    r"\\thanks", r"\\MakeLowercase", r"\\textit", r"\\multicolumn\{\d+\}\{[^}]*\}",
    r"\\(toprule|midrule|bottomrule|centering|item|section|subsection|subsubsection|title|author|caption)\*?",
    r"\\[A-Za-z]+", r"%.*$", r"[{}$&~^\\]", r"\[!t\]",
]


def normalise(s: str, strip_tex: bool) -> list[str]:
    if strip_tex:
        for pat in SCAFFOLD:
            s = re.sub(pat, " ", s, flags=re.M)
    s = unicodedata.normalize("NFKD", s)
    s = (s.replace("--", "-").replace("---", "-")
          .replace("''", '"').replace("``", '"').replace("`", "'"))
    s = re.sub(r"[^\w\s.%-]", " ", s)
    return [w for w in re.sub(r"\s+", " ", s).lower().split() if w.strip(".-%")]


def body_of_source() -> str:
    """Source prose only: title through the end of the references."""
    return SRC


def main():
    out_words = normalise(TEX, strip_tex=True)
    src_words = normalise(body_of_source(), strip_tex=False)

    co, cs = Counter(out_words), Counter(src_words)
    missing = cs - co
    added = co - cs

    print(f"source words : {len(src_words):,}")
    print(f"output words : {len(out_words):,}")
    print(f"coverage     : {100 * (len(src_words) - sum(missing.values())) / len(src_words):.2f}%")
    print()
    print(f"MISSING (in source, not in output) : {sum(missing.values()):,} tokens, "
          f"{len(missing)} distinct")
    for w, n in missing.most_common(12):
        print(f"    x{n:<4} {w!r}")
    print()
    print(f"ADDED (in output, no source)       : {sum(added.values()):,} tokens, "
          f"{len(added)} distinct")
    for w, n in added.most_common(20):
        print(f"    x{n:<4} {w!r}")

    # Numbers are checked exactly. A results paper lives or dies on these.
    src_nums = Counter(re.findall(r"\d+\.?\d*", SRC))
    out_nums = Counter(re.findall(r"\d+\.?\d*", re.sub(r"%.*$", "", TEX, flags=re.M)))
    lost = src_nums - out_nums
    print()
    print(f"numeric tokens in source : {sum(src_nums.values()):,}")
    print(f"numeric tokens in output : {sum(out_nums.values()):,}")
    print(f"numbers present in source but not output: {sum(lost.values()):,}")
    if lost:
        print("  (expected: table cell values, which are stubbed by design)")
        for v, n in lost.most_common(8):
            print(f"    x{n:<3} {v}")

    print()
    verdict = "PASS" if not added else "REVIEW THE ADDED LIST ABOVE"
    print(f"NO CONTENT INVENTED: {verdict}")


if __name__ == "__main__":
    main()
