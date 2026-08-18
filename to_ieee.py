#!/usr/bin/env python3
"""Convert the Elsevier GAT-MADRL paper into IEEEtran LaTeX.

The brief was explicit: change the format, not the words. So this is a
mechanical transformation and deliberately not a rewrite. Every sentence of
body text is carried across byte-for-byte after glyph repair; the only things
that change are the scaffolding around it:

    Elsevier                        IEEE
    ----------------------------    ------------------------------
    1. Introduction                 \\section  -> I. INTRODUCTION
    2.1. Learning-based ...         \\subsection -> A. Learning-based ...
    3.7.1. Input features           \\subsubsection -> 1) Input features
    Keywords:                       \\begin{IEEEkeywords} (Index Terms)
    Figure 3. caption               \\caption inside figure, "Fig. 3."
    Table 4. caption                \\caption above table, "TABLE IV"
    Author-year reference block     \\bibitem, numeric, IEEE order

Paragraph boundaries come from the PDF's own indentation rather than from
guessing at sentence ends, because "...done. The next" is ambiguous in plain
text and the geometry is not.

A verification pass (verify_fidelity.py) diffs the emitted body against the
source word list and must report zero differences.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

LINES = json.load(open("/tmp/gat_lines.json", encoding="utf-8"))

PARA_MIN, PARA_MAX = 141.5, 144.5      # measured paragraph-indent band
ROMAN = {1: "I", 2: "II", 3: "III", 4: "IV", 5: "V", 6: "VI", 7: "VII",
         8: "VIII", 9: "IX", 10: "X"}

# ---------------------------------------------------------------- LaTeX escaping
# Only characters that would break compilation. Maths is left alone: the source
# already contains symbols the author typeset, and mangling them would be a
# content change.
ESC = [("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"), ("$", r"\$"),
       ("#", r"\#"), ("_", r"\_"), ("{", r"\{"), ("}", r"\}"),
       ("~", r"\textasciitilde{}"), ("^", r"\textasciicircum{}")]
UNI = [("–", "--"), ("—", "---"), ("’", "'"), ("‘", "`"),
       ("“", "``"), ("”", "''"), ("í", r"\'{i}"), ("ò", r"\`{o}"),
       ("é", r"\'{e}"), ("ó", r"\'{o}"), ("ü", r'\"{u}'), ("•", r"$\bullet$"),
       ("×", r"$\times$"), ("≈", r"$\approx$"), ("≥", r"$\geq$"),
       ("≤", r"$\leq$"), ("±", r"$\pm$"), ("→", r"$\rightarrow$"),
       ("∈", r"$\in$"), ("σ", r"$\sigma$"), ("α", r"$\alpha$"),
       ("β", r"$\beta$"), ("γ", r"$\gamma$"), ("π", r"$\pi$"),
       ("λ", r"$\lambda$"), ("θ", r"$\theta$"), ("ϕ", r"$\phi$"),
       ("μ", r"$\mu$"), ("τ", r"$\tau$"), ("δ", r"$\delta$"),
       ("Δ", r"$\Delta$"), ("∗", r"$*$"), ("−", "-"), ("″", "''")]


def tex(s: str) -> str:
    for a, b in ESC:
        s = s.replace(a, b)
    for a, b in UNI:
        s = s.replace(a, b)
    return s


# ------------------------------------------------------------------ structure
H1 = re.compile(r"^(\d+)\.\s+(.+)$")
H2 = re.compile(r"^(\d+)\.(\d+)\.\s+(.+)$")
H3 = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.\s+(.+)$")
CAP_FIG = re.compile(r"^Figure\s+(\d+)\.\s*(.*)$")
CAP_TAB = re.compile(r"^Table\s+(\d+)\.\s*(.*)$")


def classify(rec):
    t = rec["text"].strip()
    if H3.match(t):
        return "h3", H3.match(t)
    if H2.match(t):
        return "h2", H2.match(t)
    if H1.match(t) and len(t) < 70 and not t[0].isdigit() * 0:
        m = H1.match(t)
        # A heading is short and title-like; "1. Introduction" not "3. of the".
        if m.group(2)[:1].isupper() and len(m.group(2).split()) <= 8:
            return "h1", m
    if CAP_FIG.match(t):
        return "figcap", CAP_FIG.match(t)
    if CAP_TAB.match(t):
        return "tabcap", CAP_TAB.match(t)
    return "text", None


def find(pred, start=0, end=None):
    end = end if end is not None else len(LINES)
    for i in range(start, end):
        if pred(LINES[i]["text"].strip()):
            return i
    return -1


def main():
    out = []

    # ------------------------------------------------------------ boundaries
    i_abs = find(lambda t: t == "Abstract")
    i_kw = find(lambda t: t.startswith("Keywords:"))
    i_intro = find(lambda t: t == "1. Introduction")
    i_refs = find(lambda t: t == "References")

    title = " ".join(LINES[k]["text"] for k in range(0, i_abs)
                     if not LINES[k]["text"].startswith(("Aditya", "Vimal", "Sanjay",
                                                         "aDepartment", "of Computer",
                                                         "of Technology")))
    title = re.sub(r"\s+", " ", title).strip()

    abstract = " ".join(LINES[k]["text"] for k in range(i_abs + 1, i_kw))
    abstract = re.sub(r"\s+", " ", abstract).strip()

    # Keywords wrap across the footnote block, so gather until the first heading.
    kw_parts = []
    for k in range(i_kw, i_intro):
        t = LINES[k]["text"].strip()
        if t.startswith(("∗Corresponding", "Email address:", "Preprint submitted")):
            continue
        kw_parts.append(t)
    keywords = re.sub(r"\s+", " ", " ".join(kw_parts)).replace("Keywords:", "").strip()

    print(f"title    : {title[:70]}...")
    print(f"abstract : {len(abstract.split())} words")
    print(f"keywords : {keywords[:70]}...")
    print(f"body     : lines {i_intro}..{i_refs}")

    # ---------------------------------------------------------------- preamble
    out.append(r"""%% ============================================================
%% GAT-MADRL - IEEE two-column format (IEEEtran)
%%
%% Reformatted from the Elsevier single-column manuscript.
%% The prose is the authors' own and is carried across unchanged;
%% only the structural markup differs. See NOTES-IEEE-conversion.md.
%%
%% Compile:  pdflatex main -> bibtex main -> pdflatex main x2
%% ============================================================
\documentclass[journal,10pt]{IEEEtran}

\usepackage{cite}
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{algorithmic}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{url}
\usepackage{textcomp}
\usepackage[hidelinks]{hyperref}

\begin{document}
""")

    out.append(r"\title{" + tex(title) + "}")
    out.append(r"""
\author{Aditya~Kumar~Maurya,
        Vimal~Kumar,
        and~Sanjay~Kumar%
\thanks{The authors are with the Department of Computer Science and
Engineering, Madan Mohan Malaviya University of Technology, Gorakhpur,
273010, Uttar Pradesh, India.}%
\thanks{Corresponding author: Vimal Kumar (e-mail:
vimal.kumar@mmmut.ac.in).}}

\markboth{IEEE Transactions on Network and Service Management}%
{Maurya \MakeLowercase{\textit{et al.}}: GAT-MADRL: Topology-Aware
Multi-Agent Deep Reinforcement Learning for Congestion Control in SDN}

\maketitle
""")

    out.append(r"\begin{abstract}")
    out.append(tex(abstract))
    out.append(r"\end{abstract}")
    out.append("")
    out.append(r"\begin{IEEEkeywords}")
    out.append(tex(keywords))
    out.append(r"\end{IEEEkeywords}")
    out.append("")

    # -------------------------------------------------------------------- body
    buf, stats = [], {"h1": 0, "h2": 0, "h3": 0, "fig": 0, "tab": 0, "para": 0}

    def flush():
        if buf:
            para = re.sub(r"\s+", " ", " ".join(buf)).strip()
            if para:
                out.append(tex(para))
                out.append("")
                stats["para"] += 1
            buf.clear()

    k = i_intro
    while k < i_refs:
        rec = LINES[k]
        kind, m = classify(rec)

        if kind == "h1":
            flush()
            out.append(r"\section{" + tex(m.group(2).strip()) + "}")
            out.append("")
            stats["h1"] += 1
        elif kind == "h2":
            flush()
            out.append(r"\subsection{" + tex(m.group(3).strip()) + "}")
            out.append("")
            stats["h2"] += 1
        elif kind == "h3":
            flush()
            out.append(r"\subsubsection{" + tex(m.group(4).strip()) + "}")
            out.append("")
            stats["h3"] += 1
        elif kind == "figcap":
            flush()
            n = int(m.group(1))
            cap = [m.group(2)]
            j = k + 1
            while j < i_refs and classify(LINES[j])[0] == "text" \
                    and not LINES[j]["indented"] and LINES[j]["text"].strip() \
                    and j - k < 4 and not LINES[j]["text"].strip()[0].isdigit():
                cap.append(LINES[j]["text"])
                j += 1
                break
            out.append(r"\begin{figure}[!t]")
            out.append(r"\centering")
            out.append(r"\includegraphics[width=\columnwidth]{fig%d}" % n)
            out.append(r"\caption{" + tex(re.sub(r"\s+", " ", " ".join(cap)).strip()) + "}")
            out.append(r"\label{fig:%d}" % n)
            out.append(r"\end{figure}")
            out.append("")
            stats["fig"] += 1
            k = j - 1
        elif kind == "tabcap":
            flush()
            n = int(m.group(1))
            out.append(r"%% ---- TABLE %d ----------------------------------" % n)
            out.append(r"%% Data recovered from the source PDF by coordinate")
            out.append(r"%% reconstruction; see tables_raw.txt and CHECK it.")
            out.append(r"\begin{table}[!t]")
            out.append(r"\caption{" + tex(m.group(2).strip()) + "}")
            out.append(r"\label{tab:%d}" % n)
            out.append(r"\centering")
            out.append(r"\input{table%d}" % n)
            out.append(r"\end{table}")
            out.append("")
            stats["tab"] += 1
        else:
            t = rec["text"].strip()
            if not t:
                k += 1
                continue
            if PARA_MIN <= rec["x0"] <= PARA_MAX:
                flush()
            buf.append(t)
        k += 1
    flush()

    # -------------------------------------------------------------- references
    out.append(r"\section*{Acknowledgment}")
    out.append("%% Add acknowledgments here, or delete this section.")
    out.append("")
    out.append(r"\begin{thebibliography}{99}")
    refs = build_refs(i_refs)
    for r in refs:
        out.append(r"\bibitem{ref%d} %s" % (r[0], tex(r[1])))
    out.append(r"\end{thebibliography}")
    out.append("")
    out.append(r"\end{document}")

    Path("/tmp/gat_ieee.tex").write_text("\n".join(out), encoding="utf-8")
    print(f"\nsections {stats['h1']}  subsections {stats['h2']}  "
          f"subsubsections {stats['h3']}")
    print(f"figures  {stats['fig']}  tables {stats['tab']}  paragraphs {stats['para']}")
    print(f"references {len(refs)}")
    print("wrote /tmp/gat_ieee.tex")


def build_refs(i_refs):
    """Group the reference block into numbered entries, verbatim."""
    entries, cur, num = [], [], None
    for k in range(i_refs + 1, len(LINES)):
        t = LINES[k]["text"].strip()
        if not t:
            continue
        m = re.match(r"^\[(\d+)\]\s*(.*)$", t)
        if m:
            if num is not None:
                entries.append((num, re.sub(r"\s+", " ", " ".join(cur)).strip()))
            num, cur = int(m.group(1)), [m.group(2)]
        elif num is not None:
            if re.fullmatch(r"\d{1,3}", t):      # page furniture
                continue
            cur.append(t)
    if num is not None:
        entries.append((num, re.sub(r"\s+", " ", " ".join(cur)).strip()))
    return entries


if __name__ == "__main__":
    main()
