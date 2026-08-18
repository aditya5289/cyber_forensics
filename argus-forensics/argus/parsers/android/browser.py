"""Chrome / Chromium / Android browser history, downloads and search terms."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ...core.models import Artifact, Category, Recovery
from ..common import any_table_probe, as_int, as_text, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch, guess

# Chrome's PageTransition core types (ui/base/page_transition_types.h)
TRANSITION = {0: "link", 1: "typed", 2: "auto bookmark", 3: "auto subframe",
              4: "manual subframe", 5: "generated", 6: "start page",
              7: "form submit", 8: "reload", 9: "keyword",
              10: "keyword generated"}


@register(
    name="android.browser",
    patterns=["history", "history.db", "browser2.db", "browser.db"],
    platform="", priority=75,
    probe=any_table_probe(("urls", "visits"), ("history",)),
    description="Chromium-family browsing history, downloads and search terms",
)
def parse(path: Path, ctx: ParseContext) -> ParseResult:
    """Chromium browsing history."""
    res = ParseResult(parser="android.browser", source=ctx.rel(path))
    app = _app_from_path(path)
    with ForensicSQLite(path) as db:
        if db.has_table("urls"):
            visit_counts = {}
            if db.has_table("visits"):
                for r in db.query("SELECT url, COUNT(*) c, MAX(visit_time) last, "
                                  "MAX(transition) t FROM visits GROUP BY url"):
                    visit_counts[as_int(r["url"])] = r

            for row, recovery, conf in rows_with_deleted(db, "urls", ctx):
                url = as_text(pick(row, "url", default=""))
                if not url:
                    continue
                ts = from_epoch(pick(row, "last_visit_time"), "webkit")
                if ts is None:
                    ts = guess(pick(row, "last_visit_time"), "last_visit_time")
                if not ctx.in_span(ts):
                    continue
                uid = as_int(row.get("_rowid") or row.get("id"))
                vc = visit_counts.get(uid, {})
                art = Artifact(
                    category=Category.WEB, subtype="Visited page", timestamp=ts,
                    body=as_text(pick(row, "title", default="")) or url,
                    app=app, source_path=ctx.rel(path), source_table="urls",
                    source_row=uid, recovery=recovery, confidence=conf,
                    attributes={
                        "url": url,
                        "domain": urlparse(url).netloc,
                        "title": as_text(pick(row, "title", default="")),
                        "visit_count": as_int(pick(row, "visit_count")) or vc.get("c"),
                        "typed_count": as_int(pick(row, "typed_count")),
                        "hidden": as_int(pick(row, "hidden")),
                        "transition": TRANSITION.get(
                            (as_int(vc.get("t")) or 0) & 0xFF, ""),
                        "search_terms": _search_terms(url),
                    },
                )
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        # ------------------------------------------------------- downloads
        if db.has_table("downloads"):
            for row, recovery, conf in rows_with_deleted(db, "downloads", ctx):
                target = as_text(pick(row, "target_path", "full_path", default=""))
                ts = from_epoch(pick(row, "start_time"), "webkit") or \
                     guess(pick(row, "start_time"), "start_time")
                if not ctx.in_span(ts):
                    continue
                art = Artifact(
                    category=Category.WEB, subtype="Download", timestamp=ts,
                    body=target or as_text(pick(row, "tab_url", default="")),
                    app=app, source_path=ctx.rel(path), source_table="downloads",
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf,
                    attributes={
                        "target_path": target,
                        "received_bytes": as_int(pick(row, "received_bytes")),
                        "total_bytes": as_int(pick(row, "total_bytes")),
                        "mime_type": as_text(pick(row, "mime_type", default="")),
                        "referrer": as_text(pick(row, "referrer", default="")),
                        "tab_url": as_text(pick(row, "tab_url", default="")),
                        "danger_type": as_int(pick(row, "danger_type")),
                    },
                )
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        # -------------------------------------------- keyword search terms
        if db.has_table("keyword_search_terms"):
            for row, recovery, conf in rows_with_deleted(
                    db, "keyword_search_terms", ctx):
                term = as_text(pick(row, "term", "lower_term", default=""))
                if not term:
                    continue
                art = Artifact(
                    category=Category.WEB, subtype="Search term",
                    body=term, app=app, source_path=ctx.rel(path),
                    source_table="keyword_search_terms",
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf, attributes={"term": term},
                )
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1

        res.warnings.extend(db.warnings)
    return res


def _app_from_path(path: Path) -> str:
    p = path.as_posix().lower()
    for marker, name in (("com.android.chrome", "Chrome"),
                         ("com.chrome.beta", "Chrome Beta"),
                         ("org.mozilla", "Firefox"),
                         ("com.brave", "Brave"),
                         ("com.opera", "Opera"),
                         ("com.microsoft.emmx", "Edge"),
                         ("com.duckduckgo", "DuckDuckGo"),
                         ("com.android.browser", "Android Browser")):
        if marker in p:
            return name
    return "Browser"


def _search_terms(url: str) -> str:
    try:
        qs = parse_qs(urlparse(url).query)
    except ValueError:
        return ""
    for key in ("q", "query", "search_query", "p", "text", "wd"):
        if key in qs and qs[key]:
            return qs[key][0]
    return ""
