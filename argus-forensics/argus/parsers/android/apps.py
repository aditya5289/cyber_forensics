"""Installed application inventory and generic app-database sweep.

Lab manual Step 18 / §6.5 asks for per-application artifacts.  Two mechanisms
here:

* :func:`parse_packages` reads the installed-package list so the case shows
  *what was on the device* even for apps whose data could not be read.
* :func:`parse_generic_app_db` is the catch-all: any SQLite database found
  under an application's private directory that no dedicated parser claimed is
  still surveyed — table names, row counts, and any recoverable
  message-shaped rows.  Without this, evidence in a niche app is silently
  invisible, which is the worst failure mode an analysis tool has.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ...core.models import Artifact, Category, Recovery
from ..common import as_int, as_text, pick
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import guess

PACKAGE_LABELS = {
    "com.whatsapp": "WhatsApp", "com.instagram.android": "Instagram",
    "com.facebook.katana": "Facebook", "com.facebook.orca": "Messenger",
    "com.snapchat.android": "Snapchat", "org.telegram.messenger": "Telegram",
    "com.twitter.android": "X (Twitter)", "com.google.android.gm": "Gmail",
    "com.android.chrome": "Chrome", "com.spotify.music": "Spotify",
    "com.ubercab": "Uber", "net.one97.paytm": "Paytm",
    "com.google.android.apps.maps": "Google Maps",
    "com.signal.android": "Signal", "org.thoughtcrime.securesms": "Signal",
    "com.discord": "Discord", "com.zhiliaoapp.musically": "TikTok",
    "com.linkedin.android": "LinkedIn", "com.reddit.frontpage": "Reddit",
    "com.microsoft.teams": "Microsoft Teams", "us.zoom.videomeetings": "Zoom",
}

# Column-name heuristics for the generic sweep
TEXTY = re.compile(r"(body|text|message|content|caption|title|note|comment|"
                   r"description|snippet|data1)$", re.I)
TIMEY = re.compile(r"(time|date|timestamp|_at|_ts|created|modified)", re.I)
PARTY = re.compile(r"(address|number|sender|recipient|from|to|jid|handle|"
                   r"user|author|contact|phone|email)", re.I)


@register(
    name="android.packages",
    patterns=["packages.list", "packages.xml", "installed_packages.txt"],
    platform="android", priority=85,
    description="Installed application inventory",
)
def parse_packages(path: Path, ctx: ParseContext) -> ParseResult:
    """Installed packages."""
    res = ParseResult(parser="android.packages", source=ctx.rel(path))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        res.warnings.append(f"{path.name}: {exc}")
        return res

    packages: list[tuple[str, dict]] = []
    if path.suffix.lower() == ".xml":
        for m in re.finditer(
                r'<package[^>]*\bname="([^"]+)"([^>]*)>', text):
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(2)))
            packages.append((m.group(1), attrs))
    else:
        for line in text.splitlines():
            parts = line.split()
            if parts:
                packages.append((parts[0], {"uid": parts[1] if len(parts) > 1 else "",
                                            "data_dir": parts[3] if len(parts) > 3 else ""}))

    for name, attrs in packages:
        label = PACKAGE_LABELS.get(name, name.split(".")[-1].title())
        art = Artifact(
            category=Category.APP, subtype="Installed application",
            body=f"{label} ({name})", app=label,
            source_path=ctx.rel(path),
            timestamp=guess(attrs.get("ft") and int(attrs["ft"], 16)
                            if re.fullmatch(r"[0-9a-fA-F]+", attrs.get("ft", ""))
                            else None, "install_time"),
            attributes={
                "package": name, "label": label,
                "version": attrs.get("version", ""),
                "version_name": attrs.get("versionName", ""),
                "uid": attrs.get("uid", ""),
                "data_dir": attrs.get("data_dir", ""),
                "installer": attrs.get("installer", ""),
                "known_messaging_app": name in PACKAGE_LABELS,
            },
        )
        res.artifacts.append(art)
    if not packages:
        res.notes.append(f"{path.name}: no package entries parsed")
    return res


@register(
    name="app.generic",
    patterns=["*.db", "*.sqlite", "*.sqlite3", "*.db3"],
    platform="", priority=5,          # last resort: runs after every specific parser
    description="Generic survey of unrecognised application databases",
)
def parse_generic_app_db(path: Path, ctx: ParseContext) -> ParseResult:
    """Unrecognised application database."""
    res = ParseResult(parser="app.generic", source=ctx.rel(path))
    from ..registry import parsers_for
    # When run directly from the registry this defers to whichever specific
    # parser owns the file. `dispatch` calls it a second time, deliberately, if
    # those parsers decoded nothing — see the fallback there — and passes
    # `force` so this guard does not veto that second attempt.
    if not getattr(ctx, "force_generic", False):
        claimed = [s for s in parsers_for(path, ctx.platform)
                   if s.name != "app.generic"]
        if claimed:
            return res                                # a specific parser owns it

    app = _app_from_path(path)
    try:
        db = ForensicSQLite(path)
    except Exception as exc:
        res.notes.append(f"{path.name}: not readable as SQLite ({exc})")
        return res

    with db:
        tables = {t: s for t, s in db.schemas().items()
                  if not t.startswith(("sqlite_", "android_metadata"))}
        if not tables:
            return res

        summary = {}
        for tname, schema in tables.items():
            try:
                n = len(db.query(f'SELECT 1 FROM "{tname}" LIMIT 5000'))
            except Exception:
                n = 0
            summary[tname] = n

        # Inventory artifact so the database itself is visible in the case
        res.artifacts.append(Artifact(
            category=Category.APP, subtype="Application database",
            body=f"{path.name} — {len(tables)} tables, "
                 f"{sum(summary.values())} rows",
            app=app, source_path=ctx.rel(path),
            attributes={"tables": summary,
                        "header": db.header_report(),
                        "note": "No dedicated parser; surveyed generically."},
        ))

        # Message-shaped rows, live and deleted
        for tname, schema in tables.items():
            text_cols = [c for c in schema.columns if TEXTY.search(c)]
            time_cols = [c for c in schema.columns if TIMEY.search(c)]
            party_cols = [c for c in schema.columns if PARTY.search(c)]
            if not (text_cols and time_cols):
                continue
            emitted = 0
            for row, recovery, conf in _all_rows(db, tname, ctx):
                if emitted >= 3000:
                    break
                body = next((as_text(row.get(c)) for c in text_cols
                             if as_text(row.get(c)).strip()), "")
                if not body or len(body) < 2:
                    continue
                ts = next((guess(row.get(c), c) for c in time_cols
                           if guess(row.get(c), c)), None)
                if not ctx.in_span(ts):
                    continue
                art = Artifact(
                    category=Category.MESSAGE, subtype=f"{app} record",
                    timestamp=ts, body=body, app=app,
                    source_path=ctx.rel(path), source_table=tname,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=min(conf, 0.8),
                    attributes={"heuristic": True,
                                "columns_used": {"text": text_cols[:3],
                                                 "time": time_cols[:3]}},
                )
                for c in party_cols[:3]:
                    v = as_text(row.get(c))
                    if v and len(v) < 80:
                        art.add_participant(v, "", role="party")
                res.artifacts.append(art)
                emitted += 1
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _all_rows(db: ForensicSQLite, table: str, ctx: ParseContext):
    from ..common import rows_with_deleted
    yield from rows_with_deleted(db, table, ctx, min_confidence=0.6)


def _app_from_path(path: Path) -> str:
    parts = path.as_posix().split("/")
    for part in reversed(parts):
        if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}", part):
            return PACKAGE_LABELS.get(part, part.split(".")[-1].title())
    return path.stem.title()
