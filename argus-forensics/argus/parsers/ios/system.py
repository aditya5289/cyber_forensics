"""iOS system telemetry — KnowledgeC, PowerLog and notifications.

`KnowledgeC.db` is the single richest behavioural source on an iPhone. iOS
records, for its own analytics, every app launch, every screen lock and unlock,
every Now-Playing item, every Siri request and every device plug-in, with
start and end timestamps. It is not intended as an audit trail, which is
exactly why it is so useful: a user who deletes their messages does not think
to clear KnowledgeC.

Why this matters evidentially: message databases tell you what a device sent.
KnowledgeC tells you whether *someone was holding it* at that second — screen
unlocked, app in the foreground, the handset in use. That distinction decides
whether a message can be attributed to a person rather than to a phone.

Structure: Core Data, so `Z`-prefixed columns and Apple absolute time. The
central table is `ZOBJECT`, with `ZSTREAMNAME` naming the event class:

===============================  =====================================
``/app/inFocus``                 app in the foreground, with duration
``/app/usage``                   cumulative app usage
``/device/isLocked``             lock state transitions
``/display/isBacklit``           screen on/off
``/audio/nowPlaying``            media playback
``/siri/*``                      Siri invocations
``/app/webUsage``                in-app browsing
``/portrait/*``, ``/watch/*``    peripheral state
===============================  =====================================
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.models import Artifact, Category, Direction, Recovery
from ..common import any_table_probe, as_float, as_int, as_text, pick, rows_with_deleted
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch, guess

US = 1_000_000

STREAM_LABELS = {
    "/app/inFocus": ("App in foreground", Category.ACTIVITY),
    "/app/usage": ("App usage", Category.ACTIVITY),
    "/app/activity": ("App activity", Category.ACTIVITY),
    "/app/install": ("App installed", Category.APP),
    "/app/intents": ("App intent", Category.ACTIVITY),
    "/app/webUsage": ("In-app browsing", Category.WEB),
    "/device/isLocked": ("Device lock state", Category.SECURITY),
    "/device/isPluggedIn": ("Charger connected", Category.DEVICE),
    "/display/isBacklit": ("Screen on", Category.ACTIVITY),
    "/audio/nowPlaying": ("Media playing", Category.ACTIVITY),
    "/siri/ui": ("Siri invoked", Category.ACTIVITY),
    "/bluetooth/isConnected": ("Bluetooth connected", Category.NETWORK),
    "/carplay/isConnected": ("CarPlay connected", Category.NETWORK),
    "/notification/usage": ("Notification", Category.ACTIVITY),
    "/safari/history": ("Safari browsing", Category.WEB),
    "/watch/nearby": ("Paired watch nearby", Category.DEVICE),
}

APP_LABELS = {
    "net.whatsapp.WhatsApp": "WhatsApp",
    "com.apple.MobileSMS": "Apple Messages",
    "com.apple.mobilephone": "Apple Phone",
    "com.burbn.instagram": "Instagram",
    "com.toyopagroup.picaboo": "Snapchat",
    "ph.telegra.Telegraph": "Telegram",
    "org.whispersystems.signal": "Signal",
    "com.facebook.Messenger": "Messenger",
    "com.apple.mobilesafari": "Safari",
    "com.google.Gmail": "Gmail",
    "com.apple.mobilemail": "Apple Mail",
    "com.apple.Maps": "Apple Maps",
    "com.google.Maps": "Google Maps",
    "com.apple.camera": "Camera",
    "com.apple.mobileslideshow": "Photos",
}


def _app_label(bundle: str) -> str:
    if not bundle:
        return "iOS"
    return APP_LABELS.get(bundle, bundle.rsplit(".", 1)[-1].title())


@register(
    name="ios.knowledgec",
    patterns=["KnowledgeC.db", "knowledgeC.db", "CoreDuetKnowledge*.db"],
    platform="ios", priority=84,
    probe=any_table_probe(("ZOBJECT",)),
    description="iOS KnowledgeC — app launches, lock state, screen and Siri events",
)
def parse_knowledgec(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS KnowledgeC device-usage timeline."""
    res = ParseResult(parser="ios.knowledgec", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        if not db.has_table("ZOBJECT"):
            res.notes.append(f"{path.name}: no ZOBJECT table")
            return res

        columns = {c.upper() for c in db.columns("ZOBJECT")}
        # Column names drift between iOS versions; resolve what is present.
        stream_col = next((c for c in ("ZSTREAMNAME",) if c in columns), "")
        start_col = next((c for c in ("ZSTARTDATE",) if c in columns), "")
        end_col = next((c for c in ("ZENDDATE",) if c in columns), "")
        value_col = next((c for c in ("ZVALUESTRING",) if c in columns), "")
        created_col = next((c for c in ("ZCREATIONDATE",) if c in columns), "")

        if not stream_col:
            res.notes.append(f"{path.name}: ZOBJECT has no ZSTREAMNAME column "
                             f"— unrecognised KnowledgeC variant")
            return res

        focus_seconds: Dict[str, float] = {}
        counts: Dict[str, int] = {}

        for row, recovery, conf in rows_with_deleted(db, "ZOBJECT", ctx):
            stream = as_text(row.get(stream_col))
            if not stream:
                continue
            start = from_epoch(row.get(start_col), "apple") if start_col else None
            end = from_epoch(row.get(end_col), "apple") if end_col else None
            if start is None and created_col:
                start = from_epoch(row.get(created_col), "apple")
            if not ctx.in_span(start):
                continue

            label, category = STREAM_LABELS.get(
                stream, (stream.strip("/").replace("/", " ").title(),
                         Category.ACTIVITY))
            value = as_text(row.get(value_col)) if value_col else ""
            app_label = _app_label(value) if value and "." in value else ""
            duration = None
            if start is not None and end is not None and end >= start:
                duration = round((end - start) / US, 1)

            counts[stream] = counts.get(stream, 0) + 1
            if stream == "/app/inFocus" and duration:
                focus_seconds[app_label or value] = \
                    focus_seconds.get(app_label or value, 0.0) + duration

            body = label
            if app_label:
                body = f"{app_label} — {label.lower()}"
            elif value:
                body = f"{label}: {value}"
            if duration:
                body += f" ({duration:g}s)"

            art = Artifact(
                category=category, subtype=f"KnowledgeC: {label}",
                timestamp=start, timestamp_end=end, body=body,
                app=app_label or "iOS", source_path=ctx.rel(path),
                source_table="ZOBJECT",
                source_row=as_int(row.get("Z_PK") or row.get("_rowid")),
                recovery=recovery, confidence=conf,
                attributes={
                    "stream": stream, "value": value,
                    "bundle_id": value if "." in value else "",
                    "duration_seconds": duration,
                    "note": ("KnowledgeC is iOS's own analytics store. Users "
                             "who clear their message history rarely clear it, "
                             "so it often survives deliberate cleanup."
                             if stream in ("/app/inFocus", "/device/isLocked")
                             else ""),
                },
            )
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1

        if counts:
            top = sorted(focus_seconds.items(), key=lambda kv: -kv[1])[:5]
            res.notes.append(
                f"{ctx.rel(path)}: {sum(counts.values())} KnowledgeC events "
                f"across {len(counts)} streams."
                + (f" Most foreground time: "
                   + ", ".join(f"{a} {s/60:.0f}min" for a, s in top)
                   if top else ""))
            # A device-usage summary artifact makes the aggregate visible
            # without an examiner having to total thousands of rows by hand.
            res.artifacts.append(Artifact(
                category=Category.DEVICE, subtype="Device usage summary",
                body=("Foreground time by application, derived from "
                      f"{counts.get('/app/inFocus', 0)} KnowledgeC focus events"),
                app="iOS", source_path=ctx.rel(path),
                attributes={
                    "foreground_seconds_by_app": {
                        k: round(v, 1) for k, v in
                        sorted(focus_seconds.items(), key=lambda kv: -kv[1])[:40]},
                    "event_counts_by_stream": dict(
                        sorted(counts.items(), key=lambda kv: -kv[1])),
                    "note": ("Derived from KnowledgeC. Establishes which "
                             "applications were actually used and for how long, "
                             "independently of whether their own databases "
                             "survived."),
                },
            ))
        res.warnings.extend(db.warnings)
    return res


@register(
    name="ios.powerlog",
    patterns=["CurrentPowerlog.PLSQL", "powerlog*.PLSQL", "Powerlog*.db"],
    platform="ios", priority=76,
    probe=any_table_probe(("PLApplicationAgent_EventForward_Application",),
                          ("PLAccountingOperator_EventNone_Nodes",),
                          ("PLApplicationAgent_EventNone_AppRunTime",)),
    description="iOS PowerLog — app runtime and device power events",
)
def parse_powerlog(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS PowerLog.

    PowerLog exists for battery diagnostics and retains roughly three days of
    data. Within that window it corroborates KnowledgeC independently — two
    separate stores agreeing on when an app ran is considerably stronger than
    either alone.
    """
    res = ParseResult(parser="ios.powerlog", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        candidates = [t for t in db.schemas()
                      if t.startswith("PLApplicationAgent")
                      or t.startswith("PLAccountingOperator")]
        if not candidates:
            res.notes.append(f"{path.name}: no PowerLog application tables")
            return res

        total = 0
        for table in candidates[:8]:
            cols = {c.lower(): c for c in db.columns(table)}
            bundle_col = next((cols[c] for c in
                               ("bundleid", "bundle_id", "appname", "nodename")
                               if c in cols), "")
            ts_col = next((cols[c] for c in
                           ("timestamp", "starttime", "time", "date")
                           if c in cols), "")
            if not (bundle_col and ts_col):
                continue
            dur_col = next((cols[c] for c in ("duration", "runtime", "value")
                            if c in cols), "")

            for row, recovery, conf in rows_with_deleted(db, table, ctx):
                bundle = as_text(row.get(bundle_col))
                if not bundle:
                    continue
                ts = guess(row.get(ts_col), ts_col)
                if not ctx.in_span(ts):
                    continue
                duration = as_float(row.get(dur_col)) if dur_col else None
                label = _app_label(bundle)
                art = Artifact(
                    category=Category.ACTIVITY, subtype="PowerLog app runtime",
                    timestamp=ts, body=(f"{label} running"
                                        + (f" ({duration:g}s)" if duration else "")),
                    app=label, source_path=ctx.rel(path), source_table=table,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf,
                    attributes={
                        "bundle_id": bundle, "duration_seconds": duration,
                        "powerlog_table": table,
                        "note": ("PowerLog retains roughly three days. Where it "
                                 "overlaps KnowledgeC, the two corroborate each "
                                 "other independently."),
                    },
                )
                res.artifacts.append(art)
                total += 1
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
                if total >= 8000:
                    break
            if total >= 8000:
                res.notes.append(f"{ctx.rel(path)}: truncated at 8 000 events")
                break
        res.warnings.extend(db.warnings)
    return res


@register(
    name="ios.notifications",
    patterns=["*.notifications", "ClearedNotifications.plist",
              "DeliveredNotifications.plist"],
    platform="ios", priority=74,
    description="iOS delivered and cleared notifications",
)
def parse_ios_notifications(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS notification store.

    As on Android, notifications preview content from apps whose own stores are
    encrypted, so this can be the only readable copy of a Signal or Telegram
    message.
    """
    res = ParseResult(parser="ios.notifications", source=ctx.rel(path))
    from .. import plist_reader

    try:
        data = plist_reader.read(path)
    except Exception as exc:
        res.notes.append(f"{path.name}: not a readable plist ({exc})")
        return res

    flat = plist_reader.flatten(data)
    records: Dict[str, Dict[str, Any]] = {}
    for key, value in flat.items():
        match = re.match(r"^(.*?\[\d+\])\.(.*)$", key)
        if not match:
            continue
        group, field = match.groups()
        records.setdefault(group, {})[field.lower()] = value

    for group, fields in records.items():
        title = next((str(v) for k, v in fields.items()
                      if "title" in k and v), "")
        body = next((str(v) for k, v in fields.items()
                     if ("body" in k or "message" in k) and v), "")
        bundle = next((str(v) for k, v in fields.items()
                       if "bundle" in k and v), "")
        when = next((v for k, v in fields.items()
                     if "date" in k or "time" in k), None)
        if not (title or body):
            continue
        ts = guess(when) if when is not None else None
        if not ctx.in_span(ts):
            continue
        label = _app_label(bundle)
        encrypted = bundle in ("org.whispersystems.signal",
                               "ph.telegra.Telegraph", "com.wickr.me")
        art = Artifact(
            category=Category.MESSAGE if body else Category.ACTIVITY,
            subtype=f"{label} notification", timestamp=ts,
            body=f"{title}: {body}".strip(": ") if title else body,
            app=label, direction=Direction.INCOMING,
            source_path=ctx.rel(path),
            attributes={
                "bundle_id": bundle, "title": title, "text": body,
                "previews_encrypted_app": encrypted,
                "note": ("Previews content from an app whose store is "
                         "encrypted — potentially the only readable copy."
                         if encrypted else ""),
            },
        )
        if title:
            art.add_participant("", title, role="from")
        art.add_participant("", ctx.owner_name, role="to", is_owner=True)
        res.artifacts.append(art)
    return res
