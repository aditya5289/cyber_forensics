"""Safari history, bookmarks and iOS location caches."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ...core.models import Artifact, Category, Recovery
from ..common import (any_table_probe, as_float, as_int, as_text, pick,
                      rows_with_deleted, valid_coord)
from ..registry import ParseContext, ParseResult, register
from ..sqlite_reader import ForensicSQLite
from ..timestamps import from_epoch, guess


@register(
    name="ios.safari",
    patterns=["History.db", "Safari-History.db",
              "1a0e7afc19d307da602ccdcece51af33afe92c53"],
    platform="ios", priority=80,
    probe=any_table_probe(("history_items", "history_visits")),
    description="Safari browsing history",
)
def parse_history(path: Path, ctx: ParseContext) -> ParseResult:
    """Safari history."""
    res = ParseResult(parser="ios.safari", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        titles = {}
        if db.has_table("history_visits"):
            for r in db.query("SELECT history_item, title, visit_time, "
                              "load_successful FROM history_visits"):
                titles[as_int(r["history_item"])] = r

        for row, recovery, conf in rows_with_deleted(db, "history_items", ctx):
            url = as_text(pick(row, "url", default=""))
            if not url:
                continue
            hid = as_int(row.get("_rowid") or row.get("id"))
            visit = titles.get(hid, {})
            ts = from_epoch(pick(row, "visit_time") or visit.get("visit_time"),
                            "apple")
            if ts is None:
                ts = guess(visit.get("visit_time"), "visit_time")
            if not ctx.in_span(ts):
                continue
            art = Artifact(
                category=Category.WEB, subtype="Visited page", timestamp=ts,
                body=as_text(visit.get("title", "")) or url, app="Safari",
                source_path=ctx.rel(path), source_table="history_items",
                source_row=hid, recovery=recovery, confidence=conf,
                attributes={
                    "url": url, "domain": urlparse(url).netloc,
                    "title": as_text(visit.get("title", "")),
                    "visit_count": as_int(pick(row, "visit_count")),
                    "load_successful": as_int(visit.get("load_successful")),
                    "search_terms": _terms(url),
                },
            )
            res.artifacts.append(art)
            if recovery != Recovery.ALLOCATED:
                res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


@register(
    name="ios.locations",
    patterns=["cache_encryptedA.db", "Cache.sqlite", "consolidated.db",
              "routined.sqlite", "Local.sqlite"],
    platform="ios", priority=70,
    probe=any_table_probe(("ZRTCLLOCATIONMO",), ("CellLocation",),
                          ("WifiLocation",), ("ZRTLEARNEDLOCATIONOFINTERESTMO",)),
    description="iOS location caches (significant locations, cell/Wi-Fi fixes)",
)
def parse_locations(path: Path, ctx: ParseContext) -> ParseResult:
    """iOS location caches."""
    res = ParseResult(parser="ios.locations", source=ctx.rel(path))
    with ForensicSQLite(path) as db:
        specs = [
            ("ZRTCLLOCATIONMO", "ZTIMESTAMP", "apple", "ZLATITUDE", "ZLONGITUDE",
             "Significant location"),
            ("ZRTLEARNEDLOCATIONOFINTERESTMO", "ZCREATIONDATE", "apple",
             "ZLATITUDE", "ZLONGITUDE", "Location of interest"),
            ("CellLocation", "Timestamp", "apple", "Latitude", "Longitude",
             "Cell tower fix"),
            ("WifiLocation", "Timestamp", "apple", "Latitude", "Longitude",
             "Wi-Fi fix"),
        ]
        for table, tcol, epoch, latc, lonc, label in specs:
            if not db.has_table(table):
                continue
            for row, recovery, conf in rows_with_deleted(db, table, ctx):
                lat, lon = valid_coord(pick(row, latc), pick(row, lonc))
                if lat is None:
                    continue
                ts = from_epoch(pick(row, tcol), epoch) or guess(pick(row, tcol), tcol)
                if not ctx.in_span(ts):
                    continue
                art = Artifact(
                    category=Category.PLACE, subtype=label, timestamp=ts,
                    latitude=lat, longitude=lon, app="iOS Location Services",
                    body=f"{label} at {lat:.5f}, {lon:.5f}",
                    source_path=ctx.rel(path), source_table=table,
                    source_row=as_int(row.get("_rowid")), recovery=recovery,
                    confidence=conf,
                    attributes={
                        "latitude": lat, "longitude": lon,
                        "horizontal_accuracy": as_float(
                            pick(row, "ZHORIZONTALACCURACY", "HorizontalAccuracy")),
                        "altitude": as_float(pick(row, "ZALTITUDE", "Altitude")),
                        "speed": as_float(pick(row, "ZSPEED", "Speed")),
                        "course": as_float(pick(row, "ZCOURSE")),
                        "map_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
                    },
                )
                res.artifacts.append(art)
                if recovery != Recovery.ALLOCATED:
                    res.deleted_recovered += 1
        res.warnings.extend(db.warnings)
    return res


def _terms(url: str) -> str:
    try:
        qs = parse_qs(urlparse(url).query)
    except ValueError:
        return ""
    for key in ("q", "query", "search_query", "p", "text"):
        if key in qs and qs[key]:
            return qs[key][0]
    return ""
