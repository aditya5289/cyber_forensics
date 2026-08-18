"""Visualization helpers — buckets, clusters, and heat grids for the analyst UI.

These transform raw artifact streams into chart-ready structures without
shipping hundreds of thousands of rows to the browser.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

US = 1_000_000

_CATEGORY_COLOURS = {
    "Messages": "#4c9aff",
    "Calls": "#3fb950",
    "Contacts": "#a371f7",
    "Files & Media": "#e2b33c",
    "Web": "#f778ba",
    "Locations": "#56d4dd",
    "Calendar": "#ff9a3c",
    "Applications": "#8b949e",
}


def timeline_buckets(entries: List[Dict[str, Any]],
                     resolution: str = "hour",
                     tz_offset_minutes: int = 0) -> Dict[str, Any]:
    """Aggregate timeline entries into time buckets for interactive charts.

    ``resolution`` is one of: minute, hour, day, week.
    """
    from datetime import datetime, timedelta, timezone

    if not entries:
        return {"buckets": [], "categories": {}, "resolution": resolution,
                "total": 0}

    tz = timezone(timedelta(minutes=tz_offset_minutes))
    buckets: Counter = Counter()
    by_cat: Dict[str, Counter] = defaultdict(Counter)

    def bucket_key(ts: int) -> str:
        dt = datetime.fromtimestamp(ts / US, tz=timezone.utc).astimezone(tz)
        if resolution == "minute":
            return dt.strftime("%Y-%m-%dT%H:%M")
        if resolution == "hour":
            return dt.strftime("%Y-%m-%dT%H")
        if resolution == "week":
            iso = dt.isocalendar()
            return f"{iso.year}-W{iso.week:02d}"
        return dt.strftime("%Y-%m-%d")

    for e in entries:
        ts = e.get("timestamp")
        if ts is None:
            continue
        key = bucket_key(int(ts))
        buckets[key] += 1
        cat = e.get("category") or "Other"
        by_cat[cat][key] += 1

    ordered = sorted(buckets.items())
    return {
        "resolution": resolution,
        "total": sum(buckets.values()),
        "buckets": [{"key": k, "count": c} for k, c in ordered],
        "categories": {cat: [{"key": k, "count": c}
                             for k, c in sorted(cnt.items())]
                       for cat, cnt in by_cat.items()},
        "colours": _CATEGORY_COLOURS,
    }


def cluster_places(points: List[Dict[str, Any]],
                   precision: int = 3) -> Dict[str, Any]:
    """Grid-cluster geolocated points for map heatmaps."""
    if not points:
        return {"clusters": [], "tracks": [], "heatmap": [],
                "bounds": {}, "count": 0}

    grid: Dict[Tuple[int, int], Dict[str, Any]] = {}
    by_day: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for p in points:
        lat, lon = float(p["latitude"]), float(p["longitude"])
        gx = int(round(lat * (10 ** precision)))
        gy = int(round(lon * (10 ** precision)))
        cell = grid.setdefault((gx, gy), {
            "latitude": round(lat, precision + 1),
            "longitude": round(lon, precision + 1),
            "count": 0,
            "categories": Counter(),
            "artifact_ids": [],
        })
        cell["count"] += 1
        cell["categories"][p.get("category", "")] += 1
        if len(cell["artifact_ids"]) < 8:
            cell["artifact_ids"].append(p.get("artifact_id", ""))
        day = (p.get("iso") or "")[:10]
        if day:
            by_day[day].append(p)

    clusters = []
    for (_, _), cell in sorted(grid.items(), key=lambda kv: -kv[1]["count"]):
        clusters.append({
            "latitude": cell["latitude"],
            "longitude": cell["longitude"],
            "count": cell["count"],
            "categories": dict(cell["categories"].most_common(4)),
            "artifact_ids": cell["artifact_ids"],
        })

    tracks = []
    for day, pts in sorted(by_day.items())[-30:]:
        ordered = sorted(pts, key=lambda x: x.get("timestamp") or 0)
        if len(ordered) < 2:
            continue
        tracks.append({
            "date": day,
            "points": [{"latitude": p["latitude"], "longitude": p["longitude"],
                        "timestamp": p.get("timestamp"),
                        "summary": p.get("summary", "")[:60]}
                       for p in ordered[:200]],
        })

    lats = [p["latitude"] for p in points]
    lons = [p["longitude"] for p in points]
    return {
        "count": len(points),
        "clusters": clusters[:500],
        "tracks": tracks,
        "bounds": {
            "min_lat": min(lats), "max_lat": max(lats),
            "min_lon": min(lons), "max_lon": max(lons),
        },
        "centroid": {
            "latitude": sum(lats) / len(lats),
            "longitude": sum(lons) / len(lons),
        },
    }


def temporal_insights(histogram: Dict[str, Any],
                      stacked_daily: Optional[List[Dict[str, Any]]] = None
                      ) -> Dict[str, Any]:
    """Derive examiner-facing temporal signals without hydrating artifacts."""
    by_day = histogram.get("by_day") or []
    counts = [int(d.get("count") or 0) for d in by_day]
    active_days = len([c for c in counts if c > 0])
    total = sum(counts) or 1
    median = sorted(counts)[len(counts) // 2] if counts else 0
    bursts: List[Dict[str, Any]] = []
    for row in by_day:
        c = int(row.get("count") or 0)
        if c >= max(12, median * 2):
            bursts.append({
                "date": row.get("date", ""),
                "count": c,
                "ratio": round(c / max(median, 1), 1),
            })
    bursts.sort(key=lambda x: -x["count"])
    gaps: List[Dict[str, Any]] = []
    if len(by_day) >= 2:
        from datetime import datetime, timedelta

        dates = [datetime.strptime(d["date"], "%Y-%m-%d")
                 for d in by_day if d.get("date")]
        dates.sort()
        longest = 0
        gap_start = gap_end = ""
        for i in range(1, len(dates)):
            delta = (dates[i] - dates[i - 1]).days
            if delta > longest:
                longest = delta
                gap_start = dates[i - 1].strftime("%Y-%m-%d")
                gap_end = dates[i].strftime("%Y-%m-%d")
        if longest > 2:
            gaps.append({
                "days": longest,
                "from": gap_start,
                "to": gap_end,
            })
    avg_daily = round(total / max(active_days, 1), 1)
    stacked = stacked_daily or []
    top_day = max(stacked, key=lambda x: x.get("total") or 0) if stacked else {}
    return {
        "peak_hour": histogram.get("peak_hour"),
        "peak_day": histogram.get("peak_day"),
        "night_activity_pct": histogram.get("night_activity_pct", 0),
        "active_days": histogram.get("active_days", active_days),
        "avg_events_per_active_day": avg_daily,
        "busiest_day": {
            "date": top_day.get("date", ""),
            "total": int(top_day.get("total") or 0),
        } if top_day else {},
        "bursts": bursts[:6],
        "gaps": gaps[:3],
    }


def examination_health(*, integrity_ok: bool, total: int, timestamped: int,
                       categories: int, alerts: int,
                       encrypted_stores: int) -> Dict[str, Any]:
    """0–100 readiness score with transparent breakdown."""
    breakdown: Dict[str, Any] = {}
    score = 0.0
    if integrity_ok:
        breakdown["integrity"] = 35
        score += 35
    else:
        breakdown["integrity"] = 0
    if total <= 0:
        breakdown["decode"] = 0
    else:
        ts_pct = min(1.0, timestamped / total)
        breakdown["timestamp_coverage"] = round(25 * ts_pct)
        score += breakdown["timestamp_coverage"]
        richness = min(1.0, categories / 6.0)
        breakdown["category_richness"] = round(20 * richness)
        score += breakdown["category_richness"]
        breakdown["volume"] = 10 if total >= 50 else round(10 * total / 50)
        score += breakdown["volume"]
    penalty = min(15, alerts * 4 + encrypted_stores * 2)
    breakdown["risk_penalty"] = -penalty
    score = max(0, min(100, round(score - penalty)))
    label = ("excellent" if score >= 85 else "good" if score >= 70
             else "fair" if score >= 50 else "limited")
    return {"score": score, "label": label, "breakdown": breakdown}


def chart_series(histogram: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise histogram output for dashboard mini-charts."""
    by_hour = histogram.get("by_hour") or []
    peak_h = max((h.get("count", 0) for h in by_hour), default=1) or 1
    by_weekday = histogram.get("by_weekday") or []
    peak_d = max((d.get("count", 0) for d in by_weekday), default=1) or 1
    by_day = histogram.get("by_day") or []
    return {
        "hourly": [{"label": f"{h.get('hour', 0):02d}:00",
                      "count": h.get("count", 0),
                      "pct": round(100 * h.get("count", 0) / peak_h, 1)}
                     for h in by_hour],
        "weekday": [{"label": (d.get("day") or "")[:3],
                       "count": d.get("count", 0),
                       "pct": round(100 * d.get("count", 0) / peak_d, 1)}
                      for d in by_weekday],
        "daily": by_day[-60:],
        "night_activity_pct": histogram.get("night_activity_pct", 0),
        "peak_hour": histogram.get("peak_hour"),
        "active_days": histogram.get("active_days", 0),
    }


def mercator_project(lat: float, lon: float, bounds: Dict[str, float],
                     width: float, height: float,
                     pad: float = 24) -> Tuple[float, float]:
    """Project lat/lon into canvas coordinates."""
    min_lat = bounds.get("min_lat", lat)
    max_lat = bounds.get("max_lat", lat)
    min_lon = bounds.get("min_lon", lon)
    max_lon = bounds.get("max_lon", lon)
    if max_lat == min_lat:
        max_lat += 0.01
        min_lat -= 0.01
    if max_lon == min_lon:
        max_lon += 0.01
        min_lon -= 0.01

    def mx(lon_v: float) -> float:
        return math.radians(lon_v)

    def my(lat_v: float) -> float:
        s = math.sin(math.radians(lat_v))
        return math.log((1 + s) / (1 - s + 1e-9)) / 2

    x0, x1 = mx(min_lon), mx(max_lon)
    y0, y1 = my(min_lat), my(max_lat)
    x = pad + (mx(lon) - x0) / max(x1 - x0, 1e-9) * (width - 2 * pad)
    y = pad + (1 - (my(lat) - y0) / max(y1 - y0, 1e-9)) * (height - 2 * pad)
    return x, y
