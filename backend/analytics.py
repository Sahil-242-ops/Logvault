"""Aggregations for the Event Analytics screen (geo map, top sources, time-of-day heatmap)."""
import re
from typing import Any, Dict

from .db import db
from .geoip import geoip

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
TIME_RE = re.compile(r"(?:T|\s|:)(\d{1,2}):(\d{2}):\d{2}")


def geo_summary(limit: int = 300) -> Dict[str, Any]:
    by_ip: Dict[str, Dict[str, Any]] = {}
    for source_ip, _ts, _recv, is_anom, threat, severity in db.get_analytics_rows():
        if not source_ip or source_ip in ("None", "Unknown", "-"):
            continue
        s = by_ip.setdefault(source_ip, {"ip": source_ip, "events": 0, "anomalies": 0, "max_threat": 0, "severity": "INFO"})
        s["events"] += 1
        if is_anom:
            s["anomalies"] += 1
        s["max_threat"] = max(s["max_threat"], threat or 0)
        if SEV_RANK.get(severity or "INFO", 0) > SEV_RANK.get(s["severity"], 0):
            s["severity"] = severity

    points, countries = [], {}
    internal = {"ips": 0, "events": 0, "anomalies": 0}
    unresolved = {"ips": 0, "events": 0, "anomalies": 0}
    for s in by_ip.values():
        g = geoip.lookup(s["ip"])
        if g.get("scope") == "internal":
            bucket = internal
        elif g.get("resolved"):
            s.update({k: g[k] for k in ("country", "country_code", "city", "lat", "lon")})
            points.append(s)
            c = countries.setdefault(g.get("country_code") or "??", {
                "country": g.get("country") or "Unknown", "country_code": g.get("country_code"),
                "ips": 0, "events": 0, "anomalies": 0, "max_threat": 0})
            c["ips"] += 1
            c["events"] += s["events"]
            c["anomalies"] += s["anomalies"]
            c["max_threat"] = max(c["max_threat"], s["max_threat"])
            continue
        else:
            bucket = unresolved
        bucket["ips"] += 1
        bucket["events"] += s["events"]
        bucket["anomalies"] += s["anomalies"]

    rank = lambda s: (s["anomalies"], s["max_threat"], s["events"])
    top_sources = []
    for s in sorted(by_ip.values(), key=rank, reverse=True)[:10]:
        g = geoip.lookup(s["ip"])
        loc = "Internal network" if g.get("scope") == "internal" else (
            ", ".join(p for p in (g.get("city"), g.get("country")) if p) or "Unknown location")
        top_sources.append({**s, "location": loc, "country_code": g.get("country_code"), "scope": g.get("scope")})

    return {
        "geoip_database": geoip.db_name,
        "geoip_available": geoip.available,
        "points": sorted(points, key=rank, reverse=True)[:limit],
        "countries": sorted(countries.values(), key=lambda c: (c["anomalies"], c["events"]), reverse=True),
        "internal": internal,
        "unresolved": unresolved,
        "top_sources": top_sources,
        "total_sources": len(by_ip),
    }


def time_of_day_heatmap() -> Dict[str, Any]:
    """96 x 15-minute slots by the log's own time of day (falls back to ingestion time)."""
    slots = [{"total": 0, "anomalies": 0} for _ in range(96)]
    for _ip, ts, recv, is_anom, _threat, _sev in db.get_analytics_rows():
        m = TIME_RE.search(f" {ts}") if ts else None
        if not m and recv:
            m = TIME_RE.search(recv)
        if not m:
            continue
        hour, minute = int(m.group(1)), int(m.group(2))
        if hour > 23 or minute > 59:
            continue
        slot = slots[hour * 4 + minute // 15]
        slot["total"] += 1
        if is_anom:
            slot["anomalies"] += 1
    peak = max((s["total"] for s in slots), default=0)
    return {"slots": slots, "peak": peak, "total": sum(s["total"] for s in slots)}
