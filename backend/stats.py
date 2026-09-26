"""
Aggregations for the Dashboard, Log Sources and Parsers screens, computed from stored events
(current session, like the rest of the UI).
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from .db import db
from . import containment

# Bucket widths tried in order; the first giving <= MAX_BUCKETS buckets over the data span wins
BUCKET_SECONDS = (60, 300, 900, 3600, 6 * 3600, 86400, 7 * 86400)
MAX_BUCKETS = 24


def _session_where(alias: str = "") -> Tuple[str, list]:
    if db.current_session_id:
        return f" AND {alias}session_id = ?", [db.current_session_id]
    return "", []


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _pct(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def dashboard() -> Dict[str, Any]:
    where, params = _session_where()
    conn = db.get_connection()
    c = conn.cursor()
    c.execute(f"""
        SELECT COUNT(*),
               COALESCE(SUM(is_anomalous), 0),
               COALESCE(SUM(CASE WHEN is_anomalous = 1 AND (threat_score >= 80 OR severity = 'CRITICAL') THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN detected_format IS NOT NULL AND detected_format != 'unknown' THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN json_extract(normalized_json, '$.ocsf_class_uid') > 0 THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN COALESCE(source_ip, user, host) IS NOT NULL THEN 1 ELSE 0 END), 0),
               AVG(json_extract(normalized_json, '$.parse_confidence')),
               AVG(json_extract(normalized_json, '$.processing_latency_ms'))
        FROM events WHERE 1=1 {where}
    """, params)
    total, anomalous, critical, parsed, ocsf_mapped, with_fields, avg_conf, avg_latency = c.fetchone()

    c.execute(f"SELECT COALESCE(detected_format, 'unknown'), COUNT(*) FROM events WHERE 1=1 {where} "
              f"GROUP BY 1 ORDER BY 2 DESC", params)
    formats = [{"format": f, "count": n, "pct": _pct(n, total)} for f, n in c.fetchall()]

    c.execute(f"SELECT COALESCE(severity, 'INFO'), COUNT(*) FROM events WHERE 1=1 {where} GROUP BY 1", params)
    severities = dict(c.fetchall())

    c.execute(f"SELECT received_at, is_anomalous, detected_format FROM events WHERE received_at IS NOT NULL {where}", params)
    rows = c.fetchall()

    c.execute(f"""
        SELECT e.id, e.timestamp, e.received_at, e.severity, e.threat_score, e.source_ip, e.host, e.user,
               json_extract(e.normalized_json, '$.anomaly.findings[0].rule_name'), COALESCE(s.status, 'OPEN')
        FROM events e LEFT JOIN alert_state s ON s.event_id = e.id
        WHERE e.is_anomalous = 1 {_session_where('e.')[0]}
        ORDER BY e.received_at DESC, e.threat_score DESC LIMIT 5
    """, _session_where('e.')[1])
    threats = [{"id": r[0], "timestamp": r[1], "received_at": r[2], "severity": r[3], "threat_score": r[4],
                "source_ip": r[5], "host": r[6], "user": r[7], "title": r[8] or "Anomaly detected", "status": r[9]}
               for r in c.fetchall()]
    conn.close()

    return {
        "total_events": total,
        "anomalous_events": anomalous,
        "critical_anomalies": critical,
        "parsed_events": parsed,
        "parsed_rate": _pct(parsed, total),
        "confidence": {
            "normalization": _pct(parsed, total),
            "parser": round(100 * (avg_conf or 0), 1),
            "schema_mapping": _pct(ocsf_mapped, total),
            "field_extraction": _pct(with_fields, total),
        },
        "avg_latency_ms": round(avg_latency or 0, 3),
        "formats": formats,
        "severities": severities,
        "timeline": _timeline(rows),
        "recent_threats": threats,
    }


def _timeline(rows) -> Dict[str, Any]:
    """Events / anomalies / parsed per time bucket, ending now."""
    if not rows:
        return {"bucket_seconds": 0, "buckets": []}
    now = datetime.now(timezone.utc)
    times = [(_parse_ts(r[0]), r[1], r[2]) for r in rows]
    oldest = min(t for t, _, _ in times)
    span = max((now - oldest).total_seconds(), 60)
    size = next((b for b in BUCKET_SECONDS if span / b <= MAX_BUCKETS), BUCKET_SECONDS[-1])
    count = min(MAX_BUCKETS, int(span // size) + 1)
    count = max(count, 6)
    start = now - timedelta(seconds=size * count)
    buckets = [{"start": (start + timedelta(seconds=size * i)).isoformat().replace("+00:00", "Z"),
                "events": 0, "anomalies": 0, "parsed": 0} for i in range(count)]
    for t, anom, fmt in times:
        i = int((t - start).total_seconds() // size)
        if 0 <= i < count:
            b = buckets[i]
            b["events"] += 1
            b["anomalies"] += 1 if anom else 0
            b["parsed"] += 1 if fmt and fmt != "unknown" else 0
    return {"bucket_seconds": size, "buckets": buckets}


def collectors() -> Dict[str, Any]:
    """One row per reporting system (host, else source IP) and log format."""
    where, params = _session_where()
    conn = db.get_connection()
    c = conn.cursor()
    c.execute(f"""
        SELECT COALESCE(NULLIF(host, ''), NULLIF(source_ip, ''), 'unattributed') AS origin,
               COALESCE(detected_format, 'unknown'), COUNT(*), COALESCE(SUM(is_anomalous), 0),
               MAX(threat_score), MIN(received_at), MAX(received_at),
               AVG(json_extract(normalized_json, '$.processing_latency_ms')),
               COUNT(DISTINCT source_ip)
        FROM events WHERE 1=1 {where}
        GROUP BY origin, 2 ORDER BY 3 DESC
    """, params)
    rows = c.fetchall()
    now = datetime.now(timezone.utc)
    cutoff_1m = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    c.execute(f"SELECT COUNT(*) FROM events WHERE received_at >= ? {where}", [cutoff_1m] + params)
    last_minute = c.fetchone()[0]
    conn.close()

    out: List[Dict[str, Any]] = []
    for origin, fmt, n, anomalies, max_threat, first, last, latency, distinct_ips in rows:
        age = (now - _parse_ts(last)).total_seconds() if last else None
        status = "ACTIVE" if age is not None and age < 300 else ("IDLE" if age is not None and age < 3600 else "SILENT")
        span = max((_parse_ts(last) - _parse_ts(first)).total_seconds(), 1) if first and last else 1
        out.append({
            "origin": origin, "format": fmt, "events": n, "anomalies": anomalies, "max_threat": max_threat or 0,
            "first_seen": first, "last_seen": last, "seconds_since_last": round(age) if age is not None else None,
            "status": status, "avg_latency_ms": round(latency or 0, 3), "distinct_source_ips": distinct_ips,
            # Average rate while this source was sending (a whole upload arrives at once, so it can be high)
            "events_per_minute": round(n * 60 / span, 1) if n > 1 else float(n),
            "contained": containment.is_contained("host", origin) or containment.is_contained("ip", origin),
        })
    total = sum(r["events"] for r in out)
    return {
        "collectors": out,
        "total_collectors": len(out),
        "active_collectors": sum(1 for r in out if r["status"] == "ACTIVE"),
        "total_events": total,
        "events_last_minute": last_minute,
        "avg_latency_ms": round(sum(r["avg_latency_ms"] * r["events"] for r in out) / total, 3) if total else 0,
        "formats": sorted({r["format"] for r in out}),
    }


def parser_usage() -> Dict[str, Dict[str, Any]]:
    where, params = _session_where()
    conn = db.get_connection()
    rows = conn.execute(f"""
        SELECT COALESCE(detected_format, 'unknown'), COUNT(*),
               AVG(json_extract(normalized_json, '$.processing_latency_ms')),
               AVG(json_extract(normalized_json, '$.parse_confidence')),
               MAX(received_at)
        FROM events WHERE 1=1 {where} GROUP BY 1
    """, params).fetchall()
    conn.close()
    return {r[0]: {"events": r[1], "avg_latency_ms": round(r[2] or 0, 3), "avg_confidence": round(r[3] or 0, 3),
                   "last_used": r[4]} for r in rows}
