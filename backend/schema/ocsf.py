"""
OCSF 1.1 constants, conversion of a LOGVAULT event into an OCSF-shaped event, and validation.

LOGVAULT keeps a flat normalized record for the UI and search; to_ocsf() builds the OCSF form
(class/category/activity/type ids, severity_id, time in epoch ms, src_endpoint, actor, ...)
used by exports, and validate() checks it against the OCSF base-event and class requirements.
"""
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

OCSF_VERSION = "1.1.0"

OCSF_CLASSES = {
    "Unknown": 0,
    "Process Activity": 1007,
    "Security Finding": 2001,
    "Account Change": 3001,
    "Authentication": 3002,
    "Network Activity": 4001,
    "HTTP Activity": 4002,
    "File Activity": 1001,
}

OCSF_CATEGORIES = {
    "System Activity": "system",
    "Findings": "findings",
    "Identity & Access Management": "iam",
    "Network Activity": "network",
    "Discovery": "discovery",
    "Other": "other"
}

# category key -> (category_uid, category_name)
CATEGORY_UIDS = {
    "system": (1, "System Activity"),
    "findings": (2, "Findings"),
    "iam": (3, "Identity & Access Management"),
    "network": (4, "Network Activity"),
    "discovery": (5, "Discovery"),
    "application": (6, "Application Activity"),
    "other": (0, "Uncategorized"),
}
SEVERITY_IDS = {"INFO": (1, "Informational"), "LOW": (2, "Low"), "MEDIUM": (3, "Medium"),
                "HIGH": (4, "High"), "CRITICAL": (5, "Critical")}
# Required attributes of every OCSF event (base event)
BASE_REQUIRED = ("class_uid", "category_uid", "activity_id", "severity_id", "time", "type_uid",
                 "metadata.version", "metadata.product.name")

TIME_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S,%f")


def get_ocsf_class_uid(class_name: str) -> int:
    return OCSF_CLASSES.get(class_name, 0)


def parse_time_ms(value: Any) -> Optional[int]:
    """Epoch milliseconds from the timestamp formats the parsers produce, or None."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        n = float(value)
        return int(n if n > 1e12 else n * 1000)
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in TIME_FORMATS:
            try:
                dt = datetime.strptime(re.sub(r"\s+", " ", text), fmt)
                if fmt == "%b %d %H:%M:%S":  # BSD syslog has no year
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _activity(class_uid: int, evt: Dict[str, Any]):
    et = str(evt.get("event_type") or "").upper()
    if class_uid == 3002:
        return (2, "Logoff") if "LOGOFF" in et or "LOGOUT" in et else (1, "Logon")
    if class_uid == 4002:
        method = str(evt.get("action") or "").upper()
        return {"GET": (2, "Get"), "POST": (6, "Post"), "PUT": (7, "Put"), "DELETE": (3, "Delete")}.get(method, (99, "Other"))
    if class_uid == 2001:
        return 1, "Create"
    if class_uid == 0:
        return 0, "Unknown"
    return 99, "Other"


def _status(evt: Dict[str, Any]):
    text = f"{evt.get('event_type') or ''} {evt.get('status') or ''} {evt.get('action') or ''}".upper()
    if re.search(r"FAIL|DENIED|DENY|REJECT|BLOCK|INVALID|DROP", text):
        return 2, "Failure"
    if re.search(r"SUCCESS|ACCEPT|ALLOW|PERMIT|\b2\d\d\b|OK", text):
        return 1, "Success"
    return 0, "Unknown"


def _put(d: Dict[str, Any], path: str, value: Any) -> None:
    if value in (None, "", "unknown", "Unknown"):
        return
    keys = path.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def to_ocsf(evt: Dict[str, Any], product_version: str = "1.0") -> Dict[str, Any]:
    class_uid = evt.get("ocsf_class_uid") or 0
    class_name = evt.get("ocsf_class_name") or "Base Event"
    cat_uid, cat_name = CATEGORY_UIDS.get(evt.get("ocsf_category") or "other", (0, "Uncategorized"))
    if class_uid == 0:
        cat_uid, cat_name, class_name = 0, "Uncategorized", "Base Event"
    act_id, act_name = _activity(class_uid, evt)
    sev_id, sev_name = SEVERITY_IDS.get(str(evt.get("severity") or "INFO").upper(), (0, "Unknown"))
    st_id, st_name = _status(evt)
    time_ms = parse_time_ms(evt.get("timestamp"))
    time_source = "log"
    if time_ms is None:  # OCSF requires a time: fall back to when LOGVAULT received the event
        time_ms = parse_time_ms(evt.get("received_at")) or int(datetime.now(timezone.utc).timestamp() * 1000)
        time_source = "ingestion"

    o: Dict[str, Any] = {
        "class_uid": class_uid, "class_name": class_name,
        "category_uid": cat_uid, "category_name": cat_name,
        "activity_id": act_id, "activity_name": act_name,
        "type_uid": class_uid * 100 + act_id, "type_name": f"{class_name}: {act_name}",
        "severity_id": sev_id, "severity": sev_name,
        "status_id": st_id, "status": st_name,
        "time": time_ms,
        "message": evt.get("message"),
        "raw_data": evt.get("raw_log"),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": evt.get("id"),
            "log_name": evt.get("detected_format"),
            "original_time": evt.get("timestamp"),
            "product": {"name": "LOGVAULT", "vendor_name": "BetterCallCode", "version": product_version},
        },
    }
    _put(o, "src_endpoint.ip", evt.get("source_ip"))
    _put(o, "src_endpoint.port", evt.get("source_port"))
    _put(o, "dst_endpoint.ip", evt.get("destination_ip"))
    _put(o, "dst_endpoint.port", evt.get("destination_port"))
    _put(o, "device.hostname", evt.get("host"))
    _put(o, "actor.user.name", evt.get("user"))
    _put(o, "actor.process.name", evt.get("process"))
    _put(o, "connection_info.protocol_name", evt.get("protocol"))
    if class_uid == 3002:
        _put(o, "user.name", evt.get("user"))
    anomaly = evt.get("anomaly") or {}
    findings = anomaly.get("findings") or []
    attacks = []
    for f in findings:
        tech = f.get("mitre_technique")
        if tech:
            uid, _, name = str(tech).partition(" - ")
            attacks.append({"technique": {"uid": uid.strip(), "name": name.strip() or None},
                            "tactic": {"name": f.get("mitre_tactic")} if f.get("mitre_tactic") else None})
    if attacks:
        o["attacks"] = [{k: v for k, v in a.items() if v} for a in attacks]
    if anomaly.get("is_anomalous"):
        o["finding_info"] = {"uid": evt.get("id"), "title": findings[0].get("rule_name") if findings else "Anomaly",
                             "types": sorted({f.get("rule_name") for f in findings if f.get("rule_name")})}
        o["risk_score"] = anomaly.get("threat_score")
    o["unmapped"] = {k: evt.get(k) for k in ("event_type", "category", "pii_masked", "parser_name")
                     if evt.get(k) not in (None, "")}
    o["unmapped"]["time_source"] = time_source
    return {k: v for k, v in o.items() if v not in (None, "", {}, [])}


def _get(d: Dict[str, Any], path: str):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def validate(o: Dict[str, Any]) -> Dict[str, Any]:
    """OCSF checks: required base attributes, value types, and what the event class needs."""
    errors: List[str] = []
    warnings: List[str] = []
    for path in BASE_REQUIRED:
        if _get(o, path) is None:
            errors.append(f"missing {path}")
    if _get(o, "unmapped.time_source") == "ingestion":
        warnings.append("no readable time in the log; the ingestion time is used")
    if o.get("type_uid") != (o.get("class_uid") or 0) * 100 + (o.get("activity_id") or 0):
        errors.append("type_uid must equal class_uid * 100 + activity_id")
    for side in ("src_endpoint", "dst_endpoint"):
        ip = _get(o, f"{side}.ip")
        if ip is not None:
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                errors.append(f"{side}.ip is not a valid IP address ({ip})")
        port = _get(o, f"{side}.port")
        if port is not None and not (isinstance(port, int) and 0 <= port <= 65535):
            errors.append(f"{side}.port must be an integer 0-65535 ({port})")
    cls = o.get("class_uid")
    if cls == 3002 and not (_get(o, "user.name") or _get(o, "actor.user.name")):
        warnings.append("Authentication event without a user")
    if cls in (4001, 4002) and not (o.get("src_endpoint") or o.get("dst_endpoint")):
        warnings.append("Network event without a source or destination endpoint")
    if cls == 2001 and not o.get("finding_info"):
        warnings.append("Security Finding without finding_info")
    if cls == 0:
        warnings.append("No specific OCSF class matched (stored as Base Event)")
    return {"valid": not errors, "errors": errors, "warnings": warnings}
