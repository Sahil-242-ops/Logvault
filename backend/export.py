"""
Downloads: forensic evidence bundle (zip + SHA-256 manifest), per-alert dossier, OCSF definitions.
"""
import csv
import hashlib
import io
import json
import zipfile
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .db import db
from . import containment, mapper
from .schema.ocsf import OCSF_CLASSES, OCSF_CATEGORIES, to_ocsf

OCSF_VERSION = "1.1.0"

# Normalized LOGVAULT field -> OCSF attribute path
OCSF_FIELD_MAP = {
    "timestamp": "time",
    "severity": "severity",
    "event_type": "type_name",
    "message": "message",
    "source_ip": "src_endpoint.ip",
    "source_port": "src_endpoint.port",
    "destination_ip": "dst_endpoint.ip",
    "destination_port": "dst_endpoint.port",
    "user": "actor.user.name",
    "host": "device.hostname",
    "process": "actor.process.name",
    "protocol": "connection_info.protocol_name",
    "action": "activity_name",
    "status": "status",
    "raw_log": "raw_data",
    "ocsf_class_uid": "class_uid",
    "ocsf_class_name": "class_name",
    "ocsf_category": "category_name",
    "anomaly.findings[].mitre_technique": "attacks[].technique.uid",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ocsf_definitions() -> Dict[str, Any]:
    return {
        "ocsf_version": OCSF_VERSION,
        "generated_at": _now(),
        "classes": [{"class_uid": uid, "class_name": name} for name, uid in sorted(OCSF_CLASSES.items(), key=lambda x: x[1])],
        "categories": [{"category_name": name, "key": key} for name, key in OCSF_CATEGORIES.items()],
        "field_mapping": [{"logvault_field": k, "ocsf_attribute": v} for k, v in OCSF_FIELD_MAP.items()],
        "custom_mapping_rules": [{k: r[k] for k in ("name", "kind", "signature", "anchor", "mappings", "event_type")}
                                 for r in mapper.list_rules()],
    }


def alert_dossier(event_id: str, exported_by: Optional[str]) -> Optional[Dict[str, Any]]:
    evt = db.get_event(event_id)
    if not evt:
        return None
    conn = db.get_connection()
    state = conn.execute("SELECT * FROM alert_state WHERE event_id = ?", (event_id,)).fetchone()
    conn.close()
    state = dict(state) if state else {"status": "OPEN"}
    if state.get("investigation_json"):
        state["investigation"] = json.loads(state.pop("investigation_json"))
    related = db.get_related_events(evt, limit=200)
    contained = [e for e in containment.list_entries(include_released=True)
                 if e["alert_id"] == event_id or e["value"] in (evt.get("source_ip"), evt.get("host"))]
    body = {
        "dossier_version": 1,
        "generated_at": _now(),
        "exported_by": exported_by,
        "alert": evt,
        "triage": state,
        "containment_actions": contained,
        "related_events": related,
        "related_event_count": len(related),
    }
    body["sha256_of_alert_raw_log"] = _sha256((evt.get("raw_log") or "").encode())
    return body


def forensic_bundle(exported_by: Optional[str], scope: str = "session",
                    passphrase: Optional[str] = None) -> Tuple[bytes, str]:
    """Zip of events (JSON Lines), alerts, containment list and mapping rules, plus a manifest
    with the SHA-256 of every file so the evidence can be verified later."""
    where, params = "", []
    if scope == "session" and db.current_session_id:
        where, params = " WHERE session_id = ?", [db.current_session_id]
    conn = db.get_connection()
    events = io.BytesIO()
    count = 0
    for (row,) in conn.execute(f"SELECT normalized_json FROM events{where} ORDER BY received_at", params):
        events.write(row.encode() + b"\n")
        count += 1
    alert_where = where.replace("session_id", "e.session_id")
    alerts = [dict(r) for r in conn.execute(
        f"SELECT s.* FROM alert_state s JOIN events e ON e.id = s.event_id{alert_where}", params)]
    conn.close()

    files = {
        "events.jsonl": events.getvalue(),
        "alerts.json": json.dumps(alerts, indent=2).encode(),
        "containment.json": json.dumps(containment.list_entries(include_released=True), indent=2).encode(),
        "mapping_rules.json": json.dumps(mapper.list_rules(), indent=2).encode(),
    }
    manifest = {
        "product": "LOGVAULT",
        "created_at": _now(),
        "exported_by": exported_by,
        "scope": "current session" if where else "all stored data",
        "event_count": count,
        "alert_count": len(alerts),
        "files": {name: {"sha256": _sha256(data), "bytes": len(data)} for name, data in files.items()},
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if passphrase:
        from .crypto_box import encrypt
        return encrypt(buf.getvalue(), passphrase), f"logvault-forensics-{stamp}.lvault"
    return buf.getvalue(), f"logvault-forensics-{stamp}.zip"


def evidence_fingerprint(scope: str = "all") -> Dict[str, Any]:
    """Hash chain over every stored event (in arrival order): h = SHA-256(h_prev | id | SHA-256(raw_log)).
    Any edit, deletion or reordering of stored evidence changes the final value."""
    where, params = "", []
    if scope == "session" and db.current_session_id:
        where, params = " WHERE session_id = ?", [db.current_session_id]
    h = hashlib.sha256(b"LOGVAULT-EVIDENCE-CHAIN-v1").hexdigest()
    count = 0
    conn = db.get_connection()
    for event_id, raw in conn.execute(f"SELECT id, raw_log FROM events{where} ORDER BY received_at, id", params):
        h = hashlib.sha256(f"{h}|{event_id}|{_sha256((raw or '').encode())}".encode()).hexdigest()
        count += 1
    conn.close()
    return {"algorithm": "SHA-256 hash chain", "fingerprint": h, "events": count,
            "scope": "current session" if where else "all stored data", "computed_at": _now()}


# ---------------------------------------------------------------- SIEM / data lake exports
# Everything is generated as a download: an air-gapped LOGVAULT never pushes data out itself.
SIEM_FORMATS = {
    # id: (file extension, media type, what it is for)
    "ocsf-jsonl": ("jsonl", "application/x-ndjson", "OCSF 1.1 events, one per line (any SIEM / data lake)"),
    "ocsf-jsonl-gz": ("jsonl.gz", "application/gzip", "Same, gzip-compressed for data lakes (S3/Athena, Hadoop, BigQuery)"),
    "csv": ("csv", "text/csv", "Flat columns for spreadsheets and warehouse loaders"),
    "cef": ("cef", "text/plain", "ArcSight CEF lines (ArcSight, QRadar, syslog-based SIEMs)"),
    "splunk-hec": ("json", "application/json", "Splunk HTTP Event Collector batch"),
    "elastic-bulk": ("ndjson", "application/x-ndjson", "Elasticsearch / OpenSearch _bulk request body"),
}
CSV_COLUMNS = ("id", "time", "timestamp", "detected_format", "ocsf_class_uid", "ocsf_class_name", "event_type",
               "severity", "source_ip", "source_port", "destination_ip", "destination_port", "user", "host",
               "process", "protocol", "threat_score", "is_anomalous", "mitre_technique", "message", "raw_log",
               "raw_sha256")
CEF_SEVERITY = {"INFO": 1, "LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}


def _cef_header(value) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(value) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", " ")


def _mitre(evt: Dict[str, Any]) -> Optional[str]:
    for f in (evt.get("anomaly") or {}).get("findings") or []:
        if f.get("mitre_technique"):
            return f["mitre_technique"]
    return None


def to_cef(evt: Dict[str, Any], raw_sha: str) -> str:
    anomaly = evt.get("anomaly") or {}
    ext = {
        "rt": evt.get("timestamp"), "src": evt.get("source_ip"), "spt": evt.get("source_port"),
        "dst": evt.get("destination_ip"), "dpt": evt.get("destination_port"), "suser": evt.get("user"),
        "dhost": evt.get("host"), "sproc": evt.get("process"), "proto": evt.get("protocol"),
        "act": evt.get("action"), "msg": (evt.get("message") or "")[:1024],
        "cs1Label": "mitreTechnique", "cs1": _mitre(evt),
        "cs2Label": "rawSha256", "cs2": raw_sha,
        "cs3Label": "ocsfClass", "cs3": evt.get("ocsf_class_name"),
        "cn1Label": "threatScore", "cn1": anomaly.get("threat_score", 0),
        "externalId": evt.get("id"),
    }
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    sev = CEF_SEVERITY.get(str(evt.get("severity") or "INFO").upper(), 1)
    signature = _cef_header(evt.get("ocsf_class_uid") or 0)
    name = _cef_header(evt.get("event_type") or "GENERIC_EVENT")
    return f"CEF:0|BetterCallCode|LOGVAULT|1.0|{signature}|{name}|{sev}|{extension}"


def _iter_events(scope: str, only_anomalies: bool):
    where, params = [], []
    if scope == "session" and db.current_session_id:
        where.append("session_id = ?")
        params.append(db.current_session_id)
    if only_anomalies:
        where.append("is_anomalous = 1")
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    conn = db.get_connection()
    try:
        for row in conn.execute(f"SELECT normalized_json, received_at, session_id FROM events{clause} "
                                f"ORDER BY received_at", params):
            evt = json.loads(row[0])
            evt.setdefault("received_at", row[1])
            evt.setdefault("session_id", row[2])
            yield evt
    finally:
        conn.close()


def stream_siem(fmt: str, scope: str = "session", only_anomalies: bool = False):
    """Yields the export in chunks so large stores never have to fit in memory."""
    gz = zlib.compressobj(6, zlib.DEFLATED, 31) if fmt == "ocsf-jsonl-gz" else None

    def emit(text: str) -> bytes:
        data = text.encode("utf-8")
        return gz.compress(data) if gz else data

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        for evt in _iter_events(scope, only_anomalies):
            anomaly = evt.get("anomaly") or {}
            vals = {**evt, "time": to_ocsf(evt).get("time"), "threat_score": anomaly.get("threat_score", 0),
                    "is_anomalous": bool(anomaly.get("is_anomalous")), "mitre_technique": _mitre(evt),
                    "raw_sha256": _sha256((evt.get("raw_log") or "").encode())}
            writer.writerow(["" if vals.get(c) is None else vals.get(c) for c in CSV_COLUMNS])
            if buf.tell() > 64_000:
                yield emit(buf.getvalue())
                buf.seek(0)
                buf.truncate()
        yield emit(buf.getvalue())
        return

    if fmt == "splunk-hec":
        yield emit("[\n")
    first = True
    batch = []
    for evt in _iter_events(scope, only_anomalies):
        raw_sha = _sha256((evt.get("raw_log") or "").encode())
        if fmt == "cef":
            batch.append(to_cef(evt, raw_sha))
        else:
            ocsf = to_ocsf(evt)
            ocsf.setdefault("unmapped", {})["raw_sha256"] = raw_sha
            if fmt == "splunk-hec":
                item = json.dumps({"time": ocsf["time"] / 1000, "host": evt.get("host") or "logvault",
                                   "source": "logvault", "sourcetype": "ocsf:json", "event": ocsf}, default=str)
                batch.append(item if first else "," + item)
                first = False
            elif fmt == "elastic-bulk":
                batch.append(json.dumps({"index": {"_index": "logvault-ocsf", "_id": evt.get("id")}}))
                batch.append(json.dumps(ocsf, default=str))
            else:
                batch.append(json.dumps(ocsf, separators=(",", ":"), default=str))
        if len(batch) >= 500:
            yield emit("\n".join(batch) + "\n")
            batch = []
    if batch:
        yield emit("\n".join(batch) + "\n")
    if fmt == "splunk-hec":
        yield emit("]\n")
    if gz:
        yield gz.flush()


def siem_filename(fmt: str, scope: str, only_anomalies: bool) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    kind = "anomalies" if only_anomalies else "events"
    return f"logvault-{kind}-{scope}-{fmt}-{stamp}.{SIEM_FORMATS[fmt][0]}"
