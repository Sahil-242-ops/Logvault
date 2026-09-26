"""
Downloads: forensic evidence bundle (zip + SHA-256 manifest), per-alert dossier, OCSF definitions.
"""
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .db import db
from . import containment, mapper
from .schema.ocsf import OCSF_CLASSES, OCSF_CATEGORIES

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


def forensic_bundle(exported_by: Optional[str], scope: str = "session") -> Tuple[bytes, str]:
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
