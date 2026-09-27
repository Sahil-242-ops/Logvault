import time
import json
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from .normalizer import normalizer
from .parsers.detector import detector
from .ai.local_ai import local_ai
from .config import config
from .db import db
from .ingest import split_records
from .ai import investigator
from . import analytics
from . import storage
from . import auth, containment, mapper, stats, export, audit, search_index
import asyncio
from typing import Optional

router = APIRouter()

class LogRequest(BaseModel):
    raw: str

class AIMessageRequest(BaseModel):
    message: Optional[str] = None
    raw: Optional[str] = None
    task: Optional[str] = None

@router.get("/api/health")
async def health_check():
    ai_status = await local_ai.get_status()
    return {
        "backend": "healthy",
        "network_mode": "air_gapped",
        "ai_status_message": ai_status.get("status", "LOCAL AI OFFLINE"),
        "local_ai": ai_status.get("available", False),
        "ai_provider": ai_status.get("provider"),
        "model": ai_status.get("model"),
        "fallback_available": True,
        "auto_investigate": config.AUTO_INVESTIGATE
    }

@router.get("/api/ai/status")
async def ai_status():
    status = await local_ai.get_status()
    return {
        "available": status.get("available", False),
        "status_message": status.get("status", "LOCAL AI OFFLINE"),
        "provider": status.get("provider"),
        "model": status.get("model")
    }

@router.post("/api/normalize")
async def normalize_log(req: LogRequest, store: bool = True):
    """store=false runs the full pipeline without saving (Normalizer examples)."""
    if not req.raw:
        raise HTTPException(status_code=400, detail="Raw log is required")
    result = await normalizer.normalize(req.raw)
    if store:
        db.insert_event(result)
        search_index.enqueue([result], db.current_session_id)
    return result

@router.post("/api/detect")
async def detect_log(req: LogRequest):
    if not req.raw:
        raise HTTPException(status_code=400, detail="Raw log is required")
    fmt, parsed, confidence = detector.detect_and_parse(req.raw)
    return {
        "detected_format": fmt,
        "confidence": confidence,
        "parser": f"{fmt.upper()} Parser",
        "raw_log": req.raw
    }

@router.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    if not (file.filename or '').lower().endswith(('.log', '.txt', '.csv', '.json', '.jsonl', '.xml')):
        raise HTTPException(status_code=400, detail="Unsupported file extension")

    contents = await file.read()
    if len(contents) > config.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
        
    try:
        text = contents.decode('utf-8-sig')  # tolerate a BOM from Windows-exported files
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")

    # JSON arrays, JSON Lines, CSV with header, or one record per line
    records, layout = split_records(file.filename, text)
    if not records:
        raise HTTPException(status_code=400, detail="File is empty")

    start_time = time.time()
    results = await normalizer.batch_normalize(records)
    db.insert_events(results)
    search_index.enqueue(results, db.current_session_id)

    successful = 0
    anomalous = 0
    formats = {}
    for r in results:
        fmt = r.get("detected_format", "unknown")
        if fmt != "unknown":
            successful += 1
        if r.get("anomaly", {}).get("is_anomalous"):
            anomalous += 1
        formats[fmt] = formats.get(fmt, 0) + 1

    return {
        "file": {
            "filename": file.filename,
            "total_lines": len(text.splitlines()),
            "total_records": len(results),
            "layout": layout,
            "size_bytes": len(contents)
        },
        "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        "results": results[:500],  # enough for the UI result list without freezing the browser
        "results_truncated": len(results) > 500,
        "stats": {
            "total_records": len(results),
            "successful_records": successful,
            "failed_records": len(results) - successful,
            "detected_formats": formats,
            "threats_found": anomalous
        },
        "anomaly_summary": {
            "anomalous": anomalous
        }
    }

@router.post("/api/events/{event_id}/ai-analyze")
async def ai_analyze_event(event_id: str):
    """Run local AI on one stored event (used by the Normalizer for the record being viewed,
    so uploads stay fast) and save the enriched result."""
    evt = db.get_event(event_id)
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    if evt.get("ai_provider") == "ollama":
        return evt  # already analysed
    result = await normalizer.normalize(evt.get("raw_log") or "", use_ai=True)
    result["id"] = event_id
    db.update_event(result)
    return result

@router.post("/api/ai/analyze")
async def ai_analyze(req: AIMessageRequest):
    ai_status = await local_ai.get_status()
    if not ai_status.get("available") or ai_status.get("status") != "LOCAL AI READY":
        return {
            "response": f"{ai_status.get('status', 'LOCAL AI OFFLINE')}. Returning deterministic fallback analysis.",
            "mode": "DETERMINISTIC FALLBACK"
        }
        
    prompt = req.message or req.raw or ""
    res = await local_ai.ollama.analyze(ai_status["model"], prompt)
        
    return {
        "response": res or "AI failed to generate response.",
        "mode": "LOCAL AI",
        "model": ai_status["model"]
    }

@router.get("/api/events")
async def get_events(
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    detected_format: Optional[str] = None,
    since_minutes: Optional[int] = None
):
    # Full-text search goes to OpenSearch when it is configured; SQLite stays the store of record
    if search and search_index.enabled():
        hit = await search_index.search(search, db.current_session_id, limit=max(500, limit + offset))
        if hit is not None:
            events = db.get_events_by_ids(hit["ids"])
            keep = lambda e: ((not severity or severity == "ALL" or e.get("severity") == severity)
                              and (not event_type or event_type == "ALL" or e.get("event_type") == event_type)
                              and (not source_ip or e.get("source_ip") == source_ip)
                              and (not detected_format or detected_format == "ALL" or e.get("detected_format") == detected_format))
            events = [e for e in events if keep(e)]
            return {"events": events[offset:offset + limit], "total": len(events), "search_engine": "opensearch"}
    return {**db.get_events(limit, offset, search, severity, event_type, source_ip, detected_format, since_minutes),
            "search_engine": "sqlite"}

@router.get("/api/anomalies")
async def get_anomalies(
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    min_threat_score: Optional[int] = None
):
    return db.get_anomalies(limit, offset, search, severity, source_ip, min_threat_score)

@router.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None
):
    return db.get_alerts(limit, offset, status)

ALERT_STATUSES = ("OPEN", "Investigating", "Awaiting Approval", "Resolved")

class AlertStatusRequest(BaseModel):
    status: str
    analyst: Optional[str] = None
    note: Optional[str] = None

class AlertDecisionRequest(BaseModel):
    analyst: str
    note: Optional[str] = None
    include_related: bool = False  # also approve sibling alerts (same source IP + rule) awaiting approval

def _operator(request: Request):
    return getattr(request.state, "operator", None)


def _analyst(request: Request, fallback: Optional[str] = None) -> str:
    """The signed-in operator is the analyst of record; the client-sent name is only used without sign-in."""
    op = _operator(request)
    return op["name"] if op else (fallback or "")


def _require_rank(request: Request, rank: int, action: str):
    if not auth.has_role(_operator(request), rank):
        raise HTTPException(status_code=403, detail=f"Your role is not allowed to {action}")


def _require_alert(event_id: str):
    evt = db.get_event(event_id)
    if not evt or not (evt.get("anomaly") or {}).get("is_anomalous"):
        raise HTTPException(status_code=404, detail="Alert not found")
    return evt

@router.post("/api/alerts/{event_id}/investigate")
async def investigate_alert(event_id: str):
    """Run (or re-run) the AI investigation now. Result still needs analyst approval."""
    evt = _require_alert(event_id)
    db.set_alert_status(event_id, "AI Investigating")
    result = await investigator.investigate_and_store(evt)
    return {"event_id": event_id, "status": "Awaiting Approval", "investigation": result}

@router.post("/api/alerts/{event_id}/approve")
async def approve_alert(event_id: str, req: AlertDecisionRequest, request: Request):
    """Human approval step: accept the AI proposal and resolve the alert."""
    evt = _require_alert(event_id)
    req.analyst = _analyst(request, req.analyst)
    if not req.analyst.strip():
        raise HTTPException(status_code=400, detail="Analyst name is required")
    ids = [event_id]
    if req.include_related:
        ids += db.get_sibling_alert_ids(evt, "Awaiting Approval")
    for i in ids:
        db.set_alert_status(i, "Resolved", decided_by=req.analyst.strip(), note=req.note or "Approved AI resolution")
    return {"event_id": event_id, "status": "Resolved", "resolved_ids": ids}

@router.post("/api/alerts/{event_id}/reject")
async def reject_alert(event_id: str, req: AlertDecisionRequest, request: Request):
    """Human rejects the AI proposal; the alert goes to manual investigation."""
    _require_alert(event_id)
    req.analyst = _analyst(request, req.analyst)
    if not req.analyst.strip():
        raise HTTPException(status_code=400, detail="Analyst name is required")
    db.set_alert_status(event_id, "Investigating", decided_by=req.analyst.strip(), note=req.note or "AI proposal rejected")
    return {"event_id": event_id, "status": "Investigating"}

@router.post("/api/alerts/{event_id}/status")
async def set_alert_status(event_id: str, req: AlertStatusRequest, request: Request):
    """Manual Kanban move by an analyst."""
    if req.status not in ALERT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {ALERT_STATUSES}")
    _require_alert(event_id)
    db.set_alert_status(event_id, req.status, decided_by=(_analyst(request, req.analyst) or None), note=req.note)
    return {"event_id": event_id, "status": req.status}

class StoragePolicyRequest(BaseModel):
    storage_limit_gb: float = 0  # 0 = unlimited
    retention_days: int = 0      # 0 = keep forever

@router.get("/api/storage")
async def get_storage():
    return storage.stats()

@router.put("/api/storage/policy")
async def update_storage_policy(req: StoragePolicyRequest, request: Request):
    _require_rank(request, 3, "change the storage policy")
    if req.storage_limit_gb != 0 and not (0.1 <= req.storage_limit_gb <= 100000):
        raise HTTPException(status_code=400, detail="Storage limit must be 0 (unlimited) or between 0.1 and 100000 GB")
    if req.retention_days != 0 and not (1 <= req.retention_days <= 3650):
        raise HTTPException(status_code=400, detail="Retention must be 0 (forever) or between 1 and 3650 days")
    return {"policy": storage.set_policy(req.storage_limit_gb, req.retention_days)}

@router.post("/api/storage/enforce")
async def enforce_storage_policy(request: Request):
    _require_rank(request, 3, "delete stored events")
    """Apply the size limit / retention window now (normally runs every 10 minutes)."""
    result = await asyncio.to_thread(storage.enforce)
    return {**result, "storage": storage.stats()}

@router.post("/api/storage/vacuum")
async def vacuum_storage():
    before = storage.stats()["db_file_bytes"]
    await asyncio.to_thread(db.vacuum)
    after = storage.stats()
    return {"reclaimed_bytes": max(0, before - after["db_file_bytes"]), "storage": after}

@router.get("/api/analytics/geo")
async def analytics_geo(limit: int = 300):
    return analytics.geo_summary(limit)

@router.get("/api/analytics/heatmap")
async def analytics_heatmap():
    return analytics.time_of_day_heatmap()

@router.get("/api/sources")
async def get_sources():
    return db.get_sources()

@router.get("/api/events/{event_id}")
async def get_event(event_id: str):
    evt = db.get_event(event_id)
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    return evt

@router.delete("/api/events")
async def delete_events(request: Request, confirm: bool = Query(..., description="Must be true to delete")):
    _require_rank(request, 3, "delete stored events")
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")
    db.delete_events()
    return {"status": "deleted"}


# ---------------------------------------------------------------- sign-in / operators

class LoginRequest(BaseModel):
    email: str
    password: str

class ProfileRequest(BaseModel):
    name: str
    callsign: Optional[str] = None
    org: Optional[str] = None

class PasswordRequest(BaseModel):
    current_password: str
    new_password: str

class OperatorCreateRequest(BaseModel):
    email: str
    name: str
    role: str
    password: str

@router.post("/api/auth/login")
async def login(req: LoginRequest, request: Request):
    session = auth.login(req.email, req.password)
    ip = request.client.host if request.client else None
    if not session:
        audit.record("sign_in", actor=(req.email or "").lower().strip()[:120], client_ip=ip, outcome="failed",
                     detail="wrong email or password")
        raise HTTPException(status_code=401, detail="Wrong email or password")
    audit.record("sign_in", actor=session["operator"]["email"], client_ip=ip, detail=session["operator"]["role"])
    return session

@router.post("/api/auth/demo")
async def demo_login(request: Request):
    session = auth.demo_login()
    ip = request.client.host if request.client else None
    if not session:
        audit.record("sign_in_demo", client_ip=ip, outcome="denied", detail="demo access disabled")
        raise HTTPException(status_code=403, detail="Demo access is turned off on this installation")
    audit.record("sign_in_demo", actor=session["operator"]["email"], client_ip=ip, detail=session["operator"]["role"])
    return session

@router.get("/api/auth/config")
async def auth_config():
    return {"auth_required": config.AUTH_REQUIRED, "demo_login": config.DEMO_LOGIN,
            "demo_account": auth.DEMO_ACCOUNT if config.DEMO_LOGIN else None, "roles": list(auth.ROLE_RANK)}

@router.post("/api/auth/logout")
async def logout(request: Request):
    token = request.headers.get("authorization", "")[7:]
    if token:
        auth.logout(token)
    return {"status": "signed_out"}

@router.get("/api/auth/me")
async def me(request: Request):
    op = _operator(request)
    if not op:
        raise HTTPException(status_code=401, detail="Not signed in")
    return op

@router.put("/api/auth/me")
async def update_me(req: ProfileRequest, request: Request):
    op = _operator(request)
    if not op:
        raise HTTPException(status_code=401, detail="Not signed in")
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")
    return auth.update_profile(op["email"], req.name, req.callsign, req.org)

@router.post("/api/auth/password")
async def change_password(req: PasswordRequest, request: Request):
    op = _operator(request)
    if not op:
        raise HTTPException(status_code=401, detail="Not signed in")
    try:
        auth.change_password(op["email"], req.current_password, req.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "changed"}

@router.get("/api/operators")
async def operators(request: Request):
    _require_rank(request, 3, "list operator accounts")
    return {"operators": auth.list_operators()}

@router.post("/api/operators")
async def create_operator(req: OperatorCreateRequest, request: Request):
    _require_rank(request, 3, "create operator accounts")
    if auth.get_operator(req.email):
        raise HTTPException(status_code=400, detail="An operator with this email already exists")
    try:
        return auth.create_operator(req.email, req.name, req.role, req.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------- dashboard / sources

@router.get("/api/dashboard")
async def dashboard():
    return stats.dashboard()

@router.get("/api/collectors")
async def collectors():
    return stats.collectors()


# ---------------------------------------------------------------- parsers

PARSER_CATALOG = (
    {"id": "syslog", "name": "Syslog (RFC 5424 / 3164)", "category": "os", "formats": "RFC 5424 and RFC 3164 syslog; SSH, PAM, sudo, iptables",
     "ocsf_class": "Authentication (3002)",
     "sample": "Sep 24 02:10:00 bastion01 sshd[330]: Failed password for admin from 185.220.101.5 port 50211 ssh2"},
    {"id": "cef", "name": "CEF (ArcSight)", "category": "network", "formats": "Common Event Format v0",
     "ocsf_class": "Security Finding (2001)",
     "sample": "CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|drop|7|src=185.220.101.5 dst=10.0.0.15 spt=44120 dpt=22 act=deny"},
    {"id": "apache", "name": "Apache / Nginx access", "category": "network", "formats": "Common / Combined access log",
     "ocsf_class": "HTTP Activity (4002)",
     "sample": '192.168.1.50 - frank [02/Sep/2026:19:34:02 +0000] "GET /api/v1/auth HTTP/1.1" 200 4522 "-" "Mozilla/5.0"'},
    {"id": "json", "name": "JSON / JSON Lines", "category": "cloud", "formats": "App logs, AWS CloudTrail, ECS, Suricata EVE",
     "ocsf_class": "By event content",
     "sample": '{"eventName":"ConsoleLogin","userIdentity":{"userName":"alice"},"sourceIPAddress":"203.0.113.7","errorMessage":"Failed authentication"}'},
    {"id": "windows", "name": "Windows Security events", "category": "os", "formats": "EventID key=value exports",
     "ocsf_class": "Authentication (3002)",
     "sample": "EventID=4625 AccountName=administrator Workstation=WIN-DC01 SourceIP=10.0.4.23 Status=0xC000006D"},
    {"id": "xml", "name": "XML (Windows Event / generic)", "category": "os", "formats": "Windows Event XML, any XML record",
     "ocsf_class": "Authentication (3002) / by content",
     "sample": '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">10.0.0.5</Data></EventData></Event>'},
    {"id": "csv", "name": "CSV", "category": "cloud", "formats": "CSV rows with or without a header",
     "ocsf_class": "By event content",
     "sample": "timestamp,src_ip,user,action,status\n2026-09-24T02:10:00Z,10.0.0.5,admin,login,failed"},
    {"id": "generic_kv", "name": "Generic key=value", "category": "custom", "formats": "Any key=value record",
     "ocsf_class": "By event content",
     "sample": "USR=john ACT=LOGIN RES=FAIL SRC=10.2.4.5 DEV=web01 PROT=SSH PORT=22"},
    {"id": "custom", "name": "Custom / unknown text", "category": "custom", "formats": "Free text: IPs, ports, users, times, HTTP requests found by shape",
     "ocsf_class": "By event content",
     "sample": "2026-09-24 02:10:00 WARN user admin failed login from 10.0.0.5 port 22"},
)

def _parser_pattern(parser_id: str) -> Optional[str]:
    """The regex the parser actually runs (JSON is parsed as a document, not by regex)."""
    p = detector.parsers.get(parser_id)
    for attr in ("pattern", "rfc5424_pattern", "header_pattern", "start_pattern", "kv_pattern"):
        rx = getattr(p, attr, None)
        if rx is not None:
            return rx.pattern
    return None

class BenchmarkRequest(BaseModel):
    raw: str
    parser: Optional[str] = None  # None = automatic detection, as ingestion does

@router.get("/api/parsers")
async def parsers():
    usage = stats.parser_usage()
    empty = {"events": 0, "avg_latency_ms": 0, "avg_confidence": 0, "last_used": None}
    out = [{**p, "kind": "BUILT-IN", "pattern": _parser_pattern(p["id"]), **usage.get(p["id"], empty)} for p in PARSER_CATALOG]
    for r in mapper.list_rules():
        key = f"custom:{r['name']}"
        out.append({"id": key, "name": r["name"], "category": "custom", "kind": "MAPPING RULE",
                    "formats": f"Analyst rule ({'key=value' if r['kind'] == 'kv' else 'positional'})",
                    "ocsf_class": r.get("event_type") or "By event content", "sample": r.get("sample") or "",
                    "rule_id": r["id"], "created_by": r.get("created_by"),
                    "pattern": r.get("anchor") or " ".join(f"{k}=..." for k in (r.get("signature") or [])),
                    **usage.get(key, empty)})
    return {"parsers": out, "unparsed_events": usage.get("unknown", {}).get("events", 0),
            "total_events": sum(u["events"] for u in usage.values())}

@router.post("/api/parsers/benchmark")
async def benchmark_parser(req: BenchmarkRequest):
    """Times the real parser on the given record (many runs, median) and returns what it extracted."""
    raw = req.raw.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Raw log is required")
    if len(raw) > 20000:
        raise HTTPException(status_code=400, detail="Record too long for the benchmark (20,000 characters max)")
    builtin = req.parser in detector.parsers if req.parser else False
    if req.parser and not builtin and not req.parser.startswith("custom:"):
        raise HTTPException(status_code=400, detail=f"Unknown parser '{req.parser}'")

    if builtin:
        run = lambda: detector.parsers[req.parser].parse(raw)
    elif req.parser:
        run = lambda: mapper.apply_rules(raw)
    else:
        run = lambda: detector.detect_and_parse(raw)

    def bench():
        result = run()
        timings = []
        deadline = time.perf_counter() + 0.25
        while len(timings) < 5000 and (time.perf_counter() < deadline or len(timings) < 50):
            t0 = time.perf_counter()
            run()
            timings.append(time.perf_counter() - t0)
        timings.sort()
        return result, timings

    result, timings = await asyncio.to_thread(bench)
    if builtin:
        fmt, parsed = (req.parser if result else "unknown"), result
    elif req.parser:
        fmt, parsed = (f"custom:{result[0]}", result[1]) if result else ("unknown", None)
    else:
        fmt, parsed, _conf = result
    median = timings[len(timings) // 2]
    fields = {k: v for k, v in (parsed or {}).items() if v not in (None, "")}
    return {
        "parser": fmt,
        "matched": bool(parsed),
        "runs": len(timings),
        "median_us": round(median * 1e6, 2),
        "p95_us": round(timings[max(0, int(len(timings) * 0.95) - 1)] * 1e6, 2),
        "records_per_second": int(1 / median) if median > 0 else None,
        "fields": fields,
        "field_count": len(fields),
    }


# ---------------------------------------------------------------- schema mapper

class MapperInferRequest(BaseModel):
    raw: str
    use_ai: bool = False

class MappingRuleRequest(BaseModel):
    name: str
    kind: str
    mappings: list
    signature: Optional[list] = None
    anchor: Optional[str] = None
    event_type: Optional[str] = None
    sample: Optional[str] = None

@router.post("/api/mapper/infer")
async def mapper_infer(req: MapperInferRequest):
    raw = req.raw.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Raw log is required")
    t0 = time.perf_counter()
    result = mapper.infer(raw)
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    result["ai"] = None
    if req.use_ai:
        ai = await local_ai.analyze(raw)
        result["ai"] = {"provider": ai.get("ai_provider"), "model": ai.get("ai_model"),
                        "event_type": ai.get("semantic_classification"), "severity": ai.get("severity"),
                        "reasoning": ai.get("reasoning"), "mitre_techniques": ai.get("mitre_techniques", [])}
        if ai.get("ai_provider") == "ollama" and ai.get("semantic_classification"):
            result["suggested_event_type"] = ai["semantic_classification"]
    # What the pipeline does with this record today, before any new rule
    fmt, _parsed, conf = detector.detect_and_parse(raw)
    result["current_parser"] = {"format": fmt, "confidence": conf}
    return result

@router.get("/api/mapper/rules")
async def mapper_rules():
    return {"rules": mapper.list_rules(), "target_fields": list(mapper.TARGET_FIELDS)}

@router.post("/api/mapper/rules")
async def mapper_save_rule(req: MappingRuleRequest, request: Request):
    _require_rank(request, 2, "register mapping rules")
    try:
        return mapper.save_rule(req.name, req.kind, req.mappings, req.signature, req.anchor,
                                req.event_type, req.sample, created_by=_analyst(request) or None)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/api/mapper/rules/{rule_id}")
async def mapper_delete_rule(rule_id: str, request: Request):
    _require_rank(request, 2, "delete mapping rules")
    if not mapper.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted"}


# ---------------------------------------------------------------- containment

class ContainmentRequest(BaseModel):
    kind: str  # "ip" | "host"
    value: str
    reason: Optional[str] = None
    alert_id: Optional[str] = None

@router.get("/api/containment")
async def containment_list(include_released: bool = False):
    return {"entries": containment.list_entries(include_released)}

@router.get("/api/containment/export")
async def containment_export(format: str = "iptables"):
    if format not in ("iptables", "cisco", "windows", "csv"):
        raise HTTPException(status_code=400, detail="format must be iptables, cisco, windows or csv")
    body, media, filename = containment.export(format)
    return Response(content=body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@router.post("/api/containment")
async def containment_add(req: ContainmentRequest, request: Request):
    _require_rank(request, 2, "contain IPs or hosts")
    analyst = _analyst(request) or "analyst"
    try:
        entry = containment.add(req.kind, req.value, req.reason, req.alert_id, analyst)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if req.alert_id and db.get_event(req.alert_id) and not entry["already_contained"]:
        db.set_alert_status(req.alert_id, "Investigating", decided_by=analyst,
                            note=f"Contained {req.kind} {entry['value']}")
    return entry

@router.delete("/api/containment/{entry_id}")
async def containment_release(entry_id: str, request: Request):
    _require_rank(request, 2, "release contained IPs or hosts")
    if not containment.release(entry_id, _analyst(request) or "analyst"):
        raise HTTPException(status_code=404, detail="No active containment with this id")
    return {"status": "released"}


# ---------------------------------------------------------------- exports

@router.get("/api/alerts/{event_id}/context")
async def alert_context(event_id: str, request: Request):
    """Same content as the dossier, for viewing on screen (not recorded as an evidence download)."""
    body = export.alert_dossier(event_id, _analyst(request) or None)
    if not body:
        raise HTTPException(status_code=404, detail="Alert not found")
    return body

@router.get("/api/alerts/{event_id}/dossier")
async def alert_dossier(event_id: str, request: Request):
    body = export.alert_dossier(event_id, _analyst(request) or None)
    if not body:
        raise HTTPException(status_code=404, detail="Alert not found")
    return JSONResponse(body, headers={"Content-Disposition": f'attachment; filename="logvault-dossier-{event_id[:8]}.json"'})

@router.get("/api/export/bundle")
async def export_bundle(request: Request, scope: str = "session"):
    if scope not in ("session", "all"):
        raise HTTPException(status_code=400, detail="scope must be session or all")
    data, filename = await asyncio.to_thread(export.forensic_bundle, _analyst(request) or None, scope)
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@router.get("/api/export/formats")
async def export_formats():
    return {"formats": [{"id": k, "extension": v[0], "description": v[2]} for k, v in export.SIEM_FORMATS.items()]}

@router.get("/api/export/siem")
async def export_siem(format: str = "ocsf-jsonl", scope: str = "session", only_anomalies: bool = False):
    if format not in export.SIEM_FORMATS:
        raise HTTPException(status_code=400, detail=f"format must be one of {list(export.SIEM_FORMATS)}")
    if scope not in ("session", "all"):
        raise HTTPException(status_code=400, detail="scope must be session or all")
    name = export.siem_filename(format, scope, only_anomalies)
    return StreamingResponse(export.stream_siem(format, scope, only_anomalies), media_type=export.SIEM_FORMATS[format][1],
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})

class BundleRequest(BaseModel):
    scope: str = "session"
    passphrase: Optional[str] = None  # set -> AES-256-GCM encrypted .lvault instead of .zip

@router.post("/api/export/bundle")
async def export_bundle_encrypted(req: BundleRequest, request: Request):
    """POST so the passphrase travels in the body, never in a URL or access log."""
    if req.scope not in ("session", "all"):
        raise HTTPException(status_code=400, detail="scope must be session or all")
    try:
        data, filename = await asyncio.to_thread(export.forensic_bundle, _analyst(request) or None, req.scope,
                                                 req.passphrase or None)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return Response(content=data, media_type="application/octet-stream" if req.passphrase else "application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@router.get("/api/export/ocsf")
async def export_ocsf():
    return JSONResponse(export.ocsf_definitions(),
                        headers={"Content-Disposition": 'attachment; filename="logvault-ocsf-1.1.0-definitions.json"'})



# ---------------------------------------------------------------- system status / integrity

@router.get("/api/system/status")
async def system_status(request: Request):
    """Live security posture, every value read from the running configuration."""
    from urllib.parse import urlparse
    import ipaddress as _ip
    ai_host = urlparse(config.OLLAMA_HOST).hostname or ""
    try:
        ai_local = _ip.ip_address(ai_host).is_private or _ip.ip_address(ai_host).is_loopback
    except ValueError:
        ai_local = ai_host in ("localhost", "ollama", "host.docker.internal") or "." not in ai_host
    ai = await local_ai.get_status()
    return {
        "auth_required": config.AUTH_REQUIRED,
        "tls": config.TLS or request.url.scheme == "https",
        "demo_login_enabled": config.DEMO_LOGIN,
        "password_hashing": f"PBKDF2-SHA256, {auth.PBKDF2_ROUNDS:,} rounds",
        "session_hours": auth.SESSION_HOURS,
        "operators": len(auth.list_operators()),
        "ai_endpoint": config.OLLAMA_HOST,
        "ai_endpoint_local": ai_local,
        "ai_status": ai.get("status"),
        "ai_model": ai.get("model"),
        "geoip_offline_database": analytics.geoip.available,
        "active_containments": len(containment.list_entries()),
        "mapping_rules": len(mapper.list_rules()),
        "opensearch": search_index.status(),
    }

@router.get("/api/integrity")
async def integrity(scope: str = "all"):
    if scope not in ("session", "all"):
        raise HTTPException(status_code=400, detail="scope must be session or all")
    return await asyncio.to_thread(export.evidence_fingerprint, scope)



# ---------------------------------------------------------------- audit log

@router.get("/api/audit")
async def audit_list(request: Request, limit: int = 100, offset: int = 0,
                     action: Optional[str] = None, actor: Optional[str] = None):
    _require_rank(request, 2, "read the audit log")
    return audit.list_entries(min(max(limit, 1), 500), max(offset, 0), action, actor)

@router.get("/api/audit/verify")
async def audit_verify(request: Request):
    _require_rank(request, 2, "verify the audit log")
    return await asyncio.to_thread(audit.verify)

@router.get("/api/audit/export")
async def audit_export(request: Request):
    _require_rank(request, 3, "export the audit log")
    rows = audit.list_entries(limit=1000000)["entries"][::-1]
    body = "\n".join(json.dumps(r) for r in rows) + "\n"
    return Response(content=body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": 'attachment; filename="logvault-audit-log.jsonl"'})



# ---------------------------------------------------------------- optional OpenSearch index

@router.get("/api/search/status")
async def search_status():
    return search_index.status()

@router.post("/api/search/reindex")
async def search_reindex(request: Request, scope: str = "all"):
    """Index events stored before OpenSearch was switched on."""
    _require_rank(request, 3, "rebuild the search index")
    if not search_index.enabled():
        raise HTTPException(status_code=400, detail="OpenSearch is not configured (set OPENSEARCH_URL)")
    batch, sent = [], 0
    for evt in export._iter_events(scope, False):
        batch.append(evt)
        if len(batch) >= 500:
            await search_index.index_now(batch)
            sent += len(batch)
            batch = []
    if batch:
        await search_index.index_now(batch)
        sent += len(batch)
    return {**search_index.status(), "reindexed": sent}
