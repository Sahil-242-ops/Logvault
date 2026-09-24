import time
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from pydantic import BaseModel
from .normalizer import normalizer
from .parsers.detector import detector
from .ai.local_ai import local_ai
from .config import config
from .db import db
from .ai import investigator
from . import analytics
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
async def normalize_log(req: LogRequest):
    if not req.raw:
        raise HTTPException(status_code=400, detail="Raw log is required")
    result = await normalizer.normalize(req.raw)
    db.insert_event(result)
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
    if not file.filename.endswith(('.log', '.txt', '.csv', '.json', '.jsonl')):
        raise HTTPException(status_code=400, detail="Unsupported file extension")

    contents = await file.read()
    if len(contents) > config.MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
        
    try:
        text = contents.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")
        
    lines = text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="File is empty")
        
    start_time = time.time()
    results = await normalizer.batch_normalize(lines)
    
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
        db.insert_event(r)
        
    return {
        "file": {
            "filename": file.filename,
            "total_lines": len(lines),
            "size_bytes": len(contents)
        },
        "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        "results": results[:100],  # Return up to 100 results to UI to avoid freezing
        "stats": {
            "total_records": len(lines),
            "successful_records": successful,
            "failed_records": len(lines) - successful,
            "detected_formats": formats,
            "threats_found": anomalous
        },
        "anomaly_summary": {
            "anomalous": anomalous
        }
    }

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
    source_ip: Optional[str] = None
):
    return db.get_events(limit, offset, search, severity, event_type, source_ip)

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
async def approve_alert(event_id: str, req: AlertDecisionRequest):
    """Human approval step: accept the AI proposal and resolve the alert."""
    evt = _require_alert(event_id)
    if not req.analyst.strip():
        raise HTTPException(status_code=400, detail="Analyst name is required")
    ids = [event_id]
    if req.include_related:
        ids += db.get_sibling_alert_ids(evt, "Awaiting Approval")
    for i in ids:
        db.set_alert_status(i, "Resolved", decided_by=req.analyst.strip(), note=req.note or "Approved AI resolution")
    return {"event_id": event_id, "status": "Resolved", "resolved_ids": ids}

@router.post("/api/alerts/{event_id}/reject")
async def reject_alert(event_id: str, req: AlertDecisionRequest):
    """Human rejects the AI proposal; the alert goes to manual investigation."""
    _require_alert(event_id)
    if not req.analyst.strip():
        raise HTTPException(status_code=400, detail="Analyst name is required")
    db.set_alert_status(event_id, "Investigating", decided_by=req.analyst.strip(), note=req.note or "AI proposal rejected")
    return {"event_id": event_id, "status": "Investigating"}

@router.post("/api/alerts/{event_id}/status")
async def set_alert_status(event_id: str, req: AlertStatusRequest):
    """Manual Kanban move by an analyst."""
    if req.status not in ALERT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {ALERT_STATUSES}")
    _require_alert(event_id)
    db.set_alert_status(event_id, req.status, decided_by=(req.analyst or None), note=req.note)
    return {"event_id": event_id, "status": req.status}

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
async def delete_events(confirm: bool = Query(..., description="Must be true to delete")):
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")
    db.delete_events()
    return {"status": "deleted"}
