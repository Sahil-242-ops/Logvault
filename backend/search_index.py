"""
Optional OpenSearch index for full-text search.

Off unless OPENSEARCH_URL is set (e.g. http://opensearch:9200 with the "opensearch" compose
profile). When on, every stored event is also indexed as its OCSF document; the Live Log Stream
search then asks OpenSearch and loads the matching events from SQLite, which stays the system of
record. If OpenSearch is down, indexing retries later and search falls back to SQLite.
"""
import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx

from .config import config
from .schema.ocsf import to_ocsf

_queue: "asyncio.Queue[List[Dict[str, Any]]]" = None  # created by worker() on the running loop
_state: Dict[str, Any] = {"indexed": 0, "failed": 0, "last_error": None, "reachable": None, "index_ready": False}

# Explicit field types: letting OpenSearch guess from the first document breaks later ones
# (e.g. a log time "Sep 24 02:11:00" after an ISO time was guessed to be a date).
INDEX_BODY = {
    "settings": {"number_of_replicas": 0},
    "mappings": {
        "date_detection": False,
        "properties": {
            "time": {"type": "date", "format": "epoch_millis"},
            "message": {"type": "text"},
            "raw_data": {"type": "text"},
            "class_uid": {"type": "integer"}, "category_uid": {"type": "integer"},
            "activity_id": {"type": "integer"}, "type_uid": {"type": "long"},
            "severity_id": {"type": "integer"}, "status_id": {"type": "integer"},
            "metadata": {"properties": {"original_time": {"type": "keyword"}, "uid": {"type": "keyword"},
                                        "log_name": {"type": "keyword"}, "version": {"type": "keyword"}}},
            "src_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "dst_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "logvault": {"properties": {k: {"type": "keyword"} for k in (
                "id", "session_id", "detected_format", "event_type", "severity", "source_ip", "destination_ip",
                "user", "host")} | {"is_anomalous": {"type": "boolean"}}},
            "unmapped": {"type": "object", "enabled": False},
        },
    },
}
transport: Optional[httpx.AsyncBaseTransport] = None  # tests inject a mock transport


def enabled() -> bool:
    return bool(config.OPENSEARCH_URL)


def _client() -> httpx.AsyncClient:
    auth = (config.OPENSEARCH_USER, config.OPENSEARCH_PASSWORD) if config.OPENSEARCH_USER else None
    return httpx.AsyncClient(base_url=config.OPENSEARCH_URL.rstrip("/"), auth=auth, timeout=15.0,
                             verify=config.OPENSEARCH_VERIFY_TLS, transport=transport)


def document(evt: Dict[str, Any]) -> Dict[str, Any]:
    """OCSF event plus a few flat fields that make searching and filtering simple."""
    doc = to_ocsf(evt)
    doc["logvault"] = {k: evt.get(k) for k in ("id", "detected_format", "event_type", "severity", "source_ip",
                                                "destination_ip", "user", "host", "session_id")
                       if evt.get(k) is not None}
    doc["logvault"]["is_anomalous"] = bool((evt.get("anomaly") or {}).get("is_anomalous"))
    return doc


def enqueue(events: List[Dict[str, Any]], session_id: Optional[str] = None) -> None:
    if not enabled() or not events or _queue is None:
        return
    batch = [{**e, "session_id": session_id} for e in events]
    try:
        _queue.put_nowait(batch)
    except asyncio.QueueFull:
        _state["failed"] += len(batch)
        _state["last_error"] = "index queue full; events stay searchable in SQLite"


async def ensure_index(c: httpx.AsyncClient) -> None:
    if _state["index_ready"]:
        return
    r = await c.head(f"/{config.OPENSEARCH_INDEX}")
    if r.status_code == 404:
        r = await c.put(f"/{config.OPENSEARCH_INDEX}", json=INDEX_BODY)
        if r.status_code >= 400 and "resource_already_exists" not in r.text:
            r.raise_for_status()
    _state["index_ready"] = True


async def index_now(events: List[Dict[str, Any]]) -> None:
    lines = []
    for e in events:
        lines.append(json.dumps({"index": {"_index": config.OPENSEARCH_INDEX, "_id": e.get("id")}}))
        lines.append(json.dumps(document(e), default=str))
    async with _client() as c:
        await ensure_index(c)
        r = await c.post("/_bulk", content="\n".join(lines) + "\n",
                         headers={"Content-Type": "application/x-ndjson"})
        r.raise_for_status()
        body = r.json()
    errors = [i for i in body.get("items", []) if list(i.values())[0].get("error")]
    _state["indexed"] += len(events) - len(errors)
    _state["failed"] += len(errors)
    _state["reachable"] = True
    if errors:
        _state["last_error"] = str(list(errors[0].values())[0]["error"])[:300]


async def worker():
    """Background task: drains the queue in batches, retrying while OpenSearch is unreachable."""
    global _queue
    _queue = asyncio.Queue(maxsize=1000)
    if not enabled():
        return
    while True:
        batch = await _queue.get()
        for attempt in range(5):
            try:
                await index_now(batch)
                break
            except Exception as e:  # network or HTTP error: keep trying a few times
                _state.update(reachable=False, last_error=str(e)[:300])
                await asyncio.sleep(min(30, 2 ** attempt))
        else:
            _state["failed"] += len(batch)


async def search(query: str, session_id: Optional[str], limit: int = 100) -> Optional[Dict[str, Any]]:
    """Matching event ids (best first) and total, or None when OpenSearch is off or failing."""
    if not enabled() or not query.strip():
        return None
    must: List[Dict[str, Any]] = [{"simple_query_string": {
        "query": query, "default_operator": "and", "lenient": True,
        "fields": ["message^2", "raw_data", "logvault.*", "src_endpoint.ip", "dst_endpoint.ip",
                   "actor.user.name", "device.hostname", "finding_info.title"]}}]
    if session_id:
        must.append({"term": {"logvault.session_id": session_id}})
    try:
        async with _client() as c:
            r = await c.post(f"/{config.OPENSEARCH_INDEX}/_search",
                             json={"query": {"bool": {"must": must}}, "size": limit, "_source": ["logvault.id"],
                                   "track_total_hits": True})
            if r.status_code == 404:  # index not created yet: nothing indexed
                return {"ids": [], "total": 0}
            r.raise_for_status()
            hits = r.json()["hits"]
        _state["reachable"] = True
        return {"ids": [h["_id"] for h in hits["hits"]], "total": hits["total"]["value"]}
    except Exception as e:
        _state.update(reachable=False, last_error=str(e)[:300])
        return None


def status() -> Dict[str, Any]:
    return {"enabled": enabled(), "url": config.OPENSEARCH_URL or None, "index": config.OPENSEARCH_INDEX,
            "pending_batches": _queue.qsize() if _queue else 0, **_state}
