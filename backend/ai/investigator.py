"""
Automated alert investigation.

Every anomalous event is investigated in the background: related events are correlated
(same source IP / user / host), a rule-based verdict is computed from the evidence, and
when the local Ollama model is ready it adds a narrative summary, root cause and actions.
The result is only a PROPOSAL: the alert moves to 'Awaiting Approval' and an analyst must
approve (-> Resolved) or reject (-> Investigating) it.
"""
import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from ..config import config
from ..db import db
from ..geoip import geoip
from .local_ai import local_ai
from .prompts import INVESTIGATE_PROMPT

VERDICTS = ("TRUE_POSITIVE", "SUSPICIOUS", "FALSE_POSITIVE")
VERDICT_RANK = {"FALSE_POSITIVE": 0, "SUSPICIOUS": 1, "TRUE_POSITIVE": 2}

# Response playbooks per detection rule (see backend/mitre/rules.py)
PLAYBOOKS: Dict[str, List[str]] = {
    "RULE-001": [
        "Block the source IP at the WAF / perimeter firewall",
        "Review the targeted endpoint for unparameterised SQL queries",
        "Check database audit logs for data read or modified by this source",
    ],
    "RULE-002": [
        "Block the source IP at the WAF",
        "Verify output encoding / CSP on the targeted page",
        "Search web logs for other script-injection payloads from this source",
    ],
    "RULE-003": [
        "Block the source IP at the perimeter firewall",
        "Confirm the web server denies path traversal (check response codes)",
        "Verify no sensitive files (/etc/passwd, configs) were served",
    ],
    "RULE-004": [
        "Temporarily block or rate-limit the source IP",
        "Lock or force a password reset on the targeted account",
        "Check for a successful login from this source after the failures",
    ],
    "RULE-005": [
        "Isolate the host from the network pending review",
        "Capture the process tree and command history on the host",
        "Check for persistence (cron, services, startup items)",
    ],
    "RULE-006": [
        "Verify the privilege change was authorised",
        "Revoke elevated rights if not approved",
        "Audit recent activity of the account",
    ],
    "RULE-007": [
        "Block the destination at the egress firewall",
        "Identify the data volume and type transferred",
        "Isolate the host and preserve evidence",
    ],
    "ENTROPY-001": [
        "Decode the payload in a sandbox to identify its content",
        "Check whether the host executed the encoded content",
    ],
}
DEFAULT_ACTIONS = [
    "Review the raw log and related events for context",
    "Confirm with the asset owner whether the activity is expected",
]

THREAT_RULE_TYPES = ("threat_rule", "entropy")


def _is_failed_auth(evt: Dict[str, Any]) -> bool:
    et = str(evt.get("event_type", "")).upper()
    return "AUTH" in et and ("FAIL" in et or "DENIED" in et)


def _correlate(evt: Dict[str, Any], related: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_events = [evt] + related
    rule_hits: Dict[str, int] = {}
    for e in all_events:
        for f in (e.get("anomaly") or {}).get("findings", []):
            name = f.get("rule_name")
            if name:
                rule_hits[name] = rule_hits.get(name, 0) + 1
    event_types: Dict[str, int] = {}
    for e in all_events:
        et = e.get("event_type") or "UNKNOWN"
        event_types[et] = event_types.get(et, 0) + 1
    return {
        "related_events": len(related),
        "related_anomalous": sum(1 for e in related if (e.get("anomaly") or {}).get("is_anomalous")),
        "failed_auth_count": sum(1 for e in all_events if _is_failed_auth(e)),
        "distinct_hosts": sorted({str(e.get("host")) for e in all_events if e.get("host")})[:10],
        "distinct_users": sorted({str(e.get("user")) for e in all_events if e.get("user")})[:10],
        "event_types": dict(sorted(event_types.items(), key=lambda kv: -kv[1])[:8]),
        "rule_hits": rule_hits,
    }


def _rule_verdict(evt: Dict[str, Any], corr: Dict[str, Any]) -> Dict[str, Any]:
    findings = (evt.get("anomaly") or {}).get("findings", [])
    threat_findings = [f for f in findings if f.get("type") in THREAT_RULE_TYPES]
    critical = [f for f in threat_findings if f.get("severity") == "CRITICAL"]
    rule_ids = {f.get("rule_id") for f in threat_findings}
    reasons = []

    if critical:
        reasons.append(f"Critical detection rule matched: {critical[0]['rule_name']}")
        verdict, conf = "TRUE_POSITIVE", 0.85
    elif "RULE-004" in rule_ids or corr["failed_auth_count"] >= 5:
        if corr["failed_auth_count"] >= 5:
            reasons.append(f"{corr['failed_auth_count']} failed authentications from the same source/user")
            verdict, conf = "TRUE_POSITIVE", 0.9
        else:
            reasons.append("Brute-force pattern matched but low failure volume so far")
            verdict, conf = "SUSPICIOUS", 0.6
    elif threat_findings:
        reasons.append(f"Detection rule matched: {threat_findings[0]['rule_name']}")
        verdict, conf = ("TRUE_POSITIVE", 0.75) if corr["related_anomalous"] >= 2 else ("SUSPICIOUS", 0.65)
        if corr["related_anomalous"] >= 2:
            reasons.append(f"{corr['related_anomalous']} other anomalous events from the same source")
    elif any(f.get("type") == "severity_flag" for f in findings) and not corr["related_anomalous"]:
        reasons.append("Single access-denied event; no threat rule matched and no correlated anomalies")
        verdict, conf = "FALSE_POSITIVE", 0.7
    else:
        # Flagged only by the AI enrichment during ingestion: no deterministic evidence
        reasons.append("Flagged by AI enrichment only; no deterministic detection rule matched")
        verdict, conf = "SUSPICIOUS", 0.45

    return {"verdict": verdict, "confidence": conf, "reasons": reasons}


def _actions(evt: Dict[str, Any], verdict: str) -> List[str]:
    if verdict == "FALSE_POSITIVE":
        return ["Close as false positive", "Consider tuning the rule if this pattern recurs"]
    actions: List[str] = []
    for f in (evt.get("anomaly") or {}).get("findings", []):
        for a in PLAYBOOKS.get(f.get("rule_id"), []):
            if a not in actions:
                actions.append(a)
    return actions or list(DEFAULT_ACTIONS)


def _proposed_resolution(verdict: str) -> str:
    return {
        "TRUE_POSITIVE": "Confirmed malicious activity. Apply the containment actions, then close the incident.",
        "SUSPICIOUS": "Inconclusive. Apply precautionary actions and monitor the source; close if no further activity.",
        "FALSE_POSITIVE": "Benign activity. Close the alert as a false positive.",
    }[verdict]


def _timeline(evt: Dict[str, Any], related: List[Dict[str, Any]], limit: int = 15) -> List[Dict[str, Any]]:
    items = []
    for e in [evt] + related[: limit - 1]:
        items.append({
            "id": e.get("id"),
            "time": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "severity": e.get("severity"),
            "anomalous": bool((e.get("anomaly") or {}).get("is_anomalous")),
            "message": str(e.get("message") or e.get("raw_log") or "")[:160],
            "is_alert": e.get("id") == evt.get("id"),
        })
    return items


async def _llm_opinion(evt: Dict[str, Any], corr: Dict[str, Any], related: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    status = await local_ai.get_status()
    if not (status.get("available") and status.get("status") == "LOCAL AI READY"):
        return None

    findings = (evt.get("anomaly") or {}).get("findings", [])
    alert_txt = json.dumps({
        k: evt.get(k) for k in ("event_type", "severity", "source_ip", "user", "host", "process", "message")
    }, default=str)
    findings_txt = "\n".join(
        f"- {f.get('rule_name')} [{f.get('severity')}] {f.get('mitre_technique') or ''}" for f in findings
    ) or "- none"
    related_txt = "\n".join(
        f"- {e.get('event_type')} {e.get('severity')} :: {str(e.get('raw_log') or '')[:140]}" for e in related[:8]
    ) or "- none"
    prompt = (INVESTIGATE_PROMPT
              .replace("{alert}", alert_txt + "\nRAW: " + str(evt.get("raw_log") or "")[:400])
              .replace("{findings}", findings_txt)
              .replace("{correlation}", json.dumps(corr, default=str))
              .replace("{related}", related_txt))

    response = await local_ai.ollama.analyze(status["model"], prompt, num_predict=350, timeout=60.0)
    if not response:
        return None
    try:
        data = json.loads(response.strip())
    except Exception:
        return None

    verdict = str(data.get("verdict", "")).upper().replace(" ", "_")
    if verdict not in VERDICTS:
        return None
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5
    actions = data.get("recommended_actions") or []
    if isinstance(actions, str):
        actions = [actions]
    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "summary": str(data.get("summary") or "")[:600],
        "root_cause": str(data.get("root_cause") or "")[:400],
        "attack_stage": str(data.get("attack_stage") or "")[:80],
        "recommended_actions": [str(a)[:160] for a in actions if a][:6],
        "model": status["model"],
    }


async def investigate(evt: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    related = db.get_related_events(evt)
    corr = _correlate(evt, related)
    rule = _rule_verdict(evt, corr)
    geo = geoip.lookup(evt.get("source_ip"))

    # Sibling alerts (same source + same rule) reuse one LLM opinion instead of
    # re-running inference for every line of a burst (e.g. brute force).
    llm = db.get_sibling_ai_opinion(evt)
    if llm is None:
        try:
            llm = await _llm_opinion(evt, corr, related)
        except Exception as e:
            print(f"[INVESTIGATE] LLM step failed: {e}")
            llm = None

    verdict, confidence = rule["verdict"], rule["confidence"]
    disagreement = False
    llm_adopted = False
    if llm:
        disagreement = llm["verdict"] != rule["verdict"]
        # Err on the side of caution: keep the more severe of the two verdicts
        if VERDICT_RANK[llm["verdict"]] > VERDICT_RANK[verdict]:
            verdict, confidence = llm["verdict"], llm["confidence"]
            llm_adopted = True
        elif not disagreement:
            confidence = round(max(confidence, llm["confidence"]), 2)
            llm_adopted = True
    # Only use the model's narrative when it is consistent with the final verdict
    narrative = llm if llm_adopted else None

    actions = _actions(evt, verdict)
    if llm and verdict != "FALSE_POSITIVE":
        for a in llm["recommended_actions"]:
            if a not in actions:
                actions.append(a)

    location = None
    if geo.get("scope") == "internal":
        location = "Internal network"
    elif geo.get("resolved"):
        location = ", ".join(p for p in (geo.get("city"), geo.get("country")) if p)

    summary = (narrative or {}).get("summary") or (
        f"{evt.get('event_type', 'Event')} from {evt.get('source_ip') or 'unknown source'}"
        f"{' (' + location + ')' if location else ''}: " + "; ".join(rule["reasons"]) + "."
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "root_cause": (narrative or {}).get("root_cause") or rule["reasons"][0],
        "attack_stage": (narrative or {}).get("attack_stage") or next(
            (f.get("mitre_tactic") for f in (evt.get("anomaly") or {}).get("findings", []) if f.get("mitre_tactic")), None),
        "evidence": rule["reasons"],
        "recommended_actions": actions[:8],
        "proposed_resolution": _proposed_resolution(verdict),
        "correlation": corr,
        "source_location": location,
        "timeline": _timeline(evt, related),
        "rule_verdict": {"verdict": rule["verdict"], "confidence": rule["confidence"]},
        "ai_verdict": {"verdict": llm["verdict"], "confidence": llm["confidence"]} if llm else None,
        "ai_opinion": llm,
        "ai_disagreement": disagreement,
        "engine": f"ollama:{llm['model']} + rules" if llm else "rules (local AI unavailable)",
        "duration_ms": round((time.time() - start) * 1000),
    }


async def investigate_and_store(evt: Dict[str, Any]) -> Dict[str, Any]:
    try:
        result = await investigate(evt)
    except Exception as e:
        print(f"[INVESTIGATE] Failed for {evt.get('id')}: {e}")
        result = {
            "verdict": "SUSPICIOUS", "confidence": 0.0,
            "summary": f"Automated investigation failed ({e}). Manual review required.",
            "evidence": [], "recommended_actions": list(DEFAULT_ACTIONS),
            "proposed_resolution": "Manual investigation required.", "engine": "error",
        }
    db.save_investigation(evt["id"], result, status="Awaiting Approval")
    return result


async def investigation_worker():
    """Background loop: investigates every new alert, one at a time."""
    print(f"[INVESTIGATE] Auto-investigation worker started (interval {config.INVESTIGATE_INTERVAL}s)")
    while True:
        try:
            evt = db.claim_next_uninvestigated_alert()
            if evt:
                await investigate_and_store(evt)
                continue
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[INVESTIGATE] Worker error: {e}")
        await asyncio.sleep(config.INVESTIGATE_INTERVAL)
