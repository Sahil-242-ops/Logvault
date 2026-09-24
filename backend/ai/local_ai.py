import asyncio
import json
import hashlib
import re
import time
from collections import OrderedDict
from typing import Dict, Any
from .ollama_adapter import OllamaAdapter

# Short prompt with a concrete example (small models copy placeholder text like
# "event type" verbatim, so the schema is shown by example, not by placeholders).
PARSE_PROMPT = """You are a SOC analyst. Classify ONE log record. Reply with JSON only, keys:
event_type (UPPER_SNAKE_CASE, e.g. AUTHENTICATION_FAILED, HTTP_REQUEST, FILE_ACCESS, PROCESS_START, NETWORK_CONNECTION, CONFIG_CHANGE),
severity (LOW, MEDIUM, HIGH or CRITICAL), is_suspicious (true or false), threat_score (0 to 100),
mitre_techniques (list of "Txxxx - Name", empty list if none), reasoning (one sentence about this specific record).

Example record: sshd[88]: Failed password for root from 203.0.113.9 port 22 ssh2
Example answer: {"event_type":"AUTHENTICATION_FAILED","severity":"MEDIUM","is_suspicious":true,"threat_score":60,"mitre_techniques":["T1110 - Brute Force"],"reasoning":"Failed SSH password attempt for root from an external address."}

Record: {raw_log}
Answer:"""

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
PLACEHOLDER_VALUES = {"", "string", "none", "null", "n/a", "unknown", "event type", "event_type",
                      "brief summary", "one sentence about this specific record"}
EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,48}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?\b")


def looks_like_log(raw: str) -> bool:
    """Structural fragments like '[', '{' or '},' carry nothing to analyse."""
    words = re.findall(r"[A-Za-z]{2,}", raw)
    return len(raw.strip()) >= 8 and len(words) >= 2


def validate_ai_output(data: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only well-formed values from the model; drop echoed placeholders."""
    out: Dict[str, Any] = {}
    et = str(data.get("event_type") or data.get("semantic_classification") or "").strip()
    et = re.sub(r"[\s\-]+", "_", et).upper()
    if EVENT_TYPE_RE.match(et) and et.lower() not in PLACEHOLDER_VALUES and et not in ("EVENT_TYPE", "STRING", "UNKNOWN"):
        out["semantic_classification"] = et
    sev = str(data.get("severity") or "").strip().upper()
    if sev in SEVERITIES:
        out["severity"] = sev
    try:
        out["threat_score"] = max(0, min(100, int(float(data.get("threat_score", 0)))))
    except (TypeError, ValueError):
        out["threat_score"] = 0
    sus = data.get("is_suspicious")
    out["is_suspicious"] = sus is True or str(sus).lower() == "true"
    techniques = data.get("mitre_techniques") or []
    if isinstance(techniques, str):
        techniques = [techniques]
    out["mitre_techniques"] = [str(t).strip() for t in techniques if MITRE_RE.match(str(t).strip())][:5]
    reasoning = str(data.get("reasoning") or "").strip()
    if reasoning.lower().rstrip(".") not in PLACEHOLDER_VALUES and len(reasoning) >= 8:
        out["reasoning"] = reasoning[:400]
    else:
        out["reasoning"] = ""
    return out


class LRUCache:
    """Simple LRU cache for AI responses."""
    def __init__(self, max_size=200):
        self._cache = OrderedDict()
        self._max_size = max_size

    def _hash(self, text: str) -> str:
        return hashlib.md5(text.strip().encode()).hexdigest()

    def get(self, key: str):
        h = self._hash(key)
        if h in self._cache:
            self._cache.move_to_end(h)
            return self._cache[h]
        return None

    def put(self, key: str, value):
        h = self._hash(key)
        self._cache[h] = value
        self._cache.move_to_end(h)
        if len(self._cache) > self._max_size:
            self._cache.popitem(last=False)


class LocalAI:
    def __init__(self):
        self.ollama = OllamaAdapter()
        self._cached_status = None
        self._last_status_check = 0.0
        self._response_cache = LRUCache(max_size=200)

    async def get_status(self) -> Dict[str, Any]:
        now = time.time()
        # While the model is still warming up (or offline), recheck more often
        # (5s) so we pick up "ready" quickly. Once ready, cache longer (30s)
        # since we don't need to hammer Ollama on every request.
        is_ready = bool(self._cached_status and self._cached_status.get("available"))
        cache_ttl = 30.0 if is_ready else 5.0
        if self._cached_status and (now - self._last_status_check < cache_ttl):
            return self._cached_status

        # Hard backstop: no matter what happens inside the adapter, this
        # request will get an answer within 5 seconds.
        try:
            status = await asyncio.wait_for(self.ollama.check_status(), timeout=5.0)
        except asyncio.TimeoutError:
            status = {"status": "LOCAL AI OFFLINE", "available": False, "provider": None, "model": None}

        self._cached_status = status
        self._last_status_check = now
        return status

    async def analyze(self, raw_log: str) -> Dict[str, Any]:
        # Check cache first — identical logs skip inference entirely (0ms)
        cached = self._response_cache.get(raw_log)
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["_cache_hit"] = True
            return cached_copy

        if not looks_like_log(raw_log):
            return {
                "ai_provider": "none",
                "ai_model": "none",
                "threat_score": 0,
                "is_suspicious": False,
                "reasoning": "Not analysed: record has no meaningful content (structural fragment or too short).",
                "mitre_techniques": [],
                "raw_response": None
            }

        status = await self.get_status()

        # Real Ollama inference
        if status.get("available") and status.get("status") == "LOCAL AI READY":
            prompt = PARSE_PROMPT.replace("{raw_log}", raw_log[:600].strip())  # Truncate very long logs
            try:
                response = await asyncio.wait_for(self.ollama.analyze(status["model"], prompt), timeout=20.0)
            except asyncio.TimeoutError:
                response = None

            if response:
                try:
                    cleaned = response.strip()
                    if "```json" in cleaned:
                        cleaned = cleaned.split("```json")[1].split("```")[0].strip()
                    elif "```" in cleaned:
                        cleaned = cleaned.split("```")[1].split("```")[0].strip()

                    parsed = validate_ai_output(json.loads(cleaned))
                    parsed["ai_provider"] = "ollama"
                    parsed["ai_model"] = status["model"]
                    parsed["raw_response"] = response

                    # Cache the successful result
                    self._response_cache.put(raw_log, parsed)

                    return parsed
                except Exception as e:
                    print(f"[AI] JSON parsing failed: {e}")
                    return {
                        "ai_provider": "ollama",
                        "ai_model": status["model"],
                        "threat_score": 0,
                        "is_suspicious": False,
                        "reasoning": "Local AI returned an unreadable answer; deterministic results shown.",
                        "mitre_techniques": [],
                        "raw_response": response
                    }

        # Do NOT fake AI. Explicitly return blocked/offline state
        offline_reason = "REAL OLLAMA INFERENCE BLOCKED: " + (
            "NO LOCAL MODEL INSTALLED" if status.get("status") == "LOCAL AI NO MODEL" 
            else ("OLLAMA OFFLINE" if status.get("status") == "LOCAL AI OFFLINE" else status.get("status", "UNAVAILABLE"))
        )
        return {
            "ai_provider": "none",
            "ai_model": "none",
            "semantic_classification": "GENERIC_EVENT",
            "threat_score": 0,
            "severity": "INFO",
            "is_suspicious": False,
            "reasoning": offline_reason,
            "mitre_techniques": [],
            "raw_response": None
        }

local_ai = LocalAI()
