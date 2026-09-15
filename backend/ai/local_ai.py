import json
import hashlib
import time
from collections import OrderedDict
from typing import Dict, Any
from .ollama_adapter import OllamaAdapter
from .fallback import DeterministicFallback

# Minimal, focused prompt — fewer tokens in = fewer tokens out = faster inference
PARSE_PROMPT = """Classify log in JSON. Keep values short (reasoning < 10 words):
{{"severity":"LOW|MEDIUM|HIGH|CRITICAL","threat_score":0-100,"is_suspicious":false,"semantic_classification":"event type","reasoning":"brief summary","mitre_techniques":[]}}

Log: {raw_log}"""


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
        self.fallback = DeterministicFallback()
        self._cached_status = None
        self._last_status_check = 0.0
        self._response_cache = LRUCache(max_size=200)

    async def get_status(self) -> Dict[str, Any]:
        now = time.time()
        if self._cached_status and (now - self._last_status_check < 30.0):
            return self._cached_status
        status = await self.ollama.check_status()
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

        status = await self.get_status()
        
        # Real Ollama inference
        if status.get("available") and status.get("status") == "LOCAL AI READY":
            prompt = PARSE_PROMPT.replace("{raw_log}", raw_log[:400].strip())  # Truncate very long logs
            response = await self.ollama.analyze(status["model"], prompt)
                
            if response:
                try:
                    cleaned = response.strip()
                    if "```json" in cleaned:
                        cleaned = cleaned.split("```json")[1].split("```")[0].strip()
                    elif "```" in cleaned:
                        cleaned = cleaned.split("```")[1].split("```")[0].strip()
                    
                    parsed = json.loads(cleaned)
                    parsed["ai_provider"] = "ollama"
                    parsed["ai_model"] = status["model"]
                    parsed["raw_response"] = response
                    
                    # Ensure all required keys exist and have proper types
                    if "mitre_techniques" not in parsed:
                        parsed["mitre_techniques"] = []
                    elif isinstance(parsed["mitre_techniques"], str):
                        parsed["mitre_techniques"] = [parsed["mitre_techniques"]]
                    
                    if "threat_score" not in parsed or not isinstance(parsed["threat_score"], (int, float)):
                        parsed["threat_score"] = 75 if parsed.get("is_suspicious") else 0
                    else:
                        parsed["threat_score"] = int(parsed["threat_score"])

                    # Cache the successful result
                    self._response_cache.put(raw_log, parsed)

                    return parsed
                except Exception as e:
                    print(f"[AI] JSON parsing failed: {e}")
                    fallback_result = {
                        "ai_provider": "ollama",
                        "ai_model": status["model"],
                        "semantic_classification": "Unstructured AI Analysis",
                        "threat_score": 50,
                        "severity": "MEDIUM",
                        "is_suspicious": False,
                        "reasoning": response,
                        "mitre_techniques": [],
                        "raw_response": response
                    }
                    return fallback_result

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
