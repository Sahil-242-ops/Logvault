import httpx
from ..config import config

class OllamaAdapter:
    def __init__(self):
        self.host = config.OLLAMA_HOST
        self.default_model = config.OLLAMA_DEFAULT_MODEL
        self._warmed_up = False
        self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def check_status(self):
        try:
            client = self._get_client()
            res = await client.get(f"{self.host}/api/tags", timeout=5.0)
            if res.status_code == 200:
                models = res.json().get("models", [])
                if not models:
                    self._warmed_up = False
                    return {"status": "LOCAL AI NO MODEL", "available": False, "provider": "ollama", "model": None}
                    
                available_model = next((m["name"] for m in models if self.default_model in m["name"] or m["name"] in self.default_model), models[0]["name"])
                
                # Warm-up inference test on first check — keep model loaded in memory for fast subsequent calls
                if not self._warmed_up:
                    try:
                        test_res = await client.post(
                            f"{self.host}/api/generate",
                            json={
                                "model": available_model,
                                "prompt": "Reply with JSON { \"test\": \"ok\" }",
                                "stream": False,
                                "format": "json",
                                "options": {
                                    "num_predict": 10,
                                    "temperature": 0.0
                                },
                                "keep_alive": "5m"
                            },
                            timeout=15.0
                        )
                        if test_res.status_code == 200:
                            self._warmed_up = True
                            return {"status": "LOCAL AI READY", "available": True, "provider": "ollama", "model": available_model}
                        else:
                            return {"status": "LOCAL AI ERROR", "available": False, "provider": "ollama", "model": available_model}
                    except Exception:
                        return {"status": "LOCAL AI ERROR", "available": False, "provider": "ollama", "model": available_model}

                return {"status": "LOCAL AI READY", "available": True, "provider": "ollama", "model": available_model}
        except Exception:
            pass
        self._warmed_up = False
        return {"status": "LOCAL AI OFFLINE", "available": False, "provider": None, "model": None}
        
    async def analyze(self, model: str, prompt: str):
        try:
            client = self._get_client()
            res = await client.post(
                f"{self.host}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "num_predict": 150,
                        "temperature": 0.0
                    },
                    "keep_alive": "5m"
                },
                timeout=15.0
            )
            if res.status_code == 200:
                return res.json().get("response")
        except Exception:
            return None

