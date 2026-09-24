import asyncio
import httpx
from ..config import config

class OllamaAdapter:
    def __init__(self):
        self.host = config.OLLAMA_HOST
        self.default_model = config.OLLAMA_DEFAULT_MODEL
        self._warmed_up = False
        self._warm_up_task = None
        self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def check_status(self):
        """
        Fast, non-blocking status probe. Never waits on model loading —
        that happens in the background via _warm_up() so a slow/CPU-only
        model load can never stall an incoming HTTP request.
        """
        try:
            client = self._get_client()
            res = await asyncio.wait_for(
                client.get(f"{self.host}/api/tags", timeout=4.0),
                timeout=4.0
            )
            if res.status_code == 200:
                models = res.json().get("models", [])
                if not models:
                    self._warmed_up = False
                    return {"status": "LOCAL AI NO MODEL", "available": False, "provider": "ollama", "model": None}

                available_model = next(
                    (m["name"] for m in models if self.default_model in m["name"] or m["name"] in self.default_model),
                    models[0]["name"]
                )

                if self._warmed_up:
                    return {"status": "LOCAL AI READY", "available": True, "provider": "ollama", "model": available_model}

                # Model exists but isn't confirmed warm yet — kick off warm-up
                # in the background (don't await it here) and tell the caller
                # to use the deterministic fallback for now.
                if self._warm_up_task is None or self._warm_up_task.done():
                    self._warm_up_task = asyncio.create_task(self._warm_up(available_model))

                return {"status": "LOCAL AI WARMING UP", "available": False, "provider": "ollama", "model": available_model}
        except Exception:
            pass
        self._warmed_up = False
        return {"status": "LOCAL AI OFFLINE", "available": False, "provider": None, "model": None}

    async def _warm_up(self, model: str):
        """
        Runs as a detached background task — loading a model into memory
        (especially CPU-only) can legitimately take a long time, so this
        must never be awaited from inside a request handler.
        """
        try:
            client = self._get_client()
            test_res = await asyncio.wait_for(
                client.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": model,
                        "prompt": "Reply with JSON { \"test\": \"ok\" }",
                        "stream": False,
                        "format": "json",
                        "options": {"num_predict": 10, "temperature": 0.0},
                        "keep_alive": "5m"
                    },
                    timeout=120.0
                ),
                timeout=120.0
            )
            self._warmed_up = (test_res.status_code == 200)
        except Exception:
            self._warmed_up = False

    async def analyze(self, model: str, prompt: str, num_predict: int = 150, timeout: float = 20.0):
        try:
            client = self._get_client()
            res = await asyncio.wait_for(
                client.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": {
                            "num_predict": num_predict,
                            "temperature": 0.0
                        },
                        "keep_alive": "5m"
                    },
                    timeout=timeout
                ),
                timeout=timeout
            )
            if res.status_code == 200:
                return res.json().get("response")
        except Exception:
            return None
