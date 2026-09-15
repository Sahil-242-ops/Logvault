import httpx
from ..config import config

class LlamaCppAdapter:
    def __init__(self):
        self.host = config.LLAMACPP_HOST

    async def check_status(self):
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.host}/health")
                if res.status_code == 200:
                    return {"available": True, "provider": "llamacpp", "model": "local-model"}
        except Exception:
            pass
        return {"available": False, "provider": None, "model": None}

    async def analyze(self, model: str, prompt: str):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.host}/completion",
                    json={"prompt": prompt, "n_predict": 512, "json_schema": {}} # Simplified for prototype
                )
                if res.status_code == 200:
                    return res.json().get("content")
        except Exception:
            return None
