import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uuid
import asyncio
from contextlib import asynccontextmanager
from .api import router
from .db import db
from .ai.local_ai import local_ai
from .ai.investigator import investigation_worker
from .storage import maintenance_worker
from .config import config

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    # Generate new current session ID
    db.current_session_id = str(uuid.uuid4())
    print(f"[BOOT] New Empty Application Session: {db.current_session_id}")
    # Non-blocking warm-up of local AI model so the first user request won't face cold start
    try:
        asyncio.create_task(local_ai.get_status())
    except Exception as e:
        print(f"[BOOT] AI warm-up notice: {e}")
    # Background AI investigation of new alerts (proposals still need analyst approval)
    worker = asyncio.create_task(investigation_worker()) if config.AUTO_INVESTIGATE else None
    # Storage limit / retention enforcement (no-op while unlimited)
    maintenance = asyncio.create_task(maintenance_worker())
    yield
    maintenance.cancel()
    if worker:
        worker.cancel()

app = FastAPI(title="LogVault Air-Gapped Backend", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Since it's a local tool, allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Mount frontend assets so accessing http://127.0.0.1:8000 loads the full UI
js_dir = os.path.join(FRONTEND_DIR, "js")
if os.path.exists(js_dir):
    app.mount("/js", StaticFiles(directory=js_dir), name="js")

@app.get("/")
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "LogVault Backend Online", "docs": "/docs", "health": "/api/health"}

@app.get("/styles.css")
async def serve_styles():
    css_path = os.path.join(FRONTEND_DIR, "styles.css")
    if os.path.exists(css_path):
        return FileResponse(css_path, media_type="text/css")
    return {"error": "styles.css not found"}
