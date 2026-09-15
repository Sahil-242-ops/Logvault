from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import router
from .db import db

app = FastAPI(title="LogVault Air-Gapped Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Since it's a local tool, allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

import uuid
import asyncio
from .normalizer import normalizer
from .ai.local_ai import local_ai

@app.on_event("startup")
async def startup_event():
    db.init_db()
    # Generate new current session ID
    db.current_session_id = str(uuid.uuid4())
    print(f"[BOOT] New Empty Application Session: {db.current_session_id}")
    # Non-blocking warm-up of local AI model so the first user request won't face cold start
    try:
        asyncio.create_task(local_ai.get_status())
    except Exception as e:
        print(f"[BOOT] AI warm-up notice: {e}")
