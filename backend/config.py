import os

class Config:
    # Upload limits
    MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
    UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
    DB_PATH = os.path.join(DATA_DIR, "logvault.db")
    
    # Local AI settings
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    OLLAMA_DEFAULT_MODEL = os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.2")
    # Records per uploaded file analysed by local AI during the upload itself. Default 0:
    # uploads return instantly and the UI asks for AI on the record being viewed.
    BATCH_AI_LINES = int(os.getenv("BATCH_AI_LINES", "0"))

    # Alert Center: AI auto-investigation (results still need analyst approval)
    AUTO_INVESTIGATE = os.getenv("AUTO_INVESTIGATE", "true").lower() in ("1", "true", "yes")
    INVESTIGATE_INTERVAL = float(os.getenv("INVESTIGATE_INTERVAL", "5"))

    # Storage policy defaults (0 = unlimited / keep forever). Settings screen overrides these.
    STORAGE_LIMIT_GB = float(os.getenv("STORAGE_LIMIT_GB", "0"))
    RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0"))
    STORAGE_CHECK_INTERVAL = float(os.getenv("STORAGE_CHECK_INTERVAL", "600"))

    # Sign-in. AUTH_REQUIRED=false turns off the token check (single trusted user, tests).
    AUTH_REQUIRED = os.getenv("LOGVAULT_AUTH", "true").lower() in ("1", "true", "yes")
    # Create the four evaluation operator accounts on first start
    SEED_OPERATORS = os.getenv("LOGVAULT_SEED_OPERATORS", "true").lower() in ("1", "true", "yes")
    # One-click "demo access" button / ?auth=demo sign in as the seeded SOC lead
    DEMO_LOGIN = os.getenv("LOGVAULT_DEMO_LOGIN", "true").lower() in ("1", "true", "yes")

    # Offline IP geolocation database folder (any MaxMind-format .mmdb)
    GEOIP_DIR = os.getenv("GEOIP_DIR", os.path.join(os.path.dirname(BASE_DIR), "geoip"))
    
    # Init
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

config = Config()
