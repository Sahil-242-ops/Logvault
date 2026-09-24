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
    LLAMACPP_HOST = os.getenv("LLAMACPP_HOST", "http://127.0.0.1:8080")
    # Lines per uploaded file that get local AI enrichment (the rest are deterministic)
    BATCH_AI_LINES = int(os.getenv("BATCH_AI_LINES", "3"))

    # Alert Center: AI auto-investigation (results still need analyst approval)
    AUTO_INVESTIGATE = os.getenv("AUTO_INVESTIGATE", "true").lower() in ("1", "true", "yes")
    INVESTIGATE_INTERVAL = float(os.getenv("INVESTIGATE_INTERVAL", "5"))

    # Offline IP geolocation database folder (any MaxMind-format .mmdb)
    GEOIP_DIR = os.getenv("GEOIP_DIR", os.path.join(os.path.dirname(BASE_DIR), "geoip"))
    
    # Init
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

config = Config()
