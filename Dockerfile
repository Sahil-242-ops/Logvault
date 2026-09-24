# LOGVAULT — FastAPI backend + static frontend (served by the same process on :8000)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first for layer caching
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

# Application: backend package + frontend assets served by backend/app.py
COPY backend/ backend/
COPY frontend/ frontend/
# Offline GeoIP database (scripts/download_geoip.py); baked in so nothing is fetched at runtime
COPY geoip/ geoip/

# Non-root runtime user; /app/data holds SQLite DB + uploads (mount a volume here)
RUN useradd --create-home --uid 1000 logvault \
    && mkdir -p /app/data/uploads \
    && chown -R logvault:logvault /app/data
USER logvault

EXPOSE 8000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=8).status == 200 else 1)"

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
