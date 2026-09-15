import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["backend"] == "healthy"
    assert data["network_mode"] == "air_gapped"

def test_ai_status():
    response = client.get("/api/ai/status")
    assert response.status_code == 200
    data = response.json()
    assert "available" in data
    assert "status_message" in data

def test_normalize_endpoint():
    payload = {"raw": "Jul 15 12:34:56 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"}
    response = client.post("/api/normalize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["detected_format"] == "syslog"
    assert data["anomaly"]["is_anomalous"] is True
