import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.db import db
from backend.ai.local_ai import local_ai
from backend.geoip import geoip

client = TestClient(app)
db.init_db()

OFFLINE = {"status": "LOCAL AI OFFLINE", "available": False, "provider": None, "model": None}


@pytest.fixture(autouse=True)
def offline_ai(monkeypatch):
    """Deterministic tests: the rules engine only, no Ollama."""
    async def fake_status():
        return OFFLINE
    monkeypatch.setattr(local_ai, "get_status", fake_status)


def _ingest(raw):
    res = client.post("/api/normalize", json={"raw": raw})
    assert res.status_code == 200
    return res.json()


def test_investigate_brute_force_needs_approval():
    evts = [_ingest(f"Jul 15 12:34:5{i} srv sshd[1]: Failed password for root from 203.0.113.77 port 5000{i} ssh2")
            for i in range(6)]
    alert_id = evts[-1]["id"]

    res = client.post(f"/api/alerts/{alert_id}/investigate")
    assert res.status_code == 200
    inv = res.json()["investigation"]
    assert inv["verdict"] == "TRUE_POSITIVE"
    assert inv["correlation"]["failed_auth_count"] >= 6
    assert inv["recommended_actions"]
    assert inv["engine"].startswith("rules")

    alert = next(a for a in client.get("/api/alerts?limit=500").json()["alerts"] if a["id"] == alert_id)
    assert alert["status"] == "Awaiting Approval"  # never auto-resolved


def test_approve_requires_analyst_and_resolves_related():
    evts = [_ingest(f"Jul 15 13:00:0{i} srv sshd[1]: Failed password for admin from 198.51.100.9 port 4000{i} ssh2")
            for i in range(3)]
    for e in evts:
        client.post(f"/api/alerts/{e['id']}/investigate")

    bad = client.post(f"/api/alerts/{evts[0]['id']}/approve", json={"analyst": "  "})
    assert bad.status_code == 400

    ok = client.post(f"/api/alerts/{evts[0]['id']}/approve", json={"analyst": "Tester", "include_related": True})
    assert ok.status_code == 200
    assert set(ok.json()["resolved_ids"]) == {e["id"] for e in evts}

    alerts = {a["id"]: a for a in client.get("/api/alerts?limit=500").json()["alerts"]}
    for e in evts:
        assert alerts[e["id"]]["status"] == "Resolved"
        assert alerts[e["id"]]["decided_by"] == "Tester"


def test_reject_moves_to_manual_investigation():
    e = _ingest('10.1.1.5 - - [15/Jul/2026:10:00:00 +0000] "GET /a?f=../../etc/passwd HTTP/1.1" 403 10 "-" "curl"')
    client.post(f"/api/alerts/{e['id']}/investigate")
    res = client.post(f"/api/alerts/{e['id']}/reject", json={"analyst": "Tester", "note": "known scanner"})
    assert res.status_code == 200
    alert = next(a for a in client.get("/api/alerts?limit=500").json()["alerts"] if a["id"] == e["id"])
    assert alert["status"] == "Investigating"
    assert alert["analyst_note"] == "known scanner"


def test_status_validation_and_unknown_alert():
    assert client.post("/api/alerts/does-not-exist/approve", json={"analyst": "x"}).status_code == 404
    e = _ingest("Jul 15 14:00:00 srv sshd[1]: Failed password for bob from 192.0.2.4 port 1 ssh2")
    assert client.post(f"/api/alerts/{e['id']}/status", json={"status": "Bogus"}).status_code == 400


def test_geoip_internal_and_invalid():
    assert geoip.lookup("10.0.0.1")["scope"] == "internal"
    assert geoip.lookup("192.168.1.1")["scope"] == "internal"
    assert geoip.lookup("not-an-ip")["scope"] == "unknown"
    ext = geoip.lookup("8.8.8.8")
    assert ext["scope"] == "external"
    if geoip.available:
        assert ext["resolved"] and ext["country_code"] == "US"


def test_analytics_endpoints_shape():
    geo = client.get("/api/analytics/geo").json()
    for key in ("points", "countries", "internal", "unresolved", "top_sources", "geoip_available"):
        assert key in geo
    hm = client.get("/api/analytics/heatmap").json()
    assert len(hm["slots"]) == 96
    assert hm["total"] >= 0
