"""Sign-in, dashboard/sources/parser stats, schema-mapper rules, containment and exports."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend import auth, containment, mapper
from backend.app import app
from backend.config import config
from backend.db import db

client = TestClient(app)

SSH_FAIL = "Sep 24 02:10:00 bastion01 sshd[330]: Failed password for admin from 185.220.101.5 port 50211 ssh2"
ASA = "%ASA-4-106023: Deny tcp src outside:192.168.1.45/54210 dst inside:10.0.4.92/22 by access-group OUTSIDE_IN"


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Every test here runs on a throwaway database, never the real one."""
    monkeypatch.setattr(db, "db_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(db, "current_session_id", "test-session")
    db.init_db()
    auth.init_auth_tables()
    containment.init_tables()
    mapper.init_tables()
    yield
    monkeypatch.setattr(config, "AUTH_REQUIRED", False)
    containment.reload()
    mapper.reload_rules()


def _ingest(raw):
    r = client.post("/api/normalize", json={"raw": raw})
    assert r.status_code == 200
    return r.json()


def test_sign_in_is_enforced(monkeypatch):
    monkeypatch.setattr(config, "AUTH_REQUIRED", True)
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/auth/login", json={"email": "sahil.soc@logvault.sih", "password": "wrong-pass"}).status_code == 401

    r = client.post("/api/auth/login", json={"email": "SAHIL.soc@logvault.sih", "password": "CyberSecurity2026!"})
    assert r.status_code == 200
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/events", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).json()["role"] == "Tier-3 SOC Lead"

    client.post("/api/auth/logout", headers=h)
    assert client.get("/api/events", headers=h).status_code == 401


def test_roles_limit_actions(monkeypatch):
    monkeypatch.setattr(config, "AUTH_REQUIRED", True)
    tier1 = client.post("/api/auth/login", json={"email": "sneha.triage@logvault.sih", "password": "TriageAnalyst2026!"}).json()
    h = {"Authorization": f"Bearer {tier1['token']}"}
    assert client.post("/api/containment", json={"kind": "ip", "value": "1.2.3.4"}, headers=h).status_code == 403
    assert client.delete("/api/events?confirm=true", headers=h).status_code == 403


def test_passwords_are_hashed():
    conn = db.get_connection()
    stored = conn.execute("SELECT password_hash FROM operator_accounts").fetchall()
    conn.close()
    assert stored and all(s[0].startswith("pbkdf2_sha256$") and "2026" not in s[0] for s in stored)


def test_dashboard_reflects_stored_events():
    _ingest(SSH_FAIL)
    _ingest("this line matches no parser at all")
    d = client.get("/api/dashboard").json()
    assert d["total_events"] == 2
    assert d["parsed_events"] == 1 and d["parsed_rate"] == 50.0
    assert {f["format"] for f in d["formats"]} == {"syslog", "unknown"}
    assert sum(b["events"] for b in d["timeline"]["buckets"]) == 2
    assert d["recent_threats"] and d["recent_threats"][0]["source_ip"] == "185.220.101.5"


def test_collectors_group_by_origin_and_format():
    _ingest(SSH_FAIL)
    _ingest(SSH_FAIL.replace("50211", "50212"))
    c = client.get("/api/collectors").json()
    assert c["total_collectors"] == 1
    row = c["collectors"][0]
    assert (row["origin"], row["format"], row["events"], row["status"]) == ("bastion01", "syslog", 2, "ACTIVE")


def test_parser_benchmark_runs_real_parser():
    r = client.post("/api/parsers/benchmark", json={"raw": SSH_FAIL, "parser": "syslog"}).json()
    assert r["matched"] and r["fields"]["source_ip"] == "185.220.101.5"
    assert r["runs"] >= 50 and r["median_us"] > 0
    assert client.post("/api/parsers/benchmark", json={"raw": "x", "parser": "nope"}).status_code == 400


def test_mapper_rule_is_used_for_new_events():
    inferred = client.post("/api/mapper/infer", json={"raw": ASA}).json()
    assert inferred["kind"] == "pattern"
    targets = {m["targetField"]: m["value"] for m in inferred["mappings"]}
    assert targets["source_ip"] == "192.168.1.45" and targets["destination_port"] == "22"
    assert inferred["current_parser"]["format"] == "unknown"

    r = client.post("/api/mapper/rules", json={
        "name": "Cisco ASA", "kind": "pattern", "anchor": inferred["anchor"],
        "mappings": inferred["mappings"], "event_type": "FIREWALL_BLOCKED", "sample": ASA})
    assert r.status_code == 200

    evt = _ingest(ASA.replace("192.168.1.45", "10.9.9.9"))
    assert evt["detected_format"] == "custom:Cisco ASA"
    assert evt["source_ip"] == "10.9.9.9" and evt["event_type"] == "FIREWALL_BLOCKED"
    assert any(p["id"] == "custom:Cisco ASA" and p["events"] == 1 for p in client.get("/api/parsers").json()["parsers"])


def test_kv_mapping_uses_key_names():
    inferred = client.post("/api/mapper/infer", json={"raw": "USR=john ACT=LOGIN RES=FAIL SRC=10.2.4.5 DEV=web01"}).json()
    assert inferred["kind"] == "kv"
    assert {m["rawField"]: m["targetField"] for m in inferred["mappings"]} == {
        "USR": "user", "ACT": "action", "RES": "status", "SRC": "source_ip", "DEV": "host"}


def test_contained_ip_raises_critical_alert_and_exports():
    r = client.post("/api/containment", json={"kind": "ip", "value": "185.220.101.5", "reason": "brute force"})
    assert r.status_code == 200
    assert client.post("/api/containment", json={"kind": "ip", "value": "not-an-ip"}).status_code == 400

    evt = _ingest(SSH_FAIL)
    assert evt["anomaly"]["threat_score"] == 100
    assert evt["anomaly"]["findings"][0]["rule_id"] == "CONTAIN-001"

    rules = client.get("/api/containment/export?format=iptables").text
    assert "iptables -I INPUT -s 185.220.101.5 -j DROP" in rules
    assert "deny ip host 185.220.101.5 any" in client.get("/api/containment/export?format=cisco").text

    client.delete(f"/api/containment/{r.json()['id']}")
    assert _ingest(SSH_FAIL)["anomaly"]["threat_score"] < 100


def test_forensic_bundle_manifest_hashes_match():
    evt = _ingest(SSH_FAIL)
    r = client.get("/api/export/bundle")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["event_count"] == 1
    import hashlib
    for name, meta in manifest["files"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == meta["sha256"]

    dossier = client.get(f"/api/alerts/{evt['id']}/dossier").json()
    assert dossier["alert"]["id"] == evt["id"] and "related_events" in dossier
    assert client.get("/api/export/ocsf").json()["ocsf_version"] == "1.1.0"


def test_preview_normalize_does_not_store():
    client.post("/api/normalize?store=false", json={"raw": SSH_FAIL})
    assert client.get("/api/events").json()["total"] == 0
