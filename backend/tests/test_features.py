"""Sign-in, dashboard/sources/parser stats, schema-mapper rules, containment and exports."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend import audit, auth, containment, mapper
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
    audit.init_tables()
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
    # Before a rule exists only the generic custom-text reader (or nothing) recognises it
    assert inferred["current_parser"]["format"] in ("unknown", "custom")

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


def test_audit_log_records_actions_and_detects_tampering(monkeypatch):
    monkeypatch.setattr(config, "AUTH_REQUIRED", True)
    client.post("/api/auth/login", json={"email": "sahil.soc@logvault.sih", "password": "wrong-pass"})
    t = client.post("/api/auth/login", json={"email": "sahil.soc@logvault.sih", "password": "CyberSecurity2026!"}).json()["token"]
    h = {"Authorization": f"Bearer {t}"}
    client.post("/api/containment", json={"kind": "ip", "value": "203.0.113.9", "reason": "test"}, headers=h)
    tier1 = client.post("/api/auth/login", json={"email": "sneha.triage@logvault.sih", "password": "TriageAnalyst2026!"}).json()["token"]
    client.delete("/api/events?confirm=true", headers={"Authorization": f"Bearer {tier1}"})

    log = client.get("/api/audit", headers=h).json()["entries"]
    seen = [(e["action"], e["actor"], e["outcome"]) for e in reversed(log)]
    assert ("sign_in", "sahil.soc@logvault.sih", "failed") in seen
    assert ("sign_in", "sahil.soc@logvault.sih", "success") in seen
    assert ("contain_asset", "sahil.soc@logvault.sih", "success") in seen
    assert ("delete_all_events", "sneha.triage@logvault.sih", "denied") in seen
    assert client.get("/api/audit", headers={"Authorization": f"Bearer {tier1}"}).status_code == 403
    assert client.get("/api/audit/verify", headers=h).json()["ok"] is True

    conn = db.get_connection()
    conn.execute("UPDATE audit_log SET actor = 'someone-else' WHERE action = 'contain_asset'")
    conn.commit()
    conn.close()
    result = client.get("/api/audit/verify", headers=h).json()
    assert result["ok"] is False and result["broken_at_seq"]



def test_siem_exports_every_format():
    import csv as _csv
    import gzip
    _ingest(SSH_FAIL)
    _ingest('192.168.1.45 - bob [28/Aug/2026:10:31:05 +0000] "POST /login HTTP/1.1" 401 532')

    lines = client.get("/api/export/siem?format=ocsf-jsonl").text.strip().splitlines()
    ocsf = [json.loads(l) for l in lines]
    assert len(ocsf) == 2 and {o["class_uid"] for o in ocsf} == {3002, 4002}
    assert all(o["type_uid"] == o["class_uid"] * 100 + o["activity_id"] for o in ocsf)
    assert all(o["metadata"]["version"] == "1.1.0" and len(o["unmapped"]["raw_sha256"]) == 64 for o in ocsf)

    gz = client.get("/api/export/siem?format=ocsf-jsonl-gz").content
    assert len(gzip.decompress(gz).decode().strip().splitlines()) == 2

    rows = list(_csv.DictReader(io.StringIO(client.get("/api/export/siem?format=csv").text)))
    assert len(rows) == 2 and rows[0]["source_ip"] == "185.220.101.5"

    cef = client.get("/api/export/siem?format=cef").text.strip().splitlines()
    assert all(l.startswith("CEF:0|BetterCallCode|LOGVAULT|1.0|") for l in cef) and "src=185.220.101.5" in cef[0]

    hec = json.loads(client.get("/api/export/siem?format=splunk-hec").text)
    assert len(hec) == 2 and hec[0]["sourcetype"] == "ocsf:json" and hec[0]["event"]["class_uid"] == 3002

    bulk = client.get("/api/export/siem?format=elastic-bulk").text.strip().splitlines()
    assert len(bulk) == 4 and json.loads(bulk[0])["index"]["_index"] == "logvault-ocsf"

    only = client.get("/api/export/siem?format=ocsf-jsonl&only_anomalies=true").text.strip().splitlines()
    assert len(only) == 1
    assert client.get("/api/export/siem?format=nope").status_code == 400


def test_every_event_carries_ocsf_validation():
    evt = _ingest(SSH_FAIL)
    assert evt["ocsf_validation"]["valid"] is True and evt["ocsf_validation"]["errors"] == []
    evt = _ingest("just some words here")
    assert evt["ocsf_validation"]["valid"] is True
    assert any("ingestion time" in w for w in evt["ocsf_validation"]["warnings"])



def test_encrypted_bundle_round_trip():
    from backend.crypto_box import decrypt
    from cryptography.exceptions import InvalidTag
    _ingest(SSH_FAIL)
    assert client.post("/api/export/bundle", json={"passphrase": "short"}).status_code == 400
    r = client.post("/api/export/bundle", json={"scope": "session", "passphrase": "correct horse battery"})
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('.lvault"')
    assert r.content.startswith(b"LVAULT1\n") and b"events.jsonl" not in r.content  # nothing readable
    z = zipfile.ZipFile(io.BytesIO(decrypt(r.content, "correct horse battery")))
    assert json.loads(z.read("manifest.json"))["event_count"] == 1
    with pytest.raises(InvalidTag):
        decrypt(r.content, "wrong passphrase!!")
    plain = client.post("/api/export/bundle", json={"scope": "session"})
    assert plain.headers["content-disposition"].endswith('.zip"')


def test_self_signed_certificate(tmp_path, monkeypatch):
    from backend import serve
    from cryptography import x509
    monkeypatch.setattr(serve, "CERT", str(tmp_path / "cert.pem"))
    monkeypatch.setattr(serve, "KEY", str(tmp_path / "key.pem"))
    monkeypatch.setattr(serve, "TLS_DIR", str(tmp_path))
    serve.ensure_self_signed()
    cert = x509.load_pem_x509_certificate(open(tmp_path / "cert.pem", "rb").read())
    assert "LOGVAULT" in cert.subject.rfc4514_string()



def test_opensearch_index_and_search_with_fallback(monkeypatch):
    import asyncio
    import httpx
    from backend import search_index
    docs = {}

    def fake_opensearch(request: httpx.Request):
        if request.url.path == "/_bulk":
            lines = request.content.decode().strip().splitlines()
            for action, doc in zip(lines[::2], lines[1::2]):
                docs[json.loads(action)["index"]["_id"]] = json.loads(doc)
            return httpx.Response(200, json={"errors": False, "items": [{"index": {"status": 201}}] * (len(lines) // 2)})
        if request.url.path.endswith("/_search"):
            q = json.loads(request.content)["query"]["bool"]["must"][0]["simple_query_string"]["query"].lower()
            hits = [{"_id": i} for i, d in docs.items() if q in json.dumps(d).lower()]
            return httpx.Response(200, json={"hits": {"total": {"value": len(hits)}, "hits": hits}})
        if request.method in ("HEAD", "PUT"):
            return httpx.Response(200, json={"acknowledged": True})
        return httpx.Response(404)

    monkeypatch.setattr(config, "OPENSEARCH_URL", "http://opensearch:9200")
    monkeypatch.setitem(search_index._state, "index_ready", False)
    monkeypatch.setattr(search_index, "transport", httpx.MockTransport(fake_opensearch))
    evts = [_ingest(SSH_FAIL), _ingest('192.168.1.45 - bob [28/Aug/2026:10:31:05 +0000] "POST /login HTTP/1.1" 401 532')]
    asyncio.run(search_index.index_now(evts))
    assert len(docs) == 2 and docs[evts[0]["id"]]["class_uid"] == 3002

    r = client.get("/api/events?search=bastion01").json()
    assert r["search_engine"] == "opensearch" and [e["id"] for e in r["events"]] == [evts[0]["id"]]

    # OpenSearch down -> the same search is answered by SQLite
    monkeypatch.setattr(search_index, "transport", httpx.MockTransport(lambda req: httpx.Response(503)))
    r = client.get("/api/events?search=bastion01").json()
    assert r["search_engine"] == "sqlite" and r["total"] == 1
    assert search_index.status()["reachable"] is False
