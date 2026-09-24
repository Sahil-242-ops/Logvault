import json
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.db import DatabaseManager, db

client = TestClient(app)
db.init_db()


@pytest.fixture
def tmp_db(tmp_path):
    """Pruning tests run on a throwaway database, never the real one."""
    d = DatabaseManager(str(tmp_path / "test.db"))
    d.init_db()
    return d


def _add(d, event_id, received_at, anomalous=False, size=100):
    conn = d.get_connection()
    conn.execute(
        "INSERT INTO events (id, received_at, is_anomalous, raw_log, normalized_json) VALUES (?, ?, ?, ?, ?)",
        (event_id, received_at, 1 if anomalous else 0, "x" * size, json.dumps({"id": event_id})),
    )
    conn.commit()
    conn.close()


def _ids(d):
    conn = d.get_connection()
    ids = {r[0] for r in conn.execute("SELECT id FROM events")}
    conn.close()
    return ids


def test_unlimited_policy_deletes_nothing(tmp_db):
    _add(tmp_db, "old", "2000-01-01T00:00:00Z")
    assert tmp_db.prune(0, 0) == (0, 0)
    assert _ids(tmp_db) == {"old"}


def test_retention_keeps_unresolved_alerts(tmp_db):
    _add(tmp_db, "old-normal", "2000-01-01T00:00:00Z")
    _add(tmp_db, "old-open-alert", "2000-01-01T00:00:00Z", anomalous=True)
    _add(tmp_db, "old-resolved-alert", "2000-01-01T00:00:00Z", anomalous=True)
    _add(tmp_db, "new-normal", "2999-01-01T00:00:00Z")
    tmp_db.set_alert_status("old-resolved-alert", "Resolved", decided_by="t")

    by_age, _ = tmp_db.prune(retention_days=30)
    assert by_age == 2
    assert _ids(tmp_db) == {"old-open-alert", "new-normal"}


def test_size_limit_prunes_oldest_first(tmp_db):
    for i in range(10):
        _add(tmp_db, f"e{i}", f"2026-01-{i + 1:02d}T00:00:00Z", size=1000)
    per_event = 1000 + len(json.dumps({"id": "e0"}))
    _, by_size = tmp_db.prune(max_data_bytes=per_event * 5)
    remaining = _ids(tmp_db)
    assert by_size >= 5
    assert "e9" in remaining and "e0" not in remaining  # newest kept, oldest removed


def test_storage_endpoint_and_policy_validation():
    st = client.get("/api/storage").json()
    for key in ("total_bytes", "events", "disk_free_bytes", "policy"):
        assert key in st
    assert client.put("/api/storage/policy", json={"storage_limit_gb": 0.01, "retention_days": 0}).status_code == 400
    assert client.put("/api/storage/policy", json={"storage_limit_gb": 0, "retention_days": 99999}).status_code == 400

    original = st["policy"]
    try:
        res = client.put("/api/storage/policy", json={"storage_limit_gb": 0, "retention_days": 0})
        assert res.status_code == 200
        assert res.json()["policy"] == {"storage_limit_gb": 0.0, "retention_days": 0}
    finally:
        client.put("/api/storage/policy", json=original)
