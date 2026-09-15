import pytest
from backend.normalizer import normalizer
from backend.pii_masker import PIIMasker

@pytest.mark.asyncio
async def test_normalizer_ssh():
    log = "Jul 15 12:34:56 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    res = await normalizer.normalize(log)
    
    assert res["detected_format"] == "syslog"
    assert res["event_type"] == "AUTHENTICATION_FAILED"
    assert res["user"] == "admin"
    assert res["source_ip"] == "192.168.1.100"
    assert res["source_port"] == 54321
    assert res["host"] == "server01"
    assert res["process"] == "sshd"
    assert res["protocol"] == "ssh2"
    
    # Anomaly
    assert res["anomaly"]["is_anomalous"] is True
    assert res["anomaly"]["threat_score"] == 80
    assert any(f["mitre_technique"] == "T1110 - Brute Force" for f in res["anomaly"]["findings"])

@pytest.mark.asyncio
async def test_normalizer_xss():
    log = '10.0.0.5 - - [14/Sep/2026] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1234'
    res = await normalizer.normalize(log)
    assert res["detected_format"] == "apache"
    assert res["anomaly"]["is_anomalous"] is True
    assert any("T1189" in f["mitre_technique"] for f in res["anomaly"]["findings"])

def test_pii_masker():
    masker = PIIMasker()
    res, detected = masker.mask_string("Contact me at admin@example.com")
    assert res == "Contact me at [EMAIL_REDACTED]"
    assert "EMAIL" in detected
    
    # Check dict masking doesn't mask source_ip
    data = {"source_ip": "1.2.3.4", "message": "Email admin@example.com"}
    masked, det = masker.mask_dict(data)
    assert masked["source_ip"] == "1.2.3.4"
    assert masked["message"] == "Email [EMAIL_REDACTED]"
