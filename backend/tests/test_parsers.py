import pytest
from backend.parsers.detector import detector
from backend.parsers.syslog import SyslogParser
from backend.parsers.cef import CEFParser
from backend.parsers.apache import ApacheParser
from backend.parsers.json_parser import JSONParser
from backend.parsers.windows import WindowsParser
from backend.parsers.generic_kv import GenericKVParser

def test_syslog_parser():
    parser = SyslogParser()
    log = "Jul 15 12:34:56 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    res = parser.parse(log)
    assert res is not None
    assert res["user"] == "admin"
    assert res["source_ip"] == "192.168.1.100"
    assert res["source_port"] == 54321
    assert res["action"] == "Failed"
    assert res["event_type"] == "AUTHENTICATION_FAILED"

def test_cef_parser():
    parser = CEFParser()
    log = "CEF:0|Vendor|Product|Version|101|Port Scan|High|src=10.0.0.1 dst=192.168.1.5 spt=5555 dpt=80"
    res = parser.parse(log)
    assert res is not None
    assert res["vendor"] == "Vendor"
    assert res["name"] == "Port Scan"
    assert res["source_ip"] == "10.0.0.1"

def test_apache_parser():
    parser = ApacheParser()
    log = '192.168.1.50 - user1 [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326'
    res = parser.parse(log)
    assert res is not None
    assert res["source_ip"] == "192.168.1.50"
    assert res["action"] == "GET"
    assert res["status"] == 200

def test_json_parser():
    parser = JSONParser()
    log = '{"eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.1", "userIdentity": {"userName": "alice"}}'
    res = parser.parse(log)
    assert res is not None
    assert res["action"] == "ConsoleLogin"
    assert res["source_ip"] == "203.0.113.1"
    assert res["user"] == "alice"

def test_windows_parser():
    parser = WindowsParser()
    log = "EventID=4625 AccountName=bob Workstation=WIN-PC01 SourceIP=10.10.10.1 Status=0xC000006D"
    res = parser.parse(log)
    assert res is not None
    assert res["event_id"] == "4625"
    assert res["user"] == "bob"

def test_kv_parser():
    parser = GenericKVParser()
    log = 'time="2026-09-14" user=charlie src_ip=192.168.1.2 action="login"'
    res = parser.parse(log)
    assert res is not None
    assert res["user"] == "charlie"
    assert res["source_ip"] == "192.168.1.2"

def test_detector_unknown():
    log = "This is a completely random log string with no known format."
    fmt, parsed, conf = detector.detect_and_parse(log)
    assert fmt == "unknown"
    assert parsed is None
