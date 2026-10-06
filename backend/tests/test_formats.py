"""Every format on the LogVault format list is parsed by a rule-based parser."""
import pytest

from backend.ingest import split_records
from backend.parsers.detector import detector

CASES = [
    # (name, raw line, expected format, expected fields)
    ("syslog RFC 5424", '<34>1 2026-09-24T02:10:00.003Z bastion01 sshd 330 ID47 [origin ip="10.0.0.9"] Failed password for root from 185.220.101.5 port 50211 ssh2',
     "syslog", {"syslog_format": "RFC5424", "host": "bastion01", "user": "root", "source_ip": "185.220.101.5",
                "source_port": 50211, "facility": "auth", "event_type": "AUTHENTICATION_FAILED", "origin.ip": "10.0.0.9"}),
    ("syslog RFC 3164 with PRI", "<38>Sep 24 02:10:00 bastion01 sshd[330]: Invalid user oracle from 203.0.113.8 port 4411",
     "syslog", {"syslog_format": "RFC3164", "user": "oracle", "source_ip": "203.0.113.8", "event_type": "AUTHENTICATION_FAILED"}),
    ("syslog without pid (iptables)", "Sep 24 02:10:00 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.5 DST=10.0.0.4 PROTO=TCP SPT=51544 DPT=22",
     "syslog", {"process": "kernel", "source_ip": "185.220.101.5", "destination_port": 22, "action": "blocked"}),
    ("syslog sudo", "2026-09-24T02:10:00+05:30 app01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow",
     "syslog", {"user": "alice", "command": "/bin/cat /etc/shadow", "event_type": "PROCESS_START"}),
    ("JSON", '{"@timestamp":"2026-09-24T02:10:00Z","level":"error","source":{"ip":"185.220.101.5"},"user":{"name":"admin"},"message":"login failed"}',
     "json", {"source_ip": "185.220.101.5", "user": "admin", "severity": "HIGH", "event_type": "AUTHENTICATION_FAILED"}),
    ("CEF with spaces in values", "CEF:0|Fortinet|FortiGate|7.0|13|Web Attack|8|src=203.0.113.9 dst=10.0.0.12 dpt=443 msg=SQL injection in /login cs1Label=Policy cs1=WAF-Block",
     "cef", {"source_ip": "203.0.113.9", "destination_port": 443, "message": "SQL injection in /login", "policy": "WAF-Block", "severity": "HIGH"}),
    ("CEF behind syslog header", "<134>Sep 24 02:10:00 fw01 CEF:1|Check Point|VPN-1|R81|100|Drop|Very-High|src=198.51.100.7 dst=10.0.0.1",
     "cef", {"vendor": "Check Point", "source_ip": "198.51.100.7", "severity": "CRITICAL"}),
    ("Windows Event XML", '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-08-28T10:31:08Z"/><Computer>DC-PROD-01</Computer></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">192.168.1.45</Data><Data Name="IpPort">51544</Data></EventData></Event>',
     "xml", {"event_id": "4625", "user": "Administrator", "source_ip": "192.168.1.45", "source_port": 51544, "host": "DC-PROD-01",
             "timestamp": "2026-08-28T10:31:08Z", "event_type": "AUTHENTICATION_FAILED"}),
    ("generic XML", '<?xml version="1.0"?><log level="warning"><time>2026-09-24T02:10:00Z</time><source ip="10.0.0.5"/><user>svc_backup</user><message>deleted 400 files</message></log>',
     "xml", {"source_ip": "10.0.0.5", "user": "svc_backup", "severity": "MEDIUM", "xml_root": "log"}),
    ("CSV with header", "timestamp,src_ip,user,action,status\n2026-09-24T02:10:00Z,185.220.101.5,admin,login,failed",
     "csv", {"source_ip": "185.220.101.5", "user": "admin", "csv_mode": "header", "event_type": "AUTHENTICATION_FAILED"}),
    ("CSV without header", "2026-09-24T02:10:00Z,185.220.101.5,10.0.0.4,admin,DENY",
     "csv", {"source_ip": "185.220.101.5", "destination_ip": "10.0.0.4", "csv_mode": "no header"}),
    ("Windows key=value", "EventID=4624 TargetUserName=bob IpAddress=10.0.0.7 Computer=WS01",
     "windows", {"user": "bob", "event_type": "AUTHENTICATION_SUCCESS"}),
    ("custom free text", "ALERT >> suspicious beacon 45.9.20.11 -> 10.0.0.8 every 60s",
     "custom", {"source_ip": "45.9.20.11", "destination_ip": "10.0.0.8", "severity": "CRITICAL"}),
    ("custom with one key=value", "[2026-09-24 02:10:00] AUTH-SVC ERROR login rejected user=carol from 172.16.4.2",
     "generic_kv", {"user": "carol", "source_ip": "172.16.4.2", "event_type": "AUTHENTICATION_FAILED"}),
]


@pytest.mark.parametrize("name,raw,fmt,fields", CASES, ids=[c[0] for c in CASES])
def test_format(name, raw, fmt, fields):
    got_fmt, parsed, _ = detector.detect_and_parse(raw)
    assert got_fmt == fmt
    for key, value in fields.items():
        assert parsed.get(key) == value, (key, parsed.get(key))


def test_xml_external_entities_are_refused():
    raw = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><log>&e;</log>'
    assert detector.parsers["xml"].parse(raw) is None


def test_text_with_nothing_identifiable_goes_to_ai():
    assert detector.detect_and_parse("hello world nothing here")[0] == "unknown"


def test_csv_upload_keeps_header_on_every_record():
    text = "time,src,user\n2026-09-24T02:10:00Z,1.2.3.4,a\n2026-09-24T02:11:00Z,1.2.3.5,b\n"
    records, layout = split_records("events.txt", text)
    assert layout == "csv-with-header" and len(records) == 2
    fmt, parsed, _ = detector.detect_and_parse(records[1])
    assert fmt == "csv" and parsed["source_ip"] == "1.2.3.5"


@pytest.mark.parametrize("raw,rule", [
    ("timestamp,src_ip,user,action,status\n2026-09-24T02:10:00Z,185.220.101.5,admin,login,failed", "Brute Force Authentication"),
    ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><Computer>DC01</Computer></System></Event>',
     "Security Audit Log Cleared"),
    ("EventID=7045 ServiceName=evil Computer=WS01", "New Service Installed"),
])
def test_structured_events_trigger_detection(raw, rule):
    from backend.anomaly_detector import anomaly_detector
    _, parsed, _ = detector.detect_and_parse(raw)
    parsed["raw_log"] = raw
    result = anomaly_detector.detect(parsed)
    assert result["is_anomalous"] and any(f["rule_name"] == rule for f in result["findings"])



def test_json_envelope_is_unwrapped():
    from backend.parsers.detector import detector
    cases = {
        '{"timestamp":"2026-07-15T12:34:56Z","type":"syslog","log":"Jul 15 12:34:56 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"}': ("syslog", "192.168.1.100"),
        '{"timestamp":"2026-07-15T12:42:10Z","log":"203.0.113.1 - - [15/Jul/2026:12:42:10 +0000] \\"GET /../../etc/passwd HTTP/1.1\\" 400 7"}': ("apache", "203.0.113.1"),
        '{"ts":"2026-07-15T12:45:00Z","message":"CEF:0|Palo Alto Networks|PAN-OS|11.0|TRAFFIC|drop|8|src=10.10.10.25 dst=192.168.1.5"}': ("cef", "10.10.10.25"),
    }
    for raw, (fmt, ip) in cases.items():
        got, parsed, _ = detector.detect_and_parse(raw)
        assert (got, parsed.get("source_ip"), parsed.get("envelope")) == (fmt, ip, "json"), raw
    # the wrapper's full ISO time wins over a year-less syslog time
    _, parsed, _ = detector.detect_and_parse(list(cases)[0])
    assert parsed["timestamp"] == "2026-07-15T12:34:56Z"
    # plain JSON events are unchanged
    assert detector.detect_and_parse('{"user":"alice","action":"login","src_ip":"10.0.0.1"}')[0] == "json"
