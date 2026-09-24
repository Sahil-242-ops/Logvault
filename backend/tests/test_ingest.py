import json
from backend.ingest import split_records
from backend.parsers.json_parser import JSONParser
from backend.ai.local_ai import validate_ai_output, looks_like_log


def test_pretty_printed_json_array_is_split_into_records():
    text = json.dumps([{"user": "a", "src_ip": "1.2.3.4"}, {"user": "b"}], indent=2)
    records, layout = split_records("x.json", text)
    assert layout == "json-document"
    assert len(records) == 2
    assert json.loads(records[0]) == {"user": "a", "src_ip": "1.2.3.4"}


def test_cloudtrail_wrapper_and_bom():
    text = "﻿" + json.dumps({"Records": [{"eventName": "ConsoleLogin"}, {"eventName": "GetObject"}]})
    records, layout = split_records("trail.json", text.lstrip("﻿"))
    assert layout == "json-document" and len(records) == 2


def test_json_lines_and_structural_lines_skipped():
    text = '{"a":1}\n\n{"a":2}\n'
    records, layout = split_records("x.jsonl", text)
    assert records == ['{"a":1}', '{"a":2}'] and layout == "json-lines"
    records, _ = split_records("x.log", "[\nreal log line here\n],\n}")
    assert records == ["real log line here"]


def test_csv_with_header_becomes_json_rows():
    records, layout = split_records("u.csv", "user,src_ip,status\ncarol,10.0.0.1,failed\n")
    assert layout == "csv-with-header"
    assert json.loads(records[0]) == {"user": "carol", "src_ip": "10.0.0.1", "status": "failed"}


def test_csv_without_header_falls_back_to_lines():
    records, layout = split_records("x.csv", "10.0.0.1,GET,/index\n10.0.0.2,GET,/a\n")
    assert layout == "line-per-record" and len(records) == 2


def test_json_parser_field_aliases_and_event_type():
    res = JSONParser().parse('{"src_ip":"185.220.101.1","username":"alice","action":"login","status":"failed","level":"warning"}')
    assert res["source_ip"] == "185.220.101.1"
    assert res["user"] == "alice"
    assert res["event_type"] == "AUTHENTICATION_FAILED"
    assert res["severity"] == "MEDIUM"
    res = JSONParser().parse('{"method":"GET","url":"/admin","client_ip":"10.1.1.1"}')
    assert res["event_type"] == "HTTP_REQUEST" and res["source_ip"] == "10.1.1.1"


def test_ai_output_validation_drops_placeholders():
    out = validate_ai_output({"event_type": "event type", "severity": "LOW|MEDIUM", "threat_score": "abc",
                              "reasoning": "brief summary", "mitre_techniques": "not a technique"})
    assert "semantic_classification" not in out
    assert "severity" not in out
    assert out["threat_score"] == 0 and out["reasoning"] == "" and out["mitre_techniques"] == []
    good = validate_ai_output({"event_type": "authentication failed", "severity": "high", "threat_score": 140,
                               "is_suspicious": "true", "mitre_techniques": ["T1110 - Brute Force"],
                               "reasoning": "Repeated failed logins from one IP."})
    assert good["semantic_classification"] == "AUTHENTICATION_FAILED"
    assert good["severity"] == "HIGH" and good["threat_score"] == 100 and good["is_suspicious"] is True


def test_junk_records_are_not_sent_to_ai():
    assert not looks_like_log("[")
    assert not looks_like_log('"a": 1,')
    assert looks_like_log("Failed password for root from 1.2.3.4")
