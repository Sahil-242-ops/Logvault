"""
ArcSight Common Event Format (CEF:0 and CEF:1), optionally behind a syslog header:

  [<134>Sep 24 02:10:00 fw01 ]CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key2=value with spaces

Extension values may contain spaces and escaped characters (\\= \\| \\\\ \\n); a new key
starts only at " key=". Severity 0-10 (or Low/Medium/High/Very-High) sets the level.
"""
import re
from typing import Any, Dict

# CEF extension key -> LogVault field
KEY_MAP = {
    "src": "source_ip", "c6a2": "source_ip", "dst": "destination_ip", "c6a3": "destination_ip",
    "spt": "source_port", "dpt": "destination_port", "suser": "user", "duser": "target_user",
    "shost": "source_host", "dhost": "host", "dvchost": "device_host", "act": "action", "outcome": "status",
    "proto": "protocol", "app": "application", "msg": "message", "request": "url", "requestMethod": "http_method",
    "rt": "timestamp", "start": "timestamp", "sproc": "process", "dproc": "process", "fname": "file_name",
    "filePath": "file_path", "cat": "cef_category",
}
SEVERITY_WORDS = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "very-high": "CRITICAL", "unknown": None}


def _unescape(value: str) -> str:
    return (value.replace("\\=", "=").replace("\\|", "|").replace("\\n", "\n")
            .replace("\\r", "\r").replace("\\\\", "\\")).strip()


def cef_severity(value: str):
    v = (value or "").strip().lower()
    if v.isdigit():
        n = int(v)
        return "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW"
    return SEVERITY_WORDS.get(v)


class CEFParser:
    def __init__(self):
        self.header_pattern = re.compile(
            r'CEF:(?P<cef_version>[01])\|(?P<vendor>(?:[^|\\]|\\.)*)\|(?P<product>(?:[^|\\]|\\.)*)\|'
            r'(?P<version>(?:[^|\\]|\\.)*)\|(?P<signature_id>(?:[^|\\]|\\.)*)\|(?P<name>(?:[^|\\]|\\.)*)\|'
            r'(?P<cef_severity>(?:[^|\\]|\\.)*)\|(?P<extension>.*)$', re.S)
        # A key starts at the beginning or after a space; its value runs until the next " key="
        self.kv_pattern = re.compile(r'(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]+)=(.*?)(?=\s+[A-Za-z0-9_.\[\]-]+=|$)', re.S)

    def parse(self, raw_log: str) -> Dict[str, Any]:
        match = self.header_pattern.search(raw_log)
        if not match:
            return None
        data = {k: _unescape(v) for k, v in match.groupdict().items() if k != "extension"}
        prefix = raw_log[:match.start()].strip()
        if prefix:
            if prefix[0] in '{["' or (prefix[0] == "<" and not re.match(r"<\d{1,3}>", prefix)):
                return None  # "CEF:" inside JSON / XML text, not a CEF record
            data["syslog_header"] = prefix

        extension = match.group("extension") or ""
        labels = {}
        for key, value in self.kv_pattern.findall(extension):
            value = _unescape(value)
            if re.fullmatch(r"c[sn]\d+Label", key):
                labels[key[:-5]] = value
                continue
            field = KEY_MAP.get(key, key)
            if field.endswith("_port") and value.isdigit():
                value = int(value)
            if field == "timestamp" and "timestamp" in data:
                continue  # rt wins over start
            data[field] = value
        for key, label in labels.items():  # cs1=... with cs1Label=Rule -> rule=...
            if key in data:
                data[re.sub(r"\W+", "_", label).strip("_").lower() or key] = data.pop(key)

        sev = cef_severity(data.get("cef_severity"))
        if sev:
            data["severity"] = sev
        data["event_type"] = "SECURITY_FINDING"
        data["category"] = "findings"
        return data
