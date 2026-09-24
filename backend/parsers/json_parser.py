import json
import re
from typing import Dict, Any, Optional

# Common field-name variants across JSON log sources (app logs, CloudTrail, ECS,
# firewall exports). The first alias present wins; original keys are kept.
FIELD_ALIASES = {
    "source_ip": ("source_ip", "src_ip", "srcip", "src", "sourceIPAddress", "client_ip", "clientIP",
                  "remote_addr", "remote_ip", "ip", "ip_address", "src_addr", "source.ip", "client.ip"),
    "destination_ip": ("destination_ip", "dst_ip", "dest_ip", "dstip", "dst", "server_ip", "dest_addr",
                       "destination.ip", "server.ip"),
    "source_port": ("source_port", "src_port", "sport", "srcport", "source.port"),
    "destination_port": ("destination_port", "dst_port", "dest_port", "dport", "dstport", "destination.port"),
    "user": ("user", "username", "user_name", "userName", "account", "principal", "user.name",
             "userIdentity.userName", "userIdentity.arn"),
    "host": ("host", "hostname", "host_name", "computer", "device", "host.name", "observer.hostname"),
    "process": ("process", "process_name", "proc", "program", "app", "application", "service", "process.name"),
    "message": ("message", "msg", "log", "description", "event_description"),
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "eventTime", "datetime", "date"),
    "action": ("action", "eventName", "event", "activity", "operation", "event.action"),
    "status": ("status", "outcome", "result", "event.outcome", "errorCode"),
    "protocol": ("protocol", "proto", "network.protocol"),
}

SEVERITY_WORDS = {
    "CRITICAL": ("critical", "crit", "fatal", "emerg", "emergency", "alert"),
    "HIGH": ("error", "err", "high"),
    "MEDIUM": ("warn", "warning", "medium"),
    "LOW": ("notice", "low"),
    "INFO": ("info", "informational", "debug", "trace"),
}


def _lookup(data: Dict[str, Any], path: str):
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if not isinstance(cur, (dict, list)) else None


def _severity(data: Dict[str, Any]) -> Optional[str]:
    raw = next((data.get(k) for k in ("severity", "level", "log_level", "loglevel", "priority") if data.get(k)), None)
    if raw is None:
        return None
    word = str(raw).strip().lower()
    for sev, words in SEVERITY_WORDS.items():
        if word in words:
            return sev
    return str(raw).upper() if str(raw).upper() in SEVERITY_WORDS else None


def _event_type(data: Dict[str, Any]) -> str:
    text = " ".join(str(data.get(k) or "") for k in ("action", "status", "message", "event_type", "type")).lower()
    failed = re.search(r"fail|denied|invalid|reject|unauthori[sz]ed|error|bad password", text)
    if re.search(r"log ?[io]n|sign ?in|auth|password|consolelogin", text):
        return "AUTHENTICATION_FAILED" if failed else "AUTHENTICATION_SUCCESS"
    if data.get("method") or data.get("url") or data.get("uri") or data.get("request") or re.search(r"\bhttp", text):
        return "HTTP_REQUEST"
    if data.get("path") or data.get("file") or re.search(r"\bfile[_ ]?(read|write|open|delete|access)|\b(read|write|delete)_?file", text):
        return "FILE_ACCESS"
    if data.get("command") or data.get("cmd") or re.search(r"\b(exec|execve|process_start|spawn|command)\b", text):
        return "PROCESS_START"
    if (data.get("destination_ip") or data.get("destination_port")) and re.search(r"connect|allow|deny|drop|block|accept", text):
        return "NETWORK_CONNECTION"
    return "JSON_EVENT"


class JSONParser:
    def parse(self, raw_log: str) -> Dict[str, Any]:
        try:
            data = json.loads(raw_log)
            if isinstance(data, dict):
                for field, aliases in FIELD_ALIASES.items():
                    if data.get(field) not in (None, "") and not isinstance(data.get(field), (dict, list)):
                        continue
                    value = next((v for v in (_lookup(data, a) for a in aliases) if v not in (None, "")), None)
                    if value is not None:
                        data[field] = value

                sev = _severity(data)
                if sev:
                    data["severity"] = sev
                data["event_type"] = _event_type(data)
                return data
            return None
        except json.JSONDecodeError:
            return None
