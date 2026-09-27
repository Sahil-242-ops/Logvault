"""
Windows Security events exported as text: EventID=4625 TargetUserName=... IpAddress=...
(The XML form, <Event xmlns=...>, is handled by xml_parser.py with the same field names.)
"""
import re
from typing import Any, Dict, Optional

# Security event IDs -> (event_type, action, severity)
EVENT_IDS = {
    "4624": ("AUTHENTICATION_SUCCESS", "logon", "INFO"),
    "4625": ("AUTHENTICATION_FAILED", "logon failed", "HIGH"),
    "4634": ("AUTHENTICATION_LOGOFF", "logoff", "INFO"),
    "4648": ("AUTHENTICATION_SUCCESS", "logon with explicit credentials", "MEDIUM"),
    "4672": ("PRIVILEGE_ASSIGNED", "special privileges assigned", "MEDIUM"),
    "4688": ("PROCESS_START", "process created", "INFO"),
    "4720": ("ACCOUNT_CREATED", "user account created", "MEDIUM"),
    "4722": ("ACCOUNT_ENABLED", "user account enabled", "LOW"),
    "4724": ("ACCOUNT_PASSWORD_RESET", "password reset", "MEDIUM"),
    "4728": ("ACCOUNT_GROUP_ADD", "member added to security group", "HIGH"),
    "4732": ("ACCOUNT_GROUP_ADD", "member added to local group", "HIGH"),
    "4740": ("ACCOUNT_LOCKED", "account locked out", "HIGH"),
    "4768": ("AUTHENTICATION_KERBEROS", "Kerberos TGT requested", "INFO"),
    "4771": ("AUTHENTICATION_FAILED", "Kerberos pre-auth failed", "HIGH"),
    "4776": ("AUTHENTICATION_NTLM", "NTLM credential validation", "INFO"),
    "1102": ("LOG_CLEARED", "audit log cleared", "CRITICAL"),
    "7045": ("SERVICE_INSTALLED", "service installed", "HIGH"),
}

# Windows field name -> LogVault field
FIELD_MAP = {
    "TargetUserName": "user", "SubjectUserName": "subject_user", "AccountName": "user",
    "IpAddress": "source_ip", "SourceIP": "source_ip", "SourceAddress": "source_ip",
    "IpPort": "source_port", "SourcePort": "source_port",
    "DestAddress": "destination_ip", "DestPort": "destination_port",
    "Computer": "host", "Workstation": "host", "WorkstationName": "workstation",
    "NewProcessName": "process", "ProcessName": "process", "Application": "process",
    "Status": "status", "FailureReason": "status", "LogonType": "logon_type",
    "TimeCreated": "timestamp", "SystemTime": "timestamp",
}


def apply_windows(data: Dict[str, Any], event_id: Optional[str]) -> Dict[str, Any]:
    """Map Windows field names and classify by event ID. Shared with the XML parser."""
    for win, ours in FIELD_MAP.items():
        value = data.get(win)
        if value not in (None, "", "-") and data.get(ours) in (None, ""):
            data[ours] = int(value) if ours.endswith("_port") and str(value).isdigit() else value
    if data.get("source_ip") in ("-", "::1", "127.0.0.1"):
        data["source_ip"] = data["source_ip"] if data["source_ip"] != "-" else None
    data["event_id"] = event_id
    et, action, sev = EVENT_IDS.get(str(event_id), ("WINDOWS_EVENT", None, None))
    data["event_type"] = et
    if action:
        data.setdefault("action", action)
    if sev:
        data["severity"] = sev
    data["category"] = "identity_access" if et.startswith(("AUTH", "ACCOUNT", "PRIVILEGE")) else "system"
    return data


class WindowsParser:
    def __init__(self):
        self.pattern = re.compile(r'EventID=(?P<event_id>\d+)')
        self.kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=("[^"]*"|[^\s;]+)')

    def parse(self, raw_log: str) -> Dict[str, Any]:
        m = self.pattern.search(raw_log)
        if not m:
            return None
        data = {k: v.strip('"') for k, v in self.kv_pattern.findall(raw_log) if k != "EventID"}
        return apply_windows(data, m.group("event_id"))
