"""
Field extraction for lines no specific parser recognises (the "Custom / Unknown" format).

It pulls out what can be identified reliably by shape: IP addresses (IPv4 and IPv6),
ports, timestamps, account names, HTTP requests and severity words. Syslog, CSV and
XML parsers reuse extract() to enrich free-text messages.
"""
import ipaddress
import re
from typing import Any, Dict, List, Optional

IPV4 = r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
IPV6 = r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])"
IP_RE = re.compile(f"{IPV4}|{IPV6}")
IP_PORT_RE = re.compile(rf"({IPV4})[:/](\d{{1,5}})\b")
PORT_RE = re.compile(r"\b(?:port|dport|dpt|spt|sport)[\s=:]+(\d{1,5})\b", re.I)
TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
    r"|\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?"
)
USER_RES = [
    re.compile(r"\b(?:user|username|usr|uid|account)[\s=:]+[\"']?([\w.@\\$-]{1,64})", re.I),
    # "login" is also a verb ("LOGIN FAIL"), so it only names a user as login=... / login: ...
    re.compile(r"\blogin\s*[=:]\s*[\"']?([\w.@\\$-]{1,64})", re.I),
    re.compile(r"\bfor (?:invalid user |illegal user )?([\w.@\\$-]{1,64}) from\b", re.I),
    re.compile(r"\bby (?:user )?([\w.@\\$-]{1,64})\b(?= (?:from|on|at)\b)", re.I),
]
HTTP_RE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/[\d.]+)?")
STATUS_RE = re.compile(r"\b(?:status|code|rc)[\s=:]+(\d{3})\b", re.I)
SEVERITY_RE = re.compile(r"\b(emerg(?:ency)?|alert|crit(?:ical)?|fatal|err(?:or)?|warn(?:ing)?|notice|info|debug)\b", re.I)
SEVERITY_MAP = {"emerg": "CRITICAL", "emergency": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL", "critical": "CRITICAL",
                "fatal": "CRITICAL", "err": "HIGH", "error": "HIGH", "warn": "MEDIUM", "warning": "MEDIUM",
                "notice": "LOW", "info": "INFO", "debug": "INFO"}
FAIL_RE = re.compile(r"fail|denied|invalid|reject|unauthori[sz]ed|forbidden|blocked|bad password", re.I)
AUTH_RE = re.compile(r"log ?[io]n|sign ?in|auth|password|credential", re.I)


def _valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def ips(text: str) -> List[str]:
    seen: List[str] = []
    for m in IP_RE.finditer(text):
        ip = m.group(0)
        if _valid_ip(ip) and ip not in seen:
            seen.append(ip)
    return seen


def event_type(text: str, data: Dict[str, Any]) -> str:
    if AUTH_RE.search(text):
        return "AUTHENTICATION_FAILED" if FAIL_RE.search(text) else "AUTHENTICATION_SUCCESS"
    if data.get("http_method"):
        return "HTTP_REQUEST"
    if data.get("destination_port") and FAIL_RE.search(text):
        return "NETWORK_CONNECTION"
    return "GENERIC_EVENT"


def extract(text: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fill fields that are still missing in data from free text. Returns data."""
    data = data if data is not None else {}

    def put(key, value):
        if value not in (None, "") and data.get(key) in (None, ""):
            data[key] = value

    found = ips(text)
    if found:
        put("source_ip", found[0])
        if len(found) > 1:
            put("destination_ip", found[1])
    pairs = IP_PORT_RE.findall(text)
    for ip, port in pairs:
        if ip == data.get("source_ip"):
            put("source_port", int(port))
        elif ip == data.get("destination_ip"):
            put("destination_port", int(port))
    m = PORT_RE.search(text)
    if m and 0 < int(m.group(1)) <= 65535:
        put("source_port" if data.get("destination_port") else "destination_port", int(m.group(1)))
    m = TIMESTAMP_RE.search(text)
    if m:
        put("timestamp", m.group(0))
    for rx in USER_RES:
        m = rx.search(text)
        if m and not _valid_ip(m.group(1)):
            put("user", m.group(1).strip("\"'"))
            break
    m = HTTP_RE.search(text)
    if m:
        put("http_method", m.group(1))
        put("url", m.group(2))
    m = STATUS_RE.search(text)
    if m:
        put("status", m.group(1))
    m = SEVERITY_RE.search(text)
    if m:
        put("severity", SEVERITY_MAP[m.group(1).lower()])
    return data


class HeuristicParser:
    """Last rule-based step before the AI fallback: accept a line when real fields can be pulled out."""

    MEANINGFUL = ("source_ip", "destination_ip", "user", "timestamp", "http_method")

    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        data = extract(raw_log, {})
        if not any(data.get(k) for k in self.MEANINGFUL):
            return None
        data["message"] = raw_log.strip()[:2000]
        data["event_type"] = event_type(raw_log, data)
        data["category"] = "identity_access" if data["event_type"].startswith("AUTH") else "other"
        return data
