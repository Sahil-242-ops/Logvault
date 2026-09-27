"""
Syslog: RFC 5424 and RFC 3164 (BSD), with or without the <PRI> header.

  RFC 5424: <34>1 2026-09-24T02:10:00Z host app 1234 ID47 [origin ip="10.0.0.1"] message
  RFC 3164: <34>Sep 24 02:10:00 host sshd[330]: message      (<PRI> and [pid] optional)
            2026-09-24T02:10:00+05:30 host app: message      (rsyslog high-precision timestamps)

PRI gives the facility and severity. The message is then read for SSH / PAM / sudo /
iptables patterns, and any remaining IPs, users and ports are picked up by heuristic.extract.
"""
import re
from typing import Any, Dict, Optional

from . import heuristic

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
              "ftp", "ntp", "security", "console", "solaris-cron"] + [f"local{i}" for i in range(8)]
PRI_SEVERITY = ["CRITICAL", "CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFO"]  # emerg..debug

RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+) (?P<process>\S+) "
    r"(?P<pid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<message>.*))?$", re.S)
RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$", re.S)
SD_ELEMENT = re.compile(r"\[(?P<id>[^\s\]]+)(?P<params>(?:\s+[^=\s\]]+=\"(?:[^\"\\]|\\.)*\")*)\]")
SD_PARAM = re.compile(r"([^=\s\]]+)=\"((?:[^\"\\]|\\.)*)\"")

SSH = re.compile(r"(?P<action>Accepted|Failed) (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for "
                 r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: (?P<protocol>\w+))?")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
PAM_FAIL = re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*)(?:.*?\buser=(?P<user>\S+))?")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?(?:USER=(?P<target>\S+))?.*?COMMAND=(?P<command>.+)$")
IPTABLES = re.compile(r"\bSRC=(?P<src>\S+) DST=(?P<dst>\S+).*?\bPROTO=(?P<proto>\S+)(?:.*?\bSPT=(?P<spt>\d+))?(?:.*?\bDPT=(?P<dpt>\d+))?")


class SyslogParser:
    def __init__(self):
        # Kept as attributes so the Parser Registry can show the real regexes
        self.rfc5424_pattern = RFC5424
        self.rfc3164_pattern = RFC3164
        self.ssh_pattern = SSH

    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        line = raw_log.strip()
        m = RFC5424.match(line)
        if m:
            data = {k: v for k, v in m.groupdict().items() if v not in (None, "-")}
            data["syslog_format"] = "RFC5424"
            for el in SD_ELEMENT.finditer(m.group("sd") or ""):
                for key, value in SD_PARAM.findall(el.group("params")):
                    data[f"{el.group('id')}.{key}"] = value.replace('\\"', '"')
                    if key == "ip":
                        data.setdefault("source_ip", value)
            data.pop("sd", None)
        else:
            m = RFC3164.match(line)
            if not m:
                return None
            data = {k: v for k, v in m.groupdict().items() if v is not None}
            data["syslog_format"] = "RFC3164"

        if data.get("pri"):
            pri = int(data["pri"])
            if pri > 191:
                return None
            data["facility"] = FACILITIES[pri // 8] if pri // 8 < len(FACILITIES) else str(pri // 8)
            data["severity"] = PRI_SEVERITY[pri % 8]
        self._enrich(data)
        return data

    def _enrich(self, data: Dict[str, Any]) -> None:
        msg = data.get("message") or ""
        proc = (data.get("process") or "").lower()

        m = SSH.search(msg)
        if m:
            ok = m.group("action") == "Accepted"
            data.update({"action": m.group("action"), "user": m.group("user"), "source_ip": m.group("ip"),
                         "source_port": int(m.group("port")), "protocol": m.group("protocol") or "ssh",
                         "auth_method": m.group("method"),
                         "event_type": "AUTHENTICATION_SUCCESS" if ok else "AUTHENTICATION_FAILED",
                         "severity": "INFO" if ok else "HIGH", "category": "identity_access"})
            return
        m = SSH_INVALID.search(msg)
        if m:
            data.update({"action": "Failed", "user": m.group("user"), "source_ip": m.group("ip"),
                         "event_type": "AUTHENTICATION_FAILED", "severity": "HIGH", "category": "identity_access"})
            if m.group("port"):
                data["source_port"] = int(m.group("port"))
            return
        m = PAM_FAIL.search(msg)
        if m:
            data.update({"action": "Failed", "event_type": "AUTHENTICATION_FAILED", "severity": "HIGH",
                         "category": "identity_access"})
            if m.group("ip"):
                data["source_ip"] = m.group("ip")
            if m.group("user"):
                data["user"] = m.group("user")
            return
        if proc == "sudo":
            m = SUDO.search(msg)
            if m:
                data.update({"user": m.group("user"), "command": m.group("command").strip(),
                             "target_user": m.group("target"), "event_type": "PROCESS_START",
                             "action": "sudo", "category": "system"})
                return
        m = IPTABLES.search(msg)
        if m:
            data.update({"source_ip": m.group("src"), "destination_ip": m.group("dst"), "protocol": m.group("proto"),
                         "event_type": "NETWORK_CONNECTION", "category": "network"})
            if m.group("spt"):
                data["source_port"] = int(m.group("spt"))
            if m.group("dpt"):
                data["destination_port"] = int(m.group("dpt"))
            if re.search(r"DROP|REJECT|BLOCK|DENY", msg, re.I):
                data["action"] = "blocked"
            return

        heuristic.extract(msg, data)
        data.setdefault("event_type", heuristic.event_type(msg, data))
