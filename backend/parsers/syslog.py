import re
from typing import Dict, Any

class SyslogParser:
    def __init__(self):
        # Parses basic syslog/SSH PAM auth failure & success
        self.pattern = re.compile(
            r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<process>\S+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$'
        )
        self.ssh_pattern = re.compile(
            r'(?P<action>Accepted|Failed)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<port>\d+)\s+(?P<protocol>\w+)'
        )

    def parse(self, raw_log: str) -> Dict[str, Any]:
        match = self.pattern.match(raw_log)
        if not match:
            return None
            
        data = match.groupdict()
        message = data.get('message', '')
        
        # Sub-parse SSH
        if 'sshd' in data.get('process', ''):
            ssh_match = self.ssh_pattern.search(message)
            if ssh_match:
                ssh_data = ssh_match.groupdict()
                data.update({
                    "action": ssh_data.get("action"),
                    "user": ssh_data.get("user"),
                    "source_ip": ssh_data.get("src_ip"),
                    "source_port": int(ssh_data.get("port")) if ssh_data.get("port") else None,
                    "protocol": ssh_data.get("protocol"),
                    "event_type": f"AUTHENTICATION_{ssh_data.get('action').upper()}" if ssh_data.get("action") else "AUTHENTICATION",
                    "severity": "INFO" if ssh_data.get("action") == "Accepted" else "HIGH",
                    "category": "identity_access"
                })
        
        return data
