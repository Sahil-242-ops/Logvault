import re
from typing import List, Dict, Any

THREAT_RULES = [
    {
        "id": "RULE-001",
        "name": "SQL Injection Attempt",
        "severity": "CRITICAL",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "patterns": [
            re.compile(r'(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)', re.IGNORECASE),
            re.compile(r"(?:'|%27)\s*(?:or|and)\s+", re.IGNORECASE),
            re.compile(r"(?:1\s*=\s*1|1\s*=\s*'1')", re.IGNORECASE),
            re.compile(r"(?:exec\s*\(|execute\s+|xp_cmdshell)", re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-002",
        "name": "Cross-Site Scripting (XSS)",
        "severity": "CRITICAL",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1189 - Drive-by Compromise",
        "patterns": [
            re.compile(r'<script[^>]*>', re.IGNORECASE),
            re.compile(r'javascript\s*:', re.IGNORECASE),
            re.compile(r'on(?:error|load|click|mouseover)\s*=', re.IGNORECASE),
            re.compile(r'%3cscript', re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-003",
        "name": "Path Traversal / Directory Traversal",
        "severity": "HIGH",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1005 - Data from Local System",
        "patterns": [
            re.compile(r'(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)', re.IGNORECASE),
            re.compile(r'(?:/etc/passwd|/etc/shadow|/proc/self)', re.IGNORECASE),
            re.compile(r'(?:c:\\windows\\|c:\\boot\.ini)', re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-004",
        "name": "Brute Force Authentication",
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "patterns": [
            re.compile(r'(?:failed\s+password|authentication\s+failure|login\s+fail)', re.IGNORECASE),
            re.compile(r'(?:invalid\s+user|illegal\s+user|unknown\s+user)', re.IGNORECASE),
            re.compile(r'(?:account\s+locked|too\s+many\s+attempts)', re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-005",
        "name": "Suspicious Command Execution",
        "severity": "HIGH",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "patterns": [
            re.compile(r'(?:powershell|cmd\.exe|bash\s+-c|sh\s+-c)', re.IGNORECASE),
            re.compile(r'(?:wget|curl|nc\s+-|netcat)', re.IGNORECASE),
            re.compile(r'(?:base64\s+-d|echo\s+.*\|\s*base64)', re.IGNORECASE),
            re.compile(r'(?:chmod\s+777|chmod\s+\+x)', re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-006",
        "name": "Privilege Escalation Attempt",
        "severity": "CRITICAL",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548 - Abuse Elevation Control Mechanism",
        "patterns": [
            re.compile(r'(?:sudo\s+su|su\s+-\s+root)', re.IGNORECASE),
            re.compile(r'(?:EventID[=:]?\s*4672|EventID[=:]?\s*4728)', re.IGNORECASE),
            re.compile(r'(?:/etc/sudoers|visudo)', re.IGNORECASE)
        ]
    },
    {
        "id": "RULE-007",
        "name": "Data Exfiltration Indicator",
        "severity": "HIGH",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel",
        "patterns": [
            re.compile(r'(?:scp\s+.*@|rsync\s+.*@)', re.IGNORECASE),
            re.compile(r'(?:\.zip|\.tar\.gz|\.7z|\.rar)\s', re.IGNORECASE)
        ]
    }
]
