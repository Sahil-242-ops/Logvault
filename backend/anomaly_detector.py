import math
from typing import Dict, Any, List
from .mitre.rules import THREAT_RULES

class AnomalyDetector:
    def __init__(self):
        self.rules = THREAT_RULES

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
            
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def detect(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        raw_log = normalized_event.get("raw_log", "")
        message = normalized_event.get("message", "")
        combined = f"{raw_log} {message}"
        
        # 1. Rule-based threat detection
        for rule in self.rules:
            for pattern in rule["patterns"]:
                if pattern.search(combined):
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "mitre_technique": rule["mitre_technique"],
                        "matched_pattern": pattern.pattern[:60],
                        "type": "threat_rule"
                    })
                    break  # One match per rule is sufficient

        # 2. Shannon entropy analysis
        entropy = self.shannon_entropy(raw_log)
        if entropy > 5.5:
            findings.append({
                "rule_id": "ENTROPY-001",
                "rule_name": "High Entropy Content Detected",
                "severity": "CRITICAL" if entropy > 6.5 else "HIGH",
                "entropy_score": entropy,
                "type": "entropy",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1027 - Obfuscated Files or Information"
            })

        # 3. Severity escalation check
        event_type = str(normalized_event.get("event_type", "")).upper()
        if "FAILURE" in event_type or "DENIED" in event_type or "BLOCKED" in event_type:
            if not any(f["rule_id"] == "RULE-004" for f in findings):
                findings.append({
                    "rule_id": "SEV-001",
                    "rule_name": "Access Denial Event",
                    "severity": "LOW",
                    "type": "severity_flag",
                    "mitre_tactic": None,
                    "mitre_technique": None
                })

        # Calculate max severity score
        severity_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "NONE": 0}
        max_severity = "NONE"
        max_score = 0
        
        for finding in findings:
            sev = finding.get("severity", "NONE")
            score = severity_map.get(sev, 0)
            if score > max_score:
                max_score = score
                max_severity = sev

        is_anomalous = len(findings) > 0 and max_score >= 3
        threat_score = min(max_score * 20, 100)

        return {
            "is_anomalous": is_anomalous,
            "threat_score": threat_score,
            "findings_count": len(findings),
            "max_severity": max_severity,
            "entropy": entropy,
            "findings": findings
        }

anomaly_detector = AnomalyDetector()
