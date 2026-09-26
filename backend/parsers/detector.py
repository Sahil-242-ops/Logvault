from typing import Dict, Any, Tuple
from .syslog import SyslogParser
from .cef import CEFParser
from .apache import ApacheParser
from .json_parser import JSONParser
from .windows import WindowsParser
from .generic_kv import GenericKVParser

class LogDetector:
    def __init__(self):
        self.parsers = {
            "syslog": SyslogParser(),
            "cef": CEFParser(),
            "apache": ApacheParser(),
            "json": JSONParser(),
            "windows": WindowsParser(),
            "generic_kv": GenericKVParser()
        }

    def detect_and_parse(self, raw_log: str) -> Tuple[str, Dict[str, Any], float]:
        """
        Returns (format_name, parsed_data, confidence)
        """
        # Analyst-saved mapping rules first: they were written for exactly this source
        from ..mapper import apply_rules
        custom = apply_rules(raw_log)
        if custom:
            name, parsed = custom
            return f"custom:{name}", parsed, 0.95

        # Try deterministic parsers in order of specificity
        for fmt in ["cef", "json", "apache", "windows", "syslog"]:
            parsed = self.parsers[fmt].parse(raw_log)
            if parsed:
                return fmt, parsed, 1.0
                
        # Try generic KV
        parsed = self.parsers["generic_kv"].parse(raw_log)
        if parsed and len(parsed) > 1: # Require at least 2 fields to be considered a confident KV match
            return "generic_kv", parsed, 0.8
            
        return "unknown", None, 0.0

detector = LogDetector()
