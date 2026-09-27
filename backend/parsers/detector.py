from typing import Dict, Any, Tuple
from .syslog import SyslogParser
from .cef import CEFParser
from .apache import ApacheParser
from .json_parser import JSONParser
from .windows import WindowsParser
from .xml_parser import XMLParser
from .csv_parser import CSVParser, HeaderlessCSVParser
from .generic_kv import GenericKVParser
from . import heuristic
from .heuristic import HeuristicParser

# Order matters: specific, unambiguous formats first; shape-based guesses last.
DETECTION_ORDER = ["cef", "json", "xml", "csv", "apache", "windows", "syslog"]


class LogDetector:
    def __init__(self):
        self.parsers = {
            "syslog": SyslogParser(),
            "cef": CEFParser(),
            "apache": ApacheParser(),
            "json": JSONParser(),
            "xml": XMLParser(),
            "csv": CSVParser(),
            "windows": WindowsParser(),
            "generic_kv": GenericKVParser(),
            "csv_noheader": HeaderlessCSVParser(),
            "custom": HeuristicParser(),
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

        for fmt in DETECTION_ORDER:
            parsed = self.parsers[fmt].parse(raw_log)
            if parsed:
                return fmt, parsed, 1.0

        parsed = self.parsers["generic_kv"].parse(raw_log)
        if parsed and len(parsed) > 1:
            # key=value lines often carry IPs, users and times in free text too
            heuristic.extract(raw_log, parsed)
            if parsed.get("event_type") == "GENERIC_EVENT":
                parsed["event_type"] = heuristic.event_type(raw_log, parsed)
            return "generic_kv", parsed, 0.8

        parsed = self.parsers["csv_noheader"].parse(raw_log)
        if parsed:
            return "csv", parsed, 0.7

        # Custom / unknown text: keep whatever can be identified by shape
        parsed = self.parsers["custom"].parse(raw_log)
        if parsed:
            return "custom", parsed, 0.5

        return "unknown", None, 0.0

detector = LogDetector()
