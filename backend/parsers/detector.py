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
                if fmt == "json":
                    inner = self._unwrap_envelope(parsed, raw_log)
                    if inner:
                        return inner
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

    # Formats that can travel inside a JSON wrapper's log / message field
    ENVELOPE_INNER = ["cef", "json", "xml", "apache", "windows", "syslog"]

    def _unwrap_envelope(self, outer: Dict[str, Any], raw_log: str):
        """Shippers (Filebeat, Docker, Fluentd, cloud exports) wrap each original line in JSON,
        e.g. {"timestamp": ..., "log": "Jul 15 12:34:56 host sshd[1]: ..."}. The inner line is what
        the event is about, so it is parsed with its own parser; the wrapper's fields are kept."""
        inner = outer.get("message")
        if not isinstance(inner, str) or len(inner.strip()) < 8 or inner.strip() == raw_log.strip():
            return None
        inner = inner.strip()
        for fmt in self.ENVELOPE_INNER:
            parsed = self.parsers[fmt].parse(inner)
            if parsed:
                break
        else:
            parsed = self.parsers["generic_kv"].parse(inner)
            fmt = "generic_kv" if parsed and len(parsed) > 1 else None
            if fmt:
                heuristic.extract(inner, parsed)
                if parsed.get("event_type") == "GENERIC_EVENT":
                    parsed["event_type"] = heuristic.event_type(inner, parsed)
        if not fmt:
            # Free text inside the wrapper: keep it as JSON, but still pick out IPs, users, times
            heuristic.extract(inner, outer)
            return None
        merged = {**outer, **{k: v for k, v in parsed.items() if v not in (None, "")}}
        # The wrapper's ISO timestamp is more complete than e.g. a BSD syslog time without a year
        if outer.get("timestamp") and "T" in str(outer["timestamp"]):
            merged["timestamp"] = outer["timestamp"]
        merged["message"] = parsed.get("message") or inner
        merged["envelope"] = "json"
        return fmt, merged, 1.0


detector = LogDetector()
