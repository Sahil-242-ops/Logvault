"""
CSV log records.

- With a header: the record is two lines, "header\\nrow" (file uploads are split this way,
  so every stored record keeps its column names). Columns are mapped like JSON fields.
- Without a header: a single line with 3+ comma-separated values. Columns become
  column_1..N and IPs, timestamps, users and ports are identified by their shape.
"""
import csv
import io
import re
from typing import Any, Dict, Optional

from . import heuristic
from .json_parser import map_fields

NUMERIC_OR_IP = re.compile(r"^\s*[\d.:]+\s*$")


def _row(line: str):
    try:
        return next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return None


class CSVParser:
    def __init__(self):
        self.header_pattern = re.compile(r"^[A-Za-z_@][\w .@/-]*(,[A-Za-z_@][\w .@/-]*)+$")

    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        lines = [l for l in raw_log.strip().splitlines() if l.strip()]
        if len(lines) == 2 and self.header_pattern.match(lines[0].strip()):
            header, values = _row(lines[0]), _row(lines[1])
            if not header or not values or len(values) != len(header):
                return None
            data = {h.strip(): v.strip() for h, v in zip(header, values) if h.strip() and v.strip() != ""}
            data = map_fields(data)
            if data.get("event_type") == "JSON_EVENT":
                data["event_type"] = "CSV_EVENT"
            data["csv_mode"] = "header"
            return data
        return None


class HeaderlessCSVParser:
    """A single line of 3+ comma-separated values, where at least one column is an IP or timestamp."""

    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        line = raw_log.strip()
        if "\n" in line or line.count(",") < 2 or "=" in line:
            return None
        values = _row(line)
        if not values or len(values) < 3:
            return None
        values = [v.strip() for v in values]
        if not any(heuristic.ips(v) or heuristic.TIMESTAMP_RE.fullmatch(v) for v in values):
            return None
        data: Dict[str, Any] = {f"column_{i + 1}": v for i, v in enumerate(values) if v}
        ips = [v for v in values if heuristic.ips(v) and NUMERIC_OR_IP.match(v)]
        if ips:
            data["source_ip"] = ips[0]
            if len(ips) > 1:
                data["destination_ip"] = ips[1]
        ts = next((v for v in values if heuristic.TIMESTAMP_RE.fullmatch(v)), None)
        if ts:
            data["timestamp"] = ts
        heuristic.extract(" ".join(v for v in values if v not in ips), data)
        data["event_type"] = heuristic.event_type(line, data)
        data["csv_mode"] = "no header"
        return data
