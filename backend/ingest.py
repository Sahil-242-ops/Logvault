"""
Split an uploaded file into individual log records.

Plain line-by-line splitting breaks structured files: a pretty-printed JSON array
becomes records like "[" and '"user": "alice",'. This module understands:
  * JSON documents: an array of records, or an object wrapping one
    (e.g. CloudTrail {"Records": [...]}), or a single object
  * JSON Lines (.jsonl / one object per line)
  * CSV with a header row (each row becomes a JSON object keyed by the header)
  * everything else: one record per line, skipping blank / structural lines
"""
import csv
import io
import json
import re
from typing import List, Tuple

STRUCTURAL_LINE = re.compile(r"^[\s\[\]{}(),;]*$")
WRAPPER_KEYS = ("Records", "records", "events", "Events", "logs", "Logs", "data", "items", "hits")


def _json_records(doc) -> List[str]:
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = next((doc[k] for k in WRAPPER_KEYS if isinstance(doc.get(k), list)), [doc])
        # Elasticsearch-style {"hits": {"hits": [...]}}
        if items == [doc] and isinstance(doc.get("hits"), dict) and isinstance(doc["hits"].get("hits"), list):
            items = [h.get("_source", h) for h in doc["hits"]["hits"]]
    else:
        return []
    return [json.dumps(i, separators=(",", ":"), default=str) if isinstance(i, (dict, list)) else str(i)
            for i in items if i not in (None, "")]


def _csv_records(text: str) -> List[str]:
    reader = csv.DictReader(io.StringIO(text))
    fields = reader.fieldnames or []
    # Treat as a header only if it looks like column names, not data
    if len(fields) < 2 or any(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|^\d+$", f or "") for f in fields):
        return []
    rows = []
    for row in reader:
        clean = {k: v for k, v in row.items() if k and v not in (None, "")}
        if clean:
            rows.append(json.dumps(clean, separators=(",", ":")))
    return rows


def split_records(filename: str, text: str) -> Tuple[List[str], str]:
    """Returns (records, detected_layout)."""
    name = (filename or "").lower()
    stripped = text.strip()

    if stripped[:1] in ("[", "{"):
        try:
            records = _json_records(json.loads(stripped))
            if records:
                return records, "json-document"
        except json.JSONDecodeError:
            pass  # probably JSON Lines or a log that happens to start with a bracket

    if name.endswith(".csv"):
        records = _csv_records(text)
        if records:
            return records, "csv-with-header"

    records = [line.strip() for line in text.splitlines() if line.strip() and not STRUCTURAL_LINE.match(line)]
    layout = "json-lines" if records and all(r.startswith("{") for r in records[:20]) else "line-per-record"
    return records, layout
