"""
Split an uploaded file into individual log records.

Plain line-by-line splitting breaks structured files: a pretty-printed JSON array
becomes records like "[" and '"user": "alice",'. This module understands:
  * JSON documents: an array of records, or an object wrapping one
    (e.g. CloudTrail {"Records": [...]}), or a single object
  * JSON Lines (.jsonl / one object per line)
  * CSV with a header row (each row is stored as "header\nrow" and read by the CSV parser)
  * everything else: one record per line, skipping blank / structural lines
"""
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
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


UNSAFE_XML = re.compile(r"<!DOCTYPE|<!ENTITY", re.I)


def _xml_records(text: str) -> List[str]:
    """Records of an XML document; DOCTYPE / ENTITY documents are refused (no XXE)."""
    if UNSAFE_XML.search(text):
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    children = list(root)
    local = lambda t: t.split("}", 1)[-1]
    # A wrapper holds repeated record elements; a Windows <Event> is itself one record
    if local(root.tag) != "Event" and len(children) > 1 and len({local(c.tag) for c in children}) == 1:
        return [ET.tostring(c, encoding="unicode").strip() for c in children]
    return [text.strip()]


def _csv_records(text: str) -> List[str]:
    """Each data row is stored as "header\\nrow", so the raw record keeps its column
    names and the CSV parser can read it on its own."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return []
    fields = next(csv.reader(io.StringIO(lines[0])), [])
    # Treat as a header only if it looks like column names, not data
    if len(fields) < 2 or any(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|^\d+$", f or "") for f in fields):
        return []
    return [f"{lines[0]}\n{row}" for row in lines[1:]]


def _looks_like_csv(text: str) -> bool:
    """Same column count on the first lines, and no key=value pairs."""
    lines = [l for l in text.splitlines()[:20] if l.strip()]
    if len(lines) < 2 or "=" in lines[0] or lines[0].lstrip()[:1] in "{[<":
        return False
    cols = [len(next(csv.reader(io.StringIO(l)), [])) for l in lines]
    return cols[0] >= 3 and all(c == cols[0] for c in cols)


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

    if stripped[:1] == "<" and (name.endswith(".xml") or stripped.startswith("<?xml") or "\n" in stripped):
        records = _xml_records(re.sub(r"^<\?xml[^>]*\?>", "", stripped).strip())
        if records:
            return records, "xml-document"

    if name.endswith(".csv") or _looks_like_csv(text):
        records = _csv_records(text)
        if records:
            return records, "csv-with-header"

    records = [line.strip() for line in text.splitlines() if line.strip() and not STRUCTURAL_LINE.match(line)]
    layout = "json-lines" if records and all(r.startswith("{") for r in records[:20]) else "line-per-record"
    return records, layout
