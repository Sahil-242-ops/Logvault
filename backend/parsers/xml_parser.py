"""
XML log records.

- Windows Event XML (<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">):
  System/EventID, TimeCreated, Computer, Channel, Provider and every EventData/Data[@Name].
- Any other XML record: elements and attributes are flattened into dotted keys
  (e.g. event.source.ip) and mapped with the same aliases as JSON.

Safety: documents with a DOCTYPE or ENTITY declaration are refused, which blocks
XXE and entity-expansion ("billion laughs") attacks without extra libraries.
"""
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

from .json_parser import map_fields
from .windows import apply_windows

UNSAFE = re.compile(r"<!DOCTYPE|<!ENTITY", re.I)
MAX_BYTES = 256 * 1024


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _flatten(el: ET.Element, prefix: str, out: Dict[str, Any]) -> None:
    for k, v in el.attrib.items():
        out[f"{prefix}.{_local(k)}" if prefix else _local(k)] = v
    children = list(el)
    text = (el.text or "").strip()
    if not children:
        if text and prefix:
            out[prefix] = text
        return
    counts: Dict[str, int] = {}
    for child in children:
        name = _local(child.tag)
        counts[name] = counts.get(name, 0) + 1
        key = f"{prefix}.{name}" if prefix else name
        if counts[name] > 1:
            key = f"{key}[{counts[name] - 1}]"
        _flatten(child, key, out)


class XMLParser:
    def __init__(self):
        self.start_pattern = re.compile(r"^\s*(?:<\?xml[^>]*\?>\s*)?<[A-Za-z_][\w.:-]*[\s>/]")

    def parse(self, raw_log: str) -> Optional[Dict[str, Any]]:
        text = raw_log.strip()
        if not self.start_pattern.match(text) or not text.endswith(">") or len(text) > MAX_BYTES or UNSAFE.search(text):
            return None
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return None

        if _local(root.tag) == "Event" and root.find("{*}System") is not None:
            return self._windows(root)

        flat: Dict[str, Any] = {}
        _flatten(root, "", flat)
        if not flat:
            return None
        nested: Dict[str, Any] = {}
        for key, value in flat.items():  # dotted keys -> nested dict so JSON aliases like source.ip work
            cur = nested
            parts = key.split(".")
            for part in parts[:-1]:
                nxt = cur.get(part)
                if not isinstance(nxt, dict):
                    nxt = cur[part] = {}
                cur = nxt
            if not isinstance(cur.get(parts[-1]), dict):
                cur[parts[-1]] = value
        data = map_fields({**flat, **nested})
        for k in [k for k, v in data.items() if isinstance(v, dict)]:
            data.pop(k)  # keep the flat, readable keys only
        data["xml_root"] = _local(root.tag)
        if data.get("event_type") == "JSON_EVENT":
            data["event_type"] = "XML_EVENT"
        return data

    def _windows(self, root: ET.Element) -> Dict[str, Any]:
        system = root.find("{*}System")
        data: Dict[str, Any] = {}
        event_id = (system.findtext("{*}EventID") or "").strip()
        tc = system.find("{*}TimeCreated")
        if tc is not None:
            data["TimeCreated"] = tc.get("SystemTime")
        for name in ("Computer", "Channel", "Level", "Task", "Keywords", "EventRecordID"):
            value = system.findtext(f"{{*}}{name}")
            if value:
                data[name] = value.strip()
        provider = system.find("{*}Provider")
        if provider is not None and provider.get("Name"):
            data["provider"] = provider.get("Name")
        for d in root.iterfind(".//{*}EventData/{*}Data"):
            if d.get("Name"):
                data[d.get("Name")] = (d.text or "").strip()
        data["windows_format"] = "XML"
        return apply_windows(data, event_id)
