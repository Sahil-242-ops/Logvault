"""
Schema mapper for formats no built-in parser knows.

infer(raw) looks at one sample record and proposes which part of it maps to which
normalized field (key names first, then value shapes such as IPs, ports, timestamps).
An analyst reviews the proposal and saves it as a mapping rule; saved rules are then
used by the format detector for every later record that matches them.

Two rule kinds:
  kv       - key=value records; matches when every rule key is present.
  pattern  - positional records (e.g. Cisco ASA); matches on a leading anchor regex, and
             fields are taken by position ("ip#1" = first IPv4 in the record, etc.).
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .db import db

KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s,;|]+))')
IP_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
IP_PORT_RE = re.compile(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})[/:](\d{1,5})\b')
PORT_WORD_RE = re.compile(r'\bport\s+(\d{1,5})\b', re.IGNORECASE)
TS_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
    r'|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'|\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?')
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
USER_WORD_RE = re.compile(r'\b(?:user|for|account)\s+([A-Za-z0-9_.\\@-]{2,64})\b', re.IGNORECASE)
PROTO_RE = re.compile(r'\b(tcp|udp|icmp|ssh2?|https?|ftp|smb|rdp|dns)\b', re.IGNORECASE)
ACTION_RE = re.compile(r'\b(deny|denied|drop|dropped|block(?:ed)?|allow(?:ed)?|accept(?:ed)?|permit(?:ted)?|'
                       r'fail(?:ed|ure)?|success(?:ful)?|login|logout|reject(?:ed)?)\b', re.IGNORECASE)

# Normalized target fields the mapper can assign
TARGET_FIELDS = (
    "timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "user", "host",
    "process", "protocol", "action", "status", "event_type", "severity", "message", "geo_location",
)

# key name (lower case, without separators) -> target field
KEY_ALIASES = {
    "timestamp": ("ts", "time", "timestamp", "date", "datetime", "eventtime", "logtime", "rt", "start"),
    "source_ip": ("src", "srcip", "sourceip", "sip", "clientip", "client", "remoteip", "remoteaddr",
                  "ipsrc", "fromip", "cip", "srcaddr", "ip", "sourceaddress"),
    "source_port": ("spt", "srcport", "sport", "sourceport", "clientport"),
    "destination_ip": ("dst", "dstip", "destip", "destinationip", "dip", "serverip", "targetip",
                       "dstaddr", "destinationaddress"),
    "destination_port": ("dpt", "dstport", "dport", "destport", "destinationport", "port", "targetport"),
    "user": ("usr", "user", "username", "uid", "login", "account", "suser", "duser", "actor", "principal"),
    "host": ("host", "hostname", "dev", "device", "devicename", "dvchost", "computer", "node", "server", "shost"),
    "process": ("proc", "process", "prog", "program", "app", "application", "exe", "service"),
    "protocol": ("proto", "protocol", "prot", "transport"),
    "action": ("act", "action", "op", "operation", "verb", "activity"),
    "status": ("res", "result", "status", "outcome", "code", "rc"),
    "event_type": ("evt", "event", "eventtype", "type", "category", "cat", "eventname"),
    "severity": ("sev", "severity", "level", "priority", "pri", "lvl"),
    "message": ("msg", "message", "desc", "description", "text", "details", "reason"),
    "geo_location": ("loc", "location", "geo", "city", "country", "region"),
}
_ALIAS_INDEX = {alias: target for target, aliases in KEY_ALIASES.items() for alias in aliases}


def _norm_key(k: str) -> str:
    return re.sub(r'[^a-z0-9]', '', k.lower())


def _value_type(v: str) -> Optional[str]:
    if IP_RE.fullmatch(v):
        return "IPv4 address"
    if TS_RE.fullmatch(v):
        return "Timestamp"
    if EMAIL_RE.fullmatch(v):
        return "Email / identity"
    if v.isdigit():
        return "Integer"
    return None


def _guess_from_value(key: str, value: str) -> Tuple[Optional[str], float, str]:
    vtype = _value_type(value)
    k = key.lower()
    if vtype == "IPv4 address":
        return ("destination_ip" if any(s in k for s in ("dst", "dest", "target", "server")) else "source_ip"), 0.7, vtype
    if vtype == "Timestamp":
        return "timestamp", 0.75, vtype
    if vtype == "Email / identity":
        return "user", 0.7, vtype
    if vtype == "Integer" and "port" in k:
        return ("source_port" if any(s in k for s in ("src", "source", "client")) else "destination_port"), 0.7, vtype
    return None, 0.0, vtype or "String"


def _first_token_anchor(raw: str) -> str:
    """Regex that matches the record's leading token with digits generalised,
    e.g. '%ASA-4-106023:' -> '^%ASA\\-\\d+\\-\\d+:'."""
    token = raw.strip().split()[0] if raw.strip() else ""
    parts = re.split(r'(\d+)', token)
    return "^" + "".join(r"\d+" if p.isdigit() else re.escape(p) for p in parts if p)


def infer(raw: str) -> Dict[str, Any]:
    raw = raw.strip()
    kv = [(m.group(1), next(g for g in m.groups()[1:] if g is not None)) for m in KV_RE.finditer(raw)]
    # A record is key/value shaped when the pairs cover most of it
    covered = sum(len(k) + len(v) + 1 for k, v in kv)
    if len(kv) >= 2 and covered >= 0.5 * len(re.sub(r'\s+', '', raw)):
        return _infer_kv(raw, kv)
    return _infer_positional(raw)


def _infer_kv(raw: str, pairs) -> Dict[str, Any]:
    mappings, used = [], set()
    for key, value in pairs:
        target = _ALIAS_INDEX.get(_norm_key(key))
        conf, vtype = (0.95, _value_type(value) or "String") if target else (0.0, None)
        if not target:
            target, conf, vtype = _guess_from_value(key, value)
        # The same target claimed twice: keep the first, demote the second to its own name
        if target in used:
            target, conf = None, 0.0
        if target:
            used.add(target)
        mappings.append({
            "rawField": key, "value": value, "targetField": target or f"extra.{_norm_key(key) or 'field'}",
            "confidence": round(conf if target else 0.4, 2), "type": vtype or "String", "mapped": bool(target),
        })
    return _result(raw, "kv", mappings, signature=[m["rawField"] for m in mappings])


def _infer_positional(raw: str) -> Dict[str, Any]:
    mappings = []

    def add(src, value, target, conf, vtype):
        mappings.append({"rawField": src, "value": value, "targetField": target, "confidence": conf,
                         "type": vtype, "mapped": True})

    ts = TS_RE.search(raw)
    if ts:
        add("timestamp#1", ts.group(0), "timestamp", 0.9, "Timestamp")
    ips = IP_RE.findall(raw)
    ports = {m.group(1): m.group(2) for m in IP_PORT_RE.finditer(raw)}
    for i, ip in enumerate(ips[:2]):
        add(f"ip#{i + 1}", ip, "source_ip" if i == 0 else "destination_ip", 0.8 if len(ips) > 1 else 0.85, "IPv4 address")
        if ip in ports:
            add(f"port_after_ip#{i + 1}", ports[ip], "source_port" if i == 0 else "destination_port", 0.75, "Integer (Port)")
    if not ports:
        pw = PORT_WORD_RE.search(raw)
        if pw:
            add("port#1", pw.group(1), "source_port" if ips else "destination_port", 0.7, "Integer (Port)")
    em = EMAIL_RE.search(raw)
    uw = USER_WORD_RE.search(raw)
    if em:
        add("email#1", em.group(0), "user", 0.8, "Email / identity")
    elif uw:
        add("user_word#1", uw.group(1), "user", 0.65, "String (Identifier)")
    pr = PROTO_RE.search(raw)
    if pr:
        add("protocol#1", pr.group(1), "protocol", 0.85, "Protocol")
    ac = ACTION_RE.search(raw)
    if ac:
        add("action#1", ac.group(1), "action", 0.75, "Enum (Action)")
    return _result(raw, "pattern", mappings, anchor=_first_token_anchor(raw))


def _result(raw, kind, mappings, signature=None, anchor=None) -> Dict[str, Any]:
    mapped = [m for m in mappings if m["mapped"]]
    overall = round(100 * sum(m["confidence"] for m in mapped) / len(mapped), 1) if mapped else 0.0
    return {
        "raw": raw, "kind": kind, "mappings": mappings, "signature": signature, "anchor": anchor,
        "overall_confidence": overall, "mapped_fields": len(mapped), "total_fields": len(mappings),
        "suggested_event_type": _suggest_event_type(raw),
    }


def _suggest_event_type(raw: str) -> str:
    r = raw.lower()
    if re.search(r'\b(login|logon|auth|password|sign.?in)\b', r):
        return "AUTHENTICATION_FAILED" if re.search(r'fail|denied|invalid|reject', r) else "AUTHENTICATION"
    if re.search(r'\b(deny|denied|drop|block)', r):
        return "FIREWALL_BLOCKED"
    if re.search(r'\b(allow|permit|accept|built|teardown)', r):
        return "NETWORK_CONNECTION"
    if re.search(r'\b(get|post|put|delete)\s+/', r):
        return "HTTP_REQUEST"
    return "GENERIC_EVENT"


# ---------------------------------------------------------------- rule storage

def init_tables():
    conn = db.get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS mapping_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            signature TEXT,
            anchor TEXT,
            mappings TEXT NOT NULL,
            event_type TEXT,
            sample TEXT,
            created_by TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()
    reload_rules()


_rules_cache: List[Dict[str, Any]] = []


def reload_rules():
    global _rules_cache
    conn = db.get_connection()
    rows = conn.execute("SELECT * FROM mapping_rules ORDER BY created_at").fetchall()
    conn.close()
    rules = []
    for r in rows:
        rule = dict(r)
        rule["signature"] = json.loads(rule["signature"]) if rule["signature"] else None
        rule["mappings"] = json.loads(rule["mappings"])
        try:
            rule["_anchor_re"] = re.compile(rule["anchor"]) if rule["anchor"] else None
        except re.error:
            rule["_anchor_re"] = None
        rules.append(rule)
    _rules_cache = rules


def list_rules() -> List[Dict[str, Any]]:
    rules = [{k: v for k, v in r.items() if not k.startswith("_")} for r in _rules_cache]
    from .stats import parser_usage
    usage = parser_usage()
    for r in rules:
        r["events_matched"] = usage.get(f"custom:{r['name']}", {}).get("events", 0)
    return rules


def save_rule(name: str, kind: str, mappings: List[Dict[str, Any]], signature=None, anchor=None,
              event_type=None, sample=None, created_by=None) -> Dict[str, Any]:
    name = re.sub(r'\s+', ' ', (name or "").strip())[:60]
    if not name:
        raise ValueError("Rule name is required")
    if kind not in ("kv", "pattern"):
        raise ValueError("kind must be 'kv' or 'pattern'")
    clean = [{"rawField": m["rawField"], "targetField": m["targetField"]}
             for m in mappings if m.get("targetField") and m.get("rawField")]
    if not clean:
        raise ValueError("At least one field mapping is required")
    if kind == "kv" and not signature:
        signature = [m["rawField"] for m in clean]
    if kind == "pattern":
        try:
            re.compile(anchor or "")
        except re.error as e:
            raise ValueError(f"Anchor is not a valid regex: {e}")
        if not anchor:
            raise ValueError("Pattern rules need an anchor")
    if any(r["name"].lower() == name.lower() for r in _rules_cache):
        raise ValueError(f"A rule named '{name}' already exists")
    rule_id = str(uuid.uuid4())
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO mapping_rules (id, name, kind, signature, anchor, mappings, event_type, sample, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (rule_id, name, kind, json.dumps(signature) if signature else None, anchor, json.dumps(clean),
         event_type or None, (sample or "")[:2000], created_by,
         datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")))
    conn.commit()
    conn.close()
    reload_rules()
    return next(r for r in list_rules() if r["id"] == rule_id)


def delete_rule(rule_id: str) -> bool:
    conn = db.get_connection()
    cur = conn.execute("DELETE FROM mapping_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    reload_rules()
    return cur.rowcount > 0


# ---------------------------------------------------------------- applying rules

def _extract_positional(raw: str) -> Dict[str, str]:
    values = {}
    ts = TS_RE.search(raw)
    if ts:
        values["timestamp#1"] = ts.group(0)
    ips = IP_RE.findall(raw)
    ports = {m.group(1): m.group(2) for m in IP_PORT_RE.finditer(raw)}
    for i, ip in enumerate(ips[:2]):
        values[f"ip#{i + 1}"] = ip
        if ip in ports:
            values[f"port_after_ip#{i + 1}"] = ports[ip]
    pw = PORT_WORD_RE.search(raw)
    if pw:
        values["port#1"] = pw.group(1)
    for key, rx, grp in (("email#1", EMAIL_RE, 0), ("user_word#1", USER_WORD_RE, 1),
                         ("protocol#1", PROTO_RE, 1), ("action#1", ACTION_RE, 1)):
        m = rx.search(raw)
        if m:
            values[key] = m.group(grp)
    return values


def apply_rules(raw: str) -> Optional[tuple]:
    """(rule_name, parsed_fields) for the first saved rule matching raw, else None."""
    if not _rules_cache:
        return None
    kv = None
    for rule in _rules_cache:
        if rule["kind"] == "kv":
            if kv is None:
                kv = {m.group(1): next(g for g in m.groups()[1:] if g is not None) for m in KV_RE.finditer(raw)}
            if not rule["signature"] or not all(k in kv for k in rule["signature"]):
                continue
            source = kv
        else:
            if not rule["_anchor_re"] or not rule["_anchor_re"].search(raw.strip()):
                continue
            source = _extract_positional(raw)
        parsed: Dict[str, Any] = {}
        for m in rule["mappings"]:
            val = source.get(m["rawField"])
            if val is None:
                continue
            target = m["targetField"]
            if target in ("source_port", "destination_port"):
                try:
                    val = int(val)
                except ValueError:
                    continue
            parsed[target] = val
        if rule.get("event_type") and "event_type" not in parsed:
            parsed["event_type"] = rule["event_type"]
        parsed.setdefault("message", raw)
        return rule["name"], parsed
    return None
