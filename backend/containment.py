"""
Containment list: IPs and hosts an analyst has blocked or isolated.

LOGVAULT runs inside an air-gapped network and does not reach into firewalls itself.
Instead it keeps the authoritative block list, raises a CRITICAL alert for any new log
that involves a contained IP or host, and exports the list as ready-to-apply firewall
rules (iptables, Cisco ACL, Windows Firewall) for the network team.
"""
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .db import db

HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.\-]{0,252}$')

_ips: Dict[str, Dict[str, Any]] = {}
_hosts: Dict[str, Dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def init_tables():
    conn = db.get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS containment (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            reason TEXT,
            alert_id TEXT,
            created_by TEXT,
            created_at TEXT,
            released_by TEXT,
            released_at TEXT
        )
    ''')
    conn.commit()
    conn.close()
    reload()


def reload():
    global _ips, _hosts
    conn = db.get_connection()
    rows = [dict(r) for r in conn.execute("SELECT * FROM containment WHERE released_at IS NULL")]
    conn.close()
    _ips = {r["value"]: r for r in rows if r["kind"] == "ip"}
    _hosts = {r["value"].lower(): r for r in rows if r["kind"] == "host"}


def list_entries(include_released: bool = False) -> List[Dict[str, Any]]:
    conn = db.get_connection()
    q = "SELECT * FROM containment" + ("" if include_released else " WHERE released_at IS NULL") + " ORDER BY created_at DESC"
    rows = [dict(r) for r in conn.execute(q)]
    for r in rows:
        col = "source_ip" if r["kind"] == "ip" else "host"
        r["events_since"] = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {col} = ? AND received_at >= ?", (r["value"], r["created_at"])).fetchone()[0]
    conn.close()
    return rows


def add(kind: str, value: str, reason: Optional[str], alert_id: Optional[str], created_by: str) -> Dict[str, Any]:
    value = (value or "").strip()
    if kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError(f"'{value}' is not a valid IP address")
        existing = _ips.get(value)
    elif kind == "host":
        if not HOST_RE.match(value) or value.lower() in ("unknown", "none", "-"):
            raise ValueError(f"'{value}' is not a valid host name")
        existing = _hosts.get(value.lower())
    else:
        raise ValueError("kind must be 'ip' or 'host'")
    if existing:
        return {**existing, "already_contained": True}
    entry = {"id": str(uuid.uuid4()), "kind": kind, "value": value, "reason": (reason or "").strip()[:500] or None,
             "alert_id": alert_id, "created_by": created_by, "created_at": _now()}
    conn = db.get_connection()
    conn.execute("INSERT INTO containment (id, kind, value, reason, alert_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 tuple(entry.values()))
    conn.commit()
    conn.close()
    reload()
    return {**entry, "already_contained": False}


def release(entry_id: str, released_by: str) -> bool:
    conn = db.get_connection()
    cur = conn.execute("UPDATE containment SET released_by = ?, released_at = ? WHERE id = ? AND released_at IS NULL",
                       (released_by, _now(), entry_id))
    conn.commit()
    conn.close()
    reload()
    return cur.rowcount > 0


def is_contained(kind: str, value: str) -> bool:
    return bool(value) and ((kind == "ip" and value in _ips) or (kind == "host" and value.lower() in _hosts))


def check_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Detection finding if the event involves a contained IP or host."""
    for field in ("source_ip", "destination_ip"):
        entry = _ips.get(event.get(field) or "")
        if entry:
            return _finding(f"{field.replace('_', ' ')} {entry['value']}", entry)
    host = str(event.get("host") or "").lower()
    if host in _hosts:
        return _finding(f"host {_hosts[host]['value']}", _hosts[host])
    return None


def _finding(what: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": "CONTAIN-001",
        "rule_name": "Activity From Contained Asset",
        "severity": "CRITICAL",
        "type": "containment",
        "description": f"Event involves contained {what} (contained by {entry['created_by']} at {entry['created_at']}).",
        "mitre_tactic": None,
        "mitre_technique": None,
    }


def export(fmt: str) -> Tuple[str, str, str]:
    """(body, media type, filename) with the active list as firewall rules."""
    entries = list_entries()
    ips = [e for e in entries if e["kind"] == "ip"]
    hosts = [e for e in entries if e["kind"] == "host"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    header = f"LOGVAULT containment list exported {_now()} ({len(ips)} IPs, {len(hosts)} hosts)"

    def note(e):
        return re.sub(r'[\r\n"]', ' ', f"{e['created_by']}: {e['reason'] or 'no reason given'}")[:120]

    if fmt == "iptables":
        lines = ["#!/bin/sh", f"# {header}", "# Review before applying. Host entries need their IP resolved first."]
        for e in ips:
            fam = "ip6tables" if ":" in e["value"] else "iptables"
            lines += [f"# {note(e)}",
                      f"{fam} -I INPUT -s {e['value']} -j DROP",
                      f"{fam} -I FORWARD -s {e['value']} -j DROP",
                      f"{fam} -I FORWARD -d {e['value']} -j DROP"]
        lines += [f"# isolate host: {e['value']} ({note(e)})" for e in hosts]
        return "\n".join(lines) + "\n", "text/x-shellscript", f"logvault-block-{stamp}.sh"
    if fmt == "cisco":
        lines = [f"! {header}", "ip access-list extended LOGVAULT-CONTAINMENT"]
        for e in ips:
            if ":" in e["value"]:
                continue
            lines += [f" remark {note(e)}", f" deny ip host {e['value']} any", f" deny ip any host {e['value']}"]
        lines += [" permit ip any any"]
        lines += [f"! isolate host: {e['value']}" for e in hosts]
        return "\n".join(lines) + "\n", "text/plain", f"logvault-acl-{stamp}.txt"
    if fmt == "windows":
        lines = [f"# {header}"]
        for e in ips:
            lines.append(f'New-NetFirewallRule -DisplayName "LOGVAULT block {e["value"]}" -Direction Inbound '
                         f'-RemoteAddress {e["value"]} -Action Block -Description "{note(e)}"')
        lines += [f"# isolate host: {e['value']}" for e in hosts]
        return "\n".join(lines) + "\n", "text/plain", f"logvault-block-{stamp}.ps1"
    # csv
    rows = ["kind,value,reason,created_by,created_at,alert_id"]
    for e in entries:
        rows.append(",".join('"' + str(e.get(k) or "").replace('"', '""') + '"'
                             for k in ("kind", "value", "reason", "created_by", "created_at", "alert_id")))
    return "\n".join(rows) + "\n", "text/csv", f"logvault-containment-{stamp}.csv"
