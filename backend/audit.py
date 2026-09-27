"""
Audit log: who did what, when, from where.

Every entry stores the SHA-256 of the previous entry, so editing or deleting a past entry
breaks the chain and verify() reports where. Entries are only ever appended.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .db import db

GENESIS = hashlib.sha256(b"LOGVAULT-AUDIT-v1").hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def init_tables():
    conn = db.get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            actor TEXT,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            client_ip TEXT,
            outcome TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        )
    ''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
    conn.commit()
    conn.close()


def _entry_hash(prev: str, at: str, actor, action, target, detail, client_ip, outcome) -> str:
    body = json.dumps([prev, at, actor, action, target, detail, client_ip, outcome], separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def record(action: str, actor: Optional[str] = None, target: Optional[str] = None,
           detail: Any = None, client_ip: Optional[str] = None, outcome: str = "success") -> None:
    """Append one entry. Never raises: auditing must not break the action being audited."""
    detail_text = detail if isinstance(detail, str) or detail is None else json.dumps(detail, default=str)
    if detail_text and len(detail_text) > 2000:
        detail_text = detail_text[:2000]
    conn = None
    try:
        conn = db.get_connection()
        conn.isolation_level = None       # explicit transaction below
        conn.execute("BEGIN IMMEDIATE")  # serialise writers so the chain stays linear
        row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        at = _now()
        h = _entry_hash(prev, at, actor, action, target, detail_text, client_ip, outcome)
        conn.execute(
            "INSERT INTO audit_log (at, actor, action, target, detail, client_ip, outcome, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (at, actor, action, target, detail_text, client_ip, outcome, prev, h))
        conn.execute("COMMIT")
    except Exception as e:  # logged, never propagated
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        print(f"[AUDIT] could not record {action}: {e}")
    finally:
        if conn is not None:
            conn.close()


def list_entries(limit: int = 100, offset: int = 0, action: Optional[str] = None,
                 actor: Optional[str] = None) -> Dict[str, Any]:
    where, params = [], []
    if action:
        where.append("action = ?")
        params.append(action)
    if actor:
        where.append("actor = ?")
        params.append(actor)
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    conn = db.get_connection()
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log{clause}", params).fetchone()[0]
    rows = [dict(r) for r in conn.execute(
        f"SELECT seq, at, actor, action, target, detail, client_ip, outcome, hash FROM audit_log{clause} "
        f"ORDER BY seq DESC LIMIT ? OFFSET ?", params + [limit, offset])]
    actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    conn.close()
    return {"entries": rows, "total": total, "actions": actions}


def verify() -> Dict[str, Any]:
    """Recompute the whole chain. Returns ok, entries checked and the first broken entry if any."""
    conn = db.get_connection()
    prev = GENESIS
    count = 0
    for r in conn.execute("SELECT seq, at, actor, action, target, detail, client_ip, outcome, prev_hash, hash "
                          "FROM audit_log ORDER BY seq"):
        count += 1
        seq, at, actor, action, target, detail, client_ip, outcome, prev_hash, h = r
        expected = _entry_hash(prev, at, actor, action, target, detail, client_ip, outcome)
        if prev_hash != prev or h != expected:
            conn.close()
            return {"ok": False, "entries": count, "broken_at_seq": seq,
                    "reason": "entry was modified" if prev_hash == prev else "an earlier entry was removed or changed"}
        prev = h
    conn.close()
    return {"ok": True, "entries": count, "head": prev}
