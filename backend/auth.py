"""
Operator accounts and sign-in.

Passwords are stored as PBKDF2-SHA256 hashes (random salt per account). A successful
sign-in returns a random bearer token; every /api/* call except health and sign-in must
send it. Roles gate what an operator may do (see ROLE_RANK / require_role).
"""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .config import config
from .db import db

PBKDF2_ROUNDS = 200_000
SESSION_HOURS = 12

# Higher rank = more authority
ROLE_RANK = {
    "Tier-1 Security Analyst": 1,
    "Tier-2 Senior Analyst": 2,
    "Tier-3 SOC Lead": 3,
    "Incident Commander": 3,
}

# Accounts created on first start so the evaluation build can be signed into.
# Disable with LOGVAULT_SEED_OPERATORS=false and create real accounts instead.
DEMO_OPERATORS = (
    ("sahil.soc@logvault.sih", "Agent Sahil", "Tier-3 SOC Lead", "CyberSecurity2026!"),
    ("vikram.hunt@logvault.sih", "Hunter Vikram", "Tier-2 Senior Analyst", "ThreatHunter2026!"),
    ("rajesh.cmd@logvault.sih", "Commander Rajesh", "Incident Commander", "Command2026!"),
    ("sneha.triage@logvault.sih", "Analyst Sneha", "Tier-1 Security Analyst", "TriageAnalyst2026!"),
)
DEMO_ACCOUNT = DEMO_OPERATORS[0][0]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, rounds, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def init_auth_tables():
    conn = db.get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS operator_accounts (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            callsign TEXT,
            org TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT,
            last_login TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            created_at TEXT,
            expires_at TEXT
        )
    ''')
    conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (_iso(_now()),))
    conn.commit()
    has_operators = conn.execute("SELECT COUNT(*) FROM operator_accounts").fetchone()[0] > 0
    conn.close()
    if not has_operators and config.SEED_OPERATORS:
        for email, name, role, password in DEMO_OPERATORS:
            create_operator(email, name, role, password)


def create_operator(email: str, name: str, role: str, password: str) -> Dict[str, Any]:
    if role not in ROLE_RANK:
        raise ValueError(f"Role must be one of {list(ROLE_RANK)}")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO operator_accounts (email, name, role, callsign, org, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (email.lower().strip(), name.strip(), role, None, None, hash_password(password), _iso(_now())))
    conn.commit()
    conn.close()
    return get_operator(email)


def get_operator(email: str) -> Optional[Dict[str, Any]]:
    conn = db.get_connection()
    row = conn.execute(
        "SELECT email, name, role, callsign, org, created_at, last_login FROM operator_accounts WHERE email = ?",
        (email.lower().strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_operators():
    conn = db.get_connection()
    rows = conn.execute("SELECT email, name, role, callsign, org, created_at, last_login FROM operator_accounts ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_profile(email: str, name: str, callsign: Optional[str], org: Optional[str]) -> Dict[str, Any]:
    conn = db.get_connection()
    conn.execute("UPDATE operator_accounts SET name = ?, callsign = ?, org = ? WHERE email = ?",
                 (name.strip(), (callsign or "").strip() or None, (org or "").strip() or None, email))
    conn.commit()
    conn.close()
    return get_operator(email)


def change_password(email: str, current: str, new: str):
    conn = db.get_connection()
    row = conn.execute("SELECT password_hash FROM operator_accounts WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(current, row[0]):
        conn.close()
        raise ValueError("Current password is wrong")
    if len(new) < 8:
        conn.close()
        raise ValueError("New password must be at least 8 characters")
    conn.execute("UPDATE operator_accounts SET password_hash = ? WHERE email = ?", (hash_password(new), email))
    conn.commit()
    conn.close()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def login(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Returns {"token", "operator", "expires_at"} or None when the credentials are wrong."""
    email = (email or "").lower().strip()
    conn = db.get_connection()
    row = conn.execute("SELECT password_hash FROM operator_accounts WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(password or "", row[0]):
        conn.close()
        return None
    return _open_session(conn, email)


def demo_login() -> Optional[Dict[str, Any]]:
    """One-click evaluation access as the seeded SOC lead (only while DEMO_LOGIN is enabled)."""
    if not config.DEMO_LOGIN or not get_operator(DEMO_ACCOUNT):
        return None
    return _open_session(db.get_connection(), DEMO_ACCOUNT)


def _open_session(conn, email: str) -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    now = _now()
    expires = now + timedelta(hours=SESSION_HOURS)
    conn.execute("INSERT INTO auth_sessions (token_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)",
                 (_token_hash(token), email, _iso(now), _iso(expires)))
    conn.execute("UPDATE operator_accounts SET last_login = ? WHERE email = ?", (_iso(now), email))
    conn.commit()
    conn.close()
    return {"token": token, "operator": get_operator(email), "expires_at": _iso(expires)}


def operator_for_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    conn = db.get_connection()
    row = conn.execute("SELECT email FROM auth_sessions WHERE token_hash = ? AND expires_at > ?",
                       (_token_hash(token), _iso(_now()))).fetchone()
    conn.close()
    return get_operator(row[0]) if row else None


def logout(token: str):
    conn = db.get_connection()
    conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_token_hash(token),))
    conn.commit()
    conn.close()


def has_role(operator: Optional[Dict[str, Any]], min_rank: int) -> bool:
    if operator is None:
        return not config.AUTH_REQUIRED  # auth disabled (tests / trusted single-user install)
    return ROLE_RANK.get(operator.get("role"), 0) >= min_rank
