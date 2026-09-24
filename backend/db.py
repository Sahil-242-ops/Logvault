import sqlite3
import json
from datetime import datetime, timezone
from .config import config

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.current_session_id = None

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                received_at TEXT,
                detected_format TEXT,
                parser_name TEXT,
                parser_type TEXT,
                event_type TEXT,
                severity TEXT,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                user TEXT,
                host TEXT,
                process TEXT,
                protocol TEXT,
                message TEXT,
                threat_score INTEGER,
                is_anomalous BOOLEAN,
                mitre_technique TEXT,
                category TEXT,
                raw_log TEXT,
                normalized_json TEXT,
                session_id TEXT
            )
        ''')
        # Alert triage workflow: OPEN -> AI Investigating -> Awaiting Approval -> Resolved
        # (analyst can reject back to Investigating). Keyed by the anomalous event id.
        c.execute('''
            CREATE TABLE IF NOT EXISTS alert_state (
                event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'OPEN',
                investigation_json TEXT,
                investigated_at TEXT,
                decided_by TEXT,
                decided_at TEXT,
                analyst_note TEXT,
                updated_at TEXT
            )
        ''')
        # An investigation interrupted by a restart goes back to the queue
        c.execute("UPDATE alert_state SET status = 'OPEN' WHERE status = 'AI Investigating'")
        conn.commit()
        conn.close()

    def insert_event(self, event_dict):
        conn = self.get_connection()
        c = conn.cursor()
        
        # Safely extract anomaly and mitre data
        anomaly = event_dict.get("anomaly") or {}
        is_anomalous = anomaly.get("is_anomalous", False)
        threat_score = anomaly.get("threat_score", 0)
        
        mitre_technique = None
        if anomaly.get("findings"):
            for f in anomaly["findings"]:
                if f.get("mitre_technique"):
                    mitre_technique = f["mitre_technique"]
                    break
        if not mitre_technique and event_dict.get("ai_mitre_techniques"):
            mitre_technique = event_dict["ai_mitre_techniques"][0]

        c.execute('''
            INSERT OR IGNORE INTO events (
                id, timestamp, received_at, detected_format, parser_name, parser_type, 
                event_type, severity, source_ip, source_port, destination_ip, 
                destination_port, user, host, process, protocol, message, 
                threat_score, is_anomalous, mitre_technique, category, raw_log, 
                normalized_json, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_dict.get("id"),
            event_dict.get("timestamp"),
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            event_dict.get("detected_format"),
            event_dict.get("parser_name"),
            event_dict.get("parser_type"),
            event_dict.get("event_type"),
            event_dict.get("severity"),
            event_dict.get("source_ip"),
            event_dict.get("source_port"),
            event_dict.get("destination_ip"),
            event_dict.get("destination_port"),
            event_dict.get("user"),
            event_dict.get("host"),
            event_dict.get("process"),
            event_dict.get("protocol"),
            event_dict.get("message"),
            threat_score,
            is_anomalous,
            mitre_technique,
            event_dict.get("category"),
            event_dict.get("raw_log"),
            json.dumps(event_dict),
            self.current_session_id
        ))
        conn.commit()
        conn.close()

    def get_events(self, limit=100, offset=0, search=None, severity=None, event_type=None, source_ip=None):
        conn = self.get_connection()
        c = conn.cursor()
        
        query = "SELECT normalized_json FROM events WHERE 1=1"
        params = []
        
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
        
        if search:
            query += " AND (raw_log LIKE ? OR message LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if severity and severity != 'ALL':
            query += " AND severity = ?"
            params.append(severity)
        if event_type and event_type != 'ALL':
            query += " AND event_type = ?"
            params.append(event_type)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
            
        # Count total
        count_query = query.replace("SELECT normalized_json", "SELECT COUNT(*)")
        c.execute(count_query, params)
        total = c.fetchone()[0]
        
        query += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, params)
        rows = c.fetchall()
        
        events = [json.loads(row[0]) for row in rows]
        conn.close()
        return {"events": events, "total": total}

    def get_anomalies(self, limit=100, offset=0, search=None, severity=None, source_ip=None, min_threat_score=None):
        conn = self.get_connection()
        c = conn.cursor()
        
        query = "SELECT normalized_json FROM events WHERE is_anomalous = 1"
        params = []
        
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
        
        if search:
            query += " AND (raw_log LIKE ? OR message LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if severity and severity != 'ALL':
            query += " AND severity = ?"
            params.append(severity)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if min_threat_score is not None:
            query += " AND threat_score >= ?"
            params.append(min_threat_score)
            
        count_query = query.replace("SELECT normalized_json", "SELECT COUNT(*)")
        c.execute(count_query, params)
        total = c.fetchone()[0]
        
        query += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        c.execute(query, params)
        rows = c.fetchall()
        
        anomalies = []
        for row in rows:
            evt = json.loads(row[0])
            anomaly_data = evt.get("anomaly", {})
            anomalies.append({
                "id": evt.get("id"),
                "timestamp": evt.get("timestamp"),
                "severity": evt.get("severity"),
                "threat_score": anomaly_data.get("threat_score"),
                "event_type": evt.get("event_type"),
                "source_ip": evt.get("source_ip"),
                "user": evt.get("user"),
                "host": evt.get("host"),
                "message": evt.get("message"),
                "raw_log": evt.get("raw_log"),
                "findings": anomaly_data.get("findings", []),
                "mitre_technique": anomaly_data.get("findings", [{}])[0].get("mitre_technique") if anomaly_data.get("findings") else None
            })
            
        conn.close()
        return {"anomalies": anomalies, "total": total}

    def get_alerts(self, limit=100, offset=0, status=None):
        conn = self.get_connection()
        c = conn.cursor()

        query = """
            SELECT e.normalized_json, COALESCE(s.status, 'OPEN'), s.investigation_json,
                   s.decided_by, s.decided_at, s.analyst_note
            FROM events e LEFT JOIN alert_state s ON s.event_id = e.id
            WHERE e.is_anomalous = 1
        """
        params = []

        if self.current_session_id:
            query += " AND e.session_id = ?"
            params.append(self.current_session_id)

        # Per-status counts for the workflow filter pills (before paging)
        c.execute(f"SELECT st, COUNT(*) FROM (SELECT COALESCE(s.status, 'OPEN') AS st {query[query.index('FROM'):]}) GROUP BY st", params)
        status_counts = {row[0]: row[1] for row in c.fetchall()}

        query += " ORDER BY e.threat_score DESC, e.received_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        c.execute(query, params)
        rows = c.fetchall()

        alerts = []
        for row in rows:
            evt = json.loads(row[0])
            anomaly_data = evt.get("anomaly", {})
            findings = anomaly_data.get("findings", [])
            title = findings[0].get("rule_name", "Unknown Anomaly Detected") if findings else "Anomaly Detected"
            desc = f"Threat Score {anomaly_data.get('threat_score')}. {len(findings)} findings."
            
            # Alert severity is the higher of the event's and the anomaly findings' severity
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": -1}
            severity = evt.get("severity") or "MEDIUM"
            if sev_rank.get(anomaly_data.get("max_severity"), -1) > sev_rank.get(severity, -1):
                severity = anomaly_data["max_severity"]

            alerts.append({
                "id": evt.get("id"),
                "timestamp": evt.get("timestamp"),
                "severity": severity,
                "title": title,
                "description": desc,
                "source_ip": evt.get("source_ip", "Unknown"),
                "host": evt.get("host", "Unknown"),
                "user": evt.get("user", "Unknown"),
                "threat_score": anomaly_data.get("threat_score"),
                "mitre_technique": findings[0].get("mitre_technique") if findings else None,
                "status": row[1],
                "investigation": json.loads(row[2]) if row[2] else None,
                "decided_by": row[3],
                "decided_at": row[4],
                "analyst_note": row[5]
            })

        conn.close()
        return {"alerts": alerts, "total": sum(status_counts.values()), "status_counts": status_counts}

    def _now(self):
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def set_alert_status(self, event_id, status, decided_by=None, note=None):
        conn = self.get_connection()
        c = conn.cursor()
        now = self._now()
        decided_at = now if decided_by else None
        c.execute('''
            INSERT INTO alert_state (event_id, status, decided_by, decided_at, analyst_note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                status = excluded.status,
                decided_by = COALESCE(excluded.decided_by, alert_state.decided_by),
                decided_at = COALESCE(excluded.decided_at, alert_state.decided_at),
                analyst_note = COALESCE(excluded.analyst_note, alert_state.analyst_note),
                updated_at = excluded.updated_at
        ''', (event_id, status, decided_by, decided_at, note, now))
        conn.commit()
        conn.close()

    def save_investigation(self, event_id, investigation, status="Awaiting Approval"):
        conn = self.get_connection()
        c = conn.cursor()
        now = self._now()
        c.execute('''
            INSERT INTO alert_state (event_id, status, investigation_json, investigated_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                status = excluded.status,
                investigation_json = excluded.investigation_json,
                investigated_at = excluded.investigated_at,
                updated_at = excluded.updated_at
        ''', (event_id, status, json.dumps(investigation), now, now))
        conn.commit()
        conn.close()

    def claim_next_uninvestigated_alert(self):
        """Atomically pick the highest-threat OPEN alert with no AI investigation yet
        and mark it 'AI Investigating'. Returns the event dict or None."""
        conn = self.get_connection()
        c = conn.cursor()
        query = """
            SELECT e.id, e.normalized_json FROM events e
            LEFT JOIN alert_state s ON s.event_id = e.id
            WHERE e.is_anomalous = 1
              AND (s.event_id IS NULL OR (s.status = 'OPEN' AND s.investigation_json IS NULL))
        """
        params = []
        if self.current_session_id:
            query += " AND e.session_id = ?"
            params.append(self.current_session_id)
        query += " ORDER BY e.threat_score DESC, e.received_at DESC LIMIT 1"
        c.execute(query, params)
        row = c.fetchone()
        if not row:
            conn.close()
            return None
        now = self._now()
        c.execute('''
            INSERT INTO alert_state (event_id, status, updated_at) VALUES (?, 'AI Investigating', ?)
            ON CONFLICT(event_id) DO UPDATE SET status = 'AI Investigating', updated_at = excluded.updated_at
        ''', (row[0], now))
        conn.commit()
        conn.close()
        return json.loads(row[1])

    @staticmethod
    def _primary_rule(evt):
        findings = (evt.get("anomaly") or {}).get("findings") or []
        return findings[0].get("rule_name") if findings else None

    def _sibling_alert_rows(self, evt, extra_where="", extra_params=()):
        """Anomalous events from the same source IP whose primary rule matches evt's."""
        if not evt.get("source_ip"):
            return []
        query = f"""
            SELECT e.id, e.normalized_json, s.status, s.investigation_json FROM events e
            LEFT JOIN alert_state s ON s.event_id = e.id
            WHERE e.is_anomalous = 1 AND e.source_ip = ? AND e.id != ? {extra_where}
        """
        params = [evt.get("source_ip"), evt.get("id"), *extra_params]
        if self.current_session_id:
            query += " AND e.session_id = ?"
            params.append(self.current_session_id)
        conn = self.get_connection()
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        rule = self._primary_rule(evt)
        return [r for r in rows if self._primary_rule(json.loads(r[1])) == rule]

    def get_sibling_ai_opinion(self, evt):
        for row in self._sibling_alert_rows(evt, "AND s.investigation_json IS NOT NULL"):
            opinion = json.loads(row[3]).get("ai_opinion")
            if opinion:
                return opinion
        return None

    def get_sibling_alert_ids(self, evt, status):
        return [r[0] for r in self._sibling_alert_rows(evt, "AND s.status = ?", (status,))]

    def get_related_events(self, evt, limit=50):
        """Events in this session sharing the alert's source IP, user or host."""
        clauses, params = [], []
        for col, key in (("source_ip", "source_ip"), ("user", "user"), ("host", "host")):
            val = evt.get(key)
            if val and str(val).lower() not in ("none", "unknown", "-", ""):
                clauses.append(f"{col} = ?")
                params.append(val)
        if not clauses:
            return []
        query = f"SELECT normalized_json FROM events WHERE id != ? AND ({' OR '.join(clauses)})"
        params.insert(0, evt.get("id"))
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        conn = self.get_connection()
        c = conn.cursor()
        c.execute(query, params)
        rows = [json.loads(r[0]) for r in c.fetchall()]
        conn.close()
        return rows

    def get_analytics_rows(self, limit=200000):
        """Lightweight per-event rows for geo / time-of-day aggregation."""
        query = "SELECT source_ip, timestamp, received_at, is_anomalous, threat_score, severity FROM events WHERE 1=1"
        params = []
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        conn = self.get_connection()
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows

    def get_sources(self):
        conn = self.get_connection()
        c = conn.cursor()
        
        query = """
        SELECT source_ip, 
               COUNT(*) as event_count, 
               SUM(is_anomalous) as anomaly_count,
               MAX(threat_score) as max_threat_score,
               MAX(received_at) as last_seen
        FROM events
        WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip != 'None'
        """
        params = []
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
            
        query += " GROUP BY source_ip"
        
        c.execute(query, params)
        rows = c.fetchall()
        
        sources = []
        for row in rows:
            sources.append({
                "source_ip": row[0],
                "event_count": row[1],
                "anomaly_count": row[2] or 0,
                "max_threat_score": row[3] or 0,
                "last_seen": row[4]
            })
            
        conn.close()
        return {"sources": sources, "total": len(sources)}

    def get_event(self, event_id):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT normalized_json FROM events WHERE id = ?", (event_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def delete_events(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM alert_state")
        conn.commit()
        conn.close()

db = DatabaseManager(config.DB_PATH)
