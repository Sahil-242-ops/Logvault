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
        
        query = "SELECT normalized_json FROM events WHERE is_anomalous = 1"
        params = []
        
        if self.current_session_id:
            query += " AND session_id = ?"
            params.append(self.current_session_id)
            
        query += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
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
            
            alerts.append({
                "id": evt.get("id"),
                "timestamp": evt.get("timestamp"),
                "severity": evt.get("severity", "MEDIUM"),
                "title": title,
                "description": desc,
                "source_ip": evt.get("source_ip", "Unknown"),
                "host": evt.get("host", "Unknown"),
                "user": evt.get("user", "Unknown"),
                "threat_score": anomaly_data.get("threat_score"),
                "mitre_technique": findings[0].get("mitre_technique") if findings else None,
                "status": "OPEN"
            })
            
        conn.close()
        return {"alerts": alerts, "total": len(alerts)}

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
        conn.commit()
        conn.close()

db = DatabaseManager(config.DB_PATH)
