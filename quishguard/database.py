import sqlite3
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from quishguard.config import DATA_DIR

DB_PATH = DATA_DIR / "quishguard.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_type TEXT NOT NULL,
            filename TEXT,
            qr_detected INTEGER NOT NULL,
            raw_payload TEXT,
            payload_type TEXT,
            normalized_url TEXT,
            domain TEXT,
            protocol TEXT,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            threat_types TEXT,
            indicators TEXT,
            redirect_chain TEXT,
            threat_intel TEXT,
            recommendation TEXT NOT NULL,
            client_ip TEXT,
            qr_metadata TEXT
        )
    """)
    
    # Auto-migrate existing databases
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN qr_metadata TEXT")
    except Exception:
        pass
    
    # Blocklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE NOT NULL,
            target_type TEXT NOT NULL, -- 'domain' or 'url'
            reason TEXT NOT NULL,
            added_at TEXT NOT NULL,
            added_by TEXT DEFAULT 'SOC_AUTOMATION'
        )
    """)
    
    # SIEM Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS siem_events (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

def save_scan(scan_data: Dict[str, Any]) -> str:
    scan_id = scan_data.get("id") or f"QR-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO scans (
            id, timestamp, source_type, filename, qr_detected,
            raw_payload, payload_type, normalized_url, domain, protocol,
            risk_score, classification, threat_types, indicators,
            redirect_chain, threat_intel, recommendation, client_ip, qr_metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        scan_data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        scan_data.get("source_type", "unknown"),
        scan_data.get("filename"),
        1 if scan_data.get("qr_detected") else 0,
        scan_data.get("raw_payload", ""),
        scan_data.get("payload_type", "UNKNOWN"),
        scan_data.get("normalized_url", ""),
        scan_data.get("domain", ""),
        scan_data.get("protocol", ""),
        int(scan_data.get("risk_score", 0)),
        scan_data.get("classification", "UNKNOWN"),
        json.dumps(scan_data.get("threat_types", [])),
        json.dumps(scan_data.get("indicators", [])),
        json.dumps(scan_data.get("redirect_chain", [])),
        json.dumps(scan_data.get("threat_intel", {})),
        scan_data.get("recommendation", "ALLOW"),
        scan_data.get("client_ip", "127.0.0.1"),
        json.dumps(scan_data.get("qr_metadata", {}))
    ))
    
    conn.commit()
    conn.close()
    return scan_id

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
        
    data = dict(row)
    data["qr_detected"] = bool(data["qr_detected"])
    data["threat_types"] = json.loads(data.get("threat_types") or "[]")
    data["indicators"] = json.loads(data.get("indicators") or "[]")
    data["redirect_chain"] = json.loads(data.get("redirect_chain") or "[]")
    data["threat_intel"] = json.loads(data.get("threat_intel") or "{}")
    data["qr_metadata"] = json.loads(data.get("qr_metadata") or "{}") if "qr_metadata" in data and data["qr_metadata"] else {}
    data.setdefault("qr_metadata", {})
    return data

def get_history(limit: int = 100, offset: int = 0, classification: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM scans WHERE 1=1"
    params = []
    
    if classification and classification.upper() != "ALL":
        query += " AND UPPER(classification) = ?"
        params.append(classification.upper())
        
    if search:
        query += " AND (domain LIKE ? OR normalized_url LIKE ? OR id LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])
        
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        item = dict(r)
        item["qr_detected"] = bool(item["qr_detected"])
        item["threat_types"] = json.loads(item.get("threat_types") or "[]")
        item["indicators"] = json.loads(item.get("indicators") or "[]")
        item["redirect_chain"] = json.loads(item.get("redirect_chain") or "[]")
        item["threat_intel"] = json.loads(item.get("threat_intel") or "{}")
        item["qr_metadata"] = json.loads(item.get("qr_metadata") or "{}") if "qr_metadata" in item and item["qr_metadata"] else {}
        item.setdefault("qr_metadata", {})
        results.append(item)
    return results

def get_dashboard_metrics() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SAFE'")
    safe_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'LOW RISK'")
    low_risk_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SUSPICIOUS'")
    suspicious_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification LIKE '%PHISHING%'")
    phishing_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification LIKE '%MALWARE%'")
    malware_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification LIKE '%DANGEROUS%'")
    dangerous_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_score_row = cursor.fetchone()[0]
    avg_score = round(avg_score_row or 0, 1)
    
    cursor.execute("""
        SELECT domain, COUNT(*) as count 
        FROM scans 
        WHERE domain IS NOT NULL AND domain != ''
        GROUP BY domain 
        ORDER BY count DESC 
        LIMIT 5
    """)
    top_domains = [{"domain": r[0], "count": r[1]} for r in cursor.fetchall()]
    
    cursor.execute("""
        SELECT * FROM scans 
        ORDER BY timestamp DESC 
        LIMIT 8
    """)
    recent_rows = cursor.fetchall()
    recent_scans = []
    for r in recent_rows:
        item = dict(r)
        item["threat_types"] = json.loads(item["threat_types"] or "[]")
        recent_scans.append(item)
        
    conn.close()
    
    return {
        "total_scans": total_scans,
        "safe_scans": safe_scans,
        "low_risk_scans": low_risk_scans,
        "suspicious_scans": suspicious_scans,
        "phishing_scans": phishing_scans,
        "malware_scans": malware_scans,
        "dangerous_scans": dangerous_scans,
        "avg_risk_score": avg_score,
        "top_domains": top_domains,
        "recent_scans": recent_scans
    }

def add_to_blocklist(target: str, target_type: str, reason: str, added_by: str = "SOC_ANALYST") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO blocklist (target, target_type, reason, added_at, added_by)
            VALUES (?, ?, ?, ?, ?)
        """, (target.lower().strip(), target_type, reason, datetime.utcnow().isoformat() + "Z", added_by))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()

def is_blocked(domain_or_url: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    target = domain_or_url.lower().strip()
    cursor.execute("SELECT * FROM blocklist WHERE target = ?", (target,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_blocklist() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocklist ORDER BY added_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def log_siem_event(scan_id: str, severity: str, event_type: str, details: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    event_id = f"SIEM-{uuid.uuid4().hex[:8].upper()}"
    cursor.execute("""
        INSERT INTO siem_events (id, scan_id, timestamp, severity, event_type, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_id,
        scan_id,
        datetime.utcnow().isoformat() + "Z",
        severity,
        event_type,
        json.dumps(details)
    ))
    conn.commit()
    conn.close()
    return event_id

def get_siem_events(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM siem_events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        item = dict(r)
        item["details"] = json.loads(item["details"] or "{}")
        results.append(item)
    return results

# Initialize database schema on import
init_db()
