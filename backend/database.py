"""
SQLite Persistence & Threat Audit Logging
Member 3 — Backend
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any


class ScanDatabase:
    def __init__(self, db_path: str = "data/scans.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    verdict_severity TEXT NOT NULL,
                    impersonated_brand TEXT,
                    latency_ms INTEGER,
                    scanned_at TEXT NOT NULL,
                    payload_json TEXT
                )
            """)
            conn.commit()

    def add_scan(self, report: Dict[str, Any]) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scans (
                    url, hostname, risk_score, verdict, verdict_severity,
                    impersonated_brand, latency_ms, scanned_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.get("url"),
                report.get("hostname"),
                report.get("riskScore", 0),
                report.get("verdict", "UNKNOWN"),
                report.get("verdictSeverity", "safe"),
                report.get("impersonatedBrand"),
                report.get("latencyMs", 200),
                report.get("scannedAt", datetime.now(timezone.utc).isoformat()),
                json.dumps(report)
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT id, url, hostname, risk_score, verdict, verdict_severity,
                       impersonated_brand, latency_ms, scanned_at, payload_json
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()
            
            results = []
            for r in rows:
                item = dict(r)
                if item.get("payload_json"):
                    try:
                        item["full_report"] = json.loads(item["payload_json"])
                    except Exception:
                        item["full_report"] = None
                results.append(item)
            return results

    def get_telemetry_stats(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict_severity = 'danger'").fetchone()[0]
            suspicious = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict_severity = 'warning'").fetchone()[0]
            safe = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict_severity = 'safe'").fetchone()[0]
            avg_latency = conn.execute("SELECT AVG(latency_ms) FROM scans").fetchone()[0]

            return {
                "total_scans": total,
                "phishing_detected": phishing,
                "suspicious_flagged": suspicious,
                "safe_verified": safe,
                "avg_latency_ms": round(avg_latency or 210, 1),
            }


db = ScanDatabase()
