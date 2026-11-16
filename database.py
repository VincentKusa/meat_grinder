import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
        self._migrate()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS subdomains
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY
                                AUTOINCREMENT,
                                domain
                                TEXT
                                UNIQUE,
                                source
                                TEXT
                            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS endpoints
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY
                                AUTOINCREMENT,
                                url
                                TEXT
                                UNIQUE,
                                status_code
                                INTEGER,
                                title
                                TEXT,
                                tech_stack
                                TEXT,
                                content_length
                                INTEGER,
                                webserver
                                TEXT,
                                headers_json
                                TEXT,
                                waf_detected
                                TEXT
                            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS ports
            (
                id
                INTEGER
                PRIMARY
                KEY
                AUTOINCREMENT,
                host
                TEXT,
                ip
                TEXT,
                ports
                TEXT,
                source
                TEXT,
                os
                TEXT,
                services
                TEXT,
                UNIQUE
                            (
                host,
                source
                            ))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS findings
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY
                                AUTOINCREMENT,
                                finding_type
                                TEXT,
                                url
                                TEXT,
                                details
                                TEXT,
                                severity
                                TEXT
                            )""")

    def _migrate(self):
        with self._get_conn() as conn:
            try:
                cols = [row[1] for row in conn.execute("PRAGMA table_info(endpoints)").fetchall()]
                if 'headers_json' not in cols:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN headers_json TEXT")
                if 'waf_detected' not in cols:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN waf_detected TEXT")

                cols_ports = [row[1] for row in conn.execute("PRAGMA table_info(ports)").fetchall()]
                if 'os' not in cols_ports:
                    conn.execute("ALTER TABLE ports ADD COLUMN os TEXT")
                if 'services' not in cols_ports:
                    conn.execute("ALTER TABLE ports ADD COLUMN services TEXT")
            except sqlite3.OperationalError:
                pass

    def insert_subdomain(self, domain: str, source: str):
        with self._get_conn() as conn:
            conn.execute("INSERT OR IGNORE INTO subdomains (domain, source) VALUES (?, ?)", (domain, source))

    def update_endpoint_headers(self, url: str, headers_json: str, waf: str):
        with self._get_conn() as conn:
            conn.execute("""UPDATE endpoints
                            SET headers_json = ?,
                                waf_detected = ?
                            WHERE url = ?""",
                         (headers_json, waf, url))

    def insert_endpoint(self, url: str, status: int, title: str, tech: str, length: int, webserver: str = ''):
        with self._get_conn() as conn:
            conn.execute("""INSERT
            OR IGNORE INTO endpoints 
                (url, status_code, title, tech_stack, content_length, webserver) 
                VALUES (?, ?, ?, ?, ?, ?)""", (url, status, title, tech, length, webserver))

    def insert_port(self, host: str, ip: str, ports: list, source: str, os_info: str = '', services: dict = None):
        with self._get_conn() as conn:
            conn.execute("""INSERT OR REPLACE INTO ports 
                (host, ip, ports, source, os, services) 
                VALUES (?, ?, ?, ?, ?, ?)""",
                         (host, ip, json.dumps(ports), source, os_info, json.dumps(services or {})))

    def insert_finding(self, f_type: str, url: str, details: str, severity: str):
        with self._get_conn() as conn:
            conn.execute("INSERT INTO findings (finding_type, url, details, severity) VALUES (?, ?, ?, ?)",
                         (f_type, url, details, severity))

    def get_all_subdomains(self) -> List[str]:
        with self._get_conn() as conn:
            return [row[0] for row in conn.execute("SELECT domain FROM subdomains").fetchall()]

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM endpoints").fetchall()]

    def get_all_ports(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM ports").fetchall()]

    def get_all_findings(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY severity DESC").fetchall()]

    def clear_findings(self):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM findings")