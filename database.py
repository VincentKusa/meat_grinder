import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from core.confidence import ConfidenceLevel
from core.deduplication import FindingDeduplicator


class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
        self._migrate()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent write performance
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS subdomains (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, source TEXT)"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS endpoints (
                          id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE, status_code INTEGER,
                          title TEXT, tech_stack TEXT, content_length INTEGER, webserver TEXT,
                          headers_json TEXT, waf_detected TEXT)"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, ip TEXT,
                        ports TEXT, source TEXT, os TEXT, services TEXT,
                        UNIQUE(host, source))"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        finding_type TEXT,
                        url TEXT,
                        details TEXT,
                        severity TEXT,
                        confidence TEXT DEFAULT 'MEDIUM',
                        fingerprint TEXT UNIQUE,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        occurrences INTEGER DEFAULT 1,
                        source_module TEXT)"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS os_recon (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host TEXT UNIQUE, ip TEXT, os_name TEXT,
                        os_accuracy TEXT, hostname TEXT, open_ports TEXT)"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS dns_records (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       domain TEXT,
                       record_type TEXT,
                       record_value TEXT,
                       ttl INTEGER,
                       UNIQUE(domain, record_type, record_value))"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS tls_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host TEXT UNIQUE,
                        issuer TEXT,
                        subject TEXT,
                        sans TEXT,
                        not_before TEXT,
                        not_after TEXT,
                        tls_versions TEXT,
                        cipher_suite TEXT)"""
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS scan_runs (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     target TEXT,
                     scan_mode TEXT,
                     started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     completed_at TIMESTAMP,
                     total_findings INTEGER)"""
            )

    def _migrate(self):
        with self._get_conn() as conn:
            try:
                # --- FINDINGS TABLE MIGRATIONS ---
                cols = [row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()]
                if "confidence" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'MEDIUM'")
                if "fingerprint" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT UNIQUE")
                if "first_seen" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                if "last_seen" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                if "occurrences" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN occurrences INTEGER DEFAULT 1")
                if "source_module" not in cols:
                    conn.execute("ALTER TABLE findings ADD COLUMN source_module TEXT")

                # --- ENDPOINTS TABLE MIGRATIONS (FIXED) ---
                cols_ep = [row[1] for row in conn.execute("PRAGMA table_info(endpoints)").fetchall()]
                if "title" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN title TEXT")
                if "tech_stack" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN tech_stack TEXT")
                if "content_length" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN content_length INTEGER")
                if "webserver" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN webserver TEXT")
                if "headers_json" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN headers_json TEXT")
                if "waf_detected" not in cols_ep:
                    conn.execute("ALTER TABLE endpoints ADD COLUMN waf_detected TEXT")

                # --- PORTS TABLE MIGRATIONS ---
                cols_ports = [row[1] for row in conn.execute("PRAGMA table_info(ports)").fetchall()]
                if "os" not in cols_ports:
                    conn.execute("ALTER TABLE ports ADD COLUMN os TEXT")
                if "services" not in cols_ports:
                    conn.execute("ALTER TABLE ports ADD COLUMN services TEXT")

                # --- CREATE NEW TABLES IF THEY DON'T EXIST ---
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS dns_records (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           domain TEXT, record_type TEXT, record_value TEXT, ttl INTEGER,
                           UNIQUE(domain, record_type, record_value))"""
                )
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS tls_info (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            host TEXT UNIQUE, issuer TEXT, subject TEXT, sans TEXT,
                            not_before TEXT, not_after TEXT, tls_versions TEXT, cipher_suite TEXT)"""
                )
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS scan_runs (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         target TEXT, scan_mode TEXT,
                         started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                         completed_at TIMESTAMP, total_findings INTEGER)"""
                )
                cols = [row[1] for row in conn.execute("PRAGMA table_info(scan_runs)").fetchall()]
                if "status" not in cols:
                    conn.execute("ALTER TABLE scan_runs ADD COLUMN status TEXT DEFAULT 'COMPLETED'")
                if "current_step" not in cols:
                    conn.execute("ALTER TABLE scan_runs ADD COLUMN current_step TEXT DEFAULT 'START'")
            except sqlite3.OperationalError as e:
                print(f"[!] Migration warning: {e}")

    # ==========================================
    # SUBDOMAIN METHODS
    # ==========================================
    def insert_subdomain(self, domain: str, source: str) -> bool:
        """Insert a subdomain, returns True if new"""
        with self._get_conn() as conn:
            try:
                conn.execute("INSERT INTO subdomains (domain, source) VALUES (?, ?)", (domain, source))
                return True
            except sqlite3.IntegrityError:
                return False

    def get_all_subdomains(self) -> List[str]:
        with self._get_conn() as conn:
            return [row[0] for row in conn.execute("SELECT domain FROM subdomains").fetchall()]

    # ==========================================
    # ENDPOINT METHODS
    # ==========================================
    def insert_endpoint(self, url: str, status: int, title: str, tech: str, length: int, webserver: str = ""):
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO endpoints
                (url, status_code, title, tech_stack, content_length, webserver)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (url, status, title, tech, length, webserver),
            )

    def update_endpoint_headers(self, url: str, headers_json: str, waf: str):
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE endpoints
                            SET headers_json = ?, waf_detected = ?
                            WHERE url = ?""",
                (headers_json, waf, url),
            )

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM endpoints").fetchall()]

    # ==========================================
    # PORT METHODS
    # ==========================================
    def insert_port(self, host: str, ip: str, ports: list, source: str, os_info: str = "", services: dict = None):
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ports
                (host, ip, ports, source, os, services)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (host, ip, json.dumps(ports), source, os_info, json.dumps(services or {})),
            )

    def get_all_ports(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM ports").fetchall()]

    # ==========================================
    # OS RECON METHODS
    # ==========================================
    def insert_os_recon(self, host: str, ip: str, os_name: str, accuracy: str, hostname: str, ports: str):
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO os_recon
                (host, ip, os_name, os_accuracy, hostname, open_ports)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (host, ip, os_name, accuracy, hostname, ports),
            )

    def get_all_os_recon(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM os_recon").fetchall()]

    # ==========================================
    # FINDING METHODS (WITH DEDUPLICATION)
    # ==========================================
    def insert_finding(
        self,
        f_type: str,
        url: str,
        details: str,
        severity: str,
        confidence: ConfidenceLevel = None,
        source_module: str = None,
        file_path: str = None,
        rule_id: str = None,
    ) -> bool:
        """Insert a finding with deduplication support. Returns True if new finding."""
        # Generate fingerprint
        fingerprint = FindingDeduplicator.generate_fingerprint(f_type, url, details, file_path, rule_id)

        # Get confidence level
        if confidence is None:
            confidence = ConfidenceLevel.MEDIUM

        with self._get_conn() as conn:
            # Check if finding already exists
            existing = conn.execute(
                "SELECT id, occurrences FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()

            if existing:
                # Update existing finding
                conn.execute(
                    """
                             UPDATE findings
                             SET occurrences = occurrences + 1, last_seen = CURRENT_TIMESTAMP
                             WHERE fingerprint = ?
                             """,
                    (fingerprint,),
                )
                return False  # Not a new finding
            else:
                # Insert new finding
                conn.execute(
                    """
                             INSERT INTO findings
                             (finding_type, url, details, severity, confidence, fingerprint, source_module)
                             VALUES (?, ?, ?, ?, ?, ?, ?)
                             """,
                    (f_type, url, details, severity, confidence.value, fingerprint, source_module),
                )
                return True  # New finding

    def get_all_findings(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(row)
                for row in conn.execute("SELECT * FROM findings ORDER BY severity DESC, confidence DESC").fetchall()
            ]

    def get_new_findings_since(self, timestamp: str) -> List[Dict[str, Any]]:
        """Get findings discovered since a specific timestamp"""
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM findings WHERE first_seen > ? ORDER BY severity DESC", (timestamp,)
                ).fetchall()
            ]

    def clear_findings(self):
        """Clear all findings (used at start of new scan)"""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM findings")

    # ==========================================
    # SCAN RUN TRACKING
    # ==========================================
    def get_last_scan_time(self, target: str) -> str:
        """Get the timestamp of the last completed scan for a target"""
        with self._get_conn() as conn:
            result = conn.execute(
                """SELECT completed_at FROM scan_runs
                   WHERE target = ? AND completed_at IS NOT NULL
                   ORDER BY completed_at DESC LIMIT 1""",
                (target,),
            ).fetchone()
            return result[0] if result else None

    def record_scan_run(self, target: str, scan_mode: str, total_findings: int):
        """Record a completed scan run"""
        with self._get_conn() as conn:
            conn.execute(
                """
                         INSERT INTO scan_runs (target, scan_mode, completed_at, total_findings)
                         VALUES (?, ?, CURRENT_TIMESTAMP, ?)
                         """,
                (target, scan_mode, total_findings),
            )

    # ==========================================
    # CHECKPOINT & RESUME METHODS
    # ==========================================

    def get_interrupted_scan(self, target: str):
        """Check if there's an unfinished scan for this target."""
        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT id, scan_mode, current_step FROM scan_runs
                WHERE target = ? AND status IN ('RUNNING', 'INTERRUPTED')
                ORDER BY started_at DESC LIMIT 1""",
                (target,),
            ).fetchone()
            return row  # Returns (id, scan_mode, current_step) or None

    def start_scan_run(self, target: str, mode: str) -> int:
        """Create a new scan run record."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_runs (target, scan_mode, status, current_step) " "VALUES (?, ?, 'RUNNING', 'START')",
                (target, mode),
            )
            return cursor.lastrowid

    def update_scan_step(self, run_id: int, step: str):
        """Update the current step of an ongoing scan."""
        with self._get_conn() as conn:
            conn.execute("UPDATE scan_runs SET current_step = ? WHERE id = ?", (step, run_id))

    def complete_scan_run(self, run_id: int, total_findings: int):
        """Mark a scan run as successfully completed."""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE scan_runs SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP, "
                "total_findings = ? WHERE id = ?",
                (total_findings, run_id),
            )

    def mark_scan_interrupted(self, run_id: int):
        """Mark a scan run as interrupted (for graceful shutdown)."""
        with self._get_conn() as conn:
            conn.execute("UPDATE scan_runs SET status = 'INTERRUPTED' WHERE id = ?", (run_id,))
