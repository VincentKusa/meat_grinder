"""Actively test FTP services for anonymous access and misconfigurations."""

import socket
from ftplib import FTP, error_perm

from database import ConfidenceLevel  # Import the enum
from engine.base import BaseReconModule


class FTPAnonymousChecker(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)

    def execute(self):
        print("[*] Testing FTP services for anonymous access...")

        # Query the ports table directly for hosts with port 21 open
        hosts_with_ftp = self._get_hosts_with_port_21()

        if not hosts_with_ftp:
            print("[*] No hosts with port 21 (FTP) found. Skipping FTP check.")
            return

        print(f"[*] Testing {len(hosts_with_ftp)} hosts with FTP (port 21) open...")
        confirmed_count = 0

        for host_data in hosts_with_ftp:
            host = host_data["host"]

            # Test anonymous FTP login
            creds_used = self._test_anonymous_ftp(host)

            if creds_used:
                confirmed_count += 1

                # Insert CRITICAL finding with credentials included
                self.db.insert_finding(
                    f_type="ANONYMOUS_FTP_ACCESS",
                    url=f"ftp://{host}",
                    details=(
                        f"Anonymous FTP login successful on {host}. "
                        f"Credentials used: {creds_used}. "
                        f"Directory listing accessible."
                    ),
                    severity="CRITICAL",
                    confidence=ConfidenceLevel.CONFIRMED,  # Use enum, not string
                    source_module="ftp_anonymous_checker",
                )

        print(f"[+] FTP testing complete. Confirmed {confirmed_count} anonymous FTP services.")

    def _get_hosts_with_port_21(self) -> list:
        """Query database for hosts with port 21 open."""
        with self.db._get_conn() as conn:
            rows = conn.execute("SELECT host, ip, ports FROM ports WHERE ports LIKE '%21%'").fetchall()

            hosts = []
            for row in rows:
                # Parse the ports JSON to verify 21 is actually open
                import json

                try:
                    ports_list = json.loads(row["ports"]) if row["ports"] else []
                    if 21 in ports_list:
                        hosts.append({"host": row["host"], "ip": row["ip"]})
                except (json.JSONDecodeError, TypeError):
                    # If ports field is malformed, check if '21' is in the string
                    if "21" in str(row["ports"]):
                        hosts.append({"host": row["host"], "ip": row["ip"]})

            return hosts

    def _test_anonymous_ftp(self, host: str) -> str | None:
        """
        Test if FTP allows anonymous login.
        Returns the credentials used if successful, None otherwise.
        """
        # Try common anonymous credential combinations
        credential_attempts = [
            ("anonymous", "anonymous"),
            ("anonymous", "anonymous@" + host),
            ("anonymous", "ftp"),
            ("ftp", "ftp"),
        ]

        for username, password in credential_attempts:
            try:
                ftp = FTP()
                ftp.connect(host, 21, timeout=10)

                # Try login with these credentials
                response = ftp.login(username, password)

                if "230" in response or "logged in" in response.lower():
                    # Try to list directory to confirm access
                    try:
                        ftp.nlst()
                        ftp.quit()
                        return f"{username}/{password}"  # Return successful credentials
                    except error_perm:
                        # Login worked but no directory listing
                        ftp.quit()
                        return f"{username}/{password}"
                else:
                    ftp.quit()

            except (socket.timeout, socket.error, EOFError, Exception):
                # Connection failed or login rejected, try next credentials
                continue

        return None  # No credentials worked
