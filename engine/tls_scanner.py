import socket
import ssl
from datetime import datetime

from engine.base import BaseReconModule


class TLSScanner(BaseReconModule):
    def execute(self):
        print("[*] Performing TLS/certificate intelligence...")

        endpoints = self.db.get_all_endpoints()
        https_endpoints = [ep for ep in endpoints if ep["url"].startswith("https://")]

        findings_count = 0
        for ep in https_endpoints:
            findings_count += self._analyze_tls(ep["url"])

        print(f"[+] TLS analysis complete. Found {findings_count} insights.")

    def _analyze_tls(self, url: str) -> int:
        findings = 0

        try:
            # Extract hostname from URL
            from urllib.parse import urlparse

            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443

            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

            # Parse certificate
            issuer = dict(x[0] for x in cert["issuer"])
            subject = dict(x[0] for x in cert["subject"])
            sans = [x[1] for x in cert.get("subjectAltName", [])]

            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

            # Store TLS info
            with self.db._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tls_info
                    (host, issuer, subject, sans, not_before, not_after, tls_versions, cipher_suite)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        hostname,
                        issuer.get("organizationName", "Unknown"),
                        subject.get("commonName", "Unknown"),
                        ", ".join(sans),
                        not_before.isoformat(),
                        not_after.isoformat(),
                        version,
                        cipher[0] if cipher else "Unknown",
                    ),
                )

            # Check for issues
            findings += self._check_cert_expiry(hostname, not_after)
            findings += self._check_self_signed(issuer, subject)
            findings += self._check_hostname_match(hostname, cert)
            findings += self._check_tls_version(version)
            findings += self._discover_sans(hostname, sans)

        except ssl.SSLError as e:
            self.db.insert_finding(
                "TLS_ERROR", url, f"TLS connection failed: {str(e)[:100]}", "HIGH", source_module="tls_scanner"
            )
            findings += 1
        except Exception:
            pass

        return findings

    def _check_cert_expiry(self, hostname: str, not_after: datetime) -> int:
        days_until_expiry = (not_after - datetime.now()).days

        if days_until_expiry < 0:
            self.db.insert_finding(
                "TLS_CERT_EXPIRED",
                f"tls://{hostname}",
                f"Certificate expired {abs(days_until_expiry)} days ago",
                "CRITICAL",
                source_module="tls_scanner",
            )
            return 1
        elif days_until_expiry < 30:
            self.db.insert_finding(
                "TLS_CERT_EXPIRING_SOON",
                f"tls://{hostname}",
                f"Certificate expires in {days_until_expiry} days",
                "HIGH",
                source_module="tls_scanner",
            )
            return 1
        return 0

    def _check_self_signed(self, issuer: dict, subject: dict) -> int:
        if issuer == subject:
            self.db.insert_finding(
                "TLS_SELF_SIGNED",
                f'tls://{subject.get("commonName", "unknown")}',
                "Certificate is self-signed",
                "MEDIUM",
                source_module="tls_scanner",
            )
            return 1
        return 0

    def _check_hostname_match(self, hostname: str, cert: dict) -> int:
        # Check if hostname matches certificate
        from ssl import match_hostname

        try:
            match_hostname(cert, hostname)
            return 0
        except ssl.CertificateError:
            self.db.insert_finding(
                "TLS_HOSTNAME_MISMATCH",
                f"tls://{hostname}",
                "Certificate does not match hostname",
                "HIGH",
                source_module="tls_scanner",
            )
            return 1

    def _check_tls_version(self, version: str) -> int:
        weak_versions = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
        if any(weak in version for weak in weak_versions):
            self.db.insert_finding(
                "TLS_WEAK_PROTOCOL",
                "tls://",
                f"Weak TLS version in use: {version}",
                "HIGH",
                source_module="tls_scanner",
            )
            return 1
        return 0

    def _discover_sans(self, hostname: str, sans: list) -> int:
        # Discover new subdomains from certificate SANs
        new_subs = 0
        for san in sans:
            if san.endswith(self.target) and san != hostname:
                if self.db.insert_subdomain(san, "tls_san"):
                    new_subs += 1
        return new_subs
