import random
import string

import requests
import urllib3

from database import ConfidenceLevel
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SensitiveFileScanner(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        self.files_to_check = [
            ".env",
            ".env.bak",
            ".env.local",
            ".env.production",
            ".git/config",
            ".git/HEAD",
            "wp-config.php",
            "config.php",
            "database.yml",
            "secrets.json",
            "credentials.json",
            ".aws/credentials",
            "id_rsa",
            "id_dsa",
            ".htpasswd",
            "backup.sql",
            "dump.sql",
            "db.sql",
        ]

    def _get_baseline_404_length(self, base_url: str) -> int:
        """Get the length of a custom 404 page to filter fake positives."""
        try:
            random_path = "".join(random.choices(string.ascii_lowercase, k=16))
            resp = requests.get(f"{base_url}/{random_path}", timeout=10, verify=False)
            return len(resp.text)
        except Exception:
            return 0

    def execute(self):
        print("[*] Scanning for exposed sensitive files...")
        endpoints = self.db.get_all_endpoints()
        base_urls = list(
            set([f"{ep['url'].split('://')[0]}://{ep['url'].split('://')[1].split('/')[0]}" for ep in endpoints])
        )

        print(f"[*] Checking {len(self.files_to_check)} file types across {len(base_urls)} base URLs...")
        findings_count = 0

        # FIX: Calculate baseline per base URL
        baselines = {}
        for base_url in base_urls:
            baselines[base_url] = self._get_baseline_404_length(base_url)
            if baselines[base_url] > 0:
                print(f"  [*] Baseline 404 length for {base_url}: {baselines[base_url]} bytes")

        for base_url in base_urls:
            baseline_404_len = baselines[base_url]

            for file_path in self.files_to_check:
                url = f"{base_url.rstrip('/')}/{file_path.lstrip('/')}"
                try:
                    resp = requests.get(url, timeout=10, verify=False)

                    # FIX: Ignore fake 404s (custom error pages returning 200 with static length)
                    if resp.status_code == 200 and baseline_404_len > 0:
                        # Allow 10% variance in content length
                        variance = abs(len(resp.text) - baseline_404_len) / baseline_404_len
                        if variance < 0.10:
                            continue

                    if resp.status_code == 200:
                        text = resp.text[:2000]
                        if any(
                            pattern in text
                            for pattern in ["DB_PASSWORD", "SECRET_KEY", "PRIVATE KEY", "aws_access_key", "STRIPE"]
                        ):
                            self.db.insert_finding(
                                f_type="EXPOSED_SENSITIVE_FILE",
                                url=url,
                                details="Status: 200, Regex matched potential secrets/config data",
                                severity="CRITICAL",
                                confidence=ConfidenceLevel.CONFIRMED,
                                source_module="sensitive_file_scanner",
                            )
                            findings_count += 1
                        else:
                            self.db.insert_finding(
                                f_type="EXPOSED_FILE",
                                url=url,
                                details=f"Status: 200, Content Length: {len(resp.text)} bytes (No obvious secrets)",
                                severity="MEDIUM",
                                confidence=ConfidenceLevel.MEDIUM,
                                source_module="sensitive_file_scanner",
                            )
                    elif resp.status_code == 403 and ".git" in file_path:
                        self.db.insert_finding(
                            f_type="PROTECTED_SENSITIVE_FILE",
                            url=url,
                            details="Status: 403 (File/Directory exists but access forbidden)",
                            severity="MEDIUM",
                            confidence=ConfidenceLevel.MEDIUM,
                            source_module="sensitive_file_scanner",
                        )
                except Exception:
                    pass

        print(f"[+] Found {findings_count} validated exposed sensitive files.")
