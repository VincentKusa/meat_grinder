import re

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WaybackScanner(BaseReconModule):
    WAYBACK_API = "http://web.archive.org/cdx/search/cdx"
    INTERESTING_EXTENSIONS = [".js", ".json", ".env", ".bak", ".xml", ".yaml", ".yml", ".config", ".git"]

    def execute(self):
        print("[*] Querying Wayback Machine for historical assets...")
        target = f"*.{self.target}" if not self.target.startswith("*.") else self.target

        params = {"url": target, "output": "json", "fl": "original", "collapse": "urlkey", "limit": 1000}

        try:
            resp = requests.get(self.WAYBACK_API, params=params, timeout=30, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    urls = [row[0] for row in data[1:]]  # Skip header row
                    interesting_urls = [u for u in urls if any(u.endswith(ext) for ext in self.INTERESTING_EXTENSIONS)]

                    print(f"[*] Found {len(interesting_urls)} historical interesting URLs. Sampling for secrets...")

                    findings = 0
                    for url in interesting_urls[:100]:  # Sample top 100 to save time/bandwidth
                        if self._check_historical_url(url):
                            findings += 1
                    print(f"[+] Wayback analysis complete. Found {findings} historical insights.")
                else:
                    print("[*] No historical records found in Wayback Machine.")
            else:
                print(f"[!] Wayback API returned status {resp.status_code}")
        except Exception as e:
            print(f"[!] Wayback Machine query failed: {e}")

    def _check_historical_url(self, url: str) -> bool:
        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            if resp.status_code == 200:
                content = resp.text[:4096]  # Check first 4KB

                patterns = [
                    re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}'),
                    re.compile(r"(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
                    re.compile(r"(?i)aws_access_key_id|aws_secret_access_key"),
                    re.compile(r"(?i)STRIPE_SECRET_KEY"),
                ]

                if any(p.search(content) for p in patterns):
                    self.db.insert_finding(
                        f_type="HISTORICAL_SECRET_LEAK",
                        url=url,
                        details="Historical URL contains potential secret patterns",
                        severity="HIGH",
                        source_module="wayback_scanner",
                    )
                    return True
        except Exception:
            pass
        return False
