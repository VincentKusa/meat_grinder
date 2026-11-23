import re

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebContentScanner(BaseReconModule):
    def execute(self):
        print("[*] Scanning web content (.js, .html) for hardcoded secrets...")
        endpoints = self.db.get_all_endpoints()
        print(f"[*] Analyzing content of {len(endpoints)} live endpoints...")
        findings_count = 0

        # Enhanced patterns for modern JS frameworks
        js_secret_patterns = [
            r'(?i)(?:api[_-]?key|secret[_-]?key|password|token|auth)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r"(?i)(AIza[a-zA-Z0-9_\-]{35})",  # Google API
            r"(?i)(AKIA[a-zA-Z0-9]{16})",  # AWS
            r"(?i)(ghp_[a-zA-Z0-9]{36})",  # GitHub
        ]

        for ep in endpoints:
            url = ep["url"]
            if not url.startswith("http"):
                continue

            try:
                resp = requests.get(url, timeout=10, verify=False)
                text = resp.text

                # FIX: Aggressive extraction for Next.js/Webpack chunks
                if "static/chunks" in url or "webpack" in url or url.endswith(".js"):
                    for pattern in js_secret_patterns:
                        for match in re.findall(pattern, text):
                            self.db.insert_finding(
                                f_type="DEEP_JS_SECRET",
                                url=url,
                                details=f"Hardcoded secret found in JS chunk: {match[:30]}...",
                                severity="HIGH",
                                confidence="HIGH",
                                source_module="web_content_scanner",
                            )
                            findings_count += 1

                # ... (keep your existing standard HTML secret scanning logic here) ...

            except Exception:
                pass

        print(f"[+] Found {findings_count} potential secrets in web content.")
