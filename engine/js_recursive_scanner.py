import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JSRecursiveScanner(BaseReconModule):
    SECRET_PATTERNS = [
        re.compile(
            r'(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'
        ),
        re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
        re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),
        re.compile(r"(?i)AIza[0-9A-Za-z_\-]{35}"),
        re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ]

    def execute(self):
        print("[*] Performing recursive JavaScript crawling (Depth 2)...")
        endpoints = self.db.get_all_endpoints()
        live_urls = [ep["url"] for ep in endpoints if ep["status_code"] in [200, 301, 302]]

        discovered_js = set()

        # Depth 1: Extract JS links from main HTML pages
        print("[*] Depth 1: Extracting JS files from live endpoints...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._extract_js_from_html, url): url for url in live_urls}
            for future in as_completed(futures):
                discovered_js.update(future.result())

        print(f"[*] Found {len(discovered_js)} unique JS files. Scanning and crawling deeper...")

        findings_count = 0
        # Depth 2: Fetch and scan those JS files
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._analyze_js_file, url): url for url in list(discovered_js)[:150]
            }  # Limit to 150

            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings_count += 1

        print(f"[+] Recursive JS crawling complete. Found {findings_count} deep insights.")

    def _extract_js_from_html(self, url: str) -> set:
        js_files = set()
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    js_files.add(urljoin(url, src))
        except Exception:
            pass
        return js_files

    def _analyze_js_file(self, url: str) -> bool:
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200 and (
                "javascript" in resp.headers.get("content-type", "").lower() or url.endswith(".js")
            ):
                content = resp.text[:50000]  # Cap at 50KB to avoid massive bundles

                # Check for secrets
                for pattern in self.SECRET_PATTERNS:
                    if pattern.search(content):
                        self.db.insert_finding(
                            f_type="DEEP_JS_SECRET",
                            url=url,
                            details="Hardcoded secret found in recursively discovered JS file",
                            severity="HIGH",
                            source_module="js_recursive_scanner",
                        )
                        return True
        except Exception:
            pass
        return False
