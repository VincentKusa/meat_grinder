import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SourceMapScanner(BaseReconModule):
    # Patterns to look for in source maps
    SENSITIVE_PATTERNS = [
        re.compile(r'(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}'),
        re.compile(r"(?i)(TODO|FIXME|HACK|XXX)\s*:?\s*.{10,100}"),
        re.compile(r"(?i)(internal|staging|dev|test)[\.\-_][a-z0-9\-]+\.(com|net|org|io)"),
        re.compile(r"(?i)localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"),
    ]

    def execute(self):
        print("[*] Scanning for JavaScript source maps...")

        endpoints = self.db.get_all_endpoints()
        js_files = set()

        # Collect all JS files from endpoints
        for ep in endpoints:
            if ep["status_code"] in [200, 301, 302]:
                js_files.update(self._extract_js_files(ep["url"]))

        print(f"[*] Found {len(js_files)} JS files. Checking for source maps...")

        findings_count = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_sourcemap, js_url): js_url for js_url in js_files}

            for future in as_completed(futures):
                if future.result():
                    findings_count += 1

        print(f"[+] Source map scanning complete. Found {findings_count} insights.")

    def _extract_js_files(self, url: str) -> set:
        """Extract JS file URLs from HTML"""
        js_files = set()
        try:
            from bs4 import BeautifulSoup

            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)

            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    js_files.add(urljoin(url, script["src"]))
        except Exception:
            pass
        return js_files

    def _check_sourcemap(self, js_url: str) -> bool:
        """Check if a JS file has an associated source map"""
        findings = 0

        try:
            # Method 1: Check for sourceMappingURL comment
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(js_url, headers=headers, timeout=10, verify=False)

            if resp.status_code != 200:
                return False

            content = resp.text[:50000]  # Cap at 50KB

            # Look for sourceMappingURL
            map_url = None
            match = re.search(r"//# sourceMappingURL=(.+)", content)
            if match:
                map_url = urljoin(js_url, match.group(1).strip())

            # Method 2: Try common .map extension
            if not map_url:
                map_url = js_url + ".map"

            # Fetch the source map
            map_resp = requests.get(map_url, headers=headers, timeout=10, verify=False)

            if map_resp.status_code == 200:
                try:
                    source_map = map_resp.json()

                    # Log the discovery
                    self.db.insert_finding(
                        f_type="SOURCE_MAP_EXPOSED",
                        url=map_url,
                        details=f"Source map exposed for {js_url}",
                        severity="MEDIUM",
                        source_module="sourcemap_scanner",
                    )
                    findings += 1

                    # Parse sources array
                    sources = source_map.get("sources", [])
                    if sources:
                        self.db.insert_finding(
                            f_type="SOURCE_MAP_SOURCES",
                            url=map_url,
                            details=f"Source map contains {len(sources)} "
                            f'source files: {", ".join(sources[:5])}{"..." if len(sources) > 5 else ""}',
                            severity="INFO",
                            source_module="sourcemap_scanner",
                        )
                        findings += 1

                    # Check sourcesContent for sensitive data
                    sources_content = source_map.get("sourcesContent", [])
                    if sources_content:
                        for i, source_content in enumerate(sources_content[:10]):  # Limit to 10 sources
                            if source_content:
                                for pattern in self.SENSITIVE_PATTERNS:
                                    if pattern.search(source_content):
                                        source_name = sources[i] if i < len(sources) else f"source_{i}"
                                        self.db.insert_finding(
                                            f_type="SOURCE_MAP_SECRET",
                                            url=f"{map_url}#{source_name}",
                                            details=f"Sensitive data found in source map: {source_name}",
                                            severity="HIGH",
                                            source_module="sourcemap_scanner",
                                        )
                                        findings += 1
                                        break

                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

        return findings > 0
