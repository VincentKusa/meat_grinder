import requests
import re
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from engine.base import BaseReconModule

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebContentScanner(BaseReconModule):
    # High-precision regex patterns for secrets in code
    SECRET_PATTERNS = [
        # Generic API Keys / Secrets / Passwords (looking for high entropy assignments)
        re.compile(r'(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|token|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'),
        # AWS Access Keys
        re.compile(r'(?i)AKIA[0-9A-Z]{16}'),
        # AWS Secret Keys (40 char base64-like)
        re.compile(r'(?i)(?:aws_secret_access_key|secret)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'),
        # Stripe Keys
        re.compile(r'(?i)(?:sk_live_|sk_test_|pk_live_|pk_test_)[a-zA-Z0-9]{24,}'),
        # GitHub Personal Access Tokens
        re.compile(r'(?i)ghp_[a-zA-Z0-9]{36}'),
        # JSON Web Tokens (JWT)
        re.compile(r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        # Google API Keys
        re.compile(r'(?i)AIza[0-9A-Za-z_\-]{35}'),
        # Slack Tokens
        re.compile(r'(?i)xox[baprs]-[0-9a-zA-Z\-]{10,}'),
        # Internal IP/Domain leaks in JS (often indicates hidden dev/staging APIs)
        re.compile(r'(?i)(?:https?://)(?:dev-|staging-|test-|internal-)[a-zA-Z0-9\-\.]+')
    ]

    def execute(self):
        print("[*] Scanning web content (.js, .html) for hardcoded secrets...")
        endpoints = self.db.get_all_endpoints()

        # FIX 1: Corrected list comprehension syntax and indentation
        live_endpoints = [ep['url'] for ep in endpoints if ep['status_code'] in [200, 301, 302]]

        print(f"[*] Analyzing content of {len(live_endpoints)} live endpoints...")

        found_count = 0
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._scan_endpoint, url): url for url in live_endpoints}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_count += result

        print(f"[+] Found {found_count} potential secrets in web content.")

    def _scan_endpoint(self, url: str) -> int:
        findings_in_url = 0
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)

            if resp.status_code in [200, 301, 302]:
                soup = BeautifulSoup(resp.text, 'html.parser')
                js_files = set()

                # 1. Extract <script src="...">
                for script in soup.find_all('script', src=True):
                    js_files.add(urljoin(url, script['src']))

                # 2. Extract inline <script> content (often contains config objects)
                for script in soup.find_all('script'):
                    if not script.get('src') and script.string:
                        self._scan_content(url, "inline_script", script.string)
                        findings_in_url += 1  # Count inline scan as a check

                # FIX 3: Removed duplicated "in js_url"
                for js_url in js_files:
                    if js_url.lower().endswith('.js'):
                        self._scan_content(url, js_url, self._fetch_content(js_url))
                        findings_in_url += 1

        except Exception:
            pass  # Ignore network errors, timeouts, etc.

        return findings_in_url

    def _fetch_content(self, url: str) -> str:
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            # Limit to first 100KB to avoid hanging on massive minified bundles
            resp = requests.get(url, headers=headers, timeout=5, verify=False)
            if resp.status_code == 200:
                return resp.text[:1024 * 100]
        except Exception:
            pass
        return ""

    def _scan_content(self, source_url: str, file_identifier: str, content: str):
        if not content or len(content.strip()) < 50:
            return

        for pattern in self.SECRET_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                # Deduplicate and format matches
                unique_matches = list(set(matches))
                # Truncate long matches for the report
                sanitized_matches = [m[:30] + "..." if len(m) > 30 else m for m in unique_matches[:3]]

                details = f"Matches found: {', '.join(sanitized_matches)}"
                self.db.insert_finding(
                    "HARDCODED_SECRET_IN_WEB_FILE",
                    f"{source_url} -> {file_identifier}",
                    details,
                    "CRITICAL"
                )
                break  # One finding per file is enough to flag it, prevents spamming the DB