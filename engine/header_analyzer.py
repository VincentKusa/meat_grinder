import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from engine.base import BaseReconModule


class HeaderAnalyzer(BaseReconModule):
    # WAF Signatures (Header Name -> Regex Pattern)
    WAF_SIGNATURES = {
        "Cloudflare": {"cf-ray": r".*", "server": r"cloudflare", "x-frame-options": r"cloudflare"},
        "Akamai": {"x-akamai-transformed": r".*", "x-akamai-request-id": r".*"},
        "F5 BIG-IP": {"x-waf-events": r".*", "server": r"big-?ip"},
        "Fortinet": {"server": r"fortiwaf"},
        "Sucuri": {"x-sucuri-id": r".*", "x-sucuri-cache": r".*"},
        "Imperva/Incapsula": {"x-iinfo": r".*", "x-cdn": r"incapsula"},
        "AWS WAF/ALB": {"x-amz-cf-id": r".*", "server": r"awselb"},
        "Barracuda": {"barra_counter_session": r".*", "barracuda_": r".*"},
        "ModSecurity": {"server": r"mod_security"},
    }

    # Regex to extract versions from headers
    VERSION_PATTERNS = [
        re.compile(r"(?i)server:\s*([a-zA-Z0-9\-_]+\s*[0-9\.]+)"),
        re.compile(r"(?i)x-powered-by:\s*([a-zA-Z0-9\-_]+\s*[0-9\.]+)"),
        re.compile(r"(?i)x-aspnet-version:\s*([0-9\.]+)"),
        re.compile(r"(?i)x-generator:\s*([a-zA-Z0-9\-_]+\s*[0-9\.]+)"),
    ]

    def execute(self):
        print("[*] Analyzing HTTP Headers, WAFs, and Versions...")
        endpoints = self.db.get_all_endpoints()

        # Filter to only live/interesting endpoints to save time
        targets = [ep["url"] for ep in endpoints if ep["status_code"] > 0]

        analyzed_count = 0
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._analyze_url, url): url for url in targets}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.db.update_endpoint_headers(result["url"], result["headers_json"], result["waf"])
                    analyzed_count += 1

        print(f"[+] Analyzed headers for {analyzed_count} endpoints.")

    def _analyze_url(self, url: str) -> dict:
        try:
            # Use HEAD request for speed, fallback to GET if HEAD is blocked (405)
            resp = requests.head(url, timeout=5, allow_redirects=True, verify=False)
            if resp.status_code == 405:
                resp = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        except requests.exceptions.RequestException:
            return None

        headers = {k.lower(): v for k, v in resp.headers.items()}
        headers_json = json.dumps(headers)

        # 1. Detect WAF
        detected_waf = "None"
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            match_count = 0
            for header_name, pattern in signatures.items():
                if header_name in headers and re.search(pattern, headers[header_name], re.I):
                    match_count += 1

            # If 1 or more signatures match, flag it
            if match_count > 0:
                detected_waf = waf_name
                break

        # 2. Extract Versions for Findings
        header_text = "\n".join([f"{k}: {v}" for k, v in headers.items()])
        for pattern in self.VERSION_PATTERNS:
            match = pattern.search(header_text)
            if match:
                version_str = match.group(1).strip()
                # Flag if it's a specific version (not just generic "PHP")
                if any(char.isdigit() for char in version_str):
                    self.db.insert_finding("EXPOSED_VERSION", url, f"Header exposed version: {version_str}", "MEDIUM")

        return {"url": url, "headers_json": headers_json, "waf": detected_waf}
