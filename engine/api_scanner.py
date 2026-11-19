import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIScanner(BaseReconModule):
    # Common API documentation endpoints
    API_DOCS_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/swagger-ui.html",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api/docs",
        "/graphql",
        "/graphiql",
        "/graphql/playground",
        "/.well-known/openid-configuration",
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/postman_collection.json",
        "/api/v1",
        "/api/v2",
        "/api/v3",
    ]

    # Patterns to find API endpoints in JavaScript
    API_PATTERNS = [
        re.compile(r'["\'](/api/[^"\']+)["\']'),
        re.compile(r'["\'](/v[0-9]+/[^"\']+)["\']'),
        re.compile(r'["\'](/graphql[^"\']*)["\']'),
        re.compile(r'["\']https?://[^"\']*/api/[^"\']+["\']'),
    ]

    def execute(self):
        print("[*] Discovering API surface...")

        endpoints = self.db.get_all_endpoints()
        live_endpoints = [ep["url"] for ep in endpoints if ep["status_code"] in [200, 301, 302]]

        findings_count = 0

        # Check for API documentation endpoints
        findings_count += self._check_api_docs(live_endpoints)

        # Extract API endpoints from JavaScript
        findings_count += self._extract_api_from_js(live_endpoints)

        print(f"[+] API discovery complete. Found {findings_count} API insights.")

    def _check_api_docs(self, urls: list) -> int:
        findings = 0

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for url in urls:
                for path in self.API_DOCS_PATHS:
                    target_url = urljoin(url, path)
                    futures[executor.submit(self._check_endpoint, target_url)] = target_url

            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings += 1

        return findings

    def _check_endpoint(self, url: str) -> bool:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False)

            if resp.status_code == 200:
                resp.headers.get("content-type", "")

                # Swagger/OpenAPI
                if "swagger" in url.lower() or "openapi" in url.lower():
                    self.db.insert_finding(
                        "OPENAPI_EXPOSED",
                        url,
                        "API documentation publicly accessible",
                        "MEDIUM",
                        source_module="api_scanner",
                    )
                    return True

                # GraphQL
                elif "graphql" in url.lower():
                    self.db.insert_finding(
                        "GRAPHQL_ENDPOINT", url, "GraphQL endpoint discovered", "MEDIUM", source_module="api_scanner"
                    )

                    # Check for introspection
                    if self._check_graphql_introspection(url):
                        self.db.insert_finding(
                            "GRAPHQL_INTROSPECTION_ENABLED",
                            url,
                            "GraphQL introspection is enabled (schema exposed)",
                            "MEDIUM",
                            source_module="api_scanner",
                        )
                    return True

                # Well-known endpoints
                elif ".well-known" in url:
                    self.db.insert_finding(
                        "WELL_KNOWN_ENDPOINT",
                        url,
                        "Well-known endpoint discovered",
                        "INFO",
                        source_module="api_scanner",
                    )
                    return True

                # Generic API paths
                elif "/api/" in url:
                    self.db.insert_finding(
                        "API_ENDPOINT_DISCOVERED", url, "API endpoint discovered", "INFO", source_module="api_scanner"
                    )
                    return True

        except Exception:
            pass

        return False

    def _check_graphql_introspection(self, url: str) -> bool:
        try:
            query = '{"query": "{__schema{types{name}}}"}'
            headers = {"Content-Type": "application/json"}
            resp = requests.post(url, data=query, headers=headers, timeout=5, verify=False)

            if resp.status_code == 200 and "__schema" in resp.text:
                return True
        except Exception:
            pass
        return False

    def _extract_api_from_js(self, urls: list) -> int:
        findings = 0
        api_endpoints = set()

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._extract_from_url, url): url for url in urls}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    api_endpoints.update(result)

        # Report unique API endpoints
        for endpoint in list(api_endpoints)[:20]:  # Limit to 20 to avoid spam
            self.db.insert_finding(
                "API_ENDPOINT_IN_CODE",
                endpoint,
                "API endpoint found in source code",
                "INFO",
                source_module="api_scanner",
            )
            findings += 1

        return findings

    def _extract_from_url(self, url: str) -> set:
        endpoints = set()
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)

            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract from script tags
                for script in soup.find_all("script"):
                    if script.string:
                        for pattern in self.API_PATTERNS:
                            matches = pattern.findall(script.string)
                            endpoints.update(matches)
        except Exception:
            pass

        return endpoints
