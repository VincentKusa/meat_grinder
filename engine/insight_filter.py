import json
import re

from engine.base import BaseReconModule


class InsightFilter(BaseReconModule):
    NOISE_TITLES = ["welcome to nginx", "iis windows server", "apache2 default", "test page", "parked"]
    JUICY_PATHS = ["/admin", "/api", "/.git", "/.env", "/wp-login", "/graphql", "/jenkins", "/kibana"]

    CLOUD_REGEX = re.compile(
        r"(s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|digitaloceanspaces\.com)"
    )
    TAKEOVER_TITLES = ["nosuchbucket", "repo not found", "project not found", "herokucdn.com/deployed.png"]

    OUTDATED_SERVERS = [
        re.compile(r"apache/2\.[0-3]", re.I),
        re.compile(r"nginx/1\.[0-9]\.", re.I),
        re.compile(r"iis/[5-7]\.", re.I),
        re.compile(r"microsoft-httpapi/2\.0", re.I),
        re.compile(r"php/5\.", re.I),
        re.compile(r"openssl/1\.0", re.I),
    ]

    RISKY_SERVICES = {
        "21": "FTP",
        "23": "Telnet",
        "25": "SMTP",
        "111": "RPCBind",
        "135": "MSRPC",
        "139": "NetBIOS",
        "445": "SMB",
        "1433": "MSSQL",
        "3306": "MySQL",
        "3389": "RDP",
        "5432": "PostgreSQL",
        "5900": "VNC",
        "6379": "Redis",
        "9200": "Elasticsearch",
        "27017": "MongoDB",
        "11211": "Memcached",
    }

    def execute(self):
        print("[*] Filtering noise and extracting deep insights...")

        # FIX: Removed self.db.clear_findings() from here

        self._analyze_endpoints()
        self._analyze_ports()

        total = len(self.db.get_all_findings())
        print(f"[+] Extracted {total} actionable insights.")

    def _analyze_endpoints(self):
        endpoints = self.db.get_all_endpoints()

        for ep in endpoints:
            url = ep["url"].lower()
            title = ep["title"].lower()
            status = ep["status_code"]
            webserver = ep.get("webserver", "") or ""
            waf = ep.get("waf_detected", "None")

            try:
                headers = json.loads(ep.get("headers_json", "{}")) if ep.get("headers_json") else {}
            except json.JSONDecodeError:
                headers = {}

            if any(noise in title for noise in self.NOISE_TITLES):
                continue

            if webserver:
                for pattern in self.OUTDATED_SERVERS:
                    if pattern.search(webserver):
                        self.db.insert_finding("OUTDATED_WEBSERVER", ep["url"], f"Server: {webserver}", "MEDIUM")
                        break

            if status in [401, 403, 407]:
                self.db.insert_finding(
                    "GUARDED_ENDPOINT", ep["url"], f"Status: {status}, Title: {ep['title']}, WAF: {waf}", "HIGH"
                )
                continue

            if status in [500, 502, 503, 504]:
                self.db.insert_finding("SERVER_ERROR", ep["url"], f"Status: {status}, Title: {ep['title']}", "MEDIUM")
                continue

            if "index of" in title or "parent directory" in title:
                self.db.insert_finding("DIR_LISTING", ep["url"], f"Title: {ep['title']}", "HIGH")
                continue

            if self.CLOUD_REGEX.search(url):
                self.db.insert_finding("CLOUD_STORAGE", ep["url"], "Potential exposed S3/Blob/GCP bucket", "CRITICAL")
                continue

            if any(t in title for t in self.TAKEOVER_TITLES):
                self.db.insert_finding("TAKEOVER_CANDIDATE", ep["url"], f"Title: {ep['title']}", "CRITICAL")
                continue

            if status in [200, 301, 302]:
                if "strict-transport-security" not in headers:
                    self.db.insert_finding(
                        "MISSING_HSTS", ep["url"], "Missing Strict-Transport-Security header", "MEDIUM"
                    )
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    self.db.insert_finding(
                        "MISSING_CLICKJACKING_PROTECTION", ep["url"], "Missing X-Frame-Options or CSP", "MEDIUM"
                    )

            if any(path in url for path in self.JUICY_PATHS):
                self.db.insert_finding("SENSITIVE_PATH", ep["url"], f"Title: {ep['title']}, WAF: {waf}", "MEDIUM")

    def _analyze_ports(self):
        ports_data = self.db.get_all_ports()
        for entry in ports_data:
            host = entry["host"]
            os_info = entry.get("os", "") or ""
            services_raw = entry.get("services", "{}")

            try:
                services = json.loads(services_raw) if services_raw else {}
            except json.JSONDecodeError:
                services = {}

            if os_info and os_info.lower() not in ("", "unknown"):
                self.db.insert_finding("OS_DETECTED", f"host://{host}", f"OS: {os_info}", "INFO")

            for port, service_name in services.items():
                if port == "cpe":
                    if isinstance(service_name, list):
                        for cpe in service_name:
                            if any(
                                risky in cpe.lower()
                                for risky in ["jenkins", "tomcat", "jboss", "weblogic", "sharepoint"]
                            ):
                                self.db.insert_finding(
                                    "RISKY_APPLICATION", f"host://{host}:{port}", f"CPE: {cpe}", "HIGH"
                                )
                    continue

                if port in self.RISKY_SERVICES:
                    self.db.insert_finding(
                        "RISKY_SERVICE_EXPOSED",
                        f"host://{host}:{port}",
                        f"Service: {service_name} (Port {port})",
                        "HIGH" if port in ["23", "445", "3389", "6379", "27017", "9200"] else "MEDIUM",
                    )
