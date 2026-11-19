from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdminDiscovery(BaseReconModule):
    # Common admin paths to check
    ADMIN_PATHS = [
        "/admin",
        "/administrator",
        "/admin.php",
        "/admin/login",
        "/admin/dashboard",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/pma",
        "/mysql",
        "/adminer",
        "/cpanel",
        "/dashboard",
        "/manage",
        "/management",
        "/console",
        "/portal",
        "/backend",
        "/controlpanel",
        "/manager",
        "/supervisor",
        "/jenkins",
        "/grafana",
        "/kibana",
        "/elastic",
        "/api/admin",
        "/api/management",
        "/swagger-ui.html",
        "/api-docs",
        "/.env",
        "/.git/config",
        "/server-status",
        "/server-info",
        "/info.php",
        "/phpinfo.php",
    ]

    # Admin panel fingerprints
    ADMIN_FINGERPRINTS = {
        "WordPress": ["wp-admin", "wp-login", "wordpress"],
        "Joomla": ["joomla", "administrator/index.php"],
        "Drupal": ["drupal", "user/login"],
        "Jenkins": ["jenkins", "dashboard", "login"],
        "Grafana": ["grafana", "grafana-login"],
        "Kibana": ["kibana", "elastic"],
        "phpMyAdmin": ["phpmyadmin", "pma", "mysql"],
        "cPanel": ["cpanel", "whm"],
        "Django Admin": ["django", "admin"],
        "Laravel": ["laravel"],
    }

    def execute(self):
        print("[*] Discovering admin panels and management interfaces...")

        endpoints = self.db.get_all_endpoints()
        base_urls = set()

        for ep in endpoints:
            if ep["status_code"] in [200, 301, 302]:
                # Extract base URL
                from urllib.parse import urlparse

                parsed = urlparse(ep["url"])
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)

        print(f"[*] Checking {len(self.ADMIN_PATHS)} admin paths across {len(base_urls)} base URLs...")

        findings_count = 0
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {}

            for base_url in base_urls:
                for path in self.ADMIN_PATHS:
                    target_url = urljoin(base_url + "/", path.lstrip("/"))
                    futures[executor.submit(self._check_admin_path, target_url)] = target_url

            for future in as_completed(futures):
                if future.result():
                    findings_count += 1

        print(f"[+] Admin discovery complete. Found {findings_count} insights.")

    def _check_admin_path(self, url: str) -> bool:
        """Check if an admin path exists and is accessible"""
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)

            # Check for accessible admin panels
            if resp.status_code == 200:
                content = resp.text.lower()

                # Fingerprint the admin panel
                detected_panel = None
                for panel, keywords in self.ADMIN_FINGERPRINTS.items():
                    if any(kw in content for kw in keywords):
                        detected_panel = panel
                        break

                if detected_panel:
                    self.db.insert_finding(
                        f_type="ADMIN_PANEL_DISCOVERED",
                        url=url,
                        details=f"{detected_panel} admin panel accessible",
                        severity="MEDIUM",
                        source_module="admin_discovery",
                    )
                    return True

                # Generic admin panel (no specific fingerprint)
                if any(kw in content for kw in ["login", "sign in", "username", "password", "admin"]):
                    self.db.insert_finding(
                        f_type="ADMIN_PANEL_DISCOVERED",
                        url=url,
                        details="Admin/login panel accessible (unidentified)",
                        severity="MEDIUM",
                        source_module="admin_discovery",
                    )
                    return True

            # Check for protected but existing admin panels
            elif resp.status_code in [401, 403, 407]:
                self.db.insert_finding(
                    f_type="ADMIN_PANEL_PROTECTED",
                    url=url,
                    details=f"Admin panel exists but requires authentication (HTTP {resp.status_code})",
                    severity="INFO",
                    source_module="admin_discovery",
                )
                return True

        except Exception:
            pass

        return False
