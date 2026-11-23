import requests
import urllib3

from database import ConfidenceLevel
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdminDiscovery(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        self.admin_paths = {
            "wordpress": ["/wp-admin", "/wp-login.php"],
            "jenkins": ["/jenkins", "/admin/login", "/dashboard"],
            "phpmyadmin": ["/phpmyadmin", "/pma", "/mysql"],
            "grafana": ["/grafana", "/login"],
            "cpanel": ["/cpanel", "/webmail", "/whm"],
            "django": ["/admin", "/administrator", "/admin.php"],
        }

        self.valid_fingerprints = {
            "jenkins": ["jenkins", "jenkins-agent-protocols"],
            "wordpress": ["wp-admin", "wp-login.php", "wordpress"],
            "phpmyadmin": ["phpmyadmin", "pma_", "mysql"],
            "grafana": ["grafana"],
            "cpanel": ["cpanel", "whm", "webmail"],
            "django": ["django administration", "admin"],
        }

    def execute(self):
        print("[*] Discovering admin panels and management interfaces...")
        endpoints = self.db.get_all_endpoints()
        base_urls = list(
            set([f"{ep['url'].split('://')[0]}://{ep['url'].split('://')[1].split('/')[0]}" for ep in endpoints])
        )

        print(
            f"[*] Checking {sum(len(paths) for paths in self.admin_paths.values())} "
            f"admin paths across {len(base_urls)} base URLs..."
        )
        findings_count = 0
        seen_panels = set()  # FIX: Track unique panels to prevent duplicates

        for base_url in base_urls:
            for panel_name, paths in self.admin_paths.items():
                for path in paths:
                    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

                    # FIX: Skip if we've already found this exact panel
                    panel_key = f"{base_url}|{panel_name}|{path}"
                    if panel_key in seen_panels:
                        continue

                    try:
                        resp = requests.get(url, timeout=10, verify=False, allow_redirects=False)

                        if resp.status_code in [200, 401, 403]:
                            is_valid = False
                            if panel_name in self.valid_fingerprints:
                                text_lower = resp.text.lower()
                                if any(fp in text_lower for fp in self.valid_fingerprints[panel_name]):
                                    is_valid = True

                            # Only flag if fingerprint matches OR it's a protected panel
                            if resp.status_code in [401, 403] or is_valid:
                                seen_panels.add(panel_key)  # Mark as seen

                                severity = "MEDIUM" if resp.status_code == 200 else "INFO"
                                f_type = (
                                    "ADMIN_PANEL_DISCOVERED" if resp.status_code == 200 else "ADMIN_PANEL_PROTECTED"
                                )

                                self.db.insert_finding(
                                    f_type=f_type,
                                    url=url,
                                    details=f"{panel_name.capitalize()} admin panel accessible "
                                    f"(HTTP {resp.status_code})",
                                    severity=severity,
                                    confidence=ConfidenceLevel.HIGH if is_valid else ConfidenceLevel.MEDIUM,
                                    source_module="admin_discovery",
                                )
                                findings_count += 1
                    except Exception:
                        pass

        print(f"[+] Admin discovery complete. Found {findings_count} unique insights.")
