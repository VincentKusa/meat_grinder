import requests
import re
import urllib3
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from engine.base import BaseReconModule

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SensitiveFileScanner(BaseReconModule):
    # Common sensitive files to hunt for
    SENSITIVE_FILES = [
        '.env', '.env.bak', '.env.local', '.env.production', '.env.example',
        '.git/config', '.git/HEAD', '.gitignore',
        'wp-config.php', 'wp-config.php.bak', 'wp-config.php.save',
        'config.php', 'config.php.bak', 'config.php.old',
        'config.json', 'config.yaml', 'config.yml',
        'database.yml', 'database.json', 'database.php',
        'secrets.json', 'credentials.json',
        '.aws/credentials',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '.htpasswd', '.htaccess',
        'backup.sql', 'dump.sql', 'db.sql', 'db_backup.sql'
    ]

    # Regex patterns that strongly indicate a REAL secret file (filters out fake 200 OK pages)
    SECRET_PATTERNS = [
        re.compile(
            r'(?i)(DB_PASSWORD|DB_USER|DB_HOST|DATABASE_URL|SECRET_KEY|JWT_SECRET|API_KEY|PASSWORD)\s*[:=]\s*[\'"]?[^\'"\s]+[\'"]?'),
        re.compile(r'(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        re.compile(r'(?i)aws_access_key_id|aws_secret_access_key'),
        re.compile(r'(?i)STRIPE_SECRET_KEY|STRIPE_API_KEY')
    ]

    def execute(self):
        print("[*] Scanning for exposed sensitive files (.env, .git, configs)...")
        endpoints = self.db.get_all_endpoints()

        # Extract unique base URLs to avoid redundant scanning (e.g., https://example.com/)
        base_urls = set()
        for ep in endpoints:
            parsed = urlparse(ep['url'])
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            base_urls.add(base_url)

        print(f"[*] Checking {len(self.SENSITIVE_FILES)} file types across {len(base_urls)} base URLs...")

        found_count = 0
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {}
            for base_url in base_urls:
                for file_path in self.SENSITIVE_FILES:
                    target_url = f"{base_url.rstrip('/')}/{file_path.lstrip('/')}"
                    futures[executor.submit(self._check_file, target_url)] = target_url

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_count += 1

        print(f"[+] Found {found_count} validated exposed sensitive files.")

    def _check_file(self, url: str) -> bool:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            # We only need the first 2KB to validate if it's a real config file
            resp = requests.get(url, headers=headers, timeout=5, verify=False)

            if resp.status_code == 200:
                content = resp.text[:2048]  # Read first 2KB to save bandwidth

                # Validate: Does this actually look like a secret file?
                is_sensitive = any(pattern.search(content) for pattern in self.SECRET_PATTERNS)

                if is_sensitive:
                    self.db.insert_finding(
                        "EXPOSED_SENSITIVE_FILE", url,
                        "Status: 200, Regex matched potential secrets/config data", "CRITICAL"
                    )
                    return True
                elif len(content.strip()) > 50:
                    # It's a 200 OK with content, but no obvious regex match. Flag as medium for manual review.
                    self.db.insert_finding(
                        "EXPOSED_FILE", url,
                        f"Status: 200, Content Length: {len(content)} bytes (No obvious secrets)", "MEDIUM"
                    )
                    return True

            elif resp.status_code == 403 and '.git' in url:
                # 403 on .git/ is still a finding (directory exists but is protected)
                self.db.insert_finding(
                    "PROTECTED_SENSITIVE_FILE", url,
                    "Status: 403 (File/Directory exists but access forbidden)", "MEDIUM"
                )
                return True

        except requests.exceptions.RequestException:
            pass  # Ignore timeouts, connection errors, etc.

        return False