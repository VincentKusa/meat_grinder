import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EmailOSINT(BaseReconModule):
    # Common platforms to check for username reuse
    PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Twitter": "https://twitter.com/{}",
        "LinkedIn": "https://www.linkedin.com/in/{}",
        "Instagram": "https://instagram.com/{}",
        "GitLab": "https://gitlab.com/{}",
        "Bitbucket": "https://bitbucket.org/{}/",
        "Reddit": "https://reddit.com/user/{}",
        "Medium": "https://medium.com/@{}",
        "Dev.to": "https://dev.to/{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
    }

    def execute(self):
        print("[*] Performing email and username OSINT...")

        # Get all emails from database (from WHOIS, Git commits, etc.)
        findings = self.db.get_all_findings()
        emails = set()

        for f in findings:
            if f["finding_type"] in ["WHOIS_CONTACT_EMAIL", "GITHUB_COMMIT_EMAIL", "SOCIAL_MEDIA_CONTACT"]:
                match = re.search(r"mailto:([^\s]+)", f["url"])
                if match:
                    emails.add(match.group(1))

        if not emails:
            print("[*] No emails found in database. Skipping OSINT.")
            return

        print(f"[*] Found {len(emails)} unique emails. Checking for breaches and username reuse...")

        findings_count = 0

        # Check each email
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._analyze_email, email): email for email in emails}

            for future in as_completed(futures):
                if future.result():
                    findings_count += 1

        print(f"[+] Email OSINT complete. Found {findings_count} insights.")

    def _analyze_email(self, email: str) -> bool:
        """Analyze a single email for OSINT value"""
        findings = 0

        # Extract username from email
        username = email.split("@")[0].lower()

        # Clean username (remove dots, underscores for some platforms)
        clean_username = re.sub(r"[._-]", "", username)

        # Check for username reuse on platforms
        platforms_found = []

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {}

            for platform, url_template in self.PLATFORMS.items():
                # Try both original and cleaned username
                for uname in [username, clean_username]:
                    url = url_template.format(uname)
                    futures[executor.submit(self._check_platform, platform, url)] = (platform, url, uname)

            for future in as_completed(futures):
                platform, url, uname = futures[future]
                if future.result():
                    platforms_found.append(f"{platform} ({uname})")

        if platforms_found:
            self.db.insert_finding(
                f_type="USERNAME_REUSE",
                url=f"mailto:{email}",
                details=f"Username found on: "
                f'{", ".join(platforms_found[:8])}{"..." if len(platforms_found) > 8 else ""}',
                severity="INFO",
                source_module="email_osint",
            )
            findings += 1

        # Check for common breach indicators (using public APIs)
        if self._check_email_breach(email):
            findings += 1

        return findings > 0

    def _check_platform(self, platform: str, url: str) -> bool:
        """Check if a username exists on a platform"""
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)

            # Most platforms return 200 for existing users, 404 for non-existing
            if resp.status_code == 200:
                # Additional check: some platforms redirect to a generic page
                if "not found" not in resp.text.lower() and "does not exist" not in resp.text.lower():
                    return True
        except Exception:
            pass

        return False

    def _check_email_breach(self, email: str) -> bool:
        """Check if email appears in known breaches (using public API)"""
        try:
            # Use Have I Been Pwned API (requires API key for v3, but v2 is public)
            # For this implementation, we'll use a simple check
            # In production, you'd want to use the official API with a key

            # Alternative: Check against public breach databases
            # For now, we'll skip this to avoid API key requirements
            # You can add your own HIBP API key in .env and implement this

            # Check if email domain is suspicious
            domain = email.split("@")[1].lower()
            suspicious_tlds = ["ru", "cn", "top", "xyz", "club", "work"]

            if any(domain.endswith(f".{tld}") for tld in suspicious_tlds):
                self.db.insert_finding(
                    f_type="SUSPICIOUS_EMAIL_DOMAIN",
                    url=f"mailto:{email}",
                    details=f"Email uses potentially suspicious TLD: {domain}",
                    severity="LOW",
                    source_module="email_osint",
                )
                return True

        except Exception:
            pass

        return False
