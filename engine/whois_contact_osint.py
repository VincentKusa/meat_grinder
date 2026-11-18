import urllib.parse

import requests
import whois
from bs4 import BeautifulSoup

from engine.base import BaseReconModule


class WhoisContactOSINT(BaseReconModule):
    SOCIAL_DOMAINS = [
        "twitter.com",
        "x.com",
        "linkedin.com",
        "github.com",
        "facebook.com",
        "instagram.com",
        "tiktok.com",
    ]

    def execute(self):
        print("[*] Performing WHOIS lookup and Contact OSINT...")

        try:
            w = whois.whois(self.target)
        except Exception as e:
            print(f"[!] WHOIS lookup failed for {self.target}: {e}")
            return

        registrar = w.registrar or "Unknown"
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        emails = set()
        names = set()

        # Extract emails from various WHOIS fields
        for field in ["registrant_email", "admin_email", "tech_email", "emails"]:
            val = getattr(w, field, None)
            if val:
                if isinstance(val, list):
                    emails.update([str(e).lower().strip() for e in val if e])
                else:
                    emails.add(str(val).lower().strip())

        # Extract names from various WHOIS fields
        for field in ["registrant_name", "admin_name", "tech_name", "name"]:
            val = getattr(w, field, None)
            if val:
                if isinstance(val, list):
                    names.update([str(n).strip() for n in val if n and str(n).strip() != "REDACTED FOR PRIVACY"])
                else:
                    names.add(str(val).strip())

        # Filter out privacy-protected or invalid emails
        valid_emails = [
            e for e in emails if "redacted" not in e and "privacy" not in e and "none" not in e and "@" in e
        ]

        # Save basic WHOIS info
        self.db.insert_finding(
            f_type="DOMAIN_WHOIS_INFO",
            url=f"domain://{self.target}",
            details=f"Registrar: {registrar} | Created: {creation_date}",
            severity="INFO",
        )

        if valid_emails:
            print(f"[*] Found {len(valid_emails)} unique contact emails. Running OSINT...")
            for email in valid_emails:
                self._analyze_contact(email, list(names))
        else:
            print("[*] No valid contact emails found in WHOIS (likely privacy protected).")

        print("[+] WHOIS and Contact OSINT complete.")

    def _analyze_contact(self, email: str, names: list):
        # Extract username from email (e.g., 'john.doe' from 'john.doe@example.com')
        username = email.split("@")[0]

        # Search queries: exact email match, and username match
        queries = [f'"{email}"', f'"{username}"']
        found_profiles = set()

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

        for q in queries:
            try:
                # DuckDuckGo HTML search (no API key required)
                url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(q)}"
                resp = requests.get(url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")

                    # DuckDuckGo wraps real URLs in a redirect: /l/?kh=-1&uddg=https%3A%2F%2F...
                    for a_tag in soup.find_all("a", class_="result__snippet"):
                        href = a_tag.get("href", "")
                        if "uddg=" in href:
                            # Extract and decode the real URL
                            real_url = urllib.parse.unquote(href.split("uddg=")[1])

                            # Check if it's a social media profile
                            for social in self.SOCIAL_DOMAINS:
                                if social in real_url.lower():
                                    found_profiles.add(real_url)

            except Exception:
                continue  # Ignore search timeouts or blocks

        if found_profiles:
            details = (
                f"Email: {email} | Names: {', '.join(names[:2])} | Profiles: {', '.join(list(found_profiles)[:3])}"
            )
            self.db.insert_finding(
                f_type="SOCIAL_MEDIA_CONTACT", url=f"mailto:{email}", details=details, severity="MEDIUM"
            )
        else:
            # Still log the email as a finding even if no socials are found (valuable for phishing/HR intel)
            details = f"Email: {email} | Names: {', '.join(names[:2])}"
            self.db.insert_finding(
                f_type="WHOIS_CONTACT_EMAIL", url=f"mailto:{email}", details=details, severity="INFO"
            )
