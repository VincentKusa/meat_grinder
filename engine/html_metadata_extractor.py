import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup, Comment

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTMLMetadataExtractor(BaseReconModule):
    # Patterns that reveal juicy info in HTML comments
    COMMENT_PATTERNS = [
        re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
        re.compile(r"(?i)(TODO|FIXME|HACK|XXX|BUG)\s*:?\s*(.{10,100})"),
        re.compile(r"(?i)(internal|staging|dev|test)[\.\-_][a-z0-9\-]+\.(com|net|org|io)"),
        re.compile(r"(?i)127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"),
        re.compile(r"(?i)(built|developed|designed|maintained)\s+by\s+([A-Za-z\s]{3,30})"),
    ]

    def execute(self):
        print("[*] Extracting HTML metadata, comments, and hidden fields...")
        endpoints = self.db.get_all_endpoints()
        live_endpoints = [ep["url"] for ep in endpoints if ep["status_code"] in [200, 301, 302]]

        print(f"[*] Analyzing metadata of {len(live_endpoints)} live endpoints...")
        findings_count = 0

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._extract_metadata, url): url for url in live_endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings_count += result

        print(f"[+] Extracted {findings_count} metadata insights.")

    def _extract_metadata(self, url: str) -> int:
        findings = 0
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code not in [200, 301, 302]:
                return 0

            soup = BeautifulSoup(resp.text, "html.parser")

            # 1. META TAGS (generator, author, description)
            findings += self._parse_meta_tags(soup, url)

            # 2. HTML COMMENTS (dev notes, leaked secrets)
            findings += self._parse_html_comments(soup, url)

            # 3. HIDDEN FORM FIELDS (CSRF tokens, API keys)
            findings += self._parse_hidden_fields(soup, url)

            # 4. OPEN GRAPH / TWITTER CARDS (social media accounts)
            findings += self._parse_social_meta(soup, url)

            # 5. LINK TAGS (canonical, alternate languages, preconnects)
            findings += self._parse_link_tags(soup, url)

        except Exception:
            pass
        return findings

    def _parse_meta_tags(self, soup: BeautifulSoup, url: str) -> int:
        findings = 0
        high_value_metas = ["generator", "author", "application-name", "copyright"]

        for meta in soup.find_all("meta", attrs={"name": True, "content": True}):
            name = meta["name"].lower()
            content = meta["content"].strip()

            if name in high_value_metas and content:
                self.db.insert_finding(
                    f_type="HTML_META_TAG",
                    url=url,
                    details=f"<meta name='{name}' content='{content[:80]}'>",
                    severity="INFO",
                )
                findings += 1

            # Generator tags reveal CMS versions (WordPress, Drupal, Joomla)
            if name == "generator" and content:
                self.db.insert_finding(
                    f_type="CMS_VERSION_EXPOSED", url=url, details=f"CMS: {content}", severity="MEDIUM"
                )
                findings += 1

        return findings

    def _parse_html_comments(self, soup: BeautifulSoup, url: str) -> int:
        findings = 0
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))

        for comment in comments:
            text = comment.strip()
            if len(text) < 5:
                continue

            # Check for juicy patterns
            matched = False
            for pattern in self.COMMENT_PATTERNS:
                match = pattern.search(text)
                if match:
                    safe_text = text[:150].replace("\n", " ")
                    self.db.insert_finding(
                        f_type="HTML_COMMENT_LEAK",
                        url=url,
                        details=f"Comment: <!-- {safe_text} -->",
                        severity=(
                            "HIGH"
                            if any(kw in text.lower() for kw in ["api", "key", "secret", "password"])
                            else "MEDIUM"
                        ),
                    )
                    findings += 1
                    matched = True
                    break

            # If no pattern matched but comment is long, flag it
            if not matched and len(text) > 100:
                safe_text = text[:150].replace("\n", " ")
                self.db.insert_finding(
                    f_type="HTML_COMMENT_LEAK",
                    url=url,
                    details=f"Long comment: <!-- {safe_text}... -->",
                    severity="INFO",
                )
                findings += 1

        return findings

    def _parse_hidden_fields(self, soup: BeautifulSoup, url: str) -> int:
        findings = 0
        sensitive_names = ["token", "csrf", "api", "key", "secret", "auth", "session"]

        for inp in soup.find_all("input", type="hidden"):
            name = (inp.get("name") or "").lower()
            value = inp.get("value", "")

            if any(s in name for s in sensitive_names) and value and len(value) > 10:
                safe_value = value[:30] + "..." if len(value) > 30 else value
                self.db.insert_finding(
                    f_type="HIDDEN_FORM_FIELD",
                    url=url,
                    details=f"Input name='{inp.get('name')}' value='{safe_value}'",
                    severity="MEDIUM",
                )
                findings += 1

        return findings

    def _parse_social_meta(self, soup: BeautifulSoup, url: str) -> int:
        findings = 0
        social_accounts = set()

        for meta in soup.find_all("meta", attrs={"property": True, "content": True}):
            prop = meta["property"].lower()
            content = meta["content"].strip()

            # Look for social media profile links in OG/Twitter data
            if "author" in prop or "creator" in prop:
                if any(
                    social in content.lower() for social in ["twitter.com", "x.com", "linkedin.com", "instagram.com"]
                ):
                    social_accounts.add(content)

        if social_accounts:
            self.db.insert_finding(
                f_type="SOCIAL_META_EXPOSED",
                url=url,
                details=f"Social accounts: {', '.join(list(social_accounts)[:3])}",
                severity="INFO",
            )
            findings += 1

        return findings

    def _parse_link_tags(self, soup: BeautifulSoup, url: str) -> int:
        findings = 0
        interesting_rels = ["alternate", "preconnect", "dns-prefetch", "manifest"]

        for link in soup.find_all("link", rel=True, href=True):
            rel = " ".join(link["rel"]).lower()
            href = link["href"]

            if any(r in rel for r in interesting_rels):
                # Manifest files often reveal app structure
                if "manifest" in rel:
                    self.db.insert_finding(
                        f_type="WEB_MANIFEST_FOUND",
                        url=url,
                        details=f"PWA manifest: {urljoin(url, href)}",
                        severity="INFO",
                    )
                    findings += 1

                # Alternate links reveal other language versions or API endpoints
                elif "alternate" in rel and "api" in href.lower():
                    self.db.insert_finding(
                        f_type="API_ENDPOINT_IN_LINK",
                        url=url,
                        details=f"Alternate link: {urljoin(url, href)}",
                        severity="MEDIUM",
                    )
                    findings += 1

        return findings
