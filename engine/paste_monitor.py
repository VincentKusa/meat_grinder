import re

import requests
import urllib3
from github import Github, GithubException

from config import Config
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PasteMonitor(BaseReconModule):
    # Static high-value patterns (evaluated at class definition time)
    STATIC_PATTERNS = [
        re.compile(r"(?i)AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),  # GitHub PAT
        re.compile(r"(?i)(sk_live_|sk_test_)[a-zA-Z0-9]{24,}"),  # Stripe
        re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r'(?i)(DB_PASSWORD|DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*[:=]\s*["\']?[^\s"\']+'),
    ]

    # Paste sites to check
    PASTE_SITES = [
        "pastebin.com",
        "ghostbin.com",
        "dpaste.org",
        "paste.ee",
        "hastebin.com",
    ]

    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        # Initialize dynamic patterns with instance-specific target
        self.high_value_patterns = self.STATIC_PATTERNS + [
            re.compile(r"(?i)internal[-.]" + re.escape(self.target.split(".")[0]))
        ]

    def execute(self):
        print("[*] Monitoring paste sites and GitHub for leaked data...")

        findings_count = 0

        # Strategy 1: GitHub Code Search
        findings_count += self._search_github_code()

        # Strategy 2: GitHub Commit Search (for emails)
        findings_count += self._search_github_commits()

        # Strategy 3: Paste Site Monitoring
        findings_count += self._search_paste_sites()

        print(f"[+] Paste monitoring complete. Found {findings_count} insights.")

    def _search_github_code(self) -> int:
        """Search GitHub code for target domain and related keywords"""
        findings = 0

        if not Config.GITHUB_TOKEN:
            print("[!] No GitHub token configured. Skipping code search.")
            return 0

        try:
            g = Github(Config.GITHUB_TOKEN)

            # Search queries
            queries = [
                f'"{self.target}"',
                f'"{self.target.split(".")[0]}" password OR secret OR api_key',
                f'"{self.target}" internal OR staging OR dev',
            ]

            for query in queries:
                try:
                    print(f"[*] Searching GitHub code for: {query[:50]}...")
                    results = g.search_code(query, sort="indexed", order="desc")

                    count = 0
                    for code in results[:15]:  # Limit to 15 per query to avoid rate limits
                        file_url = code.html_url
                        repo_name = code.repository.full_name

                        # Check file content for high-value patterns
                        try:
                            content = code.decoded_content.decode("utf-8", errors="ignore")[:5000]

                            for pattern in self.high_value_patterns:
                                if pattern.search(content):
                                    self.db.insert_finding(
                                        f_type="GITHUB_CODE_LEAK",
                                        url=file_url,
                                        details=f"Repo: {repo_name} | File: {code.path} | Matched pattern",
                                        severity="HIGH",
                                        source_module="paste_monitor",
                                    )
                                    findings += 1
                                    break

                            count += 1
                            if count >= 15:
                                break
                        except Exception:
                            continue

                except GithubException as e:
                    if "rate limit" in str(e).lower():
                        print("[!] GitHub API rate limit reached. Stopping code search.")
                        break
                    print(f"[!] GitHub search error: {e}")

        except Exception as e:
            print(f"[!] GitHub code search failed: {e}")

        return findings

    def _search_github_commits(self) -> int:
        """Search GitHub commits for leaked emails"""
        findings = 0

        if not Config.GITHUB_TOKEN:
            return 0

        try:
            g = Github(Config.GITHUB_TOKEN)
            query = f'author:@{self.target.split(".")[0]} OR committer:@{self.target.split(".")[0]}'

            print("[*] Searching GitHub commits for target-related emails...")
            results = g.search_commits(query, sort="author-date", order="desc")

            emails_found = set()
            count = 0

            for commit in results[:30]:
                try:
                    author_email = commit.commit.author.email
                    committer_email = commit.commit.committer.email

                    for email in [author_email, committer_email]:
                        if (
                            email
                            and "@" in email
                            and not email.endswith("@github.com")
                            and "noreply" not in email
                            and self.target.split(".")[0].lower() in email.lower()
                        ):

                            if email not in emails_found:
                                emails_found.add(email)
                                self.db.insert_finding(
                                    f_type="GITHUB_COMMIT_EMAIL",
                                    url=f"mailto:{email}",
                                    details=f"Found in commit: {commit.sha[:8]} in {commit.repository.full_name}",
                                    severity="INFO",
                                    source_module="paste_monitor",
                                )
                                findings += 1

                    count += 1
                    if count >= 30:
                        break
                except Exception:
                    continue

        except Exception as e:
            print(f"[!] GitHub commit search failed: {e}")

        return findings

    def _search_paste_sites(self) -> int:
        """Search paste sites for leaked data"""
        findings = 0

        # Use Google dorking via requests to find pastes
        search_queries = [
            f'site:pastebin.com "{self.target}"',
            f'site:ghostbin.com "{self.target}"',
            f'site:dpaste.org "{self.target}"',
        ]

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        for query in search_queries:
            try:
                # Use DuckDuckGo HTML search (no API key needed)
                url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
                resp = requests.get(url, headers=headers, timeout=10, verify=False)

                if resp.status_code == 200:
                    # Extract paste URLs from results
                    paste_pattern = re.compile(r"https?://(?:pastebin\.com|ghostbin\.com|dpaste\.org)/[a-zA-Z0-9]+")
                    matches = paste_pattern.findall(resp.text)

                    for paste_url in set(matches)[:10]:  # Limit to 10 per site
                        if self._check_paste_content(paste_url):
                            findings += 1

            except Exception:
                continue

        return findings

    def _check_paste_content(self, url: str) -> bool:
        """Check if a paste contains high-value data"""
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)

            if resp.status_code == 200:
                content = resp.text[:10000]

                # Check for target domain
                if self.target.lower() not in content.lower():
                    return False

                # Check for high-value patterns
                for pattern in self.high_value_patterns:
                    if pattern.search(content):
                        self.db.insert_finding(
                            f_type="PASTE_SITE_LEAK",
                            url=url,
                            details="Paste contains target data with potential secrets",
                            severity="HIGH",
                            source_module="paste_monitor",
                        )
                        return True

                # Even without secrets, a paste with target domain is worth noting
                self.db.insert_finding(
                    f_type="PASTE_SITE_MENTION",
                    url=url,
                    details="Paste mentions target domain",
                    severity="MEDIUM",
                    source_module="paste_monitor",
                )
                return True

        except Exception:
            pass

        return False
