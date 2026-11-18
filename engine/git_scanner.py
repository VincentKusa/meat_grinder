import json
import re
import shutil
import subprocess
from pathlib import Path

import requests
import urllib3
from bs4 import BeautifulSoup
from github import Github, GithubException

from config import Config
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GitScanner(BaseReconModule):
    def __init__(self, target: str, db, workspace, github_target: str = None):
        super().__init__(target, db, workspace)
        self.repos_dir = workspace / "git_repos"
        self.repos_dir.mkdir(exist_ok=True)
        self.target_base_name = target.split(".")[0]
        self.github_target = github_target  # NEW

    def execute(self):
        print("[*] Starting Advanced Git Repository Scanning...")
        repos_to_scan = set()

        # Strategy 1: Scrape target website for GitHub links (Always runs)
        print("[*] Strategy 1: Scraping target website for GitHub links...")
        web_repos = self._scrape_website_for_github_links()
        repos_to_scan.update(web_repos)

        # Strategy 2: GitHub API Search
        if Config.GITHUB_TOKEN:
            print("[*] Strategy 2: Searching GitHub API...")
            if self.github_target:
                print(f"[*] Explicitly targeting GitHub org/user: '{self.github_target}'")
                api_repos = self._get_explicit_github_repos(self.github_target)
                repos_to_scan.update(api_repos)
            else:
                print(f"[*] Fuzzy searching GitHub API for base name: '{self.target_base_name}'")
                api_repos = self._search_github_api_fuzzy()
                repos_to_scan.update(api_repos)
        else:
            print("[!] No GITHUB_TOKEN found in .env. Skipping GitHub API search.")

        if not repos_to_scan:
            print("[!] No related GitHub repositories found via scraping or API.")
        else:
            print(f"[*] Found {len(repos_to_scan)} unique GitHub repositories to scan.")
            self._clone_and_scan(repos_to_scan)

        # Strategy 3: Scan exposed .git directories
        self._scan_exposed_git_dirs()

    def _get_explicit_github_repos(self, target_name: str) -> set:
        """Fetches all non-archived, non-forked repos from a specific GitHub org or user."""
        found_repos = set()
        try:
            g = Github(Config.GITHUB_TOKEN)

            # Try as Organization first
            try:
                org = g.get_organization(target_name)
                print(f"[*] Found GitHub Organization: {org.name or org.login} ({org.public_repos} public repos)")
                for repo in org.get_repos():
                    if not repo.archived and not repo.fork:
                        found_repos.add(repo.html_url)
                return found_repos
            except GithubException:
                pass  # Not an org, try user

            # Try as User
            try:
                user = g.get_user(target_name)
                print(f"[*] Found GitHub User: {user.name or user.login} ({user.public_repos} public repos)")
                for repo in user.get_repos():
                    if not repo.archived and not repo.fork:
                        found_repos.add(repo.html_url)
                return found_repos
            except GithubException:
                print(f"[!] Could not find '{target_name}' as a GitHub organization or user.")

        except Exception as e:
            print(f"[!] GitHub API error: {e}")
        return found_repos

    def _search_github_api_fuzzy(self) -> set:
        """Fallback fuzzy search if no explicit target is provided."""
        found_repos = set()
        try:
            g = Github(Config.GITHUB_TOKEN)

            # Search for repos with the base name in name, description, or readme
            query = f"{self.target_base_name} in:name,description,readme"
            repos = g.search_repositories(query=query, sort="stars", order="desc")

            count = 0
            for repo in repos:
                if count >= 15:  # Limit to top 15 to avoid massive scans
                    break
                if not repo.archived and not repo.fork:
                    found_repos.add(repo.html_url)
                    count += 1

            # Also search for code containing the full domain string
            code_query = f'"{self.target}"'
            code_results = g.search_code(code_query)
            count = 0
            for code in code_results:
                if count >= 15:
                    break
                found_repos.add(code.repository.html_url)
                count += 1

        except GithubException as e:
            print(f"[!] GitHub API error: {e}")
        except Exception as e:
            print(f"[!] Error searching GitHub: {e}")

        return found_repos

    def _scrape_website_for_github_links(self) -> set:
        found_repos = set()
        target_url = f"https://{self.target}"

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp = requests.get(target_url, headers=headers, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")

            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                match = re.search(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", href)
                if match:
                    repo_path = match.group(1)
                    if repo_path.split("/")[0] not in [
                        "settings",
                        "explore",
                        "marketplace",
                        "topics",
                        "trending",
                        "collections",
                        "events",
                        "sponsors",
                        "about",
                    ]:
                        found_repos.add(f"https://github.com/{repo_path}")
        except Exception as e:
            print(f"[!] Failed to scrape website: {e}")

        return found_repos

    def _clone_and_scan(self, repos_to_scan: set):
        scanned = 0
        for repo_url in repos_to_scan:
            repo_name = repo_url.rstrip("/").split("/")[-1]
            repo_path = self.repos_dir / repo_name
            if repo_path.exists():
                shutil.rmtree(repo_path)

            print(f"[*] Cloning {repo_url}...")
            try:
                clone_url = repo_url if repo_url.endswith(".git") else f"{repo_url}.git"
                subprocess.run(
                    ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                    capture_output=True,
                    check=True,
                    timeout=120,
                )

                self._run_gitleaks(repo_path, f"github:{repo_url}")
                scanned += 1

            except subprocess.CalledProcessError:
                print(f"[!] Failed to clone {repo_url}")
            except subprocess.TimeoutExpired:
                print(f"[!] Timeout cloning {repo_url}")
            except Exception as e:
                print(f"[!] Error cloning {repo_url}: {e}")

        print(f"[+] Scanned {scanned} GitHub repositories")

    def _scan_exposed_git_dirs(self):
        print("[*] Scanning for exposed .git directories...")
        endpoints = self.db.get_all_endpoints()
        git_endpoints = [ep for ep in endpoints if "/.git/" in ep["url"].lower() or ep["url"].lower().endswith("/.git")]

        if not git_endpoints:
            print("[*] No exposed .git directories found")
            return

        print(f"[*] Found {len(git_endpoints)} potential exposed .git directories")
        base_urls = set()
        for ep in git_endpoints:
            base_urls.add(ep["url"].split("/.git")[0])

        for repo_url in base_urls:
            repo_name = repo_url.split("/")[-1].replace(".", "_").replace(":", "_")
            repo_path = self.repos_dir / f"exposed_{repo_name}"
            if repo_path.exists():
                shutil.rmtree(repo_path)

            print(f"[*] Attempting to dump .git from {repo_url}/.git ...")
            try:
                repo_path.mkdir(parents=True, exist_ok=True)
                head_url = f"{repo_url}/.git/HEAD"
                head_file = repo_path / ".git" / "HEAD"
                head_file.parent.mkdir(parents=True, exist_ok=True)

                result = subprocess.run(
                    ["curl", "-s", "-f", "-o", str(head_file), head_url], capture_output=True, timeout=10
                )

                if result.returncode == 0 and head_file.exists():
                    self.db.insert_finding(
                        "EXPOSED_GIT_DIRECTORY",
                        repo_url,
                        "Git directory is publicly accessible (HEAD found)",
                        "CRITICAL",
                    )
                shutil.rmtree(repo_path)
            except Exception as e:
                print(f"[!] Failed to dump .git from {repo_url}: {e}")

    def _run_gitleaks(self, repo_path: Path, source: str):
        report_file = self.workspace / f"gitleaks_{repo_path.name}.json"
        cmd = [
            Config.GITLEAKS_BIN,
            "detect",
            "--source",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            str(report_file),
            "--exit-code",
            "0",
        ]

        try:
            subprocess.run(cmd, capture_output=True, check=True, timeout=120)
            if report_file.exists() and report_file.stat().st_size > 2:
                with open(report_file, "r") as f:
                    findings = json.load(f)
                for finding in findings:
                    rule = finding.get("RuleID", "UNKNOWN")
                    file_path = finding.get("File", "unknown")
                    line = finding.get("StartLine", 0)
                    secret = finding.get("Secret", "")[:20] + "..." if finding.get("Secret") else "N/A"
                    details = f"Rule: {rule} | File: {file_path}:{line} | Secret: {secret}"
                    self.db.insert_finding("LEAKED_SECRET", f"{source}/{file_path}", details, "CRITICAL")
            if report_file.exists():
                report_file.unlink()
        except subprocess.CalledProcessError:
            pass
        except subprocess.TimeoutExpired:
            print(f"[!] Gitleaks timeout on {repo_path.name}")
        except Exception as e:
            print(f"[!] Error running gitleaks on {repo_path.name}: {e}")
