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
    # Keywords that indicate test/CTF repos (lower score)
    NOISE_KEYWORDS = [
        "ctf",
        "writeup",
        "test",
        "example",
        "demo",
        "sample",
        "poc",
        "handbook",
        "learning",
        "tutorial",
        "lab",
        "challenge",
    ]

    def __init__(self, target: str, db, workspace, github_target: str = None, min_score: int = 60):
        super().__init__(target, db, workspace)
        self.github_target = github_target
        self.min_score = min_score
        self.repos_dir = workspace / "git_repos"
        self.repos_dir.mkdir(exist_ok=True)

    def execute(self):
        print("[*] Starting Advanced Git Repository Scanning...")
        repos_to_scan = set()

        # Strategy 1: Scrape target website for GitHub links (if we have live endpoints)
        print("[*] Strategy 1: Scraping target website for GitHub links...")
        endpoints = self.db.get_all_endpoints()
        for ep in endpoints:
            if ep["status_code"] == 200:
                repos_to_scan.update(self._scrape_github_links(ep["url"]))

        # Strategy 2: Search GitHub API
        print("[*] Strategy 2: Searching GitHub API...")
        if self.github_target:
            print(f"[*] Explicitly targeting GitHub org/user: '{self.github_target}'")
            repos_to_scan.update(self._get_explicit_target_repos(self.github_target))
        else:
            print(f"[*] Fuzzy searching GitHub API for base name: '{self.target.split('.')[0]}'")
            repos_to_scan.update(self._fuzzy_search_github(self.target.split(".")[0]))

        # Filter and score repositories
        print(f"[*] Found {len(repos_to_scan)} unique GitHub repositories to scan.")
        filtered_repos = self._filter_and_score_repos(repos_to_scan)

        print(f"[*] {len(filtered_repos)} repositories passed the minimum score threshold ({self.min_score}).")

        if filtered_repos:
            self._clone_and_scan(filtered_repos)
        else:
            print("[*] No repositories met the relevance score threshold. Skipping Git scan.")

    def _score_repository(self, repo_url: str, linked_from_website: bool) -> int:
        """Score a repository's relevance to the target (0-100)"""
        repo_name = repo_url.rstrip("/").split("/")[-1].lower()
        owner = repo_url.rstrip("/").split("/")[-2].lower()
        target_base = self.target.split(".")[0].lower()

        # 1. Explicit target match (guarantees inclusion with max score)
        if self.github_target and owner == self.github_target.lower():
            return 100

        score = 0

        # 2. Linked from target website
        if linked_from_website:
            score += 50

        # 3. Repo name contains target base
        if target_base in repo_name:
            score += 30

        # 4. Penalize noise keywords
        for keyword in self.NOISE_KEYWORDS:
            if keyword in repo_name or keyword in owner:
                score -= 20

        # Ensure score is in range 0-100
        return max(0, min(100, score))

    def _filter_and_score_repos(self, repos: set) -> set:
        """Filter repositories based on their relevance score"""
        filtered = set()
        for repo in repos:
            # Assume not linked from website for API-discovered repos to be safe,
            # or you could track this in a dict. For simplicity, we score based on name/owner.
            score = self._score_repository(repo, linked_from_website=False)
            if score >= self.min_score:
                filtered.add(repo)
        return filtered

    def _scrape_github_links(self, url: str) -> set:
        repos = set()
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if "github.com" in href and not href.endswith(".git"):
                        # Clean up the URL to get the base repo URL
                        match = re.search(r"(https?://github\.com/[^/]+/[^/]+)", href)
                        if match:
                            repos.add(match.group(1))
        except Exception:
            pass
        return repos

    def _get_explicit_target_repos(self, target: str) -> set:
        repos = set()
        try:
            g = Github(Config.GITHUB_TOKEN)
            # Try as organization first, then user
            try:
                org = g.get_organization(target)
                for repo in org.get_repos():
                    if not repo.archived and not repo.fork:
                        repos.add(repo.html_url)
            except GithubException:
                try:
                    user = g.get_user(target)
                    for repo in user.get_repos():
                        if not repo.archived and not repo.fork:
                            repos.add(repo.html_url)
                except GithubException:
                    print(f"[!] Could not find GitHub org or user: {target}")
        except Exception as e:
            print(f"[!] GitHub API error: {e}")
        return repos

    def _fuzzy_search_github(self, base_name: str) -> set:
        repos = set()
        try:
            g = Github(Config.GITHUB_TOKEN)
            query = f'"{base_name}" in:readme OR "{base_name}" in:description OR "{base_name}" in:name'
            search_result = g.search_repositories(query, sort="stars", order="desc")
            for repo in search_result[:20]:  # Limit to top 20 to avoid massive scans
                if not repo.archived and not repo.fork:
                    repos.add(repo.html_url)
        except Exception as e:
            print(f"[!] GitHub API search error: {e}")
        return repos

    def _clone_and_scan(self, repos_to_scan: set):
        """Clones repositories and runs Gitleaks."""
        scanned = 0
        for repo_url in repos_to_scan:
            repo_name = repo_url.rstrip("/").split("/")[-1]
            repo_path = self.repos_dir / repo_name

            # Only clone if it doesn't already exist
            if repo_path.exists():
                shutil.rmtree(repo_path)

            print(f"[*] Cloning {repo_url}...")
            try:
                clone_url = repo_url if repo_url.endswith(".git") else f"{repo_url}.git"
                subprocess.run(
                    ["git", "clone", "--depth", str(Config.GIT_CLONE_DEPTH), clone_url, str(repo_path)],
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

    def _run_gitleaks(self, repo_path: Path, source_url: str):
        """Runs gitleaks on the cloned repository."""
        report_path = self.workspace / f"gitleaks_{repo_path.name}.json"
        cmd = (
            f"{Config.GITLEAKS_BIN} detect --source '{repo_path}' "
            f"--report-format json --report-path '{report_path}' --no-git --no-banner"
        )

        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

            if report_path.exists() and report_path.stat().st_size > 2:
                with open(report_path, "r") as f:
                    data = json.load(f)

                # Handle different Gitleaks versions:
                # v8+ returns a direct list. v7 returns a dict with 'Issues' or 'Report'.
                findings_list = []
                if isinstance(data, list):
                    findings_list = data
                elif isinstance(data, dict):
                    findings_list = data.get("Issues", []) or data.get("Report", [])

                for finding in findings_list:
                    # Gitleaks v8 structure
                    secret = finding.get("Secret", "")
                    rule = finding.get("RuleID", "unknown")
                    file = finding.get("File", "unknown")
                    line = finding.get("StartLine", "unknown")

                    # Truncate secret for safety in reports
                    safe_secret = secret[:20] + "..." if len(secret) > 20 else secret

                    details = f"Rule: {rule} | File: {file}:{line} | Secret: {safe_secret}"

                    self.db.insert_finding(
                        f_type="LEAKED_SECRET",
                        url=f"{source_url}/{file}",
                        details=details,
                        severity="CRITICAL",
                        source_module="git_scanner",
                        file_path=file,
                        rule_id=rule,
                    )

            # Clean up report to save space
            if report_path.exists():
                report_path.unlink()

        except subprocess.TimeoutExpired:
            print(f"[!] Gitleaks timeout on {repo_path.name}")
        except Exception as e:
            print(f"[!] Gitleaks error on {repo_path.name}: {e}")
