import json
import subprocess
from pathlib import Path

from config import Config
from engine.base import BaseReconModule


class SBOMScanner(BaseReconModule):
    # Lock files to scan
    LOCK_FILES = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "composer.lock",
    ]

    def execute(self):
        print("[*] Scanning dependencies and generating SBOM...")

        # Scan cloned repositories
        repos_dir = self.workspace / "git_repos"
        if not repos_dir.exists():
            print("[*] No repositories to scan for dependencies.")
            return

        findings_count = 0
        for repo_path in repos_dir.iterdir():
            if repo_path.is_dir():
                findings_count += self._scan_repo_dependencies(repo_path)

        print(f"[+] Dependency scan complete. Found {findings_count} insights.")

    def _scan_repo_dependencies(self, repo_path: Path) -> int:
        findings = 0

        # Look for lock files
        for lock_file in self.LOCK_FILES:
            lock_path = repo_path / lock_file
            if lock_path.exists():
                findings += self._analyze_lock_file(lock_path, repo_path.name)

        # Run Trivy if available for vulnerability scanning
        findings += self._run_trivy_scan(repo_path)

        return findings

    def _analyze_lock_file(self, lock_path: Path, repo_name: str) -> int:
        """Basic analysis of lock files for outdated/vulnerable packages"""
        findings = 0

        try:
            content = lock_path.read_text()

            # Check for known vulnerable package patterns
            vulnerable_patterns = [
                ("lodash<4.17.21", "Prototype pollution vulnerability"),
                ("requests<2.20.0", "CRLF injection vulnerability"),
                ("django<3.2", "Multiple security vulnerabilities"),
                ("flask<2.0", "Security vulnerabilities"),
            ]

            for pattern, description in vulnerable_patterns:
                if pattern.split("<")[0] in content:
                    self.db.insert_finding(
                        "VULNERABLE_DEPENDENCY",
                        f"repo://{repo_name}/{lock_path.name}",
                        f"Potentially vulnerable: {pattern} - {description}",
                        "MEDIUM",
                        source_module="sbom_scanner",
                    )
                    findings += 1

        except Exception:
            pass

        return findings

    def _run_trivy_scan(self, repo_path: Path) -> int:
        """Run Trivy for comprehensive vulnerability scanning"""
        findings = 0

        try:
            cmd = f"{Config.TRIVY_BIN} fs --scanners vuln --format json '{repo_path}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

            if result.returncode in [0, 1]:  # Trivy returns 1 if vulnerabilities found
                report = json.loads(result.stdout)

                for target in report.get("Results", []):
                    for vuln in target.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN").upper()
                        if severity in ["CRITICAL", "HIGH"]:
                            self.db.insert_finding(
                                "VULNERABLE_DEPENDENCY",
                                f'repo://{repo_path.name}/{target.get("Target", "unknown")}',
                                f'{vuln.get("VulnerabilityID")} '
                                f'in {vuln.get("PkgName")} {vuln.get("InstalledVersion")}',
                                severity,
                                source_module="sbom_scanner",
                            )
                            findings += 1

        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        return findings
