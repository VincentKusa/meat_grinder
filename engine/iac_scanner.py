import json
import subprocess
from pathlib import Path

from config import Config
from engine.base import BaseReconModule


class IaCScanner(BaseReconModule):
    # IaC file patterns
    IAC_PATTERNS = [
        "*.tf",
        "*.tfvars",  # Terraform
        "*.yaml",
        "*.yml",  # Kubernetes, Docker Compose
        "Dockerfile",  # Docker
        "*.json",  # CloudFormation, ARM templates
    ]

    def execute(self):
        print("[*] Scanning Infrastructure as Code...")

        repos_dir = self.workspace / "git_repos"
        if not repos_dir.exists():
            print("[*] No repositories to scan for IaC.")
            return

        findings_count = 0
        for repo_path in repos_dir.iterdir():
            if repo_path.is_dir():
                findings_count += self._scan_iac(repo_path)

        print(f"[+] IaC scan complete. Found {findings_count} insights.")

    def _scan_iac(self, repo_path: Path) -> int:
        findings = 0

        # Run Checkov if available
        findings += self._run_checkov(repo_path)

        # Manual checks for common misconfigurations
        findings += self._manual_iac_checks(repo_path)

        return findings

    def _run_checkov(self, repo_path: Path) -> int:
        """Run Checkov for IaC security scanning"""
        findings = 0

        try:
            cmd = f"{Config.CHECKOV_BIN} -d '{repo_path}' --output json --quiet"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

            # Checkov returns 0 if no failures, 1 if failures found
            if result.returncode in [0, 1] and result.stdout.strip():
                report = json.loads(result.stdout)

                # Safely extract failed checks regardless of JSON structure
                failed_checks = []
                if isinstance(report, dict):
                    results = report.get("results", {})
                    if isinstance(results, dict):
                        failed_checks = results.get("failed_checks", [])
                    elif isinstance(results, list):
                        failed_checks = results
                elif isinstance(report, list):
                    # Fallback if the root is directly a list of findings
                    failed_checks = report

                for check in failed_checks:
                    if not isinstance(check, dict):
                        continue

                    severity = "HIGH" if check.get("severity") in ["HIGH", "CRITICAL"] else "MEDIUM"

                    self.db.insert_finding(
                        f_type="IAC_MISCONFIGURATION",
                        url=f'iac://{repo_path.name}/{check.get("file_path", "unknown")}',
                        details=f'{check.get("check_id", "Unknown")} - {check.get("name", "Unknown")}',
                        severity=severity,
                        source_module="iac_scanner",
                    )
                    findings += 1

        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass  # Gracefully skip if checkov isn't installed or times out

        return findings

    def _manual_iac_checks(self, repo_path: Path) -> int:
        """Manual checks for common IaC misconfigurations"""
        findings = 0

        # Check Dockerfiles
        for dockerfile in repo_path.rglob("Dockerfile*"):
            findings += self._check_dockerfile(dockerfile, repo_path.name)

        # Check Terraform files
        for tf_file in repo_path.rglob("*.tf"):
            findings += self._check_terraform(tf_file, repo_path.name)

        # Check Kubernetes manifests
        for k8s_file in repo_path.rglob("*.yaml"):
            if "k8s" in str(k8s_file).lower() or "kubernetes" in str(k8s_file).lower():
                findings += self._check_kubernetes(k8s_file, repo_path.name)

        return findings

    def _check_dockerfile(self, dockerfile: Path, repo_name: str) -> int:
        findings = 0
        content = dockerfile.read_text()

        # Check for running as root
        if "USER" not in content and "FROM" in content:
            self.db.insert_finding(
                "DOCKERFILE_RUNNING_AS_ROOT",
                f"iac://{repo_name}/{dockerfile.name}",
                "Dockerfile does not specify a non-root USER",
                "MEDIUM",
                source_module="iac_scanner",
            )
            findings += 1

        # Check for secrets in Dockerfile
        if any(keyword in content for keyword in ["PASSWORD", "SECRET", "API_KEY", "TOKEN"]):
            self.db.insert_finding(
                "DOCKERFILE_SECRET_LEAK",
                f"iac://{repo_name}/{dockerfile.name}",
                "Potential secret in Dockerfile",
                "HIGH",
                source_module="iac_scanner",
            )
            findings += 1

        return findings

    def _check_terraform(self, tf_file: Path, repo_name: str) -> int:
        findings = 0
        content = tf_file.read_text()

        # Check for public S3 buckets
        if "aws_s3_bucket" in content and "acl" in content:
            if "public" in content.lower():
                self.db.insert_finding(
                    "TERRAFORM_PUBLIC_S3",
                    f"iac://{repo_name}/{tf_file.name}",
                    "S3 bucket may be configured as public",
                    "HIGH",
                    source_module="iac_scanner",
                )
                findings += 1

        # Check for open security groups
        if "aws_security_group" in content and "0.0.0.0/0" in content:
            self.db.insert_finding(
                "TERRAFORM_OPEN_SECURITY_GROUP",
                f"iac://{repo_name}/{tf_file.name}",
                "Security group allows traffic from 0.0.0.0/0",
                "HIGH",
                source_module="iac_scanner",
            )
            findings += 1

        return findings

    def _check_kubernetes(self, k8s_file: Path, repo_name: str) -> int:
        findings = 0
        content = k8s_file.read_text()

        # Check for privileged containers
        if "privileged: true" in content:
            self.db.insert_finding(
                "K8S_PRIVILEGED_POD",
                f"iac://{repo_name}/{k8s_file.name}",
                "Kubernetes pod running in privileged mode",
                "HIGH",
                source_module="iac_scanner",
            )
            findings += 1

        # Check for hostPath mounts
        if "hostPath" in content:
            self.db.insert_finding(
                "K8S_HOSTPATH_MOUNT",
                f"iac://{repo_name}/{k8s_file.name}",
                "Kubernetes pod using hostPath mount",
                "MEDIUM",
                source_module="iac_scanner",
            )
            findings += 1

        return findings
