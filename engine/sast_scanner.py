import json
import subprocess

from config import Config
from engine.base import BaseReconModule


class SASTScanner(BaseReconModule):
    def execute(self):
        print("[*] Running Deep Code SAST Scan (TruffleHog)...")

        # Target the git_repos directory where GitScanner cloned everything
        repos_dir = self.workspace / "git_repos"
        if not repos_dir.exists() or not any(repos_dir.iterdir()):
            print("[*] No cloned repositories found. Skipping SAST.")
            return

        print("[*] Scanning filesystem and git history for deep secrets...")
        report_path = self.workspace / "trufflehog_report.json"

        # --json: output format
        # --no-update: prevent trufflehog from checking for its own updates
        # --only-verified: CRITICAL for zero noise. Only report secrets that TruffleHog actively verified as live/valid.
        cmd = f"{Config.TRUFFLEHOG_BIN} filesystem '{repos_dir}' --json --no-update --only-verified > '{report_path}'"

        try:
            subprocess.run(cmd, shell=True, check=True, timeout=600)

            if report_path.exists() and report_path.stat().st_size > 2:
                with open(report_path, "r") as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            source = (
                                data.get("SourceMetadata", {})
                                .get("Data", {})
                                .get("Filesystem", {})
                                .get("file", "Unknown")
                            )
                            secret_type = (
                                data.get("SourceMetadata", {})
                                .get("Data", {})
                                .get("Filesystem", {})
                                .get("secret_type", "Unknown")
                            )

                            # Truncate secret for safety in report
                            raw_secret = data.get("Raw", "")
                            safe_secret = raw_secret[:15] + "..." if len(raw_secret) > 15 else raw_secret

                            details = f"Type: {secret_type} | Secret: {safe_secret}"
                            self.db.insert_finding(
                                f_type="DEEP_CODE_SECRET (VERIFIED)",
                                url=f"repo://{source}",
                                details=details,
                                severity="CRITICAL",
                            )
                        except json.JSONDecodeError:
                            continue
                print("[+] TruffleHog scan complete.")

            # Clean up report
            if report_path.exists():
                report_path.unlink()

        except subprocess.CalledProcessError as e:
            # Trufflehog returns non-zero if it finds nothing or errors, which is fine
            print(f"[*] TruffleHog finished (Exit code: {e.returncode}).")
        except subprocess.TimeoutExpired:
            print("[!] TruffleHog scan timed out.")
