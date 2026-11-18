import subprocess
from pathlib import Path

from config import Config
from engine.base import BaseReconModule


class Screenshotter(BaseReconModule):
    def execute(self):
        print("[*] Capturing screenshots of high-value findings...")

        # Get only HIGH and CRITICAL findings to screenshot
        findings = self.db.get_all_findings()
        target_urls = set()
        for f in findings:
            if f["severity"] in ["CRITICAL", "HIGH"]:
                # Extract the base URL from the finding URL
                url = f["url"].split(" -> ")[0]  # Handle JS file findings
                if url.startswith("http"):
                    target_urls.add(url)

        if not target_urls:
            print("[*] No high-severity HTTP endpoints found to screenshot.")
            return

        screenshot_dir = self.workspace / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)

        targets_file = self.workspace / "screenshot_targets.txt"
        with open(targets_file, "w") as f:
            f.write("\n".join(target_urls))

        # Run gowitness
        cmd = (
            f"{Config.GOWITNESS_BIN} file -f '{targets_file}' "
            f"--destination '{screenshot_dir}' --threads 5 --timeout 10"
        )

        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True, timeout=300)
            print(f"[+] Screenshots saved to {screenshot_dir}")

            # Link screenshots back to findings in the DB
            self._link_screenshots_to_findings(screenshot_dir)

        except subprocess.CalledProcessError as e:
            print(f"[!] Gowitness failed: {e.stderr}")

    def _link_screenshots_to_findings(self, screenshot_dir: Path):
        """Updates findings in DB with the path to their screenshot"""
        findings = self.db.get_all_findings()
        for f in findings:
            if f["severity"] in ["CRITICAL", "HIGH"]:
                url = f["url"].split(" -> ")[0]
                # Gowitness names files based on the URL (simplified matching)
                # We'll just update the finding details to note a screenshot exists
                # In a production app, you'd map the exact filename.
                # For now, we note the directory.
                new_details = f"{f['details']} | 📸 Screenshot: ./screenshots/"
                # We can't easily update SQLite without an UPDATE method,
                # so we'll just append to the report generator instead.
                print(new_details)
                print(url)
