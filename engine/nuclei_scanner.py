import json
import subprocess

from config import Config
from engine.base import BaseReconModule


class NucleiScanner(BaseReconModule):
    # Use tags, which Nuclei v3 resolves internally to the correct directories
    TARGET_TAGS = ["exposed-panels", "misconfiguration", "default-logins", "technologies"]

    def execute(self):
        print("[*] Running High-Signal Nuclei Scan (Panels, Misconfigs, Default Logins)...")

        endpoints = self.db.get_all_endpoints()
        live_urls = [ep["url"] for ep in endpoints if ep["status_code"] > 0]

        if not live_urls:
            print("[!] No live URLs to scan with Nuclei.")
            return

        urls_file = self.workspace / "nuclei_targets.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(live_urls))

        # Use -tags for robust internal path resolution
        tag_list = ",".join(self.TARGET_TAGS)
        cmd = (
            f"{Config.NUCLEI_BIN} -l '{urls_file}' -jsonl -silent "
            f"-severity critical,high,medium -tags {tag_list} "
            f"-timeout 10 -retries 1"
        )

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True, timeout=1200)
            out = result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Nuclei command failed with exit code {e.returncode}")
            print(f"[!] STDOUT: {e.stdout}")
            print(f"[!] STDERR: {e.stderr}")
            return
        except subprocess.TimeoutExpired:
            print("[!] Nuclei scan timed out after 20 minutes.")
            return

        findings_count = 0
        for line in out.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    url = data.get("matched-at", data.get("host", "Unknown"))
                    template_id = data.get("template-id", "Unknown")
                    severity = data.get("info", {}).get("severity", "UNKNOWN").upper()
                    description = data.get("info", {}).get("name", "No description")

                    details = f"[{template_id}] {description}"
                    self.db.insert_finding(f_type="NUCLEI_VULN/MISCONFIG", url=url, details=details, severity=severity)
                    findings_count += 1
                except json.JSONDecodeError:
                    continue

        print(f"[+] Nuclei identified {findings_count} high-signal findings.")
