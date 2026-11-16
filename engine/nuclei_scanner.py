import json
import subprocess
from pathlib import Path
from engine.base import BaseReconModule
from config import Config


class NucleiScanner(BaseReconModule):
    # High-signal, low-noise template directory paths (verified for Nuclei v3.11.1)
    TARGET_TEMPLATES = [
        "http/exposed-panels/",
        "http/misconfiguration/",
        "http/default-logins/",
        "http/technologies/"
    ]

    def execute(self):
        print("[*] Running High-Signal Nuclei Scan (Panels, Misconfigs, Default Logins)...")

        # Get live HTTP endpoints from DB
        endpoints = self.db.get_all_endpoints()
        live_urls = [ep['url'] for ep in endpoints if ep['status_code'] > 0]

        if not live_urls:
            print("[!] No live URLs to scan with Nuclei.")
            return

        urls_file = self.workspace / "nuclei_targets.txt"
        with open(urls_file, 'w') as f:
            f.write('\n'.join(live_urls))

        # Build the nuclei command using the verified directory paths
        template_paths = ",".join(self.TARGET_TEMPLATES)
        cmd = (f"{Config.NUCLEI_BIN} -l {urls_file} -json -silent "
               f"-severity critical,high,medium -t {template_paths} "
               f"-timeout 10 -retries 1")

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                check=True, timeout=1200
            )
            out = result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] Nuclei command failed with exit code {e.returncode}")
            print(f"[!] STDERR: {e.stderr}")
            return
        except subprocess.TimeoutExpired:
            print("[!] Nuclei scan timed out after 20 minutes.")
            return

        findings_count = 0
        for line in out.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    url = data.get('matched-at', data.get('host', 'Unknown'))
                    template_id = data.get('template-id', 'Unknown')
                    severity = data.get('info', {}).get('severity', 'UNKNOWN').upper()
                    description = data.get('info', {}).get('name', 'No description')

                    details = f"[{template_id}] {description}"

                    self.db.insert_finding(
                        f_type="NUCLEI_VULN/MISCONFIG",
                        url=url,
                        details=details,
                        severity=severity
                    )
                    findings_count += 1
                except json.JSONDecodeError:
                    continue

        print(f"[+] Nuclei identified {findings_count} high-signal findings.")