from pathlib import Path
from config import Config
from engine.base import BaseReconModule

class HTTPProber(BaseReconModule):
    def execute(self):
        print(f"[*] Probing live HTTP endpoints...")

        subdomains = self.db.get_all_subdomains()
        if not subdomains:
            print("[!] No subdomains found in DB to probe. Check Phase 1.")
            return

        subs_file = self.workspace / "subs_to_probe.txt"
        with open(subs_file, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")

        # Added -web-server to capture Server header (e.g., "Apache/2.4.41")
        cmd = (f"{Config.HTTPX_BIN} -l {subs_file} -status-code -tech-detect -title "
               f"-content-length -web-server -follow-redirects -json -silent")
        out = self.run_cmd(cmd, timeout=600)

        count = 0
        for item in self.parse_ndjson(out):
            url = item.get('url', '')
            if url:
                tech = ", ".join(item.get('tech', []))
                # webserver field can be a string or list depending on httpx version
                webserver = item.get('webserver', '')
                if isinstance(webserver, list):
                    webserver = ", ".join(webserver)

                self.db.insert_endpoint(
                    url=url,
                    status=item.get('status_code', 0),
                    title=item.get('title', ''),
                    tech=tech,
                    length=item.get('content_length', 0),
                    webserver=webserver
                )
                count += 1
        print(f"[+] Probed {count} live endpoints.")