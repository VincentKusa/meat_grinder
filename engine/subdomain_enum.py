from config import Config
from engine.base import BaseReconModule


class SubdomainEnumerator(BaseReconModule):
    def execute(self):
        print(f"[*] Enumerating subdomains for {self.target}...")
        cmd = f"{Config.SUBFINDER_BIN} -d {self.target} -silent -json"
        out = self.run_cmd(cmd)

        count = 0
        for item in self.parse_ndjson(out):
            host = item.get("host", item.get("name", ""))
            if host:
                self.db.insert_subdomain(host, "subfinder")
                count += 1
        print(f"[+] Discovered {count} subdomains.")
