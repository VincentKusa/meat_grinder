import json
import socket

import requests

from config import Config
from engine.base import BaseReconModule

# Common port-to-service mapping
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


class PortScanner(BaseReconModule):
    def __init__(self, target: str, db, workspace, mode: str = "passive"):
        super().__init__(target, db, workspace)
        self.mode = mode

    def execute(self):
        if self.mode == "passive":
            self._passive_scan()
        elif self.mode == "active":
            self._active_scan()
        else:
            print(f"[!] Unknown scan mode: {self.mode}")

    def _map_services(self, ports: list) -> dict:
        """Map discovered ports to service names"""
        services = {}
        for port in ports:
            services[str(port)] = PORT_SERVICE_MAP.get(port, "Unknown")
        return services

    def _passive_scan(self):
        print("[*] Running Passive Port Scan (Shodan InternetDB)...")
        subs = self.db.get_all_subdomains()
        found = 0
        for sub in subs:
            try:
                ip = socket.gethostbyname(sub)
                resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    os_info = data.get("os", "") or "Unknown"
                    cpes = data.get("cpes", [])  # Common Platform Enumeration (app fingerprints)

                    if ports:
                        services = self._map_services(ports)
                        # Merge CPEs into services for richer app detection
                        if cpes:
                            services["cpe"] = cpes
                        self.db.insert_port(sub, ip, ports, "shodan_passive", os_info, services)
                        found += 1
            except Exception:
                pass
        print(f"[+] Passive scan complete. Found open ports on {found} hosts.")

    def _active_scan(self):
        print("[*] Running Active Port Scan (Naabu - Top 100 Ports)...")
        subs_file = self.workspace / "subs_to_probe.txt"
        with open(subs_file, "w") as f:
            for sub in self.db.get_all_subdomains():
                f.write(f"{sub}\n")

        cmd = f"{Config.NAABU_BIN} -list {subs_file} -json -silent -top-ports 100"
        out = self.run_cmd(cmd, timeout=600)

        host_ports = {}
        for line in out.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get("host", data.get("ip", "unknown"))
                    port = data.get("port")
                    if host not in host_ports:
                        host_ports[host] = {"ip": data.get("ip", ""), "ports": []}
                    host_ports[host]["ports"].append(port)
                except json.JSONDecodeError:
                    continue

        for host, data in host_ports.items():
            services = self._map_services(data["ports"])
            # Active scans don't give us OS info without Nmap -O, so we leave it blank
            self.db.insert_port(host, data["ip"], data["ports"], "naabu_active", "", services)

        print(f"[+] Active scan complete. Found open ports on {len(host_ports)} hosts.")
