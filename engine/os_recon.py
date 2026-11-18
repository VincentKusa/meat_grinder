import re
import socket
import subprocess
import xml.etree.ElementTree as ET

from engine.base import BaseReconModule


class OSRecon(BaseReconModule):
    # Patterns for End-of-Life or highly vulnerable OS/Services
    EOL_PATTERNS = [
        re.compile(r"(?i)(windows (xp|vista|7|8|2003|2008))"),
        re.compile(r"(?i)(ubuntu (14\.04|16\.04|18\.04))"),
        re.compile(r"(?i)(debian (7|8|9))"),
        re.compile(r"(?i)(centos (5|6|7))"),
        re.compile(r"(?i)(apache 2\.2)"),
        re.compile(r"(?i)(openssh [1-6]\.)"),
    ]

    def execute(self):
        print("[*] Running Active OS & Service Fingerprinting (Nmap)...")

        # Get unique IPs from the ports table (populated by Shodan/Naabu)
        ports_data = self.db.get_all_ports()
        targets = set()
        for p in ports_data:
            if p["ip"] and p["ip"] != "Unknown":
                targets.add((p["host"], p["ip"]))

        # Fallback: resolve subdomains to IPs if port scanner didn't catch them
        for sub in self.db.get_all_subdomains():
            try:
                ip = socket.gethostbyname(sub)
                targets.add((sub, ip))
            except socket.gaierror:
                pass

        if not targets:
            print("[!] No targets resolved to IPs for OS reconnaissance.")
            return

        print(f"[*] Fingerprinting {len(targets)} unique IP addresses...")
        findings_count = 0

        for host, ip in targets:
            try:
                # Fast, targeted Nmap scan: SYN scan, Version detection, OS detection, Top 500 ports, Open only
                cmd = f"nmap -sS -sV -O --top-ports 500 -T4 --open -oX - {ip}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

                if result.returncode == 0 and "<nmaprun" in result.stdout:
                    self._parse_nmap_xml(result.stdout, host, ip)

                    # Check for EOL findings
                    if self._check_eol(result.stdout, host, ip):
                        findings_count += 1

            except subprocess.TimeoutExpired:
                print(f"[!] Nmap timeout for {ip}")
            except Exception as e:
                print(f"[!] Error scanning {ip}: {e}")

        print(f"[+] OS Recon complete. Flagged {findings_count} EOL/Vulnerable systems.")

    def _parse_nmap_xml(self, xml_output: str, host: str, ip: str):
        try:
            root = ET.fromstring(xml_output)
            host_elem = root.find("host")
            if not host_elem:
                return

            # Extract OS
            os_name = "Unknown"
            accuracy = "0"
            os_elem = host_elem.find("os")
            if os_elem is not None:
                os_match = os_elem.find("osmatch")
                if os_match is not None:
                    os_name = os_match.get("name", "Unknown")
                    accuracy = os_match.get("accuracy", "0")

            # Extract Hostname
            hostname = host
            hostname_elem = host_elem.find("hostnames/hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", host)

            # Extract Open Ports & Services
            open_ports = []
            for port in host_elem.findall("ports/port"):
                if port.get("state") == "open":
                    port_num = port.get("portid")
                    service = port.find("service")
                    svc_name = service.get("name", "unknown") if service is not None else "unknown"
                    svc_product = service.get("product", "") if service is not None else ""
                    svc_version = service.get("version", "") if service is not None else ""

                    version_str = f"{svc_product} {svc_version}".strip()
                    open_ports.append(f"{port_num}({svc_name}:{version_str})")

            ports_str = ", ".join(open_ports)

            # Save to DB
            self.db.insert_os_recon(host, ip, os_name, accuracy, hostname, ports_str)

        except ET.ParseError:
            pass

    def _check_eol(self, xml_output: str, host: str, ip: str) -> bool:
        """Checks Nmap output for End-of-Life OS or Services and creates a Finding"""
        # Combine OS and Service info for regex matching
        match_text = xml_output

        for pattern in self.EOL_PATTERNS:
            match = pattern.search(match_text)
            if match:
                self.db.insert_finding(
                    f_type="EOL_OS_OR_SERVICE",
                    url=f"host://{host} ({ip})",
                    details=f"Detected outdated software/OS: {match.group(1).strip()}",
                    severity="HIGH",
                )
                return True
        return False
