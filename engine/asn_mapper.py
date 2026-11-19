import re

import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ASNMapper(BaseReconModule):
    # CDN fingerprints
    CDN_FINGERPRINTS = {
        "Cloudflare": ["cloudflare", "cf-ray", "cloudflare.com"],
        "Akamai": ["akamai", "akamaized.net", "edgesuite.net"],
        "Fastly": ["fastly", "fastly.net"],
        "Amazon CloudFront": ["cloudfront.net", "amazonaws.com"],
        "Azure CDN": ["azureedge.net", "microsoft.com"],
        "Google Cloud CDN": ["googleapis.com", "google.com"],
    }

    def execute(self):
        print("[*] Mapping ASN and infrastructure details...")

        # Get all IPs from database
        ports = self.db.get_all_ports()
        ips = set()

        for p in ports:
            if p.get("ip"):
                ips.add(p["ip"])

        if not ips:
            print("[*] No IPs found in database. Skipping ASN mapping.")
            return

        print(f"[*] Analyzing {len(ips)} unique IP addresses...")

        findings_count = 0

        for ip in ips:
            if self._analyze_ip(ip):
                findings_count += 1

        # Analyze endpoints for CDN detection
        endpoints = self.db.get_all_endpoints()
        for ep in endpoints:
            if self._detect_cdn(ep["url"]):
                findings_count += 1

        print(f"[+] ASN mapping complete. Found {findings_count} insights.")

    def _analyze_ip(self, ip: str) -> bool:
        """Analyze an IP address for ASN and hosting info"""
        findings = 0

        try:
            # Use ipinfo.io (free tier: 50k requests/month)
            # Alternative: use whois or bgp.he.net
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10, verify=False)

            if resp.status_code == 200:
                data = resp.json()

                org = data.get("org", "Unknown")
                city = data.get("city", "Unknown")
                region = data.get("region", "Unknown")
                country = data.get("country", "Unknown")
                data.get("hostname", "")

                # Extract ASN from org field (format: "AS12345 Organization Name")
                asn_match = re.match(r"AS(\d+)\s+(.+)", org)
                if asn_match:
                    asn = asn_match.group(1)
                    asn_org = asn_match.group(2)

                    self.db.insert_finding(
                        f_type="ASN_DISCOVERED",
                        url=f"ip://{ip}",
                        details=f"ASN: AS{asn} | Org: {asn_org} | Location: {city}, {region}, {country}",
                        severity="INFO",
                        source_module="asn_mapper",
                    )
                    findings += 1

                    # Check for cloud providers
                    cloud_providers = ["amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "ovh"]
                    if any(provider in asn_org.lower() for provider in cloud_providers):
                        self.db.insert_finding(
                            f_type="CLOUD_HOSTED_ASSET",
                            url=f"ip://{ip}",
                            details=f"Asset hosted on cloud provider: {asn_org}",
                            severity="INFO",
                            source_module="asn_mapper",
                        )
                        findings += 1
                else:
                    # No ASN found, but log the org
                    self.db.insert_finding(
                        f_type="IP_ORGANIZATION",
                        url=f"ip://{ip}",
                        details=f"Org: {org} | Location: {city}, {region}, {country}",
                        severity="INFO",
                        source_module="asn_mapper",
                    )
                    findings += 1

        except Exception:
            pass

        return findings > 0

    def _detect_cdn(self, url: str) -> bool:
        """Detect if a URL is behind a CDN"""
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)

            # Check headers for CDN indicators
            all_headers = str(resp.headers).lower()
            all_content = resp.text[:1000].lower()

            for cdn_name, fingerprints in self.CDN_FINGERPRINTS.items():
                if any(fp.lower() in all_headers or fp.lower() in all_content for fp in fingerprints):
                    self.db.insert_finding(
                        f_type="CDN_DETECTED",
                        url=url,
                        details=f"Behind {cdn_name} CDN",
                        severity="INFO",
                        source_module="asn_mapper",
                    )
                    return True

        except Exception:
            pass

        return False
