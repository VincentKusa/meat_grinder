import requests
import urllib3

from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TakeoverVerifier(BaseReconModule):
    # Known fingerprints for subdomain takeover
    FINGERPRINTS = {
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "GitHub Pages": ["There isn't a GitHub Pages site here.", "For root URLs"],
        "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "Azure": ["404 Web Site not found"],
        "Shopify": ["Sorry, this shop is currently unavailable."],
        "Zendesk": ["Help Center Closed"],
    }

    def execute(self):
        print("[*] Verifying potential Subdomain Takeovers...")

        # Find all DANGLING_CNAME findings from the DNS scanner
        findings = self.db.get_all_findings()
        dangling_cnames = [f for f in findings if f["finding_type"] == "DANGLING_CNAME"]

        if not dangling_cnames:
            print("[*] No dangling CNAMEs found to verify.")
            return

        verified_count = 0
        for finding in dangling_cnames:
            # Extract domain from "dns://sub.example.com"
            domain = finding["url"].replace("dns://", "")
            if self._verify_takeover(domain, finding["details"]):
                verified_count += 1

        print(f"[+] Takeover verification complete. Confirmed {verified_count} vulnerable subdomains.")

    def _verify_takeover(self, domain: str, details: str) -> bool:
        try:
            # Try HTTP first, then HTTPS
            for scheme in ["http://", "https://"]:
                target = f"{scheme}{domain}"
                resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)

                for provider, fingerprints in self.FINGERPRINTS.items():
                    if any(fp.lower() in resp.text.lower() for fp in fingerprints):
                        self.db.insert_finding(
                            f_type="SUBDOMAIN_TAKEOVER_VULNERABLE",
                            url=target,
                            details=f"Confirmed {provider} takeover. Original CNAME: {details}",
                            severity="CRITICAL",
                            source_module="takeover_verifier",
                        )
                        return True
        except Exception:
            pass
        return False
