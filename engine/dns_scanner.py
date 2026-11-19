import dns.resolver
import dns.reversename

from engine.base import BaseReconModule


class DNSScanner(BaseReconModule):
    def execute(self):
        print("[*] Performing DNS intelligence gathering...")

        domains = [self.target] + self.db.get_all_subdomains()
        findings_count = 0

        for domain in domains:
            findings_count += self._analyze_domain(domain)

        print(f"[+] DNS analysis complete. Found {findings_count} insights.")

    def _analyze_domain(self, domain: str) -> int:
        findings = 0

        # Query different record types
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    value = str(rdata)
                    ttl = answers.rrset.ttl

                    # Store in database
                    with self.db._get_conn() as conn:
                        conn.execute(
                            """
                                     INSERT OR IGNORE INTO dns_records
                            (domain, record_type, record_value, ttl)
                            VALUES (?, ?, ?, ?)
                                     """,
                            (domain, rtype, value, ttl),
                        )

                    # Check for security issues
                    if rtype == "TXT":
                        findings += self._check_txt_records(domain, value)
                    elif rtype == "MX":
                        findings += self._check_mx_records(domain, value)
                    elif rtype == "CNAME":
                        findings += self._check_cname_records(domain, value)

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        return findings

    def _check_txt_records(self, domain: str, value: str) -> int:
        findings = 0

        # Check SPF
        if "v=spf1" in value:
            if "+all" in value or "all" not in value:
                self.db.insert_finding(
                    "WEAK_SPF",
                    f"dns://{domain}",
                    f"SPF record allows all senders: {value[:100]}",
                    "HIGH",
                    source_module="dns_scanner",
                )
                findings += 1

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                if "v=DMARC1" in str(rdata):
                    if "p=none" in str(rdata):
                        self.db.insert_finding(
                            "WEAK_DMARC",
                            f"dns://{dmarc_domain}",
                            "DMARC policy is set to none (no enforcement)",
                            "MEDIUM",
                            source_module="dns_scanner",
                        )
                        findings += 1
        except Exception:
            self.db.insert_finding(
                "MISSING_DMARC", f"dns://{domain}", "No DMARC record found", "MEDIUM", source_module="dns_scanner"
            )
            findings += 1

        return findings

    def _check_mx_records(self, domain: str, value: str) -> int:
        # Check for misconfigured MX (e.g., pointing to localhost)
        if "localhost" in value or "127.0.0.1" in value:
            self.db.insert_finding(
                "MX_MISCONFIGURATION",
                f"dns://{domain}",
                f"MX record points to localhost: {value}",
                "HIGH",
                source_module="dns_scanner",
            )
            return 1
        return 0

    def _check_cname_records(self, domain: str, value: str) -> int:
        # Check for dangling CNAMEs (potential subdomain takeover)
        if any(
            provider in value for provider in ["github.io", "herokuapp.com", "azurewebsites.net", "s3.amazonaws.com"]
        ):
            self.db.insert_finding(
                "DANGLING_CNAME",
                f"dns://{domain}",
                f"CNAME points to cloud provider: {value}",
                "HIGH",
                source_module="dns_scanner",
            )
            return 1
        return 0
