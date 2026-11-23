from collections import defaultdict
from datetime import datetime
from pathlib import Path


class MarkdownReporter:
    def __init__(self, db, target: str, workspace: Path, diff_mode: bool = False, last_scan: str = None):
        self.db = db
        self.target = target
        self.workspace = workspace
        self.diff_mode = diff_mode
        self.last_scan = last_scan

    def generate(self):
        print("[*] Generating Markdown report...")
        findings = self.db.get_all_findings()
        ports = self.db.get_all_ports()
        endpoints = self.db.get_all_endpoints()

        # FIX: Better Diff Mode Summary
        diff_header = ""
        if self.diff_mode and self.last_scan:
            critical_carried = len([f for f in findings if f["severity"] == "CRITICAL"])
            diff_header = f"""
## 🔄 Diff Mode Summary
- **New Findings:** {len(findings)}
- **Active Critical Risks (Carried over):** {critical_carried}
- **Comparing against:** {self.last_scan}
"""
        else:
            diff_header = "**Mode:** Standard Scan\n"

        # FIX: Group Findings by Host for better developer actionability
        findings_by_host = defaultdict(list)
        for f in findings:
            host = f["url"].split("/")[2] if "//" in f["url"] else "Unknown"
            findings_by_host[host].append(f)

        report = f"""# OSINT Insight Report: {self.target}
            **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {diff_header}
            ## Executive Summary
            - **Actionable Findings:** {len(findings)}
            - **Hosts with Open Ports:** {len(ports)}
            - **Live HTTP Endpoints:** {len(endpoints)}

            ---
            ## Detailed Findings (Grouped by Host)
            """
        for host, host_findings in sorted(findings_by_host.items()):
            report += f"\n### 🖥️ Host: `{host}`\n"
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                sev_findings = [f for f in host_findings if f["severity"] == sev]
                if sev_findings:
                    report += f"\n#### {sev} Severity ({len(sev_findings)})\n"
                    for f in sev_findings:
                        report += f"- **[{f['finding_type']}]** `{f['url']}`\n"
                        report += f"  - *Details:* {f['details']}\n"
                        if f.get("confidence"):
                            report += f"  - *Confidence:* {f['confidence']}\n"

        # Write to file
        report_path = self.workspace / f"REPORT_{self.target}.md"
        with open(report_path, "w", encoding="utf-8") as file:
            file.write(report)

        print(f"[+] Report generated: {report_path}")
