import json
from pathlib import Path
from database import DatabaseManager
from datetime import datetime

class MarkdownReporter:
    def __init__(self, db: DatabaseManager, target: str, workspace: Path):
        self.db = db
        self.target = target
        self.workspace = workspace

    def generate(self):
        findings = self.db.get_all_findings()
        ports = self.db.get_all_ports()
        endpoints = self.db.get_all_endpoints()
        report_path = self.workspace / f"REPORT_{self.target}.md"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# OSINT Insight Report: {self.target}\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write(f"## Executive Summary\n")
            f.write(f"- **Actionable Findings:** {len(findings)}\n")
            f.write(f"- **Hosts with Open Ports:** {len(ports)}\n")
            f.write(f"- **Live HTTP Endpoints:** {len(endpoints)}\n\n")

            # ============ WAF & SECURITY POSTURE ============
            waf_endpoints = [ep for ep in endpoints if ep.get('waf_detected') and ep['waf_detected'] != 'None']
            if waf_endpoints:
                f.write("## 🛡️ WAF & Firewall Detection\n\n")
                f.write("| Endpoint | Detected WAF/Firewall |\n")
                f.write("|---|---|\n")
                for ep in waf_endpoints:
                    f.write(f"| `{ep['url']}` | **{ep['waf_detected']}** |\n")
                f.write("\n")

            # ============ INFRASTRUCTURE INVENTORY ============
            if ports:
                f.write("## Infrastructure Inventory\n\n")
                f.write("### Hosts, OS & Services\n\n")
                f.write("| Host | IP | OS | Open Ports | Running Services |\n")
                f.write("|---|---|---|---|---|\n")
                for p in ports:
                    os_info = p.get('os', '') or 'Unknown'
                    try:
                        services = json.loads(p.get('services', '{}') or '{}')
                    except json.JSONDecodeError:
                        services = {}
                    svc_list = [f"{port}({name})" for port, name in services.items() if port != 'cpe']
                    svc_str = ", ".join(svc_list) if svc_list else "-"
                    f.write(f"| `{p['host']}` | {p['ip']} | {os_info} | {p['ports']} | {svc_str} |\n")
                f.write("\n")

            # ============ WEBSERVER INVENTORY ============
            webservers = {}
            for ep in endpoints:
                ws = ep.get('webserver', '')
                if ws:
                    webservers[ws] = webservers.get(ws, 0) + 1

            if webservers:
                f.write("### Web Servers Detected\n\n")
                f.write("| Web Server | Count |\n")
                f.write("|---|---|\n")
                for ws, count in sorted(webservers.items(), key=lambda x: -x[1]):
                    f.write(f"| `{ws}` | {count} |\n")
                f.write("\n")

            # ============ FINDINGS ============
            if not findings:
                f.write("*No high-value insights found.*\n")
                return

            f.write("## Detailed Findings\n\n")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                sev_findings = [fd for fd in findings if fd['severity'] == severity]
                if sev_findings:
                    f.write(f"### {severity} Severity ({len(sev_findings)})\n\n")
                    for fd in sev_findings:
                        f.write(f"- **[{fd['finding_type']}]** `{fd['url']}`\n")
                        f.write(f"  - *Details:* {fd['details']}\n\n")

            # ============ VISUAL PROOF (SCREENSHOTS) ============
            screenshot_dir = self.workspace / "screenshots"
            if screenshot_dir.exists() and any(screenshot_dir.iterdir()):
                f.write("## 📸 Visual Proof (Screenshots)\n\n")
                f.write("The following screenshots were captured for HIGH/CRITICAL findings:\n\n")

                # Get all png files
                screenshots = list(screenshot_dir.glob("*.png"))
                for i, img_path in enumerate(screenshots[:10]):  # Limit to 10 to avoid massive reports
                    # Use relative path for Markdown
                    rel_path = f"screenshots/{img_path.name}"
                    f.write(f"### Finding {i + 1}\n")
                    f.write(f"![Screenshot {i + 1}]({rel_path})\n\n")

        print(f"[+] Report generated: {report_path}")