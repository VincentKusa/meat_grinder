"""Generates a professional PDF report with charts and AI insights."""

import base64
import io
from collections import Counter
from datetime import datetime
from pathlib import Path
from string import Template

from database import DatabaseManager


class PDFReporter:
    """Generates a stakeholder-ready PDF report."""

    TEMPLATE_PATH = Path(__file__).parent / "templates" / "report.html"

    def __init__(self, db: DatabaseManager, target: str, workspace: Path, config=None):
        self.db = db
        self.target = target
        self.workspace = workspace
        self.config = config

    def generate(self):
        print("[*] Generating PDF report...")
        try:
            from weasyprint import HTML
        except ImportError:
            print("[!] WeasyPrint not installed. Run: pip install weasyprint")
            return

        # Load template
        if not self.TEMPLATE_PATH.exists():
            print(f"[!] Template not found at {self.TEMPLATE_PATH}")
            return

        template = Template(self.TEMPLATE_PATH.read_text(encoding="utf-8"))

        # Gather data
        findings = self.db.get_all_findings()
        ports = self.db.get_all_ports()
        endpoints = self.db.get_all_endpoints()
        subdomains = self.db.get_all_subdomains()

        # Compute risk metrics
        risk_score = self._calculate_risk_score(findings)
        risk = self._risk_level(risk_score)

        # Generate charts
        severity_chart_b64 = self._generate_severity_chart(findings)
        findings_trend_b64 = self._generate_findings_trend(findings)

        # Build template context
        context = self._build_context(
            findings=findings,
            ports=ports,
            endpoints=endpoints,
            subdomains=subdomains,
            risk_score=risk_score,
            risk=risk,
            severity_chart_b64=severity_chart_b64,
            findings_trend_b64=findings_trend_b64,
        )

        # Render HTML
        html = template.safe_substitute(context)

        # Generate PDF
        pdf_path = self.workspace / f"REPORT_{self.target}.pdf"
        HTML(string=html).write_pdf(str(pdf_path))
        print(f"[+] PDF report generated: {pdf_path}")

    # ==========================================
    # CONTEXT BUILDER
    # ==========================================

    def _build_context(self, **data) -> dict:
        """Build the template substitution dictionary."""
        findings = data["findings"]
        risk = data["risk"]
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine AI backend status
        ai_status = self._determine_ai_status()

        # Pre-render HTML blocks
        findings_html = self._render_findings(findings)
        attack_paths_html = self._render_attack_paths(findings)
        charts_html = self._render_charts(data["severity_chart_b64"], data["findings_trend_b64"])
        ports_rows = self._render_ports_table(data["ports"])
        web_servers_rows = self._render_web_servers_table(data["endpoints"])

        # Compute metrics
        critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
        high_findings = [f for f in findings if f["severity"] == "HIGH"]
        attack_paths = [f for f in findings if f["finding_type"] == "AI_ATTACK_PATH"]
        ai_generated = sum(1 for f in findings if "AI" in f.get("finding_type", ""))

        return {
            "TARGET": self.target,
            "GENERATED_AT": generated_at,
            "AI_BACKEND_STATUS": ai_status,
            # Risk
            "RISK_EMOJI": risk["emoji"],
            "RISK_LEVEL": risk["level"],
            "RISK_COLOR": risk["color"],
            "RISK_SCORE": str(data["risk_score"]),
            # Metrics
            "TOTAL_FINDINGS": str(len(findings)),
            "CRITICAL_COUNT": str(len(critical_findings)),
            "HIGH_COUNT": str(len(high_findings)),
            "SUBDOMAIN_COUNT": str(len(data["subdomains"])),
            "ENDPOINT_COUNT": str(len(data["endpoints"])),
            "PORT_COUNT": str(len(data["ports"])),
            "ATTACK_PATH_COUNT": str(len(attack_paths)),
            "AI_GENERATED_COUNT": str(ai_generated),
            # HTML blocks
            "FINDINGS_HTML": findings_html,
            "ATTACK_PATHS_HTML": attack_paths_html,
            "CHARTS_HTML": charts_html,
            "PORTS_TABLE_ROWS": ports_rows,
            "WEB_SERVERS_TABLE_ROWS": web_servers_rows,
        }

    def _determine_ai_status(self) -> str:
        """Determine which AI backend was primarily used."""
        if not self.config:
            return "Disabled"

        local_enabled = getattr(self.config, "AI_USE_LOCAL_FOR_SECRETS", False)
        cloud_enabled = getattr(self.config, "AI_USE_CLOUD_FOR_REASONING", False)
        has_gemini = bool(getattr(self.config, "GEMINI_API_KEY", None))

        if local_enabled and cloud_enabled and has_gemini:
            return "Hybrid (Local Ollama + Cloud Gemini)"
        if cloud_enabled and has_gemini:
            return "Cloud (Gemini)"
        if local_enabled:
            return "Local (Ollama)"
        return "Disabled"

    # ==========================================
    # HTML RENDERERS
    # ==========================================
    def _render_findings(self, findings: list) -> str:
        """Render findings grouped by severity, capped to prevent massive reports."""
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a",
            "INFO": "#2563eb",
        }
        html = ""

        # Get the limit from config (defaults to 25 if not set)
        max_findings = getattr(self.config, "MAX_FINDINGS_PER_SEVERITY", 25)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if not sev_findings:
                continue

            total_count = len(sev_findings)
            displayed_findings = sev_findings[:max_findings]

            color = colors[sev]
            html += f'<h2 style="color: {color}; border-bottom: 2px solid {color};">{sev} ({total_count})</h2>'

            for f in displayed_findings:
                details = self._escape_html(f["details"]).replace("\n", "<br>")
                url = self._escape_html(f["url"])
                ftype = self._escape_html(f["finding_type"])
                html += f"""
                <div style="margin: 10px 0; padding: 12px; background: #f9fafb;
                     border-left: 4px solid {color}; border-radius: 4px;">
                    <strong style="color: {color};">[{ftype}]</strong>
                    <code style="background: #e5e7eb; padding: 2px 6px; border-radius: 3px;
                          font-size: 0.9em;">{url}</code>
                    <div style="margin-top: 6px; color: #374151; font-size: 0.95em;">{details}</div>
                </div>
                """

            # Add a note if findings were omitted
            if total_count > max_findings:
                omitted = total_count - max_findings
                html += (
                    f'<p style="color: #6b7280; font-style: italic; text-align: center; margin-top: 15px;">... '
                    f"and {omitted} more {sev.lower()} findings omitted for brevity. Check the Markdown report "
                    f"for the complete list.</p>"
                )

        return html or "<p><em>No findings to display.</em></p>"

    def _render_attack_paths(self, findings: list) -> str:
        """Render AI-identified attack paths."""
        attack_paths = [f for f in findings if f["finding_type"] == "AI_ATTACK_PATH"]
        if not attack_paths:
            return ""

        html = '<h2 style="color: #7c3aed; border-bottom: 2px solid #7c3aed;">🎯 AI-Identified Attack Paths</h2>'
        for ap in attack_paths:
            details = self._escape_html(ap["details"]).replace("\n", "<br>")
            html += f"""
            <div style="margin: 10px 0; padding: 15px;
                 background: linear-gradient(135deg, #f3e8ff 0%, #ede9fe 100%);
                 border-left: 4px solid #7c3aed; border-radius: 6px;">
                <div style="font-size: 0.95em; color: #1f2937;">{details}</div>
            </div>
            """
        return html

    def _render_charts(self, severity_b64: str, trend_b64: str) -> str:
        """Render chart images."""
        html = ""
        if severity_b64:
            html += f'<img src="data:image/png;base64,{severity_b64}" style="max-width: 100%; margin: 10px 0;">'
        if trend_b64:
            html += f'<img src="data:image/png;base64,{trend_b64}" style="max-width: 100%; margin: 10px 0;">'
        return html

    def _render_ports_table(self, ports: list) -> str:
        """Render the hosts & services table rows."""
        rows = ""
        for p in ports[:20]:
            host = self._escape_html(p["host"])
            ip = self._escape_html(p["ip"])
            os_info = self._escape_html(p.get("os") or "Unknown")
            ports_str = self._escape_html(str(p["ports"]))
            rows += f"<tr><td><code>{host}</code></td><td>{ip}</td><td>{os_info}</td><td>{ports_str}</td></tr>\n"
        return rows or "<tr><td colspan='4'><em>No port data available.</em></td></tr>"

    def _render_web_servers_table(self, endpoints: list) -> str:
        """Render the web servers table rows."""
        rows = ""
        for ep in endpoints[:20]:
            url = self._escape_html(ep["url"])
            webserver = self._escape_html(ep.get("webserver") or "-")
            waf = self._escape_html(ep.get("waf_detected") or "-")
            rows += f"<tr><td><code>{url}</code></td><td>{webserver}</td><td>{waf}</td></tr>\n"
        return rows or "<tr><td colspan='3'><em>No endpoint data available.</em></td></tr>"

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    # ==========================================
    # RISK SCORING
    # ==========================================

    def _calculate_risk_score(self, findings: list) -> int:
        """Calculate overall risk score 0-100."""
        weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
        score = sum(weights.get(f["severity"], 0) for f in findings)
        attack_paths = sum(1 for f in findings if f["finding_type"] == "AI_ATTACK_PATH")
        score += attack_paths * 15
        return min(100, score)

    def _risk_level(self, score: int) -> dict:
        if score >= 75:
            return {"level": "CRITICAL", "color": "#dc2626", "emoji": "🔴"}
        if score >= 50:
            return {"level": "HIGH", "color": "#ea580c", "emoji": "🟠"}
        if score >= 25:
            return {"level": "MEDIUM", "color": "#ca8a04", "emoji": "🟡"}
        return {"level": "LOW", "color": "#16a34a", "emoji": "🟢"}

    # ==========================================
    # CHARTS
    # ==========================================

    @staticmethod
    def _fig_to_base64(fig) -> str:
        """Convert a matplotlib figure to a base64-encoded PNG string and close it."""
        try:
            import matplotlib.pyplot as plt

            plt.tight_layout()
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
            plt.close(fig)
            buf.seek(0)
            return base64.b64encode(buf.read()).decode("utf-8")
        except Exception as e:
            print(f"[!] Chart conversion failed: {e}")
            import matplotlib.pyplot as plt

            plt.close(fig)  # Ensure cleanup even on error
            return ""

    @staticmethod
    def _generate_severity_chart(findings: list) -> str:
        """Generate a severity distribution bar chart as base64 PNG."""
        try:
            import matplotlib.pyplot as plt

            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev = f.get("severity", "INFO")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            colors = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#ca8a04",
                "LOW": "#16a34a",
                "INFO": "#2563eb",
            }

            fig, ax = plt.subplots(figsize=(6, 3))
            bars = ax.bar(
                severity_counts.keys(),
                severity_counts.values(),
                color=[colors[k] for k in severity_counts.keys()],
            )
            ax.set_ylabel("Count", fontsize=10)
            ax.set_title("Findings by Severity", fontsize=12, fontweight="bold")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            for bar, count in zip(bars, severity_counts.values()):
                if count > 0:
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.3,
                        str(count),
                        ha="center",
                        fontsize=10,
                        fontweight="bold",
                    )

            return PDFReporter._fig_to_base64(fig)
        except Exception as e:
            print(f"[!] Chart generation failed: {e}")
            return ""

    @staticmethod
    def _generate_findings_trend(findings: list) -> str:
        """Generate a finding-type breakdown chart."""
        try:
            import matplotlib.pyplot as plt

            type_counts = Counter(f["finding_type"] for f in findings)
            top_10 = type_counts.most_common(10)

            if not top_10:
                return ""

            labels = [t[0].replace("_", " ") for t in top_10]
            values = [t[1] for t in top_10]

            fig, ax = plt.subplots(figsize=(7, 3.5))
            ax.barh(labels[::-1], values[::-1], color="#3b82f6")
            ax.set_xlabel("Count", fontsize=10)
            ax.set_title("Top Finding Types", fontsize=12, fontweight="bold")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            return PDFReporter._fig_to_base64(fig)
        except Exception as e:
            print(f"[!] Chart generation failed: {e}")
            return ""
