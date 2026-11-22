"""AI-powered analysis: adds business impact + remediation to findings."""

from engine.ai_engine import AIEngine
from engine.base import BaseReconModule


class AIAnalyzer(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        self.ai = AIEngine(self.__class__.__module__ and __import__("config").Config)

    def execute(self):
        if not self.ai.is_available():
            print("[!] No AI backend available. Skipping AI analysis.")
            return

        print("[*] 🧠 AI Analyzer: Enhancing findings with context...")

        findings = self.db.get_all_findings()
        high_value = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]

        if not high_value:
            print("[*] No high-severity findings to analyze.")
            return

        print(f"[*] 🧠 Analyzing {len(high_value)} findings with AI...")

        analyzed = 0
        for finding in high_value:
            if "[AI Analysis]" in finding.get("details", ""):
                continue

            insight = self._analyze_finding(finding)
            if insight:
                new_details = f"{finding['details']}\n\n[AI Analysis]\n{insight}"
                self._update_finding(finding["id"], new_details)
                analyzed += 1

        print(f"[+] 🧠 AI analysis complete. Enhanced {analyzed} findings.")

    def _analyze_finding(self, finding: dict) -> str:
        """Use local AI to analyze a finding (secrets stay private)."""
        safe_details = self.ai.redact_secrets(finding["details"])

        prompt = f"""You are an expert application security engineer. Analyze this finding.

            Finding Type: {finding['finding_type']}
            Target: {finding['url']}
            Context: {safe_details}

            Provide EXACTLY two lines, no markdown, no bullets:
            Business Impact: [one sentence on real-world risk]
            Remediation: [one sentence on how to fix it]"""

        response = self.ai.ask(prompt, sensitive=True, max_tokens=200)
        return response if response else ""

    def _update_finding(self, finding_id: int, new_details: str):
        with self.db._get_conn() as conn:
            conn.execute("UPDATE findings SET details = ? WHERE id = ?", (new_details, finding_id))
