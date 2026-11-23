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

        # FIX: Strict AI Gating - Only CRITICAL/HIGH, capped at 20 max
        high_value = [
            f
            for f in findings
            if f["severity"] in ["CRITICAL", "HIGH"] and f.get("confidence") in ["CONFIRMED", "HIGH"]
        ][:20]

        if not high_value:
            print("[*] No high-value findings to analyze. Skipping AI step.")
            return

        print(f"[*] 🧠 Analyzing top {len(high_value)} findings with AI...")

        analyzed = 0
        for finding in high_value:
            if "[AI Analysis]" in finding.get("details", ""):
                continue

            # Redact secrets before sending to cloud AI
            safe_details = self.ai.redact_secrets(finding["details"])

            prompt = f"""You are an expert application security engineer.

                Finding Type: {finding['finding_type']}
                Target: {finding['url']}
                Context: {safe_details}

                Provide EXACTLY two lines:
                Business Impact: [one sentence]
                Remediation: [one sentence]"""

            response = self.ai.ask(prompt, sensitive=True, max_tokens=200)

            if response:
                new_details = f"{finding['details']}\n\n[AI Analysis]\n{response}"
                # Update the finding in the database (adjust method name if your DB class uses a different one)
                with self.db._get_conn() as conn:
                    conn.execute("UPDATE findings SET details = ? WHERE id = ?", (new_details, finding["id"]))
                analyzed += 1

        print(f"[+] 🧠 AI analysis complete. Enhanced {analyzed} findings.")
