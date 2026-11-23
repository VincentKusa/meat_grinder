"""AI-powered recon: smart wordlists, logic attacks, and attack path chaining."""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3

from database import ConfidenceLevel
from engine.ai_engine import AIEngine
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AIReconHunter(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        self.ai = AIEngine(self.__class__.__module__ and __import__("config").Config)

    def execute(self):
        if not self.ai.is_available():
            print("[!] No AI backend available. Skipping AI recon.")
            return

        print("[*] 🧠 AI Recon Hunter: Generating intelligent attack surface...")

        context = self._gather_context()
        if not context["endpoints"]:
            print("[!] No context available. Skipping AI recon.")
            return

        self._generate_smart_wordlist(context)
        self._suggest_logic_attacks(context)
        self._chain_attack_paths(context)

        print("[+] 🧠 AI Recon Hunter complete.")

    def _gather_context(self) -> dict:
        """Collect everything the AI needs to reason about the target."""
        endpoints = self.db.get_all_endpoints()
        findings = self.db.get_all_findings()
        subdomains = self.db.get_all_subdomains()
        ports = self.db.get_all_ports()

        tech_stack = set()
        for ep in endpoints:
            if ep.get("tech_stack"):
                tech_stack.update([t.strip() for t in ep["tech_stack"].split(",") if t.strip()])
            if ep.get("webserver"):
                tech_stack.add(ep["webserver"])

        return {
            "target": self.target,
            "subdomains": subdomains[:20],
            "endpoints": [ep["url"] for ep in endpoints[:30]],
            "tech_stack": list(tech_stack)[:15],
            "findings_summary": [
                f"{f['finding_type']} @ {f['url']}" for f in findings if f["severity"] in ["CRITICAL", "HIGH"]
            ][:20],
            "ports": [f"{p['host']}:{p['ports']}" for p in ports[:10]],
        }

    # ==========================================
    # PHASE 1: CONTEXT-AWARE WORDLIST
    # ==========================================

    def _generate_smart_wordlist(self, context: dict):
        """AI generates target-specific paths based on industry + tech stack."""
        print("[*] 🧠 AI: Generating context-aware wordlist...")

        prompt = f"""You are an expert penetration tester performing recon.

            TARGET: {context['target']}
            TECH STACK: {', '.join(context['tech_stack']) or 'Unknown'}
            KNOWN SUBDOMAINS: {', '.join(context['subdomains'][:10])}
            KNOWN ENDPOINTS (sample): {', '.join(context['endpoints'][:10])}
            OPEN PORTS: {', '.join(context['ports'])}

            Generate exactly 20 HIGH-VALUE paths that are:
            1. Specific to this target's industry and tech stack
            2. Often missed by generic wordlists
            3. Likely to contain sensitive functionality (admin, internal APIs, config, debug, backup)

            Return ONLY a JSON array of path strings. Example: ["/api/internal/debug", "/oauth/token"]"""

        paths = self.ai.ask_json(prompt, sensitive=False, max_tokens=800)
        if paths and isinstance(paths, list):
            self._test_ai_paths([p for p in paths if isinstance(p, str)])

    def _test_ai_paths(self, paths: list):
        """Probe AI-generated paths against live endpoints."""
        base_urls = set()
        for ep in self.db.get_all_endpoints():
            parsed = urlparse(ep["url"])
            base_urls.add(f"{parsed.scheme}://{parsed.netloc}")

        findings = 0
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {}
            for base in base_urls:
                for path in paths:
                    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
                    futures[executor.submit(self._probe_path, url, path)] = url

            for future in as_completed(futures):
                if future.result():
                    findings += 1

        if findings:
            print(f"[+] 🧠 AI wordlist discovered {findings} new accessible paths")

    def _probe_path(self, url: str, original_path: str) -> bool:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)

            if resp.status_code in [200, 401, 403, 405, 500] and len(resp.text) > 100:
                severity = "HIGH" if resp.status_code in [200, 500] else "MEDIUM"
                self.db.insert_finding(
                    f_type="AI_GENERATED_ENDPOINT",
                    url=url,
                    details=(f"AI-generated path '{original_path}' " f"returned HTTP {resp.status_code}"),
                    severity=severity,
                    source_module="ai_recon_hunter",
                )
                return True
        except Exception:
            pass
        return False

    # ==========================================
    # PHASE 2: BUSINESS LOGIC ATTACKS
    # ==========================================

    def _suggest_logic_attacks(self, context: dict):
        """AI analyzes endpoints and suggests business logic attacks."""
        api_endpoints = [ep for ep in context["endpoints"] if "/api/" in ep or "/graphql" in ep]
        if not api_endpoints:
            return

        print("[*] 🧠 AI: Analyzing business logic attack surface...")

        prompt = f"""You are a senior application security engineer. Analyze these API endpoints
            and suggest 5 specific business logic attacks.

            TARGET: {context['target']}
            API ENDPOINTS: {json.dumps(api_endpoints[:15])}

            For each attack, provide:
            - name: Short attack name
            - endpoint: Target endpoint
            - test: Specific parameter manipulation to test
            - impact: Expected business impact

            Return as JSON array of objects with keys: name, endpoint, test, impact"""

        attacks = self.ai.ask_json(prompt, sensitive=False, max_tokens=1200)
        if attacks and isinstance(attacks, list):
            for attack in attacks:
                if not isinstance(attack, dict):
                    continue
                self.db.insert_finding(
                    f_type="AI_LOGIC_ATTACK_SUGGESTION",
                    url=attack.get("endpoint", context["target"]),
                    details=(f"{attack.get('name')}: {attack.get('test')} | " f"Impact: {attack.get('impact')}"),
                    severity="MEDIUM",
                    source_module="ai_recon_hunter",
                )
            print(f"[+] 🧠 AI suggested {len(attacks)} business logic attacks")

    # ==========================================
    # PHASE 3: ATTACK PATH CHAINING
    # ==========================================
    def _chain_attack_paths(self, context: dict):
        """AI chains existing findings into realistic attack narratives."""
        if not context["findings_summary"]:
            return

        print("[*] 🧠 AI: Chaining findings into attack paths...")

        findings_text = "\n".join(f"- {f}" for f in context["findings_summary"][:30])  # Limit to top 30

        prompt = f"""You are a red team lead performing a penetration test.

            TARGET: {context['target']}
            TECH STACK: {', '.join(context['tech_stack']) or 'Unknown'}
            DISCOVERED FINDINGS:
            {findings_text}

            Based on these SPECIFIC findings, generate 3 realistic attack paths. Each path must:
            1. Use ONLY the findings listed above as starting points
            2. Include 2-4 concrete, actionable steps
            3. Reference specific URLs or services discovered
            4. Explain the business impact

            Return as JSON array with keys: name, steps (array), impact, difficulty"""

        paths = self.ai.ask_json(prompt, sensitive=False, max_tokens=1500)
        if paths and isinstance(paths, list):
            for path in paths:
                if not isinstance(path, dict):
                    continue
                steps = path.get("steps", [])
                steps_str = " → ".join(steps) if isinstance(steps, list) else str(steps)
                difficulty = path.get("difficulty", "Unknown")
                severity = "CRITICAL" if difficulty == "Easy" else "HIGH" if difficulty == "Medium" else "MEDIUM"

                self.db.insert_finding(
                    f_type="AI_ATTACK_PATH",
                    url=f"attack://{context['target']}/{path.get('name', 'chain').replace(' ', '_').lower()}",
                    details=f"{path.get('name')} [{difficulty}]: {steps_str} | Final Impact: {path.get('impact')}",
                    severity=severity,
                    confidence=ConfidenceLevel.MEDIUM,
                    source_module="ai_recon_hunter",
                )
            print(f"[+] 🧠 AI identified {len(paths)} attack paths")
