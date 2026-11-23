"""Unified AI engine supporting both Ollama (local) and Gemini (cloud)."""

import json
import logging
import re
from typing import Any

import requests

try:
    from google import genai
    from google.genai import types

    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Configure a dedicated logger for the AI engine
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Capture detailed logs


class AIEngine:
    """
    Unified interface for AI models.

    - Use `ask_local()` for sensitive data (secrets stay on your machine)
    - Use `ask_cloud()` for heavy reasoning (attack paths, business logic)
    - Use `ask()` for automatic routing based on content sensitivity
    """

    def __init__(self, config):
        self.config = config
        self.gemini_client = None

        if GEMINI_AVAILABLE and self.config.GEMINI_API_KEY:
            try:
                # New SDK initialization
                self.gemini_client = genai.Client(api_key=self.config.GEMINI_API_KEY)
            except Exception as e:
                logger.error(f"Gemini initialization failed: {e}")
                print(f"[!] Gemini initialization failed: {e}")

    # ==========================================
    # PUBLIC API
    # ==========================================

    def ask(self, prompt: str, sensitive: bool = False, max_tokens: int = 1000) -> str:
        """Route to the right model based on content sensitivity."""

        # Determine which backend will be used
        if sensitive and self.config.AI_USE_LOCAL_FOR_SECRETS:
            backend = "🟢 Local Ollama"
            result = self.ask_local(prompt, max_tokens)
        elif not sensitive and self.config.AI_USE_CLOUD_FOR_REASONING and self.gemini_client:
            backend = "🔵 Cloud Gemini"
            result = self.ask_cloud(prompt, max_tokens)
        else:
            backend = "🟢 Local Ollama (Fallback)"
            result = self.ask_local(prompt, max_tokens)

        # Show which backend handled this query (first 80 chars of prompt for context)
        prompt_preview = prompt[:80].replace("\n", " ").strip()
        print(f"    [{backend}] {prompt_preview}...")

        return result

    def ask_local(self, prompt: str, max_tokens: int = 1000) -> str:
        """Query local Ollama model (private, no data leaves machine)."""
        try:
            payload = {
                "model": self.config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": max_tokens},
            }
            resp = requests.post(f"{self.config.OLLAMA_URL}/api/generate", json=payload, timeout=120)
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            print(f"[!] Ollama query failed: {e}")
        return ""

    def ask_cloud(self, prompt: str, max_tokens: int = 1000) -> str:
        """Query Google Gemini using the new SDK (high-quality reasoning)."""
        if not self.gemini_client:
            return self.ask_local(prompt, max_tokens)

        # Try the most stable, widely available models in order
        models_to_try = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]

        for model_name in models_to_try:
            try:
                response = self.gemini_client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(temperature=0.3, max_output_tokens=max_tokens),
                )
                return response.text.strip()

            except Exception as e:
                # If it's a 404/Not Found, try the next model in the list
                if "NOT_FOUND" in str(e) or "404" in str(e):
                    continue
                else:
                    # If it's a different error (e.g., rate limit, invalid key), log and break
                    logger.error(f"Gemini query failed with {model_name}: {e}")
                    break

        logger.error("All Gemini models failed. Falling back to local Ollama.")
        return self.ask_local(prompt, max_tokens)

    def ask_json(self, prompt: str, sensitive: bool = False, max_tokens: int = 1000) -> Any:
        """Ask AI and parse response as JSON. Returns dict, list, or None."""
        response = self.ask(prompt, sensitive=sensitive, max_tokens=max_tokens)
        return self._extract_json(response)

    # ==========================================
    # HELPERS
    # ==========================================

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Extract JSON from AI response (handles markdown code blocks)."""
        if not text:
            return None

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract from markdown code blocks
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Extract raw JSON array/object
        for pattern in [r"\[[\s\S]*\]", r"\{[\s\S]*\}"]:
            match = re.search(pattern, text)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    continue

        return None

    @staticmethod
    def redact_secrets(text: str) -> str:
        """Redact potential secrets from text before sending to cloud AI."""
        # Redact long alphanumeric strings (likely keys/tokens)
        text = re.sub(r"[A-Za-z0-9_\-]{32,}", "[REDACTED_SECRET]", text)
        # Redact common secret patterns
        text = re.sub(r"(?i)(AKIA|ghp_|sk_live_|sk_test_)[A-Za-z0-9]{16,}", "[REDACTED_KEY]", text)
        text = re.sub(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END", "[REDACTED_PRIVATE_KEY]-----END", text)
        return text

    def is_available(self) -> bool:
        """Check if any AI backend is available."""
        # Check Ollama
        try:
            resp = requests.get(f"{self.config.OLLAMA_URL}/api/tags", timeout=5)
            if resp.status_code == 200:
                return True
        except Exception:
            pass

        # Check Gemini
        if self.gemini_client:
            return True

        return False
