import hashlib
import re
from typing import Tuple


class SecretRedactor:
    # Patterns for different secret types
    PATTERNS = {
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        "jwt": re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "generic_secret": re.compile(r"[a-zA-Z0-9_\-]{32,}"),
    }

    @staticmethod
    def redact_secret(secret: str, preview_length: int = 8) -> Tuple[str, str]:
        """
        Redact a secret and return (fingerprint, preview)
        Example: "AKIAIOSFODNN7EXAMPLE" -> ("sha256:abc123...", "AKIA****")
        """
        if not secret or len(secret) < preview_length:
            return ("", secret)

        # Generate fingerprint
        fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:12]

        # Create preview
        preview = secret[:preview_length] + "*" * (len(secret) - preview_length)

        return (f"sha256:{fingerprint}", preview)

    @staticmethod
    def redact_finding_details(details: str) -> str:
        """Redact secrets in finding details"""
        # Look for "Secret: ..." pattern
        secret_match = re.search(r"Secret:\s*([^\s|]+)", details)
        if secret_match:
            original_secret = secret_match.group(1)
            fingerprint, preview = SecretRedactor.redact_secret(original_secret)
            details = details.replace(f"Secret: {original_secret}", f"Secret: {preview} (fingerprint: {fingerprint})")

        return details
