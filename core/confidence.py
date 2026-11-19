from enum import Enum


class ConfidenceLevel(Enum):
    CONFIRMED = "CONFIRMED"  # Verified as real/exploitable
    HIGH = "HIGH"  # Very likely real
    MEDIUM = "MEDIUM"  # Likely real but needs verification
    LOW = "LOW"  # Possible but uncertain
    INFO = "INFO"  # Informational only


class FindingClassifier:
    # Map finding types to default confidence levels
    DEFAULT_CONFIDENCE = {
        "EXPOSED_SENSITIVE_FILE": ConfidenceLevel.CONFIRMED,
        "LEAKED_SECRET": ConfidenceLevel.HIGH,
        "DEEP_CODE_SECRET": ConfidenceLevel.CONFIRMED,
        "HARDCODED_SECRET_IN_WEB_FILE": ConfidenceLevel.HIGH,
        "CLOUD_ASSET_DISCOVERED": ConfidenceLevel.MEDIUM,
        "MISSING_HSTS": ConfidenceLevel.HIGH,
        "MISSING_CLICKJACKING_PROTECTION": ConfidenceLevel.HIGH,
        "OUTDATED_WEBSERVER": ConfidenceLevel.MEDIUM,
        "GUARDED_ENDPOINT": ConfidenceLevel.MEDIUM,
        "SERVER_ERROR": ConfidenceLevel.LOW,
        "HTML_COMMENT_LEAK": ConfidenceLevel.LOW,
        "DOMAIN_WHOIS_INFO": ConfidenceLevel.INFO,
        "SOCIAL_MEDIA_CONTACT": ConfidenceLevel.MEDIUM,
    }

    @staticmethod
    def get_confidence(finding_type: str, details: str = None) -> ConfidenceLevel:
        """Get confidence level for a finding type, with optional detail-based adjustment"""
        base_confidence = FindingClassifier.DEFAULT_CONFIDENCE.get(finding_type, ConfidenceLevel.MEDIUM)

        # Adjust based on details if provided
        if details:
            # TruffleHog verified secrets are CONFIRMED
            if "verified" in details.lower() or "trufflehog" in details.lower():
                return ConfidenceLevel.CONFIRMED

            # Test fixtures are LOW confidence
            if any(path in details.lower() for path in ["test", "example", "fixture", "sample"]):
                return ConfidenceLevel.LOW

        return base_confidence
