import hashlib


class FindingDeduplicator:
    @staticmethod
    def generate_fingerprint(
        finding_type: str, url: str, details: str, file_path: str = None, rule_id: str = None
    ) -> str:
        """Generate a canonical fingerprint for a finding to detect duplicates"""
        # Normalize inputs
        normalized_url = url.lower().strip()
        normalized_details = details.lower().strip()

        # Create fingerprint components
        components = [
            finding_type,
            normalized_url,
            rule_id or "",
            file_path or "",
            # Extract secret hash if present (first 20 chars)
            normalized_details[:100],
        ]

        # Generate SHA256 hash
        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    @staticmethod
    def is_duplicate(cursor, fingerprint: str) -> bool:
        """Check if a finding with this fingerprint already exists"""
        cursor.execute("SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,))
        return cursor.fetchone() is not None
