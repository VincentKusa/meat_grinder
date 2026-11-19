class RepoRelevanceScorer:
    # Keywords that indicate test/CTF repos (lower score)
    NOISE_KEYWORDS = [
        "ctf",
        "writeup",
        "test",
        "example",
        "demo",
        "sample",
        "poc",
        "handbook",
        "learning",
        "tutorial",
        "lab",
        "challenge",
    ]

    @staticmethod
    def score_repository(
        repo_url: str, target_domain: str, explicit_target: str = None, linked_from_website: bool = False
    ) -> int:
        """
        Score a repository's relevance to the target (0-100)
        Higher score = more likely to contain relevant secrets
        """
        score = 0
        repo_name = repo_url.split("/")[-1].lower()
        owner = repo_url.split("/")[-2].lower()
        target_base = target_domain.split(".")[0].lower()

        # Explicit target match (highest priority)
        if explicit_target and owner == explicit_target.lower():
            score += 50

        # Linked from target website
        if linked_from_website:
            score += 50

        # Repo name contains target base
        if target_base in repo_name:
            score += 30

        # Penalize noise keywords
        for keyword in RepoRelevanceScorer.NOISE_KEYWORDS:
            if keyword in repo_name or keyword in owner:
                score -= 20

        # Ensure score is in range 0-100
        return max(0, min(100, score))

    @staticmethod
    def should_scan_repo(score: int, min_score: int = 60) -> bool:
        """Determine if a repo should be scanned based on its score"""
        return score >= min_score
