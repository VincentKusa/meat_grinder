import os
import shutil
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Centralized configuration for MEAT-GRINDER engine"""

    # ==========================================
    # WORKSPACE & PATHS
    # ==========================================
    WORKSPACE_DIR = Path(os.getenv("WORKSPACE_DIR", "./workspaces"))
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    # ==========================================
    # API KEYS & TOKENS
    # ==========================================
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    # Optional: Add more API keys as needed
    # VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    # HUNTER_IO_API_KEY = os.getenv("HUNTER_IO_API_KEY")

    # ==========================================
    # GO-BASED RECONNAISSANCE BINARIES
    # ==========================================
    SUBFINDER_BIN = "subfinder"
    HTTPX_BIN = "pdhttpx"  # Using pdhttpx to avoid Python httpx conflict
    NAABU_BIN = "naabu"
    GITLEAKS_BIN = "gitleaks"
    NUCLEI_BIN = "nuclei"
    GOWITNESS_BIN = "gowitness"
    TRUFFLEHOG_BIN = "trufflehog"

    # ==========================================
    # SYSTEM BINARIES
    # ==========================================
    MOBSFSCAN_BIN = "mobsfscan"
    TRIVY_BIN = "trivy"
    CHECKOV_BIN = "checkov"

    # ==========================================
    # SCANNER CONFIGURATION
    # ==========================================
    # Timeouts (in seconds)
    HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))

    # Thread/Worker counts
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "50"))

    # Git scanner settings
    GIT_MIN_SCORE = int(os.getenv("GIT_MIN_SCORE", "60"))
    GIT_CLONE_DEPTH = int(os.getenv("GIT_CLONE_DEPTH", "1"))

    # ==========================================
    # FEATURE FLAGS
    # ==========================================
    ENABLE_SCREENSHOTS = os.getenv("ENABLE_SCREENSHOTS", "true").lower() == "true"
    ENABLE_MOBILE_SCANNING = os.getenv("ENABLE_MOBILE_SCANNING", "true").lower() == "true"
    ENABLE_IAC_SCANNING = os.getenv("ENABLE_IAC_SCANNING", "true").lower() == "true"

    # ==========================================
    # REPORTING
    # ==========================================
    REDACT_SECRETS = os.getenv("REDACT_SECRETS", "true").lower() == "true"
    SECRET_PREVIEW_LENGTH = int(os.getenv("SECRET_PREVIEW_LENGTH", "8"))

    # ==========================================
    # AI INTEGRATION
    # ==========================================
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
    OLLAMA_CODE_MODEL = os.getenv("OLLAMA_CODE_MODEL", "qwen2.5-coder:7b")

    AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
    AI_USE_LOCAL_FOR_SECRETS = os.getenv("AI_USE_LOCAL_FOR_SECRETS", "true").lower() == "true"
    AI_USE_CLOUD_FOR_REASONING = os.getenv("AI_USE_CLOUD_FOR_REASONING", "true").lower() == "true"

    @classmethod
    def validate_binaries(cls) -> dict:
        """
        Validate that all required binaries are installed and accessible.
        Returns a dict of {binary_name: is_available}
        """
        binaries = {
            "subfinder": cls.SUBFINDER_BIN,
            "httpx": cls.HTTPX_BIN,
            "naabu": cls.NAABU_BIN,
            "gitleaks": cls.GITLEAKS_BIN,
            "nuclei": cls.NUCLEI_BIN,
            "trufflehog": cls.TRUFFLEHOG_BIN,
            "mobsfscan": cls.MOBSFSCAN_BIN,
            "trivy": cls.TRIVY_BIN,
            "checkov": cls.CHECKOV_BIN,
        }

        optional_binaries = {
            "gowitness": cls.GOWITNESS_BIN,
        }

        results = {}

        # Check required binaries
        for name, binary in binaries.items():
            results[name] = shutil.which(binary) is not None

        # Check optional binaries
        for name, binary in optional_binaries.items():
            results[name] = shutil.which(binary) is not None

        return results

    @classmethod
    def print_status(cls):
        """Print configuration status for debugging"""
        print("=" * 60)
        print("MEAT-GRINDER CONFIGURATION STATUS")
        print("=" * 60)

        print(f"\n📁 Workspace: {cls.WORKSPACE_DIR.absolute()}")

        print("\n🔑 API Keys:")
        print(f"  GitHub Token: {'✓ Set' if cls.GITHUB_TOKEN else '✗ Not set'}")
        print(f"  Shodan API Key: {'✓ Set' if cls.SHODAN_API_KEY else '✗ Not set'}")

        print("\n🔧 Binary Validation:")
        binaries = cls.validate_binaries()
        for name, available in binaries.items():
            status = "✓" if available else "✗"
            print(f"  {status} {name}")

        print("\n⚙️  Settings:")
        print(f"  HTTP Timeout: {cls.HTTP_TIMEOUT}s")
        print(f"  Scan Timeout: {cls.SCAN_TIMEOUT}s")
        print(f"  Max Workers: {cls.MAX_WORKERS}")
        print(f"  Git Min Score: {cls.GIT_MIN_SCORE}")
        print(f"  Redact Secrets: {cls.REDACT_SECRETS}")

        print("\n" + "=" * 60)
