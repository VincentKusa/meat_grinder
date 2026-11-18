import argparse

from config import Config
from database import DatabaseManager
from engine.cloud_scanner import CloudScanner
from engine.git_scanner import GitScanner
from engine.header_analyzer import HeaderAnalyzer
from engine.html_metadata_extractor import HTMLMetadataExtractor
from engine.http_prober import HTTPProber
from engine.insight_filter import InsightFilter
from engine.mobile_scanner import MobileScanner
from engine.nuclei_scanner import NucleiScanner
from engine.os_recon import OSRecon
from engine.port_scanner import PortScanner
from engine.sast_scanner import SASTScanner
from engine.screenshotter import Screenshotter
from engine.sensitive_file_scanner import SensitiveFileScanner
from engine.subdomain_enum import SubdomainEnumerator
from engine.web_content_scanner import WebContentScanner
from engine.whois_contact_osint import WhoisContactOSINT
from reporting.markdown_gen import MarkdownReporter


def main():
    parser = argparse.ArgumentParser(description="MEAT-GRINDER: Advanced OSINT Engine")
    parser.add_argument("target", help="Target domain (e.g., vulnbank.org)")
    parser.add_argument(
        "--mode",
        choices=["passive", "active"],
        default="passive",
        help="Port scan mode: 'passive' (Shodan) or 'active' (Naabu). Default: passive",
    )
    parser.add_argument("--skip-git", action="store_true", help="Skip Git repository scanning")
    parser.add_argument(
        "--github-target",
        type=str,
        default=None,
        help="Explicit GitHub username or organization to scan (e.g., Commando-X)",
    )
    parser.add_argument("--apk-url", type=str, default=None, help="Direct URL to target's Android APK file")
    parser.add_argument("--ipa-url", type=str, default=None, help="Direct URL to target's iOS IPA file")

    args = parser.parse_args()

    target = args.target
    workspace = Config.WORKSPACE_DIR / target
    workspace.mkdir(parents=True, exist_ok=True)

    db_path = workspace / "recon_data.db"
    db = DatabaseManager(db_path)

    # FIX: Clear old findings at the START of the run, not in the middle
    db.clear_findings()

    print("=== MEAT-GRINDER ENGINE INITIATED ===")
    print(f"Target: {target} | Scan Mode: {args.mode.upper()}")
    if args.github_target:
        print(f"GitHub Target: {args.github_target}")
    print()

    SubdomainEnumerator(target, db, workspace).execute()
    WhoisContactOSINT(target, db, workspace).execute()
    PortScanner(target, db, workspace, mode=args.mode).execute()

    if args.mode == "active":
        OSRecon(target, db, workspace).execute()
    else:
        print("[*] Skipping Active OS Recon (Use --mode active to enable Nmap fingerprinting)")

    HTTPProber(target, db, workspace).execute()
    HeaderAnalyzer(target, db, workspace).execute()
    SensitiveFileScanner(target, db, workspace).execute()
    WebContentScanner(target, db, workspace).execute()
    HTMLMetadataExtractor(target, db, workspace).execute()
    NucleiScanner(target, db, workspace).execute()
    CloudScanner(target, db, workspace).execute()
    MobileScanner(target, db, workspace, apk_url=args.apk_url, ipa_url=args.ipa_url).execute()

    if not args.skip_git:
        GitScanner(target, db, workspace, github_target=args.github_target).execute()
        SASTScanner(target, db, workspace).execute()

    InsightFilter(target, db, workspace).execute()
    Screenshotter(target, db, workspace).execute()
    MarkdownReporter(db, target, workspace).generate()

    print("\n[!] Engine run complete.")


if __name__ == "__main__":
    main()
