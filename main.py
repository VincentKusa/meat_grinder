import argparse
import sys

from config import Config
from database import DatabaseManager
from engine.admin_discovery import AdminDiscovery
from engine.api_scanner import APIScanner
from engine.asn_mapper import ASNMapper
from engine.browser_evidence import BrowserEvidence
from engine.cloud_scanner import CloudScanner
from engine.dns_scanner import DNSScanner
from engine.email_osint import EmailOSINT
from engine.git_scanner import GitScanner
from engine.header_analyzer import HeaderAnalyzer
from engine.html_metadata_extractor import HTMLMetadataExtractor
from engine.http_prober import HTTPProber
from engine.iac_scanner import IaCScanner
from engine.insight_filter import InsightFilter
from engine.js_recursive_scanner import JSRecursiveScanner
from engine.mobile_scanner import MobileScanner
from engine.nuclei_scanner import NucleiScanner
from engine.os_recon import OSRecon
from engine.paste_monitor import PasteMonitor
from engine.port_scanner import PortScanner
from engine.sast_scanner import SASTScanner
from engine.sbom_scanner import SBOMScanner
from engine.sensitive_file_scanner import SensitiveFileScanner
from engine.sourcemap_scanner import SourceMapScanner
from engine.subdomain_enum import SubdomainEnumerator
from engine.takeover_verifier import TakeoverVerifier
from engine.tls_scanner import TLSScanner
from engine.wayback_scanner import WaybackScanner
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

    # Advanced features
    parser.add_argument("--doctor", action="store_true", help="Run pre-flight checks and exit")
    parser.add_argument(
        "--git-min-score", type=int, default=60, help="Minimum repo relevance score (0-100) for scanning"
    )
    parser.add_argument("--diff", action="store_true", help="Show only new findings since the last scan")
    parser.add_argument("--no-screenshots", action="store_true", help="Disable browser evidence/screenshot capture")

    args = parser.parse_args()

    # Pre-flight check
    if args.doctor:
        Config.print_status()
        sys.exit(0)

    target = args.target
    workspace = Config.WORKSPACE_DIR / target
    workspace.mkdir(parents=True, exist_ok=True)

    db_path = workspace / "recon_data.db"
    db = DatabaseManager(db_path)

    # Get last scan time for diff mode
    last_scan = db.get_last_scan_time(target) if args.diff else None

    # Clear findings only if not in diff mode
    if not args.diff:
        db.clear_findings()

    print("=== MEAT-GRINDER ENGINE INITIATED ===")
    print(f"Target: {target} | Scan Mode: {args.mode.upper()}")
    if args.github_target:
        print(f"GitHub Target: {args.github_target}")
    if args.diff and last_scan:
        print(f"Diff Mode: Showing findings since {last_scan}")
    print()

    # ==========================================
    # 1. Passive Discovery & Intelligence
    # ==========================================
    SubdomainEnumerator(target, db, workspace).execute()
    WhoisContactOSINT(target, db, workspace).execute()
    DNSScanner(target, db, workspace).execute()
    WaybackScanner(target, db, workspace).execute()

    # ==========================================
    # 2. Port & OS Reconnaissance
    # ==========================================
    PortScanner(target, db, workspace, mode=args.mode).execute()
    if args.mode == "active":
        OSRecon(target, db, workspace).execute()
    else:
        print("[*] Skipping Active OS Recon (Use --mode active to enable Nmap fingerprinting)")
    ASNMapper(target, db, workspace).execute()

    # ==========================================
    # 3. Web Surface Analysis
    # ==========================================
    HTTPProber(target, db, workspace).execute()
    HeaderAnalyzer(target, db, workspace).execute()
    TLSScanner(target, db, workspace).execute()

    # ==========================================
    # 4. Deep Content & Secret Scanning
    # ==========================================
    SensitiveFileScanner(target, db, workspace).execute()
    WebContentScanner(target, db, workspace).execute()
    JSRecursiveScanner(target, db, workspace).execute()
    HTMLMetadataExtractor(target, db, workspace).execute()
    APIScanner(target, db, workspace).execute()
    SourceMapScanner(target, db, workspace).execute()
    AdminDiscovery(target, db, workspace).execute()

    # ==========================================
    # 5. Vulnerability & Misconfiguration
    # ==========================================
    NucleiScanner(target, db, workspace).execute()
    CloudScanner(target, db, workspace).execute()

    # ==========================================
    # 6. Mobile Analysis (Optional)
    # ==========================================
    if args.apk_url or args.ipa_url:
        MobileScanner(target, db, workspace, apk_url=args.apk_url, ipa_url=args.ipa_url).execute()

    # ==========================================
    # 7. Code & Repository Analysis
    # ==========================================
    if not args.skip_git:
        GitScanner(target, db, workspace, github_target=args.github_target, min_score=args.git_min_score).execute()
        SASTScanner(target, db, workspace).execute()
        SBOMScanner(target, db, workspace).execute()
        IaCScanner(target, db, workspace).execute()

    PasteMonitor(target, db, workspace).execute()
    EmailOSINT(target, db, workspace).execute()

    # ==========================================
    # 8. Filtering & Evidence
    # ==========================================
    TakeoverVerifier(target, db, workspace).execute()
    InsightFilter(target, db, workspace).execute()
    if not args.no_screenshots:
        BrowserEvidence(target, db, workspace).execute()

    # ==========================================
    # 9. Record & Report
    # ==========================================
    total_findings = len(db.get_all_findings())
    db.record_scan_run(target, args.mode, total_findings)

    MarkdownReporter(db, target, workspace, diff_mode=args.diff, last_scan=last_scan).generate()

    print("\n[!] Engine run complete.")


if __name__ == "__main__":
    main()
