"""MEAT-GRINDER: Advanced OSINT Engine - Main Execution Pipeline"""

import argparse
import concurrent.futures
import signal
import sys

from config import Config
from database import DatabaseManager
from engine.admin_discovery import AdminDiscovery
from engine.ai_analyzer import AIAnalyzer
from engine.ai_recon_hunter import AIReconHunter
from engine.api_scanner import APIScanner
from engine.asn_mapper import ASNMapper
from engine.browser_evidence import BrowserEvidence
from engine.cloud_scanner import CloudScanner
from engine.dns_scanner import DNSScanner
from engine.email_osint import EmailOSINT
from engine.ftp_anonymous_checker import FTPAnonymousChecker
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
from reporting.pdf_reporter import PDFReporter


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
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Skip scanning and only generate Markdown/PDF reports from existing DB data",
    )

    args = parser.parse_args()

    # Initialize target and workspace early for early-exit flags
    target = args.target
    # Extract domain name without the top-level extension (e.g., "vulnbank.org" -> "vulnbank")
    target_name = target.rsplit(".", 1)[0]
    workspace = Config.WORKSPACE_DIR / target_name

    # ==========================================
    # Handle report-only mode
    # ==========================================
    if args.report_only:
        db_path = workspace / f"{target_name}.db"
        if not db_path.exists():
            print(f"[!] No database found for '{target_name}'. Run a full scan first.")
            sys.exit(1)

        print(f"[*] Report-only mode: Loading existing data for '{target_name}'...")
        db = DatabaseManager(db_path)
        last_scan = db.get_last_scan_time(target) if args.diff else None

        MarkdownReporter(db, target, workspace, diff_mode=args.diff, last_scan=last_scan).generate()
        PDFReporter(db, target, workspace, config=Config).generate()

        print("[+] Reporting complete!")
        sys.exit(0)

    # ==========================================
    # Pre-flight check
    # ==========================================
    if args.doctor:
        Config.print_status()
        sys.exit(0)

    # ==========================================
    # Standard Scan Initialization
    # ==========================================
    workspace.mkdir(parents=True, exist_ok=True)
    db_path = workspace / f"{target_name}.db"
    db = DatabaseManager(db_path)

    # Check for interrupted scan
    interrupted_scan = db.get_interrupted_scan(target)
    current_run_id = None
    start_step = "START"

    if interrupted_scan:
        run_id, scan_mode, last_step = interrupted_scan
        print(f"[*] Found interrupted scan (last completed: {last_step}). Resuming...")
        current_run_id = run_id
        start_step = last_step
        # Do NOT clear findings if resuming an interrupted scan
    else:
        current_run_id = db.start_scan_run(target, args.mode)
        if not args.diff:
            db.clear_findings()

    # ==========================================
    # Wave-Based Concurrent Execution Pipeline
    # ==========================================
    # Each wave contains modules that can run IN PARALLEL.
    # Waves execute sequentially to respect data dependencies.
    waves = [
        # Wave 1: Foundation (Must finish before anything else)
        [
            ("SubdomainEnumerator", lambda: SubdomainEnumerator(target, db, workspace).execute()),
        ],
        # Wave 2: Passive Intelligence (Independent, needs subdomains)
        [
            ("WhoisContactOSINT", lambda: WhoisContactOSINT(target, db, workspace).execute()),
            ("DNSScanner", lambda: DNSScanner(target, db, workspace).execute()),
            ("WaybackScanner", lambda: WaybackScanner(target, db, workspace).execute()),
        ],
        # Wave 3: Infrastructure (Independent)
        [
            ("PortScanner", lambda: PortScanner(target, db, workspace, mode=args.mode).execute()),
            ("ASNMapper", lambda: ASNMapper(target, db, workspace).execute()),
        ],
        # Wave 4: Active OS Recon (Only if active mode)
        [
            (
                "OSRecon",
                lambda: (
                    OSRecon(target, db, workspace).execute()
                    if args.mode == "active"
                    else print("[*] Skipping Active OS Recon")
                ),
            ),
        ],
        # Wave 5: Web Probing (Must finish before deep web scanning)
        [
            ("HTTPProber", lambda: HTTPProber(target, db, workspace).execute()),
        ],
        # Wave 6: Deep Web Surface (All independent, read from 'endpoints' table)
        [
            ("HeaderAnalyzer", lambda: HeaderAnalyzer(target, db, workspace).execute()),
            ("TLSScanner", lambda: TLSScanner(target, db, workspace).execute()),
            ("SensitiveFileScanner", lambda: SensitiveFileScanner(target, db, workspace).execute()),
            ("WebContentScanner", lambda: WebContentScanner(target, db, workspace).execute()),
            ("JSRecursiveScanner", lambda: JSRecursiveScanner(target, db, workspace).execute()),
            ("HTMLMetadataExtractor", lambda: HTMLMetadataExtractor(target, db, workspace).execute()),
            ("APIScanner", lambda: APIScanner(target, db, workspace).execute()),
            ("SourceMapScanner", lambda: SourceMapScanner(target, db, workspace).execute()),
            ("AdminDiscovery", lambda: AdminDiscovery(target, db, workspace).execute()),
        ],
        # Wave 7: Vulnerability & Cloud (Independent)
        [
            ("NucleiScanner", lambda: NucleiScanner(target, db, workspace).execute()),
            ("CloudScanner", lambda: CloudScanner(target, db, workspace).execute()),
            ("FTPAnonymousChecker", lambda: FTPAnonymousChecker(target, db, workspace).execute()),
        ],
        # Wave 8: Mobile (Optional, independent)
        [
            (
                "MobileScanner",
                lambda: (
                    MobileScanner(target, db, workspace, apk_url=args.apk_url, ipa_url=args.ipa_url).execute()
                    if (args.apk_url or args.ipa_url)
                    else print("[*] Skipping Mobile Analysis")
                ),
            ),
        ],
        # Wave 9: Code Intelligence (Independent, can be heavy)
        [
            (
                "GitScanner",
                lambda: (
                    GitScanner(
                        target, db, workspace, github_target=args.github_target, min_score=args.git_min_score
                    ).execute()
                    if not args.skip_git
                    else print("[*] Skipping Git Scanning")
                ),
            ),
            (
                "SASTScanner",
                lambda: (
                    SASTScanner(target, db, workspace).execute() if not args.skip_git else print("[*] Skipping SAST")
                ),
            ),
            (
                "SBOMScanner",
                lambda: (
                    SBOMScanner(target, db, workspace).execute() if not args.skip_git else print("[*] Skipping SBOM")
                ),
            ),
            (
                "IaCScanner",
                lambda: IaCScanner(target, db, workspace).execute() if not args.skip_git else print("[*] Skipping IaC"),
            ),
        ],
        # Wave 10: OSINT & Verification (Independent)
        [
            ("PasteMonitor", lambda: PasteMonitor(target, db, workspace).execute()),
            ("EmailOSINT", lambda: EmailOSINT(target, db, workspace).execute()),
            ("TakeoverVerifier", lambda: TakeoverVerifier(target, db, workspace).execute()),
        ],
        # Wave 11: Filtering & AI (Sequential recommended due to resource limits)
        [
            ("InsightFilter", lambda: InsightFilter(target, db, workspace).execute()),
            (
                "AIAnalyzer",
                lambda: AIAnalyzer(target, db, workspace).execute() if Config.AI_ENABLED else print("[*] AI Disabled"),
            ),
            (
                "AIReconHunter",
                lambda: (
                    AIReconHunter(target, db, workspace).execute() if Config.AI_ENABLED else print("[*] AI Disabled")
                ),
            ),
            (
                "BrowserEvidence",
                lambda: (
                    BrowserEvidence(target, db, workspace).execute()
                    if not args.no_screenshots
                    else print("[*] Screenshots Disabled")
                ),
            ),
        ],
    ]

    # ==========================================
    # Graceful Interrupt Handler
    # ==========================================
    def signal_handler(sig, frame):
        if current_run_id:
            print("\n[!] Scan interrupted by user. Saving progress to database...")
            db.mark_scan_interrupted(current_run_id)
            print("[+] Progress saved. Run the exact same command to resume.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print("=== MEAT-GRINDER ENGINE INITIATED ===")
    print(f"Target: {target} | Scan Mode: {args.mode.upper()}")
    if start_step != "START":
        print(f"[*] Resuming from step: {start_step}")
    print()

    # ==========================================
    # Execute Pipeline
    # ==========================================
    resume_mode = start_step != "START"
    max_workers = int(getattr(Config, "MAX_WORKERS", 50))

    for wave_index, wave in enumerate(waves):
        # Handle resume logic
        if resume_mode:
            wave_names = [name for name, _ in wave]
            if start_step not in wave_names:
                continue
            else:
                # Found the wave, execute from this step onward in this wave
                start_idx = wave_names.index(start_step)
                wave = wave[start_idx:]
                resume_mode = False

        print(f"\n{'='*60}")
        print(f"[*] Executing Wave {wave_index + 1} ({len(wave)} concurrent tasks)...")
        print(f"{'='*60}")

        # Run the current wave concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks in the wave
            future_to_name = {executor.submit(func): name for name, func in wave}

            for future in concurrent.futures.as_completed(future_to_name):
                name = future_to_name[future]
                db.update_scan_step(current_run_id, name)
                try:
                    future.result()
                    print(f"[+] {name} completed successfully.")
                except Exception as e:
                    print(f"[!] Module {name} failed with error: {e}")
                    print("[*] Continuing with other modules in this wave...")

    # ==========================================
    # Finalize & Report
    # ==========================================
    total_findings = len(db.get_all_findings())
    db.complete_scan_run(current_run_id, total_findings)
    current_run_id = None  # Prevent signal handler from overwriting completed status

    last_scan = db.get_last_scan_time(target) if args.diff else None
    MarkdownReporter(db, target, workspace, diff_mode=args.diff, last_scan=last_scan).generate()
    PDFReporter(db, target, workspace, config=Config).generate()

    print("\n[!] Engine run complete.")


if __name__ == "__main__":
    main()
