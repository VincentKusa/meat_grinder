import argparse
import sys
from pathlib import Path
from config import Config
from database import DatabaseManager
from engine.subdomain_enum import SubdomainEnumerator
from engine.port_scanner import PortScanner
from engine.http_prober import HTTPProber
from engine.header_analyzer import HeaderAnalyzer
from engine.sensitive_file_scanner import SensitiveFileScanner
from engine.web_content_scanner import WebContentScanner
from engine.git_scanner import GitScanner
from engine.insight_filter import InsightFilter
from reporting.markdown_gen import MarkdownReporter
from engine.nuclei_scanner import NucleiScanner

def main():
    parser = argparse.ArgumentParser(description="MEAT-GRINDER: Advanced OSINT Engine")
    parser.add_argument("target", help="Target domain (e.g., vulnbank.org)")
    parser.add_argument("--mode", choices=['passive', 'active'], default='passive',
                        help="Port scan mode: 'passive' (Shodan) or 'active' (Naabu). Default: passive")
    parser.add_argument("--skip-git", action='store_true', help="Skip Git repository scanning")
    parser.add_argument("--github-target", type=str, default=None,
                        help="Explicit GitHub username or organization to scan (e.g., Commando-X)")
    args = parser.parse_args()

    target = args.target
    workspace = Config.WORKSPACE_DIR / target
    workspace.mkdir(parents=True, exist_ok=True)

    db_path = workspace / "recon_data.db"
    db = DatabaseManager(db_path)

    # FIX: Clear old findings at the START of the run, not in the middle
    db.clear_findings()

    print(f"=== MEAT-GRINDER ENGINE INITIATED ===")
    print(f"Target: {target} | Scan Mode: {args.mode.upper()}")
    if args.github_target:
        print(f"GitHub Target: {args.github_target}")
    print()

    SubdomainEnumerator(target, db, workspace).execute()
    PortScanner(target, db, workspace, mode=args.mode).execute()
    HTTPProber(target, db, workspace).execute()
    HeaderAnalyzer(target, db, workspace).execute()
    SensitiveFileScanner(target, db, workspace).execute()
    WebContentScanner(target, db, workspace).execute()
    NucleiScanner(target, db, workspace).execute()

    if not args.skip_git:
        GitScanner(target, db, workspace, github_target=args.github_target).execute()

    InsightFilter(target, db, workspace).execute()
    MarkdownReporter(db, target, workspace).generate()

    print("\n[!] Engine run complete.")

if __name__ == "__main__":
    main()