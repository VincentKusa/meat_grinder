import plistlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import requests

from config import Config
from engine.base import BaseReconModule


class MobileScanner(BaseReconModule):
    # Android permissions considered dangerous
    DANGEROUS_PERMISSIONS = [
        "CAMERA",
        "RECORD_AUDIO",
        "READ_CONTACTS",
        "READ_SMS",
        "SEND_SMS",
        "READ_CALL_LOG",
        "ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE",
        "CALL_PHONE",
    ]

    def __init__(self, target: str, db, workspace, apk_url: str = None, ipa_url: str = None):
        super().__init__(target, db, workspace)
        self.apk_url = apk_url
        self.ipa_url = ipa_url
        self.mobile_dir = workspace / "mobile_analysis"
        self.mobile_dir.mkdir(exist_ok=True)

    def execute(self):
        if self.apk_url:
            self._analyze_android(self.apk_url)
        if self.ipa_url:
            self._analyze_ios(self.ipa_url)
        if not self.apk_url and not self.ipa_url:
            print("[*] No mobile app URL provided. Skipping mobile analysis.")

    # ============================================================
    # ANDROID ANALYSIS
    # ============================================================
    def _analyze_android(self, apk_url: str):
        print(f"[*] Analyzing Android APK: {apk_url}")
        apk_path = self.mobile_dir / "target_app.apk"
        extract_dir = self.mobile_dir / "apk_extracted"

        try:
            # 1. Download APK
            self._download_file(apk_url, apk_path)

            # 2. Run MobSF for general secrets/misconfigs
            self._run_mobsf(apk_path, apk_url, "apk")

            # 3. Deep AndroidManifest.xml analysis
            self._analyze_android_manifest(apk_path, extract_dir, apk_url)

            print("[+] Android analysis complete.")
        except Exception as e:
            print(f"[!] Android analysis failed: {e}")
        finally:
            if apk_path.exists():
                apk_path.unlink()
            if extract_dir.exists():
                shutil.rmtree(extract_dir)

    def _analyze_android_manifest(self, apk_path: Path, extract_dir: Path, apk_url: str):
        print("[*] Deep-analyzing AndroidManifest.xml...")
        try:
            # Use apktool to decode the manifest (handles binary XML)
            subprocess.run(
                ["apktool", "d", "-f", "-o", str(extract_dir), str(apk_path)],
                capture_output=True,
                check=True,
                timeout=120,
            )

            manifest_path = extract_dir / "AndroidManifest.xml"
            if not manifest_path.exists():
                print("[!] AndroidManifest.xml not found after decode.")
                return

            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = "{http://schemas.android.com/apk/res/android}"
            package = root.get("package", "unknown")

            # 1. Check allowBackup (data extraction via adb)
            if root.get(f"{ns}allowBackup") == "true":
                self.db.insert_finding(
                    f_type="ANDROID_ALLOW_BACKUP",
                    url=f"mobile://{apk_url}/AndroidManifest.xml",
                    details=f"Package: {package} | allowBackup=true (full app data extractable via adb)",
                    severity="HIGH",
                )

            # 2. Check debuggable flag
            app_elem = root.find("application")
            if app_elem is not None and app_elem.get(f"{ns}debuggable") == "true":
                self.db.insert_finding(
                    f_type="ANDROID_DEBUGGABLE",
                    url=f"mobile://{apk_url}/AndroidManifest.xml",
                    details=f"Package: {package} | debuggable=true (production build is debuggable!)",
                    severity="CRITICAL",
                )

            # 3. Find exported components (attack surface)
            exported_components = []
            for component_type in ["activity", "service", "receiver", "provider"]:
                for comp in root.iter(component_type):
                    exported = comp.get(f"{ns}exported")
                    # Android 17+: exported=true if intent-filter exists
                    has_intent_filter = comp.find("intent-filter") is not None
                    if exported == "true" or (exported is None and has_intent_filter):
                        name = comp.get(f"{ns}name", "unknown")
                        exported_components.append(f"{component_type}:{name}")

            if exported_components:
                self.db.insert_finding(
                    f_type="ANDROID_EXPORTED_COMPONENTS",
                    url=f"mobile://{apk_url}/AndroidManifest.xml",
                    details=f"Exported: {', '.join(exported_components[:5])}"
                    f"{'...' if len(exported_components) > 5 else ''}",
                    severity="HIGH",
                )

            # 4. Find custom URL schemes (deep link hijacking)
            url_schemes = set()
            for data in root.iter("data"):
                scheme = data.get(f"{ns}scheme")
                if scheme and scheme not in ["http", "https", "file", "content"]:
                    url_schemes.add(scheme)
            if url_schemes:
                self.db.insert_finding(
                    f_type="ANDROID_CUSTOM_URL_SCHEME",
                    url=f"mobile://{apk_url}/AndroidManifest.xml",
                    details=f"Custom schemes: {', '.join(url_schemes)} (deep link attack surface)",
                    severity="MEDIUM",
                )

            # 5. Dangerous permissions
            dangerous = []
            for perm in root.iter("uses-permission"):
                perm_name = perm.get(f"{ns}name", "")
                if any(d in perm_name for d in self.DANGEROUS_PERMISSIONS):
                    dangerous.append(perm_name.split(".")[-1])
            if dangerous:
                self.db.insert_finding(
                    f_type="ANDROID_DANGEROUS_PERMISSIONS",
                    url=f"mobile://{apk_url}/AndroidManifest.xml",
                    details=f"Permissions: {', '.join(dangerous[:8])}",
                    severity="MEDIUM",
                )

            # 6. Network security config check
            nsc_path = extract_dir / "res" / "xml" / "network_security_config.xml"
            if nsc_path.exists():
                nsc_content = nsc_path.read_text()
                if 'cleartextTrafficPermitted="true"' in nsc_content:
                    self.db.insert_finding(
                        f_type="ANDROID_CLEARTEXT_ALLOWED",
                        url=f"mobile://{apk_url}/network_security_config.xml",
                        details="Cleartext (HTTP) traffic explicitly permitted",
                        severity="HIGH",
                    )

        except subprocess.CalledProcessError as e:
            print(f"[!] apktool failed: {e.stderr}")
        except Exception as e:
            print(f"[!] Manifest analysis failed: {e}")

    # ============================================================
    # iOS ANALYSIS
    # ============================================================
    def _analyze_ios(self, ipa_url: str):
        print(f"[*] Analyzing iOS IPA: {ipa_url}")
        ipa_path = self.mobile_dir / "target_app.ipa"
        extract_dir = self.mobile_dir / "ipa_extracted"

        try:
            self._download_file(ipa_url, ipa_path)
            self._run_mobsf(ipa_path, ipa_url, "ipa")

            # Extract IPA (it's a zip)
            with zipfile.ZipFile(ipa_path, "r") as z:
                z.extractall(extract_dir)

            # Find the .app bundle
            app_dirs = list(extract_dir.rglob("*.app"))
            if not app_dirs:
                print("[!] No .app bundle found in IPA.")
                return

            app_dir = app_dirs[0]
            self._analyze_ios_plist(app_dir, ipa_url)
            self._analyze_ios_entitlements(app_dir, ipa_url)

            print("[+] iOS analysis complete.")
        except Exception as e:
            print(f"[!] iOS analysis failed: {e}")
        finally:
            if ipa_path.exists():
                ipa_path.unlink()
            if extract_dir.exists():
                shutil.rmtree(extract_dir)

    def _analyze_ios_plist(self, app_dir: Path, ipa_url: str):
        print("[*] Parsing iOS Info.plist...")
        plist_path = app_dir / "Info.plist"
        if not plist_path.exists():
            return

        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)

            bundle_id = plist.get("CFBundleIdentifier", "unknown")

            # 1. URL Schemes (deep linking)
            url_types = plist.get("CFBundleURLTypes", [])
            schemes = set()
            for url_type in url_types:
                for scheme in url_type.get("CFBundleURLSchemes", []):
                    schemes.add(scheme)
            if schemes:
                self.db.insert_finding(
                    f_type="IOS_URL_SCHEMES",
                    url=f"mobile://{ipa_url}/Info.plist",
                    details=f"Bundle: {bundle_id} | Schemes: {', '.join(schemes)}",
                    severity="MEDIUM",
                )

            # 2. App Transport Security (ATS) bypasses
            ats = plist.get("NSAppTransportSecurity", {})
            if ats.get("NSAllowsArbitraryLoads") is True:
                self.db.insert_finding(
                    f_type="IOS_ATS_BYPASS",
                    url=f"mobile://{ipa_url}/Info.plist",
                    details=f"Bundle: {bundle_id} | NSAllowsArbitraryLoads=true (all HTTP allowed)",
                    severity="HIGH",
                )

            # 3. ATS exceptions for specific domains
            exceptions = ats.get("NSExceptionDomains", {})
            for domain, config in exceptions.items():
                if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    self.db.insert_finding(
                        f_type="IOS_ATS_EXCEPTION",
                        url=f"mobile://{ipa_url}/Info.plist",
                        details=f"Domain: {domain} | HTTP allowed",
                        severity="MEDIUM",
                    )

            # 4. Hardcoded sensitive keys in plist
            sensitive_keys = [
                "APIKey",
                "SecretKey",
                "AuthToken",
                "FirebaseURL",
                "AWSCredentials",
                "StripeKey",
                "GoogleMapsKey",
                "TwitterConsumerKey",
            ]
            for key in sensitive_keys:
                if key in plist:
                    self.db.insert_finding(
                        f_type="IOS_PLIST_SECRET",
                        url=f"mobile://{ipa_url}/Info.plist",
                        details=f"Bundle: {bundle_id} | Key: {key} = {str(plist[key])[:30]}",
                        severity="HIGH",
                    )

            # 5. External URL loading
            if plist.get("NSAllowsLocalNetworking") is True:
                self.db.insert_finding(
                    f_type="IOS_LOCAL_NETWORK_ACCESS",
                    url=f"mobile://{ipa_url}/Info.plist",
                    details=f"Bundle: {bundle_id} | Local network access allowed",
                    severity="INFO",
                )

        except Exception as e:
            print(f"[!] Plist parsing failed: {e}")

    def _analyze_ios_entitlements(self, app_dir: Path, ipa_url: str):
        print("[*] Parsing iOS entitlements...")
        # Entitlements are embedded in the binary; try to find the plist
        entitlement_paths = list(app_dir.rglob("*.entitlements")) + list(
            app_dir.rglob("archived-expanded-entitlements.xcent")
        )

        for ent_path in entitlement_paths:
            try:
                with open(ent_path, "rb") as f:
                    ent = plistlib.load(f)

                # Keychain access groups (shared credentials between apps)
                keychain_groups = ent.get("keychain-access-groups", [])
                if keychain_groups:
                    self.db.insert_finding(
                        f_type="IOS_KEYCHAIN_GROUPS",
                        url=f"mobile://{ipa_url}/{ent_path.name}",
                        details=f"Keychain groups: {', '.join(keychain_groups)}",
                        severity="INFO",
                    )

                # Associated domains (universal links)
                assoc_domains = ent.get("com.apple.developer.associated-domains", [])
                if assoc_domains:
                    self.db.insert_finding(
                        f_type="IOS_ASSOCIATED_DOMAINS",
                        url=f"mobile://{ipa_url}/{ent_path.name}",
                        details=f"Universal links: {', '.join(assoc_domains[:5])}",
                        severity="INFO",
                    )

                # Push notification environment
                aps_env = ent.get("aps-environment")
                if aps_env:
                    self.db.insert_finding(
                        f_type="IOS_PUSH_ENVIRONMENT",
                        url=f"mobile://{ipa_url}/{ent_path.name}",
                        details=f"Push environment: {aps_env}",
                        severity="INFO",
                    )

            except Exception:
                pass  # Binary plists or malformed files

    # ============================================================
    # SHARED HELPERS
    # ============================================================
    def _download_file(self, url: str, dest: Path):
        print(f"[*] Downloading {dest.name}...")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

    def _run_mobsf(self, app_path: Path, app_url: str, app_type: str):
        print(f"[*] Running MobSF static analysis on {app_type.upper()}...")
        report_path = self.mobile_dir / f"mobsf_{app_type}_report.json"
        cmd = f"{Config.MOBSFSCAN_BIN} '{app_path}' --json --output '{report_path}'"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode == 0 and report_path.exists():
                self._parse_mobsf_results(report_path, app_url)
        except Exception as e:
            print(f"[!] MobSF scan failed: {e}")

    def _parse_mobsf_results(self, report_path: Path, app_url: str):
        import json

        try:
            with open(report_path, "r") as f:
                data = json.load(f)

            for file_name, file_data in data.get("files", {}).items():
                for finding in file_data.get("findings", []):
                    if finding.get("severity") in ["HIGH", "CRITICAL", "WARNING"]:
                        self.db.insert_finding(
                            f_type="MOBILE_APP_SECRET/MISCONFIG",
                            url=f"mobile://{app_url}/{file_name}",
                            details=f"Rule: {finding.get('rule')} | Line: {finding.get('line')}",
                            severity="HIGH" if finding.get("severity") in ["HIGH", "CRITICAL"] else "MEDIUM",
                        )
        except Exception:
            pass
