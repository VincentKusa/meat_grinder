# 🥩 MEAT-GRINDER

### Modular Engine for Asset Tracking & Reconnaissance

MEAT-GRINDER is a production-grade, modular OSINT and reconnaissance engine built in Python. It orchestrates
industry-standard CLI tools to map an organization's external attack surface, filtering out the "noise" (CDNs, default
pages) to extract the "meat" (exposed panels, misconfigurations, guarded endpoints, and cloud leaks).

---

## ⚡ Quick Start

### 1. Clone & Setup Environment

```bash
git clone <your-repository-url> meat_grinder
cd meat_grinder

# Install OS-level dependencies
sudo apt update
sudo apt install python3-pip python3-venv golang-go curl wget unzip pipx -y

# Install isolated CLI tools (prevents dependency conflicts)
pipx install checkov
pipx install mobsfscan
pipx ensurepath

# Install Go-based reconnaissance tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Move Go binaries to PATH
sudo cp $(go env GOPATH)/bin/{subfinder,httpx,naabu,gitleaks,nuclei} /usr/local/bin/
sudo chmod +x /usr/local/bin/{subfinder,httpx,naabu,gitleaks,nuclei}

# Install Trivy (SBOM/IaC scanning)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
```

### 2. Initialize Nuclei Templates

```bash
rm -rf ~/.local/nuclei-templates
wget -qO /tmp/nuclei-templates.zip https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip
unzip -q /tmp/nuclei-templates.zip -d /tmp/
mkdir -p ~/.local/nuclei-templates
mv /tmp/nuclei-templates-main/* ~/.local/nuclei-templates/
rm /tmp/nuclei-templates.zip
```

### 3. Configure Python Environment & Secrets

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
nano .env  # Add your GITHUB_TOKEN here
```

---

## 🚀 Usage & Options

Run the engine against a target domain. Results are saved in `workspaces/<target>/`.

### Basic Commands

```bash
# 1. Standard Run (Passive port scanning + Fuzzy GitHub search)
python3 main.py example.com

# 2. Explicit GitHub Target (Highly recommended to reduce noise)
python3 main.py vulnbank.org --github-target Commando-X

# 3. Aggressive Run (Active Naabu port scanning + Nmap OS fingerprinting)
python3 main.py example.com --mode active

# 4. Fast Run (Skip Git/SAST scanning for speed)
python3 main.py example.com --skip-git
```

### Advanced Options

| Flag                      | Description                                                                 |
|:--------------------------|:----------------------------------------------------------------------------|
| `--mode active`           | Enables active SYN port scanning (Naabu) and deep OS fingerprinting (Nmap). |
| `--github-target <org>`   | Explicitly targets a GitHub org/user, bypassing fuzzy search.               |
| `--git-min-score <0-100>` | Minimum relevance score to clone/scan a repo (Default: `60`).               |
| `--apk-url <url>`         | Direct URL to an Android `.apk` file for static analysis.                   |
| `--ipa-url <url>`         | Direct URL to an iOS `.ipa` file for static analysis.                       |
| `--diff`                  | Continuous monitoring mode: shows *only* new findings since the last scan.  |
| `--no-screenshots`        | Disables Playwright browser evidence capture.                               |
| `--doctor`                | Runs a pre-flight check to verify all binaries and configurations.          |

### Viewing Results

```bash
cat workspaces/<target>/REPORT_<target>.md
```

---

## 📚 Documentation & Deep Dive

### 🏗 Architecture

Instead of writing slow network scanners from scratch, MEAT-GRINDER uses Python as the **Orchestrator** and delegates
heavy lifting to specialized, highly optimized Go-based CLI tools. Data is persisted in a local SQLite database,
ensuring crash resilience and enabling continuous monitoring (`--diff`).

### 🔍 Core Capabilities

#### 1. Infrastructure & Network Intelligence

- **Subdomain Enumeration:** Passive harvesting via `subfinder`.
- **Port Scanning:** Dual-mode support. `passive` uses Shodan InternetDB (zero packets); `active` uses `naabu` for
  wire-speed SYN scanning.
- **OS & Service Fingerprinting:** Active mode triggers `nmap` (`-sS -sV -O`) to detect exact OS versions, service
  banners, and End-of-Life (EOL) software.
- **DNS & TLS Intelligence:** Analyzes A/MX/TXT records, detects dangling CNAMEs (subdomain takeover), validates
  SPF/DMARC, and inspects SSL certificates for expiry, weak protocols, and SAN discovery.

#### 2. Web Surface Analysis

- **HTTP Probing:** Uses `httpx` to extract status codes, titles, tech stacks, and content lengths.
- **Header & WAF Analysis:** Detects Cloudflare, Akamai, etc., and flags missing security headers (HSTS, CSP).
- **Sensitive File Hunting:** Regex-validated scanning for `.env`, `.git`, and config files. Ignores fake "200 OK"
  custom 404 pages.
- **Frontend Secret Scanning:** Downloads and scans linked `.js` files and inline scripts for hardcoded AWS, Stripe,
  GitHub, and JWT secrets.
- **HTML Metadata Extraction:** Parses `<meta>` tags, HTML comments (dev notes, internal URLs), hidden form fields, and
  Open Graph data.
- **API Surface Discovery:** Actively hunts for exposed Swagger/OpenAPI docs, GraphQL endpoints, and internal API paths
  in source code.

#### 3. Code & Repository Intelligence

- **Git Discovery:** Scrapes target websites and queries the GitHub API to find relevant repositories.
- **Relevance Scoring:** Repositories are scored 0-100. Test/CTF repos are penalized; explicit matches are prioritized.
- **Surface Scanning:** Runs `gitleaks` on cloned repos to detect 100+ secret patterns.
- **Deep SAST:** Runs `trufflehog` with `--only-verified` to dig through git history and confirm if discovered secrets
  are still live.
- **SBOM & Dependency Scanning:** Analyzes lock files (`package-lock.json`, `requirements.txt`) and runs `trivy` to find
  vulnerable or outdated packages.
- **IaC Security:** Runs `checkov` and custom parsers to detect misconfigurations in Dockerfiles, Terraform, and
  Kubernetes manifests.

#### 4. Mobile Application Analysis

- **Android (`.apk`):** Uses `apktool` to decode `AndroidManifest.xml`, flagging `allowBackup=true`, `debuggable=true`,
  exported components, custom URL schemes, and cleartext traffic allowances.
- **iOS (`.ipa`):** Unzips the bundle to parse `Info.plist` and entitlements, detecting ATS bypasses
  (`NSAllowsArbitraryLoads`), hardcoded API keys, and universal link configurations.
- **Static Analysis:** Both formats are passed through `mobsfscan` for comprehensive security rule matching.

#### 5. Cloud & HUMINT

- **Cloud Permutation:** Generates smart permutations of the target name to check for exposed or private AWS S3, Azure
  Blob, and GCP Storage buckets.
- **Contact OSINT:** Extracts registrar emails from WHOIS, filters out privacy proxies, and uses DuckDuckGo to pivot
  usernames to public LinkedIn, GitHub, or Twitter profiles.

### 🎯 Advanced Features

- **Finding Deduplication:** Every finding is fingerprinted using SHA256 hashing. Duplicate discoveries are merged, and
  occurrence counts are tracked to eliminate report noise.
- **Confidence Levels:** Findings are classified as `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` based on the source
  and verification status (e.g., TruffleHog verified secrets are `CONFIRMED`).
- **Continuous Monitoring:** The `--diff` flag compares the current run against the last recorded scan timestamp,
  generating a report of *only* new assets, ports, or secrets.
- **Browser Evidence:** Replaces fragile screenshot tools with Playwright to reliably capture visual proof of
  high-severity HTTP findings.

### 🛠 Tooling Inventory

| Category            | Tools Used                                                   | Purpose                                                                              |
|:--------------------|:-------------------------------------------------------------|:-------------------------------------------------------------------------------------|
| **Recon CLI**       | `subfinder`, `httpx`, `naabu`, `nuclei`                      | Passive/active discovery, probing, and templated vulnerability scanning.             |
| **Secret Scanning** | `gitleaks`, `trufflehog`                                     | Surface and deep-history git secret detection.                                       |
| **System Analysis** | `nmap`, `trivy`, `checkov`                                   | OS fingerprinting, SBOM/dependency scanning, and IaC misconfiguration detection.     |
| **Mobile**          | `mobsfscan`, `apktool`                                       | Static analysis and manifest parsing for Android/iOS.                                |
| **Python Core**     | `requests`, `PyGithub`, `dnspython`, `playwright`, `sqlite3` | Orchestration, API interaction, DNS parsing, browser evidence, and persistent state. |

---

### Verify your environment is perfectly configured:

```
python3 main.py vulnbank.org --doctor
```

### Ultimate, maximum-overdrive command

```
python3 main.py vulnbank.org \
  --mode active \
  --github-target Commando-X \
  --git-min-score 60 \
  --apk-url "https://github.com/juice-shop/juice-shop/releases/download/v17.1.1/juice-shop_17.1.1.apk" \
  --ipa-url "https://example.com/target-app-release.ipa" \
  --diff \
  --no-screenshots
```

### The "Fast & Focused" Command

```
python3 main.py vulnbank.org \
  --mode active \
  --skip-git \
  --apk-url "https://example.com/app.apk" \
  --no-screenshots
```

*⚠️ **Disclaimer:** This tool is intended for educational purposes and authorized security testing only. The authors are
not responsible for any misuse or damage caused by this program. Always ensure you have explicit, written permission
before scanning active targets.*
