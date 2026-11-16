# 🥩 MEAT-GRINDER 
### Modular Engine for Asset Tracking & Reconnaissance

MEAT-GRINDER is a production-grade, modular OSINT and reconnaissance engine built in Python. It orchestrates industry-standard CLI tools to map an organization's external attack surface, filtering out the "noise" (CDNs, default pages) to extract the "meat" (exposed panels, misconfigurations, guarded endpoints, and cloud leaks).

## 🏗 Architecture

Instead of writing slow network scanners from scratch, MEAT-GRINDER uses Python as the **Orchestrator** and delegates heavy lifting to specialized Go-based CLI tools. 

1. **Subfinder** (Passive Subdomain Enum)
2. **Naabu / Shodan** (Active/Passive Port Scanning)
3. **HTTPX** (HTTP Probing & Tech Detection)
4. **SQLite** (Persistent State & Data Relational Mapping)
5. **Python Heuristics** (Noise Filtering & Insight Extraction)

## 🚀 Features

- **Clean OOP Design:** Modular architecture. Adding a new recon phase is as simple as creating a new class that inherits from `BaseReconModule`.
- **Dual Port Scanning:** 
  - `passive`: Queries Shodan InternetDB (Zero packets sent to target, no API key required).
  - `active`: Uses Naabu for blazing-fast SYN scanning.
- **Deep Endpoint Triage:** Automatically categorizes endpoints into:
  - 🛡️ **Guarded:** 401, 403, 407 (Authentication required).
  - 💥 **Errors:** 500, 502, 503 (Server misconfigurations).
  - 📂 **Directory Listings:** Exposed file indexes.
  - ☁️ **Cloud Storage:** Exposed S3, Azure Blobs, GCP buckets.
  - 🎣 **Takeover Candidates:** Dead CNAMEs pointing to unclaimed cloud resources.
- **Persistent State:** All data is stored in SQLite. If the engine crashes, you don't lose your data.
- **Actionable Reporting:** Generates a clean, severity-grouped Markdown report.

## 🛠 Installation (Kali Linux)

### 1. Prerequisites
Ensure you have Python 3, `pip`, and `golang` installed.
```bash
sudo apt update
sudo apt install python3-pip python3-venv golang-go -y
```

## 🔐 Git Repository Scanning

MEAT-GRINDER includes comprehensive Git repository scanning to find leaked secrets, API keys, and credentials.

### What Gets Scanned

1. **GitHub Repositories**: Automatically discovers and scans all repositories belonging to the target GitHub organization or user.
2. **Exposed `.git` Directories**: Scans any `.git` directories discovered on the target's web servers during HTTP probing.

### How It Works

- Uses the GitHub API to enumerate repositories (requires `GITHUB_TOKEN` in `.env`)
- Clones each repository with `--depth 1` to save bandwidth
- Runs **Gitleaks** against each repository to detect:
  - AWS Access Keys
  - GitHub Tokens
  - Database Credentials
  - API Keys (Stripe, Slack, etc.)
  - Private Keys
  - And 100+ other secret patterns
- Parses findings and inserts them into the database as `CRITICAL` severity
- Cleans up cloned repositories after scanning to save disk space

### Configuration

Add your GitHub Personal Access Token to `.env`:

```env
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## 🔍 Infrastructure Intelligence

MEAT-GRINDER now extracts deep infrastructure details beyond just URLs:

### Operating System Detection
- **Passive Mode:** Extracts OS from Shodan InternetDB (e.g., "Ubuntu", "Windows Server 2019")
- **Active Mode:** OS detection requires Nmap integration (future enhancement)

### Web Server Version Detection
- Captures the `Server` HTTP header via HTTPX (e.g., `Apache/2.4.41`, `nginx/1.18.0`, `cloudflare`)
- Automatically flags **outdated** web servers as findings:
  - Apache 2.0-2.3
  - Nginx 1.0-1.9
  - IIS 5-7
  - PHP 5.x
  - OpenSSL 1.0.x

### Application & Service Detection
- **Port-to-Service Mapping:** Automatically identifies 30+ common services (SSH, RDP, MySQL, Redis, Elasticsearch, MongoDB, etc.)
- **CPE Fingerprinting:** Uses Shodan's Common Platform Enumeration data to identify specific applications (Jenkins, Tomcat, JBoss, WebLogic, SharePoint)
- **Risky Service Flagging:** Automatically flags exposed database ports, remote access services, and in-memory stores as HIGH/MEDIUM findings

### Example Report Output

```markdown
## Infrastructure Inventory

### Hosts, OS & Services

| Host | IP | OS | Open Ports | Running Services |
|---|---|---|---|---|
| `api.example.com` | 1.2.3.4 | Ubuntu | [22, 80, 443] | 22(SSH), 80(HTTP), 443(HTTPS) |
| `db.example.com` | 1.2.3.5 | Windows | [3306, 3389] | 3306(MySQL), 3389(RDP) |

### Web Servers Detected

| Web Server | Count |
|---|---|
| `Apache/2.4.41` | 12 |
| `nginx/1.18.0` | 8 |
| `cloudflare` | 45 |
```

### Usage

Run the engine against a target domain.

```bash
# Default: Passive Port Scanning + Fuzzy GitHub Search
python3 main.py example.com

# Explicitly target a specific GitHub organization or user (Bypasses fuzzy search)
python3 main.py vulnbank.org --github-target Commando-X

# Active Port Scanning (Naabu) + Skip Git scanning for speed
python3 main.py example.com --mode active --skip-git
```

## 🕵️ Sensitive File & Secret Detection

MEAT-GRINDER actively hunts for exposed configuration files (`.env`, `.env.bak`, `config.php`, `.git/config`, `database.yml`, etc.) on all discovered web endpoints.

### Zero False Positives
Many servers return a generic `200 OK` custom "404 Page" for any requested URL. To prevent noise, the `SensitiveFileScanner` reads the first 2KB of any `200 OK` response and applies strict Regex validation. It will **only** flag the file as `CRITICAL` if it detects actual secret patterns, such as:
- `DB_PASSWORD`, `DATABASE_URL`, `SECRET_KEY`, `JWT_SECRET`
- `-----BEGIN RSA PRIVATE KEY-----`
- `aws_access_key_id`, `STRIPE_SECRET_KEY`

Files that return `200 OK` but contain no recognizable secret patterns are downgraded to `MEDIUM` for manual review, ensuring you never waste time on fake positives.

## 🕸️ Web Content & Frontend Secret Scanning

Developers frequently hardcode secrets directly into frontend JavaScript files, assuming minification or obscurity provides security. MEAT-GRINDER actively hunts for these leaks.

### How It Works
1. **Extraction:** Fetches the HTML of all live endpoints and extracts all linked `.js` files (`<script src="...">`) and inline `<script>` blocks.
2. **Targeted Download:** Downloads these files (capped at 100KB to avoid massive, slow bundle downloads).
3. **High-Precision Regex:** Scans the content for specific, high-value patterns, including:
   - AWS Access/Secret Keys (`AKIA...`)
   - Stripe Live/Test Keys (`sk_live_...`)
   - GitHub Personal Access Tokens (`ghp_...`)
   - Google API Keys (`AIza...`)
   - Slack Tokens (`xoxb-...`)
   - JSON Web Tokens (JWTs)
   - Generic high-entropy `api_key`, `secret`, or `password` assignments.
   - Internal/Staging domain leaks (e.g., `api-dev.vulnbank.org`).

### Zero Noise Guarantee
The regex patterns are designed to match *specific formats* and *high-entropy strings*. It will not flag a variable named `let password = "";`. It only flags when an actual, lengthy secret value is assigned, ensuring every finding is actionable.

## 🚀 Installation & Setup

Follow these steps to clone, configure, and start the engine on a fresh Kali Linux environment.

### 1. Clone the Repository
```bash
git clone <your-repository-url> meat_grinder
cd meat_grinder
```
# Install System Dependencies & Go Tools
Ensure Python 3, pip, and golang are installed, then compile the required reconnaissance binaries.

# Install OS-level dependencies

```
sudo apt update
sudo apt install python3-pip python3-venv golang-go curl wget -y
```

# Install Go-based reconnaissance tools
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/zricethezav/gitleaks/v8@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

# Move binaries to global PATH and set execute permissions
```
sudo cp $(go env GOPATH)/bin/{subfinder,httpx,naabu,gitleaks,nuclei} /usr/local/bin/
sudo chmod +x /usr/local/bin/{subfinder,httpx,naabu,gitleaks,nuclei}
```

# Initialize Nuclei templates (Critical: bypasses GitHub API rate limits)
```
rm -rf ~/.local/nuclei-templates
wget -qO /tmp/nuclei-templates.tar.gz https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip
unzip -q /tmp/nuclei-templates.tar.gz -d /tmp/ 2>/dev/null || tar -xzf /tmp/nuclei-templates.tar.gz -C /tmp/
mkdir -p ~/.local/nuclei-templates
mv /tmp/nuclei-templates*/* ~/.local/nuclei-templates/ 2>/dev/null
```

# Create and activate virtual environment
```
python3 -m venv venv
source venv/bin/activate
```

# Install Python dependencies
```
pip install -r requirements.txt
cp .env.example .env
```

# Inside .env, add your GitHub Personal Access Token:
```
GITHUB_TOKEN=ghp_your_actual_github_token_here
```

# Run the engine against a target domain. 
The engine will automatically create a workspaces/<target>/ directory containing the SQLite database and the final Markdown report.
```
# 1. Standard Run (Passive port scanning + Fuzzy GitHub search)
python3 main.py example.com

# 2. Explicit GitHub Target (Highly recommended if you know the org/user)
python3 main.py vulnbank.org --github-target Commando-X

# 3. Aggressive Run (Active port scanning via Naabu)
python3 main.py example.com --mode active

# 4. Fast Run (Skip Git repository scanning for speed)
python3 main.py example.com --skip-git
```

# Viewing Results
Once the run completes, view the actionable insights in the generated report:

```
cat workspaces/<target>/REPORT_<target>.md
```