# ⚙️ Configuration Reference

This document provides a comprehensive reference for all configuration options in MEAT-GRINDER, including environment
variables, CLI arguments, and internal constants.

---

## 📋 Overview

MEAT-GRINDER uses a three-tier configuration system:

1. **Environment Variables** (`.env` file) — API keys, feature flags, and runtime settings
2. **CLI Arguments** — Per-scan options and target-specific configuration
3. **Config.py Constants** — Internal defaults and binary paths

Configuration is loaded in this order (later sources override earlier):

```text
Config.py defaults → .env file → CLI arguments
```

---

## 🔑 Environment Variables

All environment variables are defined in the `.env` file at the project root. Copy `.env.example` to `.env` and
customize:

```bash
cp .env.example .env
nano .env
```

### API Keys & Tokens

| Variable             | Required | Description                                                      | Example                                    |
|----------------------|----------|------------------------------------------------------------------|--------------------------------------------|
| `GITHUB_TOKEN`       | **Yes**  | GitHub Personal Access Token for API access (needs `repo` scope) | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| `SHODAN_API_KEY`     | No       | Shodan API key for passive port scanning and OSINT               | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`         |
| `VIRUSTOTAL_API_KEY` | No       | VirusTotal API key for enhanced subdomain enumeration            | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`         |
| `GEMINI_API_KEY`     | No       | Google Gemini API key for cloud-based AI analysis                | `AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`      |

**How to obtain:**

- **GitHub Token:** https://github.com/settings/tokens (select `repo` scope)
- **Shodan API Key:** https://account.shodan.io/
- **VirusTotal API Key:** https://www.virustotal.com/gui/my-apikey
- **Gemini API Key:** https://aistudio.google.com/api-keys

### Workspace & Paths

| Variable        | Default        | Description                                                    |
|-----------------|----------------|----------------------------------------------------------------|
| `WORKSPACE_DIR` | `./workspaces` | Directory where scan results, databases, and reports are saved |

**Example:**

```env
WORKSPACE_DIR=./workspaces
```

All target-specific data is stored in `workspaces/<target>/`:

```text
workspaces/
└── vulnbank.org/
    ├── recon_data.db          # SQLite database
    ├── REPORT_vulnbank.org.md # Markdown report
    ├── REPORT_vulnbank.org.pdf # PDF report
    ├── screenshots/           # Browser evidence
    └── git_repos/             # Cloned repositories
```

### Performance & Timeouts

| Variable       | Default | Description                                                         |
|----------------|---------|---------------------------------------------------------------------|
| `HTTP_TIMEOUT` | `10`    | Timeout for individual HTTP requests (seconds)                      |
| `SCAN_TIMEOUT` | `300`   | Maximum timeout for long-running scans like Nmap or Trivy (seconds) |
| `MAX_WORKERS`  | `50`    | Maximum number of concurrent workers for threaded operations        |

**Tuning recommendations:**

- **Fast network, low latency:** Increase `MAX_WORKERS` to `100`
- **Slow network, high latency:** Decrease `HTTP_TIMEOUT` to `5`
- **Large targets with many repos:** Increase `SCAN_TIMEOUT` to `600`

### Git Scanning Configuration

| Variable          | Default | Description                                                                      |
|-------------------|---------|----------------------------------------------------------------------------------|
| `GIT_MIN_SCORE`   | `60`    | Minimum relevance score (0-100) for a GitHub repository to be cloned and scanned |
| `GIT_CLONE_DEPTH` | `1`     | Git clone depth (1 = shallow clone, saves bandwidth and disk space)              |

**Relevance scoring algorithm:**

```python
score = 0

# Explicit target match (guarantees inclusion)
if owner == explicit_target:
    score = 100

# Linked from target website
if linked_from_website:
    score += 50

# Repo name contains target base
if target_base in repo_name:
    score += 30

# Penalize noise keywords (ctf, writeup, test, example, demo)
for keyword in NOISE_KEYWORDS:
    if keyword in repo_name:
        score -= 20

# Clamp to 0-100
score = max(0, min(100, score))
```

**Recommendations:**

- **Strict filtering (fewer repos, faster):** `GIT_MIN_SCORE=80`
- **Broad scanning (more repos, slower):** `GIT_MIN_SCORE=40`
- **Default balanced approach:** `GIT_MIN_SCORE=60`

### AI Integration

| Variable                     | Default                  | Description                                                                |
|------------------------------|--------------------------|----------------------------------------------------------------------------|
| `AI_ENABLED`                 | `true`                   | Enable/disable AI-powered analysis features                                |
| `AI_USE_LOCAL_FOR_SECRETS`   | `true`                   | Use local Ollama for sensitive data analysis (secrets never leave machine) |
| `AI_USE_CLOUD_FOR_REASONING` | `true`                   | Use cloud Gemini for heavy reasoning tasks (attack paths, wordlists)       |
| `OLLAMA_URL`                 | `http://localhost:11434` | Ollama API endpoint                                                        |
| `OLLAMA_MODEL`               | `llama3.2`               | Default Ollama model for general analysis                                  |
| `OLLAMA_CODE_MODEL`          | `qwen2.5-coder:7b`       | Ollama model specialized for code analysis                                 |

**AI routing logic:**

```python
if sensitive_data and AI_USE_LOCAL_FOR_SECRETS:
    use_ollama()  # Secrets stay on your machine
elif not sensitive and AI_USE_CLOUD_FOR_REASONING and has_gemini_key:
    use_gemini()  # Better reasoning for complex tasks
else:
    use_ollama()  # Fallback to local
```

**Hardware requirements:**

- **Ollama (local):** 8GB+ RAM recommended, works with integrated graphics
- **Gemini (cloud):** No local hardware requirements, requires API key

### Feature Flags

| Variable                 | Default | Description                                                             |
|--------------------------|---------|-------------------------------------------------------------------------|
| `ENABLE_SCREENSHOTS`     | `true`  | Enable/disable Playwright browser evidence capture                      |
| `ENABLE_MOBILE_SCANNING` | `true`  | Enable/disable mobile application analysis (requires mobsfscan/apktool) |
| `ENABLE_IAC_SCANNING`    | `true`  | Enable/disable Infrastructure as Code scanning (requires checkov/trivy) |

### Reporting & Security

| Variable                | Default | Description                                                                  |
|-------------------------|---------|------------------------------------------------------------------------------|
| `REDACT_SECRETS`        | `true`  | Automatically redact sensitive secrets in the final Markdown report          |
| `SECRET_PREVIEW_LENGTH` | `8`     | Number of characters to show before redacting a secret (e.g., `8f6d****...`) |

**Example redaction:**

```text
# Before redaction:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# After redaction (SECRET_PREVIEW_LENGTH=8):
AWS_ACCESS_KEY_ID=AKIAIOSF***************
```

---

## 🖥️ CLI Arguments

### Basic Usage

```bash
python3 main.py <target> [options]
```

### Required Arguments

| Argument | Description           | Example        |
|----------|-----------------------|----------------|
| `target` | Target domain to scan | `vulnbank.org` |

### Optional Arguments

| Argument           | Default   | Description                                                   |
|--------------------|-----------|---------------------------------------------------------------|
| `--mode`           | `passive` | Port scan mode: `passive` (Shodan) or `active` (Naabu + Nmap) |
| `--skip-git`       | `false`   | Skip Git repository scanning entirely                         |
| `--github-target`  | `None`    | Explicit GitHub username or organization to scan              |
| `--apk-url`        | `None`    | Direct URL to target's Android APK file for mobile analysis   |
| `--ipa-url`        | `None`    | Direct URL to target's iOS IPA file for mobile analysis       |
| `--git-min-score`  | `60`      | Minimum repo relevance score (0-100) for scanning             |
| `--diff`           | `false`   | Show only new findings since the last scan                    |
| `--no-screenshots` | `false`   | Disable browser evidence/screenshot capture                   |
| `--doctor`         | `false`   | Run pre-flight checks and exit                                |

### Usage Examples

#### Basic Passive Scan

```bash
python3 main.py example.com
```

- Uses Shodan for port scanning (zero packets sent)
- Skips active Nmap fingerprinting
- Fastest scan mode

#### Full Active Scan

```bash
python3 main.py example.com --mode active
```

- Uses Naabu for wire-speed SYN scanning
- Runs Nmap for deep OS/service fingerprinting
- Most comprehensive scan

#### Targeted GitHub Scanning

```bash
python3 main.py example.com --github-target Commando-X
```

- Explicitly scans all repos owned by `Commando-X`
- Bypasses fuzzy search and relevance filtering
- Guarantees all target repos are analyzed

#### Mobile Application Analysis

```bash
python3 main.py example.com \
  --apk-url "https://example.com/app.apk" \
  --ipa-url "https://example.com/app.ipa"
```

- Downloads and analyzes both Android and iOS apps
- Runs MobSF static analysis
- Parses manifests and plists for security issues

#### Continuous Monitoring (Diff Mode)

```bash
# First run (baseline)
python3 main.py example.com --mode active

# Subsequent runs (only new findings)
python3 main.py example.com --mode active --diff
```

- Compares current scan to last recorded scan
- Only reports new assets, ports, or secrets
- Perfect for cron jobs and automated monitoring

#### Fast Scan (Skip Heavy Modules)

```bash
python3 main.py example.com \
  --mode passive \
  --skip-git \
  --no-screenshots
```

- Skips Git scanning (saves time and bandwidth)
- Disables screenshot capture (saves disk space)
- Uses passive mode (no active scanning)
- Fastest possible scan

#### Pre-flight Check

```bash
python3 main.py example.com --doctor
```

- Verifies all required tools are installed
- Checks API keys are configured
- Validates workspace is writable
- Exits without scanning

---

## 🐍 Config.py Constants

The `Config` class in `config.py` defines internal defaults and binary paths. These are typically not modified unless
you have custom tool installations.

### Binary Paths

```python
class Config:
    # Go binaries (ProjectDiscovery)
    SUBFINDER_BIN = "subfinder"
    HTTPX_BIN = "pdhttpx"  # Renamed to avoid conflict with Python httpx
    NAABU_BIN = "naabu"
    GITLEAKS_BIN = "gitleaks"
    NUCLEI_BIN = "nuclei"
    TRUFFLEHOG_BIN = "trufflehog"

    # System binaries
    MOBSFSCAN_BIN = "mobsfscan"
    TRIVY_BIN = "trivy"
    CHECKOV_BIN = "checkov"
```

**Why `pdhttpx`?**
The Python `httpx` package shadows ProjectDiscovery's `httpx` binary. To avoid conflicts, we renamed the
ProjectDiscovery binary to `pdhttpx` in `config.py`.

### Default Values

```python
class Config:
    # Workspace
    WORKSPACE_DIR = Path("./workspaces")

    # API Keys (loaded from .env)
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    # Timeouts
    HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))

    # Workers
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "50"))

    # Git
    GIT_MIN_SCORE = int(os.getenv("GIT_MIN_SCORE", "60"))
    GIT_CLONE_DEPTH = int(os.getenv("GIT_CLONE_DEPTH", "1"))

    # AI
    AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
    AI_USE_LOCAL_FOR_SECRETS = os.getenv("AI_USE_LOCAL_FOR_SECRETS", "true").lower() == "true"
    AI_USE_CLOUD_FOR_REASONING = os.getenv("AI_USE_CLOUD_FOR_REASONING", "true").lower() == "true"
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
    OLLAMA_CODE_MODEL = os.getenv("OLLAMA_CODE_MODEL", "qwen2.5-coder:7b")

    # Feature Flags
    ENABLE_SCREENSHOTS = os.getenv("ENABLE_SCREENSHOTS", "true").lower() == "true"
    ENABLE_MOBILE_SCANNING = os.getenv("ENABLE_MOBILE_SCANNING", "true").lower() == "true"
    ENABLE_IAC_SCANNING = os.getenv("ENABLE_IAC_SCANNING", "true").lower() == "true"

    # Reporting
    REDACT_SECRETS = os.getenv("REDACT_SECRETS", "true").lower() == "true"
    SECRET_PREVIEW_LENGTH = int(os.getenv("SECRET_PREVIEW_LENGTH", "8"))
```

---

## 🚩 Feature Flags Explained

### `ENABLE_SCREENSHOTS`

**What it does:** Controls whether Playwright captures screenshots of HIGH/CRITICAL findings.

**When to disable:**

- Running in headless CI/CD environments
- Saving disk space
- Speeding up scans (screenshots add ~2-5 seconds per finding)

**Impact:**

- `true`: Visual evidence embedded in PDF/Markdown reports
- `false`: No screenshots, text-only reports

### `ENABLE_MOBILE_SCANNING`

**What it does:** Controls whether mobile application analysis runs.

**When to disable:**

- No mobile apps to analyze
- `mobsfscan` or `apktool` not installed
- Speeding up scans

**Impact:**

- `true`: Analyzes APK/IPA files if URLs provided
- `false`: Skips mobile analysis entirely

### `ENABLE_IAC_SCANNING`

**What it does:** Controls whether Infrastructure as Code scanning runs.

**When to disable:**

- No IaC files to analyze
- `checkov` or `trivy` not installed
- Speeding up scans

**Impact:**

- `true`: Scans Dockerfiles, Terraform, Kubernetes manifests
- `false`: Skips IaC analysis entirely

---

## 🧠 AI Configuration Deep Dive

### Hybrid AI Architecture

MEAT-GRINDER uses a **hybrid AI approach** to balance privacy and intelligence:

| Task                   | Backend          | Why                                 |
|------------------------|------------------|-------------------------------------|
| Secret analysis        | **Local Ollama** | Secrets never leave your machine    |
| Attack path chaining   | **Cloud Gemini** | Better reasoning for complex tasks  |
| Wordlist generation    | **Cloud Gemini** | Creative, context-aware suggestions |
| Business logic attacks | **Cloud Gemini** | Deep API analysis                   |

### Configuration Scenarios

#### Scenario 1: Maximum Privacy (Air-gapped)

```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=true
AI_USE_CLOUD_FOR_REASONING=false
GEMINI_API_KEY=
```

- All AI tasks run locally on Ollama
- No data leaves your machine
- Slower but 100% private

#### Scenario 2: Maximum Intelligence (Cloud-only)

```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=false
AI_USE_CLOUD_FOR_REASONING=true
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- All AI tasks run on Gemini
- Fastest and smartest
- **WARNING:** Secrets may be sent to Google (redaction recommended)

#### Scenario 3: Balanced (Default)

```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=true
AI_USE_CLOUD_FOR_REASONING=true
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- Sensitive data stays local
- Complex reasoning uses cloud
- Best of both worlds

### Ollama Setup

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start service
sudo systemctl start ollama
sudo systemctl enable ollama

# Pull models
ollama pull llama3.2
ollama pull qwen2.5-coder:7b

# Verify
curl http://localhost:11434/api/tags
```

**Hardware requirements:**

- **Minimum:** 8GB RAM, integrated graphics
- **Recommended:** 16GB RAM, dedicated GPU (6GB+ VRAM)
- **Optimal:** 32GB RAM, NVIDIA GPU with CUDA

---

## 🚀 Performance Tuning

### Speed Up Scans

#### Skip Heavy Modules

```bash
python3 main.py example.com --skip-git --no-screenshots
```

- Skips Git cloning and screenshot capture
- Reduces scan time by 50-70%

#### Use Passive Mode

```bash
python3 main.py example.com --mode passive
```

- No active port scanning
- No Nmap fingerprinting
- Fastest possible scan

#### Reduce Concurrent Workers

```env
# .env
MAX_WORKERS=20
```

- Reduces system load
- Prevents rate limiting
- More stable on slow networks

#### Shallow Git Clones

```env
# .env
GIT_CLONE_DEPTH=1
```

- Only clones latest commit
- Saves bandwidth and disk space
- Faster Git scanning

### Reduce Noise

#### Strict Git Filtering

```bash
python3 main.py example.com --git-min-score 80
```

- Only scans highly relevant repos
- Avoids CTFs, tutorials, and unrelated projects

#### Explicit GitHub Target

```bash
python3 main.py example.com --github-target Commando-X
```

- Scans only repos owned by target
- Eliminates false positives from fuzzy search

### Resource Management

#### Limit Disk Usage

```bash
# Clean up old workspaces
rm -rf workspaces/old-target/

# Keep only recent scans
find workspaces/ -type d -mtime +30 -exec rm -rf {} \;
```

#### Monitor Resource Usage

```bash
# Check disk usage
du -sh workspaces/

# Check database size
ls -lh workspaces/*/recon_data.db

# Monitor running processes
htop
```

---

## 🔒 Security Best Practices

### API Key Protection

**Never commit `.env` to Git:**

```bash
# .gitignore
.env
workspaces/
*.db
```

**Use minimal permissions:**

- GitHub token: Only `repo` scope (not `admin:org`)
- Shodan key: Read-only access
- Gemini key: No special permissions needed

**Rotate tokens regularly:**

```bash
# Generate new GitHub token
# Update .env
GITHUB_TOKEN=ghp_new_token_here

# Restart scan
python3 main.py example.com
```

### Scan Authorization

**ALWAYS get written permission before scanning:**

- Bug bounty programs: Check scope and rules
- Pentest engagements: Signed statement of work
- Own infrastructure: Documented authorization

**Respect rate limits:**

- GitHub API: 5,000 requests/hour (authenticated)
- Shodan API: 100 requests/day (free tier)
- VirusTotal API: 4 requests/minute (free tier)

### Data Handling

**Redact secrets in shared reports:**

```env
# .env
REDACT_SECRETS=true
SECRET_PREVIEW_LENGTH=8
```

**Store reports securely:**

```bash
# Encrypt sensitive reports
gpg -c REPORT_vulnbank.org.pdf

# Delete workspaces after analysis
rm -rf workspaces/vulnbank.org/
```

**Network impact:**

- Use `--mode passive` for minimal impact
- Monitor for rate limiting or blocking
- Respect `SCAN_TIMEOUT` settings

---

## 📝 Complete `.env` Example

```env
# ==========================================
# API KEYS & TOKENS
# ==========================================

# GitHub Personal Access Token (Required for GitScanner)
# Generate at: https://github.com/settings/tokens (needs 'repo' scope)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Shodan API Key (Optional, but recommended for passive port scanning)
# Generate at: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key_here

# VirusTotal API Key (Optional, enhances subdomain enumeration)
# Generate at: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Google Gemini API Key (Optional, for cloud-based AI analysis)
# Generate at: https://aistudio.google.com/apikey
GEMINI_API_KEY=your_gemini_api_key_here

# ==========================================
# WORKSPACE & PATHS
# ==========================================

# Directory where scan results, databases, and reports are saved
WORKSPACE_DIR=./workspaces

# ==========================================
# PERFORMANCE & TIMEOUTS
# ==========================================

# Timeout for individual HTTP requests (in seconds)
HTTP_TIMEOUT=10

# Maximum timeout for long-running scans like Nmap or Trivy (in seconds)
SCAN_TIMEOUT=300

# Maximum number of concurrent workers for threaded operations (e.g., file scanning)
MAX_WORKERS=50

# ==========================================
# GIT SCANNING CONFIGURATION
# ==========================================

# Minimum relevance score (0-100) for a GitHub repository to be cloned and scanned
# Higher values reduce noise from unrelated repos (e.g., CTFs, tutorials)
GIT_MIN_SCORE=60

# Git clone depth (1 = shallow clone, saves bandwidth and disk space)
GIT_CLONE_DEPTH=1

# ==========================================
# AI INTEGRATION
# ==========================================

# Enable/disable AI-powered analysis features
AI_ENABLED=true

# Use local Ollama for sensitive data analysis (secrets never leave machine)
AI_USE_LOCAL_FOR_SECRETS=true

# Use cloud Gemini for heavy reasoning tasks (attack paths, wordlists)
AI_USE_CLOUD_FOR_REASONING=true

# Ollama API endpoint
OLLAMA_URL=http://localhost:11434

# Default Ollama model for general analysis
OLLAMA_MODEL=llama3.2

# Ollama model specialized for code analysis
OLLAMA_CODE_MODEL=qwen2.5-coder:7b

# ==========================================
# FEATURE FLAGS
# ==========================================

# Enable/disable Playwright browser evidence capture (screenshots)
ENABLE_SCREENSHOTS=true

# Enable/disable mobile application analysis (requires mobsfscan/apktool)
ENABLE_MOBILE_SCANNING=true

# Enable/disable Infrastructure as Code scanning (requires checkov/trivy)
ENABLE_IAC_SCANNING=true

# ==========================================
# REPORTING & SECURITY
# ==========================================

# Automatically redact sensitive secrets in the final Markdown report
REDACT_SECRETS=true

# Number of characters to show before redacting a secret (e.g., 8)
SECRET_PREVIEW_LENGTH=8
```

---

## 🔍 Troubleshooting Configuration Issues

### "GITHUB_TOKEN not set"

**Problem:** Git scanning fails without authentication.
**Solution:** Add `GITHUB_TOKEN` to `.env` file.

### "Ollama connection refused"

**Problem:** AI features can't connect to local model.
**Solution:**

```bash
sudo systemctl start ollama
curl http://localhost:11434/api/tags
```

### "Gemini API key invalid"

**Problem:** Cloud AI features fail.
**Solution:** Verify API key at https://aistudio.google.com/apikey

### "MAX_WORKERS too high"

**Problem:** System runs out of memory or hits rate limits.
**Solution:** Reduce `MAX_WORKERS` to `20` in `.env`

### "SCAN_TIMEOUT too low"

**Problem:** Large repos or slow networks cause timeouts.
**Solution:** Increase `SCAN_TIMEOUT` to `600` in `.env`

---

## 📌 Quick Reference

### Common Configurations

| Use Case              | Command                                                   |
|-----------------------|-----------------------------------------------------------|
| Fast passive scan     | `python3 main.py example.com --mode passive --skip-git`   |
| Full active scan      | `python3 main.py example.com --mode active`               |
| Targeted GitHub scan  | `python3 main.py example.com --github-target org-name`    |
| Mobile app analysis   | `python3 main.py example.com --apk-url url --ipa-url url` |
| Continuous monitoring | `python3 main.py example.com --diff`                      |
| Pre-flight check      | `python3 main.py example.com --doctor`                    |

### Environment Variable Checklist

- [ ] `GITHUB_TOKEN` set (required for Git scanning)
- [ ] `SHODAN_API_KEY` set (optional, enhances passive scanning)
- [ ] `GEMINI_API_KEY` set (optional, enables cloud AI)
- [ ] `WORKSPACE_DIR` exists and is writable
- [ ] `AI_ENABLED` matches your privacy requirements
- [ ] `REDACT_SECRETS=true` for shared reports

---

*Last Updated: 2026-11-22*
*Configuration Version: 1.0*
