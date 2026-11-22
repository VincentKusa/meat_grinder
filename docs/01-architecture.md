# 🏗️ Architecture Deep Dive

This document provides a comprehensive overview of MEAT-GRINDER's architecture, including execution flow, data
pipelines, module design patterns, and system integration points.

---

## 📋 Overview

MEAT-GRINDER is a **modular, multi-vector OSINT and reconnaissance engine** designed to:

1. **Discover** attack surfaces across web, mobile, cloud, and code repositories
2. **Analyze** findings using both deterministic tools and AI-powered reasoning
3. **Report** actionable intelligence in stakeholder-ready formats (Markdown, PDF)

### Core Design Principles

| Principle               | Description                                                                                       |
|-------------------------|---------------------------------------------------------------------------------------------------|
| **Modularity**          | Each reconnaissance capability is an independent module inheriting from `BaseReconModule`         |
| **Persistence**         | All data is stored in SQLite, enabling crash recovery and continuous monitoring (`--diff`)        |
| **Hybrid Intelligence** | Combines fast, deterministic CLI tools with AI-powered contextual analysis                        |
| **Privacy-First**       | Sensitive data (secrets) processed locally via Ollama; only non-sensitive reasoning uses cloud AI |
| **Crash Resilience**    | Each module runs independently; a failure in one doesn't halt the entire pipeline                 |

---

## 🔄 Execution Pipeline

MEAT-GRINDER executes reconnaissance in **7 sequential phases**, each building on data collected by previous phases.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    MEAT-GRINDER EXECUTION FLOW                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: Discovery                                                     │
│  ├─ SubdomainEnumerator (subfinder)                                     │
│  ├─ WhoisContactOSINT (python-whois + DuckDuckGo)                       │
│  ├─ DNSScanner (dnspython)                                              │
│  └─ WaybackScanner (Archive.org CDX API)                                │
│                                                                         │
│  Phase 2: Infrastructure                                                │
│  ├─ PortScanner (naabu/shodan)                                          │
│  ├─ OSRecon (nmap) [active mode only]                                   │
│  └─ ASNMapper (ipinfo.io API)                                           │
│                                                                         │
│  Phase 3: Web Surface                                                   │
│  ├─ HTTPProber (httpx)                                                  │
│  ├─ HeaderAnalyzer (requests)                                           │
│  ├─ TLSScanner (ssl socket)                                             │
│  ├─ SensitiveFileScanner (requests + regex)                             │
│  ├─ WebContentScanner (requests + regex)                                │
│  ├─ JSRecursiveScanner (Depth 2 JS crawling)                            │
│  ├─ HTMLMetadataExtractor (BeautifulSoup)                               │
│  ├─ APIScanner (requests + regex)                                       │
│  ├─ SourceMapScanner (requests + JSON)                                  │
│  └─ AdminDiscovery (requests)                                           │
│                                                                         │
│  Phase 4: Vulnerability                                                 │
│  ├─ NucleiScanner (nuclei)                                              │
│  └─ CloudScanner (requests + permutations)                              │
│                                                                         │
│  Phase 5: Mobile [optional]                                             │
│  └─ MobileScanner (mobsfscan + apktool + plistlib)                      │
│                                                                         │
│  Phase 6: Code Intelligence                                             │
│  ├─ GitScanner (PyGithub + gitleaks)                                    │
│  ├─ SASTScanner (trufflehog)                                            │
│  ├─ SBOMScanner (trivy)                                                 │
│  ├─ IaCScanner (checkov + custom parsers)                               │
│  ├─ PasteMonitor (PyGithub + requests)                                  │
│  └─ EmailOSINT (requests)                                               │
│                                                                         │
│  Phase 7: Analysis & Reporting                                          │
│  ├─ TakeoverVerifier (requests)                                         │
│  ├─ InsightFilter (deduplication + scoring)                             │
│  ├─ AIAnalyzer (Ollama/Gemini)                                          │
│  ├─ AIReconHunter (Ollama/Gemini)                                       │
│  ├─ BrowserEvidence (playwright)                                        │
│  ├─ MarkdownReporter                                                    │
│  └─ PDFReporter (weasyprint + matplotlib)                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase Dependencies

| Phase                       | Depends On               | Produces                                    |
|-----------------------------|--------------------------|---------------------------------------------|
| **1. Discovery**            | Nothing (entry point)    | Subdomains, DNS records, WHOIS data         |
| **2. Infrastructure**       | Phase 1 (subdomains)     | Open ports, OS fingerprints, ASN data       |
| **3. Web Surface**          | Phase 1 + 2 (endpoints)  | HTTP metadata, secrets, API endpoints       |
| **4. Vulnerability**        | Phase 3 (live endpoints) | Nuclei findings, cloud buckets              |
| **5. Mobile**               | CLI args (APK/IPA URLs)  | Mobile app findings                         |
| **6. Code Intelligence**    | Phase 1 (target domain)  | Git secrets, dependencies, IaC issues       |
| **7. Analysis & Reporting** | All previous phases      | Deduplicated findings, AI insights, reports |

---

## 📊 Data Flow Architecture

Data flows through MEAT-GRINDER in a **linear pipeline** with persistent storage at each stage.

```text
┌──────────────┐
│  CLI Tools   │─────► JSON/NDJSON Output
│  (subfinder, │
│   naabu,     │
│   httpx,     │
│   nuclei,    │
│   gitleaks,  │
│   trufflehog)│
└──────────────┘
        │
        ▼
┌──────────────┐
│   Parsers    │─────► Structured Data
│  (Python     │      (dicts, lists)
│   modules)   │
└──────────────┘
        │
        ▼
┌──────────────┐
│  SQLite DB   │─────► Persistent State
│  (recon_     │      (findings, endpoints,
│   data.db)   │       ports, subdomains)
└──────────────┘
        │
        ▼
┌──────────────┐
│  AI Engine   │─────► Enhanced Context
│  (Ollama +   │      (business impact,
│   Gemini)    │       remediation, attack paths)
└──────────────┘
        │
        ▼
┌──────────────┐
│  Reporters   │─────► Markdown/PDF Output
│  (Markdown,  │      (REPORT_<target>.md,
│   PDF)       │       REPORT_<target>.pdf)
└──────────────┘
```

### Data Persistence Strategy

All intermediate data is stored in SQLite tables:

| Table         | Written By                      | Read By                              |
|---------------|---------------------------------|--------------------------------------|
| `subdomains`  | SubdomainEnumerator, TLSScanner | HTTPProber, PortScanner              |
| `endpoints`   | HTTPProber, HeaderAnalyzer      | All web scanners, reporters          |
| `ports`       | PortScanner                     | OSRecon, ASNMapper                   |
| `findings`    | All modules                     | InsightFilter, AIAnalyzer, reporters |
| `os_recon`    | OSRecon                         | Reporters                            |
| `dns_records` | DNSScanner                      | TakeoverVerifier                     |
| `tls_info`    | TLSScanner                      | Reporters                            |
| `scan_runs`   | main.py                         | MarkdownReporter (diff mode)         |

---

## 🧩 Module Architecture

### BaseReconModule Pattern

All reconnaissance modules inherit from `BaseReconModule`, which provides:

```python
class BaseReconModule:
    def __init__(self, target: str, db: DatabaseManager, workspace: Path):
        self.target = target  # Target domain (e.g., "vulnbank.org")
        self.db = db  # Database connection manager
        self.workspace = workspace  # Target-specific workspace directory

    def execute(self):
        """Main execution method - must be implemented by subclasses."""
        raise NotImplementedError
```

### Module Lifecycle

```text
┌─────────────────────────────────────────────────────────┐
│  1. Initialization (main.py)                            │
│     MyScanner(target, db, workspace)                    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  2. Execution (execute method)                          │
│     ├─ Gather input data (from DB or external APIs)     │
│     ├─ Process data (scanning, parsing, analysis)       │
│     ├─ Insert findings (self.db.insert_finding)         │
│     └─ Print progress/status                            │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  3. Cleanup (automatic)                                 │
│     ├─ Close file handles                               │
│     ├─ Remove temporary files                           │
│     └─ Return control to main.py                        │
└─────────────────────────────────────────────────────────┘
```

### Example Module Implementation

```python
"""Example module demonstrating the BaseReconModule pattern."""

import requests
import urllib3
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ExampleScanner(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        # Module-specific initialization

    def execute(self):
        print("[*] Running example scanner...")

        # 1. Gather input data
        endpoints = self.db.get_all_endpoints()

        # 2. Process data
        findings_count = 0
        for ep in endpoints:
            if self._check_endpoint(ep["url"]):
                findings_count += 1

        # 3. Report results
        print(f"[+] Example scanner complete. Found {findings_count} insights.")

    def _check_endpoint(self, url: str) -> bool:
        """Internal helper method."""
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if "sensitive_data" in resp.text:
                # Insert finding into database
                self.db.insert_finding(
                    f_type="EXAMPLE_FINDING",
                    url=url,
                    details="Found sensitive data pattern",
                    severity="HIGH",
                    source_module="example_scanner"
                )
                return True
        except Exception as e:
            print(f"[!] Error checking {url}: {e}")

        return False
```

---

## 🗄️ Database Architecture

### SQLite Schema Overview

MEAT-GRINDER uses a **single SQLite database per target** stored at `workspaces/<target>/recon_data.db`.

```text
┌─────────────────────────────────────────────────────────────┐
│                    recon_data.db                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  subdomains  │  │  endpoints   │  │    ports     │      │
│  │              │  │              │  │              │      │
│  │  domain      │  │  url         │  │  host        │      │
│  │  source      │  │  status_code │  │  ip          │      │
│  └──────────────┘  │  title       │  │  ports (JSON)│      │
│                    │  tech_stack  │  │  os          │      │
│                    └──────────────┘  │  services    │      │
│                           │          └──────────────┘      │
│                           │                 │              │
│                           ▼                 ▼              │
│                    ┌──────────────────────────────┐        │
│                    │         findings             │        │
│                    │                              │        │
│                    │  finding_type                │        │
│                    │  url                         │        │
│                    │  details                     │        │
│                    │  severity                    │        │
│                    │  confidence                  │        │
│                    │  fingerprint (UNIQUE)        │        │
│                    │  first_seen                  │        │
│                    │  last_seen                   │        │
│                    │  occurrences                 │        │
│                    │  source_module               │        │
│                    └──────────────────────────────┘        │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   os_recon   │  │ dns_records  │  │   tls_info   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                             │
│  ┌──────────────┐                                           │
│  │  scan_runs   │  (tracks --diff history)                  │
│  └──────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Deduplication Mechanism

The `findings` table uses a **SHA256 fingerprint** to prevent duplicate entries:

```python
def generate_fingerprint(finding_type, url, details, file_path, rule_id):
    components = [
        finding_type,
        url.lower().strip(),
        rule_id or "",
        file_path or "",
        details[:100]  # First 100 chars for uniqueness
    ]
    fingerprint_str = "|".join(components)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
```

**Behavior:**

- If fingerprint exists → Increment `occurrences`, update `last_seen`
- If fingerprint is new → Insert new row with `occurrences=1`

### Schema Migration

The `database.py` module automatically migrates older databases on startup:

```python
def _migrate(self):
    with self._get_conn() as conn:
        # Check if column exists
        cols = [row[1] for row in conn.execute("PRAGMA table_info(endpoints)").fetchall()]

        # Add missing columns
        if "title" not in cols:
            conn.execute("ALTER TABLE endpoints ADD COLUMN title TEXT")
        if "waf_detected" not in cols:
            conn.execute("ALTER TABLE endpoints ADD COLUMN waf_detected TEXT")
```

---

## 🧠 AI Integration Architecture

MEAT-GRINDER uses a **hybrid AI approach** to balance privacy and intelligence.

```text
┌─────────────────────────────────────────────────────────────────┐
│                    AI ENGINE (ai_engine.py)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Routing Logic                                           │  │
│  │  ─────────────────                                       │  │
│  │  if sensitive_data and AI_USE_LOCAL_FOR_SECRETS:         │  │
│  │      → Use Ollama (local, private)                       │  │
│  │  elif not sensitive and AI_USE_CLOUD_FOR_REASONING:      │  │
│  │      → Use Gemini (cloud, smart)                         │  │
│  │  else:                                                   │  │
│  │      → Fallback to Ollama                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────┐         ┌─────────────────────┐       │
│  │   LOCAL OLLAMA      │         │   CLOUD GEMINI      │       │
│  │                     │         │                     │       │
│  │  • Secrets analysis │         │  • Attack paths     │       │
│  │  • Business impact  │         │  • Wordlist gen     │       │
│  │  • Remediation      │         │  • Logic attacks    │       │
│  │                     │         │                     │       │
│  │  ✅ 100% private    │         │  ✅ Better reasoning│       │
│  │  ✅ No data leaves  │         │  ✅ Faster          │       │
│  │  ⚠️  Slower         │         │  ⚠️  API costs      │       │
│  └─────────────────────┘         └─────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### AI Module Integration

| Module            | AI Backend   | Purpose                                                |
|-------------------|--------------|--------------------------------------------------------|
| **AIAnalyzer**    | Local Ollama | Adds business impact + remediation to findings         |
| **AIReconHunter** | Cloud Gemini | Generates wordlists, suggests attacks, chains findings |

### Data Flow Through AI

```text
┌──────────────┐
│   Findings   │─────► AIAnalyzer (Local Ollama)
│   (HIGH/     │       ├─ Redact secrets
│    CRITICAL) │       ├─ Analyze context
│              │       └─ Append business impact
└──────────────┘
        │
        ▼
┌──────────────┐
│   Context    │─────► AIReconHunter (Cloud Gemini)
│   (endpoints,│       ├─ Generate smart wordlist
│    findings, │       ├─ Suggest logic attacks
│    tech      │       └─ Chain attack paths
│    stack)    │
└──────────────┘
        │
        ▼
┌──────────────┐
│   Enhanced   │─────► Reporters
│   Findings   │       ├─ Markdown report
│              │       └─ PDF report
└──────────────┘
```

---

## 📄 Reporting Architecture

MEAT-GRINDER generates two report formats: **Markdown** (for technical teams) and **PDF** (for stakeholders).

### Markdown Reporter

```text
┌─────────────────────────────────────────────────────────┐
│  MarkdownReporter                                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Input:                                                 │
│  ├─ findings (from DB)                                  │
│  ├─ ports (from DB)                                     │
│  ├─ endpoints (from DB)                                 │
│  └─ screenshots (from workspace/screenshots/)           │
│                                                         │
│  Processing:                                            │
│  ├─ Group findings by severity                          │
│  ├─ Format tables (infrastructure, WAF detection)       │
│  ├─ Embed screenshots (relative paths)                  │
│  └─ Apply diff mode (if --diff flag)                    │
│                                                         │
│  Output:                                                │
│  └─ workspaces/<target>/REPORT_<target>.md              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### PDF Reporter

```text
┌─────────────────────────────────────────────────────────┐
│  PDFReporter                                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Input:                                                 │
│  ├─ findings (from DB)                                  │
│  ├─ ports, endpoints, subdomains (from DB)              │
│  └─ HTML template (reporting/templates/report.html)     │
│                                                         │
│  Processing:                                            │
│  ├─ Calculate risk score (0-100)                        │
│  ├─ Generate charts (matplotlib → base64 PNG)           │
│  │   ├─ Severity distribution bar chart                 │
│  │   └─ Top finding types horizontal bar chart          │
│  ├─ Render HTML template (string.Template)              │
│  └─ Convert HTML → PDF (weasyprint)                     │
│                                                         │
│  Output:                                                │
│  └─ workspaces/<target>/REPORT_<target>.pdf             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Report Structure

Both reports follow this structure:

1. **Executive Summary** — Risk score, key metrics
2. **Visual Analytics** — Charts (PDF only)
3. **Infrastructure Overview** — Hosts, ports, web servers
4. **AI-Identified Attack Paths** — Chained attack narratives
5. **Detailed Findings** — Grouped by severity (CRITICAL → INFO)
6. **Visual Evidence** — Screenshots (if enabled)

---

## ⚙️ Configuration Flow

Configuration cascades through three layers:

```text
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Config.py Defaults                            │
│  ─────────────────────────────                          │
│  • Hardcoded defaults (timeouts, paths, binary names)   │
│  • Loaded at import time                                │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2: .env File                                     │
│  ─────────────────────                                  │
│  • API keys, feature flags, performance tuning          │
│  • Loaded via python-dotenv                             │
│  • Overrides Config.py defaults                         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3: CLI Arguments                                 │
│  ──────────────────────                                 │
│  • Per-scan options (--mode, --skip-git, --diff)        │
│  • Parsed via argparse                                  │
│  • Overrides .env settings                              │
└─────────────────────────────────────────────────────────┘
```

### Configuration Priority

```python
# Example: HTTP_TIMEOUT resolution
timeout = int(os.getenv("HTTP_TIMEOUT", "10"))  # .env or default
```

**Priority order:** CLI args > .env > Config.py defaults

---

## 🔒 Security Architecture

### Secret Handling

MEAT-GRINDER implements multiple layers of secret protection:

```text
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Detection                                     │
│  ──────────────────                                     │
│  • Regex patterns for AWS, Stripe, GitHub, JWT, etc.    │
│  • High-entropy string detection                        │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2: Verification                                  │
│  ────────────────────                                   │
│  • TruffleHog --only-verified (tests secrets live)      │
│  • Eliminates 99% of false positives                    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Redaction                                     │
│  ──────────────────                                     │
│  • AIAnalyzer redacts before sending to cloud AI        │
│  • Reports show only first 8 chars (configurable)       │
│  • Example: AKIAIOSF***************                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Local Processing                              │
│  ────────────────────────                               │
│  • Sensitive findings analyzed by local Ollama          │
│  • Secrets never leave the machine                      │
└─────────────────────────────────────────────────────────┘
```

### API Key Protection

- **Never committed to Git** (`.gitignore` excludes `.env`)
- **Minimal permissions** (GitHub token needs only `repo` scope)
- **Rotated regularly** (recommended every 90 days)

---

## 🚀 Performance Architecture

### Concurrency Model

MEAT-GRINDER uses **ThreadPoolExecutor** for I/O-bound tasks:

```python
# Example: Concurrent HTTP requests
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(self._check_url, url): url for url in urls}
    for future in as_completed(futures):
        result = future.result()
```

### Bottleneck Mitigation

| Bottleneck             | Solution                                     |
|------------------------|----------------------------------------------|
| **Slow HTTP requests** | `timeout=10` prevents hanging                |
| **Large JS files**     | Cap at 50KB (`resp.text[:50000]`)            |
| **Many subdomains**    | Limit to top 100 for expensive operations    |
| **Git cloning**        | Shallow clones (`--depth 1`)                 |
| **Database writes**    | `INSERT OR IGNORE` prevents duplicate errors |

---

## 📦 External Tool Integration

MEAT-GRINDER orchestrates multiple external tools:

```text
┌─────────────────────────────────────────────────────────┐
│  External Tools                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Discovery:                                             │
│  ├─ subfinder (subdomain enumeration)                   │
│  └─ python-whois (registrar info)                       │
│                                                         │
│  Network:                                               │
│  ├─ naabu (active port scanning)                        │
│  ├─ nmap (OS/service fingerprinting)                    │
│  └─ dnspython (DNS queries)                             │
│                                                         │
│  Web:                                                   │
│  ├─ pdhttpx (HTTP probing)                              │
│  ├─ nuclei (vulnerability scanning)                     │
│  └─ playwright (browser screenshots)                    │
│                                                         │
│  Code:                                                  │
│  ├─ gitleaks (Git secret scanning)                      │
│  ├─ trufflehog (verified secret detection)              │
│  ├─ trivy (dependency vulnerabilities)                  │
│  └─ checkov (IaC misconfigurations)                     │
│                                                         │
│  Mobile:                                                │
│  ├─ mobsfscan (static analysis)                         │
│  └─ apktool (Android manifest parsing)                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Tool Output Parsing

All external tools output **JSON or NDJSON**, which is parsed by Python modules:

```python
# Example: Parsing subfinder NDJSON output
for line in result.stdout.splitlines():
    data = json.loads(line)
    db.insert_subdomain(data["host"], data["source"])
```

---

## 🎯 Key Design Decisions

### Why SQLite?

- **Zero configuration** — No database server required
- **Portable** — Single file per target, easy to backup/move
- **Fast** — Optimized for read-heavy workloads
- **Crash-safe** — Atomic transactions prevent corruption

### Why Modular Architecture?

- **Extensibility** — Add new scanners without modifying core
- **Testability** — Each module can be tested in isolation
- **Maintainability** — Clear separation of concerns
- **Reusability** — Modules can be imported into other projects

### Why Hybrid AI?

- **Privacy** — Sensitive data stays local (Ollama)
- **Intelligence** — Complex reasoning uses cloud (Gemini)
- **Flexibility** — Users can choose local-only or cloud-only
- **Cost control** — Minimize API calls for sensitive tasks

---

## 📚 Further Reading

- **[Module Reference](02-modules-recon.md)** — Detailed documentation for each reconnaissance module
- **[Database Schema](05-database-schema.md)** — Complete SQLite table definitions
- **[Configuration Reference](07-configuration.md)** — All environment variables and CLI arguments
- **[Development Guide](09-development.md)** — How to add new modules and contribute

---

*Last Updated: 2026-11-22*
*Architecture Version: 1.0*
