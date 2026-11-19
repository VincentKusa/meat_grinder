# 📚 MEAT-GRINDER Technical Documentation

## Table of Contents

- [Architecture Deep Dive](#architecture-deep-dive)
- [Module Reference](#module-reference)
- [Database Schema](#database-schema)
- [Finding Types Catalog](#finding-types-catalog)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Development Guide](#development-guide)

---

## Architecture Deep Dive

### Execution Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    MEAT-GRINDER EXECUTION FLOW                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: Discovery                                             │
│  ├─ SubdomainEnumerator (subfinder)                             │
│  ├─ WhoisContactOSINT (python-whois + DuckDuckGo)               │
│  └─ DNSScanner (dnspython)                                      │
│                                                                 │
│  Phase 2: Infrastructure                                        │
│  ├─ PortScanner (naabu/shodan)                                  │
│  └─ OSRecon (nmap) [active mode only]                           │
│                                                                 │
│  Phase 3: Web Surface                                           │
│  ├─ HTTPProber (httpx)                                          │
│  ├─ HeaderAnalyzer (requests)                                   │
│  ├─ TLSScanner (ssl socket)                                     │
│  ├─ SensitiveFileScanner (requests + regex)                     │
│  ├─ WebContentScanner (requests + regex)                        │
│  ├─ HTMLMetadataExtractor (BeautifulSoup)                       │
│  └─ APIScanner (requests + regex)                               │
│                                                                 │
│  Phase 4: Vulnerability                                         │
│  ├─ NucleiScanner (nuclei)                                      │
│  └─ CloudScanner (requests + permutations)                      │
│                                                                 │
│  Phase 5: Mobile [optional]                                     │
│  └─ MobileScanner (mobsfscan + apktool + plistlib)              │
│                                                                 │
│  Phase 6: Code Intelligence                                     │
│  ├─ GitScanner (PyGithub + gitleaks)                            │
│  ├─ SASTScanner (trufflehog)                                    │
│  ├─ SBOMScanner (trivy)                                         │
│  └─ IaCScanner (checkov + custom parsers)                       │
│                                                                 │
│  Phase 7: Analysis & Reporting                                  │
│  ├─ InsightFilter (deduplication + scoring)                     │
│  ├─ BrowserEvidence (playwright)                                │
│  └─ MarkdownReporter (markdown generation)                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow Architecture

```
┌──────────────┐
│   CLI Tools  │─────► JSON/NDJSON Output
└──────────────┘
       │
       ▼
┌──────────────┐
│   Parsers    │─────► Structured Data
└──────────────┘
       │
       ▼
┌──────────────┐
│  SQLite DB   │─────► Persistent State
└──────────────┘
       │
       ▼
┌──────────────┐
│  Reporters   │─────► Markdown/JSON Output
└──────────────┘
```

---

## Module Reference

### 1. SubdomainEnumerator

**Tool:** `subfinder`
**Purpose:** Passive subdomain discovery from 30+ sources

**How it works:**

- Queries VirusTotal, Censys, Shodan, Certificate Transparency logs, etc.
- No packets sent to target (completely passive)
- Outputs NDJSON format
- Parses and stores unique subdomains in database

**Output:**

```json
{
    "host": "api.example.com",
    "source": "virustotal"
}
{
    "host": "dev.example.com",
    "source": "censys"
}
```

**Database Impact:**

- Table: `subdomains`
- Columns: `domain`, `source`

---

### 2. PortScanner

**Tools:** `naabu` (active) or Shodan InternetDB (passive)
**Purpose:** Discover open ports and services

**Passive Mode:**

- Queries Shodan InternetDB API
- Zero packets sent to target
- No API key required
- Returns: ports, OS, services, CPE data

**Active Mode:**

- Uses `naabu` for SYN scanning
- Scans top 100 ports by default
- Wire-speed performance
- Returns: open ports only

**Output (Passive):**

```json
{
    "ip": "1.2.3.4",
    "ports": [
        22,
        80,
        443
    ],
    "os": "Ubuntu",
    "services": {
        "22": "SSH",
        "80": "HTTP"
    }
}
```

**Database Impact:**

- Table: `ports`
- Columns: `host`, `ip`, `ports`, `source`, `os`, `services`

---

### 3. OSRecon

**Tool:** `nmap`
**Purpose:** Deep OS and service fingerprinting (active mode only)

**Command:**

```bash
nmap -sS -sV -O --top-ports 500 -T4 --open -oX - <target>
```

**What it detects:**

- Exact OS version (e.g., "Linux 5.4.0-42-generic")
- Service versions (e.g., "Apache 2.4.41")
- End-of-Life software
- Open ports with service banners

**Output:** XML format, parsed with `xml.etree.ElementTree`

**Database Impact:**

- Table: `os_recon`
- Columns: `host`, `ip`, `os_name`, `os_accuracy`, `hostname`, `open_ports`
- Findings: `EOL_OS_OR_SERVICE` (HIGH severity)

---

### 4. HTTPProber

**Tool:** `httpx` (ProjectDiscovery)
**Purpose:** Probe live HTTP endpoints and extract metadata

**Command:**

```bash
httpx -l subs.txt -status-code -tech-detect -title -content-length -web-server -json -silent
```

**What it extracts:**

- HTTP status codes
- Page titles
- Technology stack (via Wappalyzer signatures)
- Content length
- Web server headers

**Output:** NDJSON format

```json
{
    "url": "https://example.com",
    "status_code": 200,
    "title": "Example Domain",
    "tech": [
        "WordPress",
        "jQuery"
    ],
    "content_length": 1234,
    "webserver": "Apache/2.4.41"
}
```

**Database Impact:**

- Table: `endpoints`
- Columns: `url`, `status_code`, `title`, `tech_stack`, `content_length`, `webserver`

---

### 5. HeaderAnalyzer

**Tool:** Python `requests`
**Purpose:** Analyze HTTP headers for WAF detection and security misconfigurations

**WAF Detection (Passive):**

- Cloudflare: `cf-ray`, `cf-cache-status` headers
- Akamai: `x-akamai-transformed` header
- Sucuri: `x-sucuri-id` header
- Imperva: `x-iinfo` header
- AWS WAF: `x-amzn-requestid` header

**Security Headers Checked:**

- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options` (Clickjacking protection)
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options`
- `X-XSS-Protection`

**Findings:**

- `MISSING_HSTS` (MEDIUM)
- `MISSING_CLICKJACKING_PROTECTION` (MEDIUM)
- `OUTDATED_WEBSERVER` (HIGH)

**Database Impact:**

- Updates `endpoints` table: `headers_json`, `waf_detected`
- Inserts findings

---

### 6. SensitiveFileScanner

**Tool:** Python `requests` + regex **Purpose:** Hunt for exposed configuration files with zero false positives

**Files Checked:**

```
.env, .env.bak, .env.local, .env.production
.git/config, .git/HEAD
wp-config.php, config.php, config.json
database.yml, secrets.json, credentials.json
.aws/credentials
id_rsa, id_dsa, id_ecdsa, id_ed25519
.htpasswd, .htaccess
backup.sql, dump.sql, db.sql
```

**Regex Validation (prevents false positives):**

```python
# Only flags if actual secrets are present
r'(?i)(DB_PASSWORD|SECRET_KEY|JWT_SECRET)\s*[:=]\s*[\'"]?[^\'"\s]+[\'"]?'
r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----'
r'(?i)aws_access_key_id|aws_secret_access_key'
r'(?i)STRIPE_SECRET_KEY'
```

**Logic:**

1. Request file
2. If 200 OK, read first 2KB
3. Apply regex patterns
4. If match found → CRITICAL finding
5. If no match but content exists → MEDIUM finding
6. If 403 on .git → MEDIUM finding

**Findings:**

- `EXPOSED_SENSITIVE_FILE` (CRITICAL)
- `EXPOSED_FILE` (MEDIUM)
- `PROTECTED_SENSITIVE_FILE` (MEDIUM)

---

### 7. WebContentScanner

**Tool:** Python `requests` + `BeautifulSoup` + regex **Purpose:** Extract hardcoded secrets from JavaScript and HTML

**Process:**

1. Fetch HTML of live endpoints
2. Extract all `<script src="...">` tags
3. Extract inline `<script>` blocks
4. Download JS files (max 100KB each)
5. Apply high-precision regex patterns

**Secret Patterns:**

```python
# AWS Keys
r'(?i)AKIA[0-9A-Z]{16}'

# Stripe Keys
r'(?i)(sk_live_|sk_test_|pk_live_|pk_test_)[a-zA-Z0-9]{24,}'

# GitHub Tokens
r'(?i)ghp_[a-zA-Z0-9]{36}'

# Google API Keys
r'(?i)AIza[0-9A-Za-z_\-]{35}'

# Slack Tokens
r'(?i)xox[baprs]-[0-9a-zA-Z\-]{10,}'

# JWTs
r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'

# Generic high-entropy secrets
r'(?i)(api[_-]?key|secret[_-]?key|password)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'

# Internal/staging domains
r'(?i)(https?://)(dev-|staging-|test-|internal-)[a-zA-Z0-9\-\.]+'
```

**Findings:**

- `HARDCODED_SECRET_IN_WEB_FILE` (HIGH)
- `INTERNAL_DOMAIN_LEAK` (MEDIUM)

---

### 8. HTMLMetadataExtractor

**Tool:** Python `BeautifulSoup`
**Purpose:** Extract metadata from HTML that HTTPX misses

**What it extracts:**

**1. Meta Tags:**

```html
<meta name="generator" content="WordPress 5.8">
<meta name="author" content="John Doe">
```

→ Finding: `CMS_VERSION_EXPOSED` (MEDIUM), `HTML_META_TAG` (INFO)

**2. HTML Comments:**

```html
<!-- TODO: Remove this API key before production -->
<!-- Internal URL: api-dev.example.com -->
<!-- Built by Jane Smith -->
```

→ Finding: `HTML_COMMENT_LEAK` (HIGH/MEDIUM/INFO)

**3. Hidden Form Fields:**

```html
<input type="hidden" name="csrf_token" value="abc123...">
<input type="hidden" name="api_key" value="sk_live_...">
```

→ Finding: `HIDDEN_FORM_FIELD` (MEDIUM)

**4. Social Media Links:**

```html
<meta property="og:author" content="https://twitter.com/johndoe">
```

→ Finding: `SOCIAL_META_EXPOSED` (INFO)

**5. Link Tags:**

```html
<link rel="manifest" href="/manifest.json">
<link rel="alternate" href="https://api.example.com">
```

→ Finding: `WEB_MANIFEST_FOUND` (INFO), `API_ENDPOINT_IN_LINK` (MEDIUM)

---

### 9. APIScanner

**Tool:** Python `requests` + regex **Purpose:** Discover API endpoints and documentation

**API Documentation Paths Checked:**

```
/swagger.json, /swagger.yaml, /swagger-ui.html
/openapi.json, /openapi.yaml
/api-docs, /api/docs
/graphql, /graphiql, /graphql/playground
/.well-known/openid-configuration
/.well-known/apple-app-site-association
/.well-known/assetlinks.json
/postman_collection.json
/api/v1, /api/v2, /api/v3
```

**GraphQL Introspection Check:**

```python
query = '{"query": "{__schema{types{name}}}"}'
# If response contains "__schema", introspection is enabled
```

**JavaScript API Extraction:**

```python
r'["\'](/api/[^"\']+)["\']'
r'["\'](/v[0-9]+/[^"\']+)["\']'
r'["\'](/graphql[^"\']*)["\']'
```

**Findings:**

- `OPENAPI_EXPOSED` (MEDIUM)
- `GRAPHQL_ENDPOINT` (MEDIUM)
- `GRAPHQL_INTROSPECTION_ENABLED` (MEDIUM)
- `WELL_KNOWN_ENDPOINT` (INFO)
- `API_ENDPOINT_DISCOVERED` (INFO)
- `API_ENDPOINT_IN_CODE` (INFO)

---

### 10. NucleiScanner

**Tool:** `nuclei`
**Purpose:** Template-based vulnerability and misconfiguration scanning

**Command:**

```bash
nuclei -l targets.txt -jsonl -silent \
  -severity critical,high,medium \
  -tags exposed-panels,misconfiguration,default-logins,technologies \
  -timeout 10 -retries 1
```

**Template Categories:**

- `exposed-panels`: Grafana, Jenkins, Kibana, phpMyAdmin
- `misconfiguration`: CORS misconfigs, open redirects
- `default-logins`: admin/admin, root/root
- `technologies`: Vulnerable tech stack detection

**Output:** NDJSON format

```json
{
    "template-id": "grafana-default-login",
    "info": {
        "name": "Grafana Default Login",
        "severity": "high"
    },
    "matched-at": "https://grafana.example.com/login",
    "host": "https://grafana.example.com"
}
```

**Findings:**

- `NUCLEI_VULN/MISCONFIG` (severity from template)

---

### 11. CloudScanner

**Tool:** Python `requests`
**Purpose:** Discover exposed cloud storage buckets

**Permutations Generated:**

```python
base_name = "vulnbank"
permutations = [
    "vulnbank",
    "vulnbank-dev",
    "vulnbank-prod",
    "vulnbank-staging",
    "vulnbank-backup",
    "vulnbank-assets",
    "dev-vulnbank",
    "prod-vulnbank"
]
```

**Cloud Providers Checked:**

```python
("AWS S3", "https://{name}.s3.amazonaws.com"),
("AWS S3 Website", "http://{name}.s3-website-{region}.amazonaws.com"),
("Azure Blob", "https://{name}.blob.core.windows.net"),
("GCP Storage", "https://storage.googleapis.com/{name}"),
("DigitalOcean Spaces", "https://{name}.nyc3.digitaloceanspaces.com")
```

**Regions for AWS:**

```python
['us-east-1', 'eu-west-1', 'ap-south-1']
```

**Logic:**

- 200 OK → Public bucket (HIGH)
- 403 Forbidden → Private but exists (INFO)
- DNS resolution failure → Doesn't exist (skip)

**Findings:**

- `CLOUD_ASSET_DISCOVERED` (HIGH if public, INFO if private)

---

### 12. MobileScanner

**Tools:** `mobsfscan`, `apktool`, `plistlib`
**Purpose:** Static analysis of mobile applications

#### Android Analysis

**1. MobSF Scan:**

```bash
mobsfscan target.apk --json --output report.json
```

Detects: Hardcoded secrets, insecure configs, dangerous permissions

**2. AndroidManifest.xml Analysis (via apktool):**

```bash
apktool d -f -o extracted/ target.apk
```

**Checks:**

- `android:allowBackup="true"` → Data extractable via adb (HIGH)
- `android:debuggable="true"` → Production debuggable (CRITICAL)
- Exported components (activities, services, receivers) (HIGH)
- Custom URL schemes (deep link hijacking) (MEDIUM)
- Dangerous permissions (CAMERA, SMS, CONTACTS) (MEDIUM)
- `network_security_config.xml` with `cleartextTrafficPermitted="true"` (HIGH)

**Findings:**

- `ANDROID_ALLOW_BACKUP` (HIGH)
- `ANDROID_DEBUGGABLE` (CRITICAL)
- `ANDROID_EXPORTED_COMPONENTS` (HIGH)
- `ANDROID_CUSTOM_URL_SCHEME` (MEDIUM)
- `ANDROID_DANGEROUS_PERMISSIONS` (MEDIUM)
- `ANDROID_CLEARTEXT_ALLOWED` (HIGH)
- `MOBILE_APP_SECRET/MISCONFIG` (HIGH/MEDIUM)

#### iOS Analysis

**1. MobSF Scan:**

```bash
mobsfscan target.ipa --json --output report.json
```

**2. Info.plist Parsing:**

```python
# Unzip IPA (it's a ZIP file)
with zipfile.ZipFile(ipa_path, 'r') as z:
    z.extractall(extract_dir)

# Parse Info.plist
with open(plist_path, 'rb') as f:
    plist = plistlib.load(f)
```

**Checks:**

- `CFBundleURLSchemes` → Custom URL schemes (MEDIUM)
- `NSAllowsArbitraryLoads=true` → ATS bypass (HIGH)
- `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads` (MEDIUM)
- Hardcoded keys: `APIKey`, `SecretKey`, `AuthToken`, `FirebaseURL`, `AWSCredentials` (HIGH)
- `NSAllowsLocalNetworking=true` (INFO)

**3. Entitlements Parsing:**

```python
# Check for *.entitlements files
# Parse keychain-access-groups, associated-domains, aps-environment
```

**Findings:**

- `IOS_URL_SCHEMES` (MEDIUM)
- `IOS_ATS_BYPASS` (HIGH)
- `IOS_ATS_EXCEPTION` (MEDIUM)
- `IOS_PLIST_SECRET` (HIGH)
- `IOS_LOCAL_NETWORK_ACCESS` (INFO)
- `IOS_KEYCHAIN_GROUPS` (INFO)
- `IOS_ASSOCIATED_DOMAINS` (INFO)
- `IOS_PUSH_ENVIRONMENT` (INFO)

---

### 13. GitScanner

**Tools:** `PyGithub`, `gitleaks`
**Purpose:** Discover and scan GitHub repositories for secrets

**Discovery Strategies:**

**1. Website Scraping:**

```python
# Fetch target website HTML
# Extract all GitHub links
soup = BeautifulSoup(html, 'html.parser')
for a in soup.find_all('a', href=True):
    if 'github.com' in a['href']:
        repos.add(a['href'])
```

**2. GitHub API Search:**

```python
g = Github(token)
query = f'"{target}" in:readme OR "{target}" in:description'
repos = g.search_repositories(query)
```

**3. Explicit Target:**

```python
org = g.get_organization('Commando-X')
repos = org.get_repos()
```

**Relevance Scoring Algorithm:**

```python
score = 0

# Explicit target match
if owner == explicit_target:
    score += 50

# Linked from website
if linked_from_website:
    score += 50

# Repo name contains target
if target_base in repo_name:
    score += 30

# Penalize noise
for keyword in ['ctf', 'writeup', 'test', 'example', 'demo']:
    if keyword in repo_name:
        score -= 20

# Clamp to 0-100
score = max(0, min(100, score))
```

**Cloning:**

```bash
git clone --depth 1 <repo_url>
```

**Gitleaks Scan:**

```bash
gitleaks detect --source <repo_path> --report-format json --report-path report.json
```

**Findings:**

- `LEAKED_SECRET` (CRITICAL)

---

### 14. SASTScanner

**Tool:** `trufflehog`
**Purpose:** Deep git history scanning for secrets

**Command:**

```bash
trufflehog filesystem <repos_dir> --json --no-update --only-verified
```

**Why `--only-verified`:**

- TruffleHog actively tests discovered secrets
- Only reports secrets that are still live/valid
- Eliminates 99% of false positives
- Much higher confidence than Gitleaks

**Output:** NDJSON format

```json
{
    "SourceMetadata": {
        "Data": {
            "Filesystem": {
                "file": "config.py",
                "line": 42
            }
        }
    },
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "DetectorName": "AWS"
}
```

**Findings:**

- `DEEP_CODE_SECRET (VERIFIED)` (CRITICAL)

---

### 15. SBOMScanner

**Tools:** `trivy`, custom parsers **Purpose:** Software Bill of Materials and dependency vulnerability scanning

**Lock Files Analyzed:**

```
package-lock.json, yarn.lock, pnpm-lock.yaml
requirements.txt, poetry.lock, Pipfile.lock
go.mod, go.sum
Cargo.lock
pom.xml, build.gradle
composer.lock
```

**Trivy Command:**

```bash
trivy fs --scanners vuln --format json <repo_path>
```

**Vulnerability Patterns (custom):**

```python
vulnerable_patterns = [
    ('lodash<4.17.21', 'Prototype pollution'),
    ('requests<2.20.0', 'CRLF injection'),
    ('django<3.2', 'Multiple vulnerabilities'),
    ('flask<2.0', 'Security vulnerabilities'),
]
```

**Findings:**

- `VULNERABLE_DEPENDENCY` (CRITICAL/HIGH/MEDIUM)

---

### 16. IaCScanner

**Tools:** `checkov`, custom parsers **Purpose:** Infrastructure as Code security scanning

**Checkov Command:**

```bash
checkov -d <repo_path> --output json --quiet
```

**Manual Checks:**

**Dockerfile:**

- Missing `USER` directive → Running as root (MEDIUM)
- Secrets in Dockerfile (PASSWORD, SECRET, API_KEY) (HIGH)

**Terraform:**

- `aws_s3_bucket` with `acl = "public"` (HIGH)
- `aws_security_group` with `0.0.0.0/0` (HIGH)

**Kubernetes:**

- `privileged: true` in pod spec (HIGH)
- `hostPath` mounts (MEDIUM)

**Findings:**

- `IAC_MISCONFIGURATION` (HIGH/MEDIUM)
- `DOCKERFILE_RUNNING_AS_ROOT` (MEDIUM)
- `DOCKERFILE_SECRET_LEAK` (HIGH)
- `TERRAFORM_PUBLIC_S3` (HIGH)
- `TERRAFORM_OPEN_SECURITY_GROUP` (HIGH)
- `K8S_PRIVILEGED_POD` (HIGH)
- `K8S_HOSTPATH_MOUNT` (MEDIUM)

---

### 17. DNSScanner

**Tool:** `dnspython`
**Purpose:** DNS intelligence and security analysis

**Record Types Queried:**

```python
['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
```

**Security Checks:**

**SPF Validation:**

```python
if 'v=spf1' in txt_record:
    if '+all' in txt_record or 'all' not in txt_record:
        # WEAK SPF - allows all senders
```

**DMARC Validation:**

```python
dmarc_domain = f'_dmarc.{domain}'
if 'v=DMARC1' in dmarc_record:
    if 'p=none' in dmarc_record:
        # WEAK DMARC - no enforcement
```

**Dangling CNAME Detection:**

```python
cloud_providers = ['github.io', 'herokuapp.com', 'azurewebsites.net', 's3.amazonaws.com']
if any(provider in cname for provider in cloud_providers):
    # DANGLING CNAME - potential subdomain takeover
```

**Findings:**

- `WEAK_SPF` (HIGH)
- `MISSING_DMARC` (MEDIUM)
- `WEAK_DMARC` (MEDIUM)
- `DANGLING_CNAME` (HIGH)
- `MX_MISCONFIGURATION` (HIGH)

---

### 18. TLSScanner

**Tool:** Python `ssl` + `socket`
**Purpose:** TLS certificate and protocol analysis

**Process:**

```python
context = ssl.create_default_context()
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert()
        cipher = ssock.cipher()
        version = ssock.version()
```

**Checks:**

**Certificate Expiry:**

```python
days_until_expiry = (not_after - datetime.now()).days
if days_until_expiry < 0:
    # TLS_CERT_EXPIRED (CRITICAL)
elif days_until_expiry < 30:
    # TLS_CERT_EXPIRING_SOON (HIGH)
```

**Self-Signed Detection:**

```python
if issuer == subject:
    # TLS_SELF_SIGNED (MEDIUM)
```

**Hostname Mismatch:**

```python
try:
    ssl.match_hostname(cert, hostname)
except ssl.CertificateError:
    # TLS_HOSTNAME_MISMATCH (HIGH)
```

**Weak Protocol Detection:**

```python
weak_versions = ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']
if any(weak in version for weak in weak_versions):
    # TLS_WEAK_PROTOCOL (HIGH)
```

**SAN Discovery:**

```python
for san in cert['subjectAltName']:
    if san.endswith(target_domain) and san != hostname:
        # New subdomain discovered!
        db.insert_subdomain(san, 'tls_san')
```

**Findings:**

- `TLS_CERT_EXPIRED` (CRITICAL)
- `TLS_CERT_EXPIRING_SOON` (HIGH)
- `TLS_SELF_SIGNED` (MEDIUM)
- `TLS_HOSTNAME_MISMATCH` (HIGH)
- `TLS_WEAK_PROTOCOL` (HIGH)
- `TLS_ERROR` (HIGH)

---

### 19. WhoisContactOSINT

**Tools:** `python-whois`, `requests`, `BeautifulSoup`
**Purpose:** Extract registrar info and pivot to social media

**WHOIS Extraction:**

```python
w = whois.whois(target)
registrar = w.registrar
creation_date = w.creation_date

# Extract emails
emails = set()
for field in ['registrant_email', 'admin_email', 'tech_email', 'emails']:
    val = getattr(w, field, None)
    if val:
        emails.add(val)

# Filter out privacy proxies
valid_emails = [e for e in emails if 'redacted' not in e and 'privacy' not in e]
```

**Username Pivoting:**

```python
username = email.split('@')[0]  # johndoe@example.com → johndoe
queries = [f'"{email}"', f'"{username}"']
```

**DuckDuckGo Search:**

```python
url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
resp = requests.get(url, headers=headers)
soup = BeautifulSoup(resp.text, 'html.parser')

# Extract real URLs from redirect links
for a_tag in soup.find_all('a', class_='result__snippet'):
    href = a_tag.get('href', '')
    if 'uddg=' in href:
        real_url = urllib.parse.unquote(href.split('uddg=')[1])
```

**Social Media Matching:**

```python
social_domains = ['twitter.com', 'x.com', 'linkedin.com', 'github.com', 'facebook.com']
for social in social_domains:
    if social in real_url.lower():
        # Found social media profile!
```

**Findings:**

- `DOMAIN_WHOIS_INFO` (INFO)
- `SOCIAL_MEDIA_CONTACT` (MEDIUM)
- `WHOIS_CONTACT_EMAIL` (INFO)

---

### 20. BrowserEvidence

**Tool:** `playwright`
**Purpose:** Capture screenshots of high-severity findings

**Process:**

```python
async with async_playwright() as p:
    browser = await p.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    )

    for url in target_urls:
        page = await context.new_page()
        await page.goto(url, timeout=30000, wait_until='networkidle')
        await page.screenshot(path=f'screenshots/{i}.png')
        await page.close()
```

**Output:**

- PNG screenshots in `workspaces/<target>/screenshots/`
- Embedded in final Markdown report

---

### 21. InsightFilter

**Tool:** Python **Purpose:** Deduplicate findings and assign confidence levels

**Deduplication Algorithm:**

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

**Confidence Assignment:**

```python
DEFAULT_CONFIDENCE = {
    'EXPOSED_SENSITIVE_FILE': ConfidenceLevel.CONFIRMED,
    'LEAKED_SECRET': ConfidenceLevel.HIGH,
    'DEEP_CODE_SECRET': ConfidenceLevel.CONFIRMED,
    'HARDCODED_SECRET_IN_WEB_FILE': ConfidenceLevel.HIGH,
    'CLOUD_ASSET_DISCOVERED': ConfidenceLevel.MEDIUM,
    'MISSING_HSTS': ConfidenceLevel.HIGH,
    'HTML_COMMENT_LEAK': ConfidenceLevel.LOW,
    'DOMAIN_WHOIS_INFO': ConfidenceLevel.INFO,
}
```

**Occurrence Tracking:**

```python
if finding_exists(fingerprint):
    UPDATE
    findings
    SET
    occurrences = occurrences + 1
else:
    INSERT
    new
    finding
```

---

### 22. MarkdownReporter

**Tool:** Python **Purpose:** Generate clean, severity-grouped Markdown reports

**Report Structure:**

```markdown
# OSINT Insight Report: <target>

**Generated:** <timestamp>

## Executive Summary

- Actionable Findings: X
- Hosts with Open Ports: Y
- Live HTTP Endpoints: Z

## 🛡️ WAF & Firewall Detection

| Endpoint | Detected WAF/Firewall |
|---|---|

## Infrastructure Inventory

### Hosts, OS & Services

| Host | IP | OS | Open Ports | Running Services |
|---|---|---|---|---|

## Detailed Findings

### CRITICAL Severity (X)

- **[FINDING_TYPE]** `url`
    - *Details:* ...

### HIGH Severity (Y)

...

### MEDIUM Severity (Z)

...

## 📸 Visual Evidence

![Screenshot 1](screenshots/1.png)
```

**Diff Mode:**

```python
if diff_mode:
    findings = db.get_new_findings_since(last_scan_timestamp)
```

### 23. WaybackScanner

- **Tool:** Archive.org CDX API + Python `requests`
- **Purpose:** Historical asset discovery.
- **How it works:**
    - Queries the Wayback Machine API for historical URLs associated with the target domain.
    - Filters for interesting file extensions (`.js`, `.env`, `.bak`, `.git`, `.xml`).
    - Fetches the archived content (up to top 100 samples) and scans for leaked secrets that may have been deleted from
      the live site but remain in archives.
- **Findings:** `HISTORICAL_SECRET_LEAK` (HIGH).

### 24. JSRecursiveScanner

- **Tool:** Python `requests` + `BeautifulSoup` + regex
- **Purpose:** Deep JavaScript analysis (Depth 2).
- **How it works:**
    - **Depth 1:** Parses live HTML endpoints to extract all linked external `.js` files (e.g., `vendor.js`, `main.js`).
    - **Depth 2:** Downloads these external JS files (capped at 50KB) and scans them for hardcoded API keys, AWS
      credentials, and JWT secrets that are often missed by surface-level HTML scanning.
- **Findings:** `DEEP_JS_SECRET` (HIGH).

### 25. TakeoverVerifier

- **Tool:** Python `requests`
- **Purpose:** Active verification of subdomain takeovers.
- **How it works:**
    - Reads `DANGLING_CNAME` findings from the `DNSScanner`.
    - Actively sends HTTP/HTTPS requests to the dangling subdomains.
    - Compares responses against a database of known provider fingerprints (e.g., AWS S3 "NoSuchBucket", GitHub Pages
      "404", Heroku "No such app").
    - If a match is found, the finding is upgraded from INFO to CRITICAL, confirming the subdomain is claimable.
- **Findings:** `SUBDOMAIN_TAKEOVER_VULNERABLE` (CRITICAL).

### 26. PasteMonitor

- **Tool:** PyGithub + Python `requests`
- **Purpose:** Monitor paste sites and GitHub for leaked data
- **How it works:**
    - Searches GitHub code for target domain and related keywords
    - Searches GitHub commits for target-related email addresses
    - Checks paste sites (Pastebin, Ghostbin, dpaste) for leaked data
    - Filters results for high-value patterns (AWS keys, GitHub tokens, private keys)
- **Findings:** `GITHUB_CODE_LEAK` (HIGH), `GITHUB_COMMIT_EMAIL` (INFO), `PASTE_SITE_LEAK` (HIGH), `PASTE_SITE_MENTION`
  (MEDIUM)

### 27. SourceMapScanner

- **Tool:** Python `requests` + JSON parsing
- **Purpose:** Discover and analyze JavaScript source maps
- **How it works:**
    - Extracts all JS files from live endpoints
    - Checks for `.map` files via sourceMappingURL comments or `.js.map` extension
    - Parses source maps to extract original source files
    - Scans source content for sensitive data (API keys, internal URLs, TODO comments)
- **Findings:** `SOURCE_MAP_EXPOSED` (MEDIUM), `SOURCE_MAP_SOURCES` (INFO), `SOURCE_MAP_SECRET` (HIGH)

### 28. EmailOSINT

- **Tool:** Python `requests`
- **Purpose:** Perform OSINT on discovered email addresses
- **How it works:**
    - Extracts emails from database (WHOIS, Git commits, etc.)
    - Checks for username reuse across 10+ platforms (GitHub, Twitter, LinkedIn, etc.)
    - Analyzes email domains for suspicious TLDs
- **Findings:** `USERNAME_REUSE` (INFO), `SUSPICIOUS_EMAIL_DOMAIN` (LOW)

### 29. AdminDiscovery

- **Tool:** Python `requests`
- **Purpose:** Discover admin panels and management interfaces
- **How it works:**
    - Checks 35+ common admin paths across all base URLs
    - Fingerprints admin panels (WordPress, Jenkins, Grafana, phpMyAdmin, etc.)
    - Detects protected but existing admin panels (401/403 responses)
- **Findings:** `ADMIN_PANEL_DISCOVERED` (MEDIUM), `ADMIN_PANEL_PROTECTED` (INFO)

### 30. ASNMapper

- **Tool:** ipinfo.io API + Python `requests`
- **Purpose:** Map ASN, hosting providers, and CDN usage
- **How it works:**
    - Queries ipinfo.io for all discovered IPs
    - Extracts ASN, organization, and location data
    - Detects cloud providers (AWS, GCP, Azure, DigitalOcean)
    - Identifies CDN usage (Cloudflare, Akamai, Fastly, CloudFront)
- **Findings:** `ASN_DISCOVERED` (INFO), `CLOUD_HOSTED_ASSET` (INFO), `CDN_DETECTED` (INFO), `IP_ORGANIZATION` (INFO)

---

## Database Schema

### Tables

#### `subdomains`

```sql
CREATE TABLE subdomains
(
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    source TEXT
);
```

#### `endpoints`

```sql
CREATE TABLE endpoints
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT UNIQUE,
    status_code    INTEGER,
    title          TEXT,
    tech_stack     TEXT,
    content_length INTEGER,
    webserver      TEXT,
    headers_json   TEXT,
    waf_detected   TEXT
);
```

#### `ports`

```sql
CREATE TABLE ports
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host     TEXT,
    ip       TEXT,
    ports    TEXT, -- JSON array
    source   TEXT,
    os       TEXT,
    services TEXT, -- JSON object
    UNIQUE (host, source)
);
```

#### `findings`

```sql
CREATE TABLE findings
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_type  TEXT,
    url           TEXT,
    details       TEXT,
    severity      TEXT,
    confidence    TEXT      DEFAULT 'MEDIUM',
    fingerprint   TEXT UNIQUE,
    first_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    occurrences   INTEGER   DEFAULT 1,
    source_module TEXT
);
```

#### `os_recon`

```sql
CREATE TABLE os_recon
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT UNIQUE,
    ip          TEXT,
    os_name     TEXT,
    os_accuracy TEXT,
    hostname    TEXT,
    open_ports  TEXT
);
```

#### `dns_records`

```sql
CREATE TABLE dns_records
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT,
    record_type  TEXT,
    record_value TEXT,
    ttl          INTEGER,
    UNIQUE (domain, record_type, record_value)
);
```

#### `tls_info`

```sql
CREATE TABLE tls_info
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host         TEXT UNIQUE,
    issuer       TEXT,
    subject      TEXT,
    sans         TEXT,
    not_before   TEXT,
    not_after    TEXT,
    tls_versions TEXT,
    cipher_suite TEXT
);
```

#### `scan_runs`

```sql
CREATE TABLE scan_runs
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT,
    scan_mode      TEXT,
    started_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at   TIMESTAMP,
    total_findings INTEGER
);
```

---

## Finding Types Catalog

### CRITICAL Severity

- `EXPOSED_SENSITIVE_FILE` - .env, .git/config with actual secrets
- `LEAKED_SECRET` - Secrets found in Git repos (Gitleaks)
- `DEEP_CODE_SECRET (VERIFIED)` - Verified live secrets (TruffleHog)
- `ANDROID_DEBUGGABLE` - Production app is debuggable
- `TLS_CERT_EXPIRED` - Certificate has expired
- `VULNERABLE_DEPENDENCY` - Critical CVE in dependencies
- `SUBDOMAIN_TAKEOVER_VULNERABLE` - Confirmed claimable subdomain (AWS S3, GitHub Pages, Heroku, etc.)

### HIGH Severity

- `HARDCODED_SECRET_IN_WEB_FILE` - Secrets in JavaScript/HTML
- `ANDROID_ALLOW_BACKUP` - App data extractable via adb
- `ANDROID_EXPORTED_COMPONENTS` - Attack surface via intents
- `ANDROID_CLEARTEXT_ALLOWED` - HTTP traffic permitted
- `IOS_ATS_BYPASS` - NSAllowsArbitraryLoads=true
- `IOS_PLIST_SECRET` - Hardcoded keys in Info.plist
- `CLOUD_ASSET_DISCOVERED` - Public cloud bucket
- `OPENAPI_EXPOSED` - API documentation publicly accessible
- `GRAPHQL_INTROSPECTION_ENABLED` - Schema exposed
- `WEAK_SPF` - SPF allows all senders
- `DANGLING_CNAME` - Subdomain takeover candidate
- `TLS_CERT_EXPIRING_SOON` - Certificate expires in <30 days
- `TLS_HOSTNAME_MISMATCH` - Certificate doesn't match hostname
- `TLS_WEAK_PROTOCOL` - TLSv1.0/1.1 or SSL in use
- `EOL_OS_OR_SERVICE` - End-of-Life software detected
- `OUTDATED_WEBSERVER` - Old Apache/Nginx/IIS version
- `IAC_MISCONFIGURATION` - IaC security issues
- `DOCKERFILE_SECRET_LEAK` - Secrets in Dockerfile
- `TERRAFORM_PUBLIC_S3` - Public S3 bucket
- `TERRAFORM_OPEN_SECURITY_GROUP` - 0.0.0.0/0 access
- `K8S_PRIVILEGED_POD` - Privileged container
- `NUCLEI_VULN/MISCONFIG` - Nuclei-detected vulnerabilities
- `HISTORICAL_SECRET_LEAK` - Secrets found in Wayback Machine archives
- `DEEP_JS_SECRET` - Secrets found in external/linked JavaScript files
- `GITHUB_CODE_LEAK` - Target data found in public GitHub repositories
- `PASTE_SITE_LEAK` - Target data with secrets found on paste sites
- `SOURCE_MAP_SECRET` - Sensitive data found in JavaScript source maps

### MEDIUM Severity

- `EXPOSED_FILE` - File exists but no obvious secrets
- `PROTECTED_SENSITIVE_FILE` - 403 on .git directory
- `MISSING_HSTS` - No Strict-Transport-Security header
- `MISSING_CLICKJACKING_PROTECTION` - No X-Frame-Options
- `ANDROID_CUSTOM_URL_SCHEME` - Deep link attack surface
- `ANDROID_DANGEROUS_PERMISSIONS` - CAMERA, SMS, etc.
- `IOS_URL_SCHEMES` - Deep linking surface
- `IOS_ATS_EXCEPTION` - Specific domain allows HTTP
- `CMS_VERSION_EXPOSED` - Generator meta tag reveals version
- `HTML_COMMENT_LEAK` - Sensitive info in comments
- `HIDDEN_FORM_FIELD` - Sensitive hidden inputs
- `API_ENDPOINT_IN_LINK` - API paths in link tags
- `GRAPHQL_ENDPOINT` - GraphQL endpoint discovered
- `WEAK_DMARC` - DMARC policy=none
- `MISSING_DMARC` - No DMARC record
- `MX_MISCONFIGURATION` - MX points to localhost
- `TLS_SELF_SIGNED` - Self-signed certificate
- `DOCKERFILE_RUNNING_AS_ROOT` - No USER directive
- `K8S_HOSTPATH_MOUNT` - Host filesystem access
- `VULNERABLE_DEPENDENCY` - Medium-severity CVE
- `SOCIAL_MEDIA_CONTACT` - Social profiles found
- `PASTE_SITE_MENTION` - Target domain mentioned on paste sites
- `SOURCE_MAP_EXPOSED` - JavaScript source map publicly accessible
- `ADMIN_PANEL_DISCOVERED` - Admin panel or management interface found

### LOW Severity

- `HTML_COMMENT_LEAK` - Long comments (dev notes)
- `SERVER_ERROR` - 500/502/503 responses
- `VULNERABLE_DEPENDENCY` - Low-severity CVE
- `SUSPICIOUS_EMAIL_DOMAIN` - Email uses potentially suspicious TLD

### INFO Severity

- `DOMAIN_WHOIS_INFO` - Registrar info
- `WHOIS_CONTACT_EMAIL` - Contact emails found
- `HTML_META_TAG` - Meta tags extracted
- `SOCIAL_META_EXPOSED` - Social links in meta
- `WEB_MANIFEST_FOUND` - PWA manifest
- `API_ENDPOINT_DISCOVERED` - API paths found
- `API_ENDPOINT_IN_CODE` - APIs in JavaScript
- `WELL_KNOWN_ENDPOINT` - .well-known paths
- `CLOUD_ASSET_DISCOVERED` - Private cloud bucket
- `IOS_LOCAL_NETWORK_ACCESS` - Local network allowed
- `IOS_KEYCHAIN_GROUPS` - Shared credentials
- `IOS_ASSOCIATED_DOMAINS` - Universal links
- `IOS_PUSH_ENVIRONMENT` - APNs environment
- `GITHUB_COMMIT_EMAIL` - Email addresses found in GitHub commits
- `USERNAME_REUSE` - Username found on multiple platforms
- `ASN_DISCOVERED` - ASN and organization information
- `CLOUD_HOSTED_ASSET` - Asset hosted on cloud provider
- `CDN_DETECTED` - Asset behind CDN
- `IP_ORGANIZATION` - IP organization and location
- `SOURCE_MAP_SOURCES` - Source files listed in source map
- `ADMIN_PANEL_PROTECTED` - Admin panel exists but requires authentication
-

---

## Configuration Reference

### Environment Variables (.env)

```bash
# Required
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Optional
SHODAN_API_KEY=xxxxxxxxxxxxxxxxxxxx

# Configuration
WORKSPACE_DIR=./workspaces
HTTP_TIMEOUT=10
SCAN_TIMEOUT=300
MAX_WORKERS=50
GIT_MIN_SCORE=60
GIT_CLONE_DEPTH=1

# Feature Flags
ENABLE_SCREENSHOTS=true
ENABLE_MOBILE_SCANNING=true
ENABLE_IAC_SCANNING=true

# Reporting
REDACT_SECRETS=true
SECRET_PREVIEW_LENGTH=8
```

### CLI Arguments

```bash
python3 main.py <target> [options]

Required:
  target                  Target domain (e.g., vulnbank.org)

Optional:
  --mode {passive,active}
                          Port scan mode (default: passive)
  --skip-git              Skip Git repository scanning
  --github-target ORG     Explicit GitHub org/user to scan
  --apk-url URL           Android APK URL for analysis
  --ipa-url URL           iOS IPA URL for analysis
  --git-min-score N       Minimum repo relevance score (0-100, default: 60)
  --diff                  Show only new findings since last scan
  --no-screenshots        Disable browser evidence capture
  --doctor                Run pre-flight checks and exit
```

### Config.py Constants

```python
class Config:
    # Workspace
    WORKSPACE_DIR = Path("./workspaces")

    # API Keys
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    # Go Binaries
    SUBFINDER_BIN = "subfinder"
    HTTPX_BIN = "pdhttpx"
    NAABU_BIN = "naabu"
    GITLEAKS_BIN = "gitleaks"
    NUCLEI_BIN = "nuclei"
    TRUFFLEHOG_BIN = "trufflehog"

    # System Binaries
    MOBSFSCAN_BIN = "mobsfscan"
    TRIVY_BIN = "trivy"
    CHECKOV_BIN = "checkov"

    # Timeouts
    HTTP_TIMEOUT = 10
    SCAN_TIMEOUT = 300

    # Workers
    MAX_WORKERS = 50

    # Git
    GIT_MIN_SCORE = 60
    GIT_CLONE_DEPTH = 1
```

---

## Troubleshooting Guide

### Common Issues

#### 1. "httpx: No such option '-l'"

**Problem:** Python `httpx` package is shadowing ProjectDiscovery's `httpx`
**Solution:**

```bash
pip uninstall httpx
# Or rename the binary in config.py to "pdhttpx"
```

#### 2. "nuclei: no templates provided"

**Problem:** Nuclei templates not installed **Solution:**

```bash
rm -rf ~/.local/nuclei-templates
wget -qO /tmp/nuclei-templates.zip https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip
unzip -q /tmp/nuclei-templates.zip -d /tmp/
mkdir -p ~/.local/nuclei-templates
mv /tmp/nuclei-templates-main/* ~/.local/nuclei-templates/
```

#### 3. "trivy: Permission denied"

**Problem:** Installing Trivy without sudo **Solution:**

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
```

#### 4. "greenlet build failed"

**Problem:** Python 3.14 incompatibility with old greenlet **Solution:**

```bash
# Unpin playwright in requirements.txt
playwright>=1.45.0  # Instead of ==1.40.0
pip install --upgrade playwright
```

#### 5. "checkov/mobsfscan dependency conflicts"

**Problem:** Conflicting package versions **Solution:**

```bash
# Use pipx for isolated installations
pipx install checkov
pipx install mobsfscan
```

#### 6. "Gowitness failed"

**Problem:** Cloudflare blocking headless browsers **Solution:** Use Playwright instead (already implemented in
BrowserEvidence module)

#### 7. "No findings from Nuclei"

**Problem:** Target is clean or behind WAF **Solution:** Check if templates are loaded:

```bash
nuclei -tl | wc -l  # Should show 10,000+
```

#### 8. "GitHub API rate limit exceeded"

**Problem:** Unauthenticated API calls **Solution:** Add GITHUB_TOKEN to .env file

#### 9. "TruffleHog returns 0 verified secrets"

**Problem:** Secrets were rotated or are test fixtures **Solution:** This is normal! TruffleHog only reports live
secrets.

#### 10. "Playwright: OS not officially supported"

**Problem:** Kali Linux not in official support list **Solution:** Ignore warning - fallback Ubuntu 24.04 build works
fine

---

## Development Guide

### Adding a New Module

1. **Create module file:**

```python
# engine/my_scanner.py
from engine.base import BaseReconModule


class MyScanner(BaseReconModule):
    def execute(self):
        print("[*] Running my scanner...")

        # Your logic here
        self.db.insert_finding(
            f_type="MY_FINDING",
            url="https://example.com",
            details="Found something",
            severity="HIGH",
            source_module="my_scanner"
        )
```

2. **Add to main.py:**

```python
from engine.my_scanner import MyScanner

# In main() function:
MyScanner(target, db, workspace).execute()
```

3. **Update database.py if needed:**

```python
# Add new table or columns
conn.execute("""CREATE TABLE IF NOT EXISTS my_table (...)""")
```

### Code Style

- Use Black formatter (line length: 120)
- Use isort for imports
- Use flake8 for linting
- Add type hints
- Write docstrings

### Testing

```bash
# Run pre-commit checks
pre-commit run --all-files

# Test on known vulnerable target
python3 main.py demo.owasp-juice.shop --mode active
```

### Debugging

```bash
# Enable verbose output
export PYTHONUNBUFFERED=1

# Check database
sqlite3 workspaces/<target>/recon_data.db
> SELECT * FROM findings WHERE severity='CRITICAL';

# Check tool output
python3 main.py <target> 2>&1 | tee debug.log
```

---

## Example Report Output

```markdown
# OSINT Insight Report: vulnbank.org

**Generated:** 2026-11-19 10:30:45

## Executive Summary

- **Actionable Findings:** 108
- **Hosts with Open Ports:** 1
- **Live HTTP Endpoints:** 1

## 🛡️ WAF & Firewall Detection

| Endpoint | Detected WAF/Firewall |
|---|---|
| `https://www.vulnbank.org` | **Cloudflare** |

## Infrastructure Inventory

### Hosts, OS & Services

| Host | IP | OS | Open Ports | Running Services |
|---|---|---|---|---|
| `www.vulnbank.org` | 172.67.134.11 | Unknown | [80, 443] | 80(HTTP), 443(HTTPS) |

## Detailed Findings

### CRITICAL Severity (106)

- **[EXPOSED_SENSITIVE_FILE]** `https://www.vulnbank.org/.env`
    - *Details:* Status: 200, Regex matched potential secrets/config data
    - *Confidence:* CONFIRMED
    - *First Seen:* 2026-11-19 10:15:23
    - *Last Seen:* 2026-11-19 10:15:23

- **[LEAKED_SECRET]** `github:https://github.com/Commando-X/vuln-bank/exposed_env_files.py`
    - *Details:* Rule: generic-api-key | File: exposed_env_files.py:4 | Secret: 8f6d*************** (fingerprint:sha256:
      abc123)
    - *Confidence:* HIGH
    - *Occurrences:* 7

### HIGH Severity (2)

- **[MISSING_HSTS]** `https://www.vulnbank.org`
    - *Details:* Missing Strict-Transport-Security header
    - *Confidence:* HIGH

## 📸 Visual Evidence

### Screenshot 1

![Screenshot 1](screenshots/screenshot_1.png)
```

---

## Performance Tips

### Speed Up Scans

1. **Skip Git scanning:**

```bash
python3 main.py example.com --skip-git
```

2. **Increase Git relevance threshold:**

```bash
python3 main.py example.com --git-min-score 80
```

3. **Disable screenshots:**

```bash
python3 main.py example.com --no-screenshots
```

4. **Use passive mode:**

```bash
python3 main.py example.com --mode passive
```

### Reduce Noise

1. **Use explicit GitHub target:**

```bash
python3 main.py example.com --github-target Commando-X
```

2. **Filter by confidence in report:**

```bash
# Only show CONFIRMED and HIGH confidence findings
grep -E "CONFIRMED|HIGH" REPORT_*.md
```

### Resource Management

1. **Limit concurrent workers:**

```bash
# In .env
MAX_WORKERS=20  # Default is 50
```

2. **Shallow Git clones:**

```bash
# In .env
GIT_CLONE_DEPTH=1  # Already default
```

3. **Clean up old workspaces:**

```bash
rm -rf workspaces/old-target/
```

---

## Security Considerations

### API Key Protection

- Never commit `.env` to Git
- Use `.gitignore` to exclude sensitive files
- Rotate tokens regularly
- Use minimal permissions for GitHub tokens

### Scan Authorization

- **ALWAYS** get written permission before scanning
- Only scan targets you own or are authorized to test
- Respect rate limits and terms of service
- Use passive mode when possible to reduce impact

### Data Handling

- Findings may contain sensitive information
- Store reports securely
- Redact secrets in shared reports (`REDACT_SECRETS=true`)
- Delete workspaces after analysis

### Network Impact

- Active scanning sends packets to target
- Use `--mode passive` for minimal impact
- Respect `SCAN_TIMEOUT` settings
- Monitor for rate limiting or blocking

---

## License & Disclaimer

This tool is provided for educational purposes and authorized security testing only. The authors are not responsible for
any misuse or damage caused by this program.

**ALWAYS ensure you have explicit, written permission before scanning active targets.**

---

## Support & Contributions

For issues, feature requests, or contributions, please open an issue on the GitHub repository.

**Happy Hunting!** 🥩
