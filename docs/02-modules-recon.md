# 🔍 Discovery, Web, Network, and Mobile Modules

This document details the core reconnaissance modules of MEAT-GRINDER, categorized by their operational phase. These modules form the foundation of the engine's attack surface mapping capabilities.

---

## 📋 Module Categories Overview

| Category | Modules | Purpose |
|---|---|---|
| **Discovery & OSINT** | 6 | Subdomain, WHOIS, DNS, historical, email, ASN intelligence |
| **Network & Infrastructure** | 3 | Port scanning, OS fingerprinting, TLS analysis |
| **Web Surface & Content** | 11 | HTTP probing, headers, secrets, APIs, source maps, admin panels |
| **Mobile** | 1 | Android and iOS static analysis |
| **Vulnerability & Cloud** | 2 | Template-based scanning, cloud storage discovery |

---

## 🌐 1. Discovery & OSINT Modules

### 1.1 SubdomainEnumerator

**Tool:** `subfinder`
**Purpose:** Passive subdomain discovery from 30+ sources.

**How it works:**
- Queries VirusTotal, Censys, Shodan, Certificate Transparency logs, etc.
- No packets sent to target (completely passive)
- Outputs NDJSON format
- Parses and stores unique subdomains in database

**Output format:**
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
- **Table:** `subdomains`
- **Columns:** `domain`, `source`

---

### 1.2 WhoisContactOSINT

**Tools:** `python-whois`, `requests`, `BeautifulSoup`
**Purpose:** Extract registrar info and pivot to social media.

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

### 1.3 DNSScanner

**Tool:** `dnspython`
**Purpose:** DNS intelligence and security analysis.

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

### 1.4 WaybackScanner

**Tool:** Archive.org CDX API + Python `requests`
**Purpose:** Historical asset discovery.

**How it works:**
- Queries the Wayback Machine API for historical URLs associated with the target domain
- Filters for interesting file extensions (`.js`, `.env`, `.bak`, `.git`, `.xml`)
- Fetches the archived content (up to top 100 samples) and scans for leaked secrets that may have been deleted from the live site but remain in archives

**Findings:**
- `HISTORICAL_SECRET_LEAK` (HIGH)

---

### 1.5 EmailOSINT

**Tool:** Python `requests`
**Purpose:** Perform OSINT on discovered email addresses.

**How it works:**
- Extracts emails from database (WHOIS, Git commits, etc.)
- Checks for username reuse across 10+ platforms (GitHub, Twitter, LinkedIn, etc.)
- Analyzes email domains for suspicious TLDs

**Findings:**
- `USERNAME_REUSE` (INFO)
- `SUSPICIOUS_EMAIL_DOMAIN` (LOW)

---

### 1.6 ASNMapper

**Tool:** ipinfo.io API + Python `requests`
**Purpose:** Map ASN, hosting providers, and CDN usage.

**How it works:**
- Queries ipinfo.io for all discovered IPs
- Extracts ASN, organization, and location data
- Detects cloud providers (AWS, GCP, Azure, DigitalOcean)
- Identifies CDN usage (Cloudflare, Akamai, Fastly, CloudFront)

**Findings:**
- `ASN_DISCOVERED` (INFO)
- `CLOUD_HOSTED_ASSET` (INFO)
- `CDN_DETECTED` (INFO)
- `IP_ORGANIZATION` (INFO)

---

## 🖥️ 2. Network & Infrastructure Modules

### 2.1 PortScanner

**Tools:** `naabu` (active) or Shodan InternetDB (passive)
**Purpose:** Discover open ports and services.

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
    "ports": [22, 80, 443],
    "os": "Ubuntu",
    "services": {
        "22": "SSH",
        "80": "HTTP"
    }
}
```

**Database Impact:**
- **Table:** `ports`
- **Columns:** `host`, `ip`, `ports`, `source`, `os`, `services`

---

### 2.2 OSRecon

**Tool:** `nmap`
**Purpose:** Deep OS and service fingerprinting (active mode only).

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
- **Table:** `os_recon`
- **Columns:** `host`, `ip`, `os_name`, `os_accuracy`, `hostname`, `open_ports`

**Findings:**
- `EOL_OS_OR_SERVICE` (HIGH)

---

### 2.3 TLSScanner

**Tool:** Python `ssl` + `socket`
**Purpose:** TLS certificate and protocol analysis.

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

## 🌍 3. Web Surface & Content Modules

### 3.1 HTTPProber

**Tool:** `httpx` (ProjectDiscovery)
**Purpose:** Probe live HTTP endpoints and extract metadata.

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
    "tech": ["WordPress", "jQuery"],
    "content_length": 1234,
    "webserver": "Apache/2.4.41"
}
```

**Database Impact:**
- **Table:** `endpoints`
- **Columns:** `url`, `status_code`, `title`, `tech_stack`, `content_length`, `webserver`

---

### 3.2 HeaderAnalyzer

**Tool:** Python `requests`
**Purpose:** Analyze HTTP headers for WAF detection and security misconfigurations.

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

### 3.3 SensitiveFileScanner

**Tool:** Python `requests` + regex
**Purpose:** Hunt for exposed configuration files with zero false positives.

**Files Checked:**
- `.env`, `.env.bak`, `.env.local`, `.env.production`
- `.git/config`, `.git/HEAD`
- `wp-config.php`, `config.php`, `config.json`
- `database.yml`, `secrets.json`, `credentials.json`
- `.aws/credentials`
- `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`
- `.htpasswd`, `.htaccess`
- `backup.sql`, `dump.sql`, `db.sql`

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

### 3.4 WebContentScanner

**Tool:** Python `requests` + `BeautifulSoup` + regex
**Purpose:** Extract hardcoded secrets from JavaScript and HTML.

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

### 3.5 HTMLMetadataExtractor

**Tool:** Python `BeautifulSoup`
**Purpose:** Extract metadata from HTML that HTTPX misses.

**What it extracts:**

**1. Meta Tags:**
```html
<meta name="generator" content="WordPress 5.8">
<meta name="author" content="John Doe">
```
→ Findings: `CMS_VERSION_EXPOSED` (MEDIUM), `HTML_META_TAG` (INFO)

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
→ Findings: `WEB_MANIFEST_FOUND` (INFO), `API_ENDPOINT_IN_LINK` (MEDIUM)

---

### 3.6 APIScanner

**Tool:** Python `requests` + regex
**Purpose:** Discover API endpoints and documentation.

**API Documentation Paths Checked:**
- `/swagger.json`, `/swagger.yaml`, `/swagger-ui.html`
- `/openapi.json`, `/openapi.yaml`
- `/api-docs`, `/api/docs`
- `/graphql`, `/graphiql`, `/graphql/playground`
- `/.well-known/openid-configuration`
- `/.well-known/apple-app-site-association`
- `/.well-known/assetlinks.json`
- `/postman_collection.json`
- `/api/v1`, `/api/v2`, `/api/v3`

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

### 3.7 JSRecursiveScanner

**Tool:** Python `requests` + `BeautifulSoup` + regex
**Purpose:** Deep JavaScript analysis (Depth 2).

**How it works:**
- **Depth 1:** Parses live HTML endpoints to extract all linked external `.js` files (e.g., `vendor.js`, `main.js`)
- **Depth 2:** Downloads these external JS files (capped at 50KB) and scans them for hardcoded API keys, AWS credentials, and JWT secrets that are often missed by surface-level HTML scanning

**Findings:**
- `DEEP_JS_SECRET` (HIGH)

---

### 3.8 SourceMapScanner

**Tool:** Python `requests` + JSON parsing
**Purpose:** Discover and analyze JavaScript source maps.

**How it works:**
- Extracts all JS files from live endpoints
- Checks for `.map` files via `sourceMappingURL` comments or `.js.map` extension
- Parses source maps to extract original source files
- Scans source content for sensitive data (API keys, internal URLs, TODO comments)

**Findings:**
- `SOURCE_MAP_EXPOSED` (MEDIUM)
- `SOURCE_MAP_SOURCES` (INFO)
- `SOURCE_MAP_SECRET` (HIGH)

---

### 3.9 AdminDiscovery

**Tool:** Python `requests`
**Purpose:** Discover admin panels and management interfaces.

**How it works:**
- Checks 35+ common admin paths across all base URLs
- Fingerprints admin panels (WordPress, Jenkins, Grafana, phpMyAdmin, etc.)
- Detects protected but existing admin panels (401/403 responses)

**Findings:**
- `ADMIN_PANEL_DISCOVERED` (MEDIUM)
- `ADMIN_PANEL_PROTECTED` (INFO)

---

### 3.10 TakeoverVerifier

**Tool:** Python `requests`
**Purpose:** Active verification of subdomain takeovers.

**How it works:**
- Reads `DANGLING_CNAME` findings from the `DNSScanner`
- Actively sends HTTP/HTTPS requests to the dangling subdomains
- Compares responses against a database of known provider fingerprints (e.g., AWS S3 "NoSuchBucket", GitHub Pages "404", Heroku "No such app")
- If a match is found, the finding is upgraded from INFO to CRITICAL, confirming the subdomain is claimable

**Findings:**
- `SUBDOMAIN_TAKEOVER_VULNERABLE` (CRITICAL)

---

## 📱 4. Mobile Application Modules

### 4.1 MobileScanner

**Tools:** `mobsfscan`, `apktool`, `plistlib`
**Purpose:** Static analysis of mobile applications.

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

## 🛡️ 5. Vulnerability & Cloud Modules

### 5.1 NucleiScanner

**Tool:** `nuclei`
**Purpose:** Template-based vulnerability and misconfiguration scanning.

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

### 5.2 CloudScanner

**Tool:** Python `requests`
**Purpose:** Discover exposed cloud storage buckets.

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

## 📊 Module Summary Table

| # | Module | Tool(s) | Primary Output |
|---|---|---|---|
| 1 | SubdomainEnumerator | subfinder | Subdomains |
| 2 | WhoisContactOSINT | python-whois, requests | WHOIS data, social profiles |
| 3 | DNSScanner | dnspython | DNS records, SPF/DMARC issues |
| 4 | WaybackScanner | Archive.org API | Historical secrets |
| 5 | EmailOSINT | requests | Username reuse, suspicious domains |
| 6 | ASNMapper | ipinfo.io API | ASN, CDN, cloud provider data |
| 7 | PortScanner | naabu / Shodan | Open ports, services |
| 8 | OSRecon | nmap | OS fingerprints, EOL software |
| 9 | TLSScanner | ssl + socket | Certificate issues, SANs |
| 10 | HTTPProber | httpx | Live endpoints, tech stack |
| 11 | HeaderAnalyzer | requests | WAF detection, missing headers |
| 12 | SensitiveFileScanner | requests + regex | Exposed config files |
| 13 | WebContentScanner | requests + regex | Hardcoded secrets in JS/HTML |
| 14 | HTMLMetadataExtractor | BeautifulSoup | Meta tags, comments, hidden fields |
| 15 | APIScanner | requests + regex | API endpoints, GraphQL |
| 16 | JSRecursiveScanner | requests + regex | Deep JS secrets |
| 17 | SourceMapScanner | requests + JSON | Source map exposure |
| 18 | AdminDiscovery | requests | Admin panels |
| 19 | TakeoverVerifier | requests | Confirmed takeovers |
| 20 | MobileScanner | mobsfscan, apktool | Mobile app findings |
| 21 | NucleiScanner | nuclei | Template-based vulns |
| 22 | CloudScanner | requests | Exposed cloud buckets |

---

## 🔗 Cross-Reference: Modules → Database Tables

| Module | Tables Written |
|---|---|
| SubdomainEnumerator | `subdomains` |
| WhoisContactOSINT | `findings` |
| DNSScanner | `dns_records`, `findings` |
| WaybackScanner | `findings` |
| EmailOSINT | `findings` |
| ASNMapper | `findings` |
| PortScanner | `ports` |
| OSRecon | `os_recon`, `findings` |
| TLSScanner | `tls_info`, `subdomains`, `findings` |
| HTTPProber | `endpoints` |
| HeaderAnalyzer | `endpoints`, `findings` |
| SensitiveFileScanner | `findings` |
| WebContentScanner | `findings` |
| HTMLMetadataExtractor | `findings` |
| APIScanner | `findings` |
| JSRecursiveScanner | `findings` |
| SourceMapScanner | `findings` |
| AdminDiscovery | `findings` |
| TakeoverVerifier | `findings` |
| MobileScanner | `findings` |
| NucleiScanner | `findings` |
| CloudScanner | `findings` |

---

## 📌 Key Design Principles

1. **Passive-First:** All discovery modules (subdomains, DNS, WHOIS) are completely passive to minimize detection risk.
2. **Regex Validation:** Sensitive file scanning uses strict regex to eliminate false positives.
3. **Depth Crawling:** JavaScript analysis goes 2 levels deep to catch secrets in vendor bundles.
4. **Active Verification:** Subdomain takeovers are actively verified before being marked CRITICAL.
5. **Graceful Degradation:** If a tool fails, the engine continues with other modules.
6. **Database-Centric:** All modules write to SQLite, enabling crash recovery and continuous monitoring.

---

*Last Updated: 2026-11-22*
*Total Modules: 22*
*Total Finding Types Generated: 84*
