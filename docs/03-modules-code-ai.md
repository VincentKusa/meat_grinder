# 💻 Code Intelligence, OSINT & AI Modules

This document covers the advanced reconnaissance modules that analyze source code, repositories, paste sites, and leverage AI for intelligent attack surface discovery. These modules represent the "elite" capabilities of MEAT-GRINDER.

---

## 📋 Module Categories Overview

| Category | Modules | Purpose |
|---|---|---|
| **Code Intelligence** | 4 | Git repos, SAST, dependencies, IaC |
| **OSINT & Monitoring** | 2 | Paste sites, email/username OSINT |
| **AI-Powered Analysis** | 2 | Contextual analysis, attack path chaining |

---

## 🔐 1. Code Intelligence Modules

### 1.1 GitScanner

**Tools:** `PyGithub`, `gitleaks`
**Purpose:** Discover and scan GitHub repositories for leaked secrets.

#### Discovery Strategies

**Strategy 1: Website Scraping**
```python
# Fetch target website HTML
# Extract all GitHub links
soup = BeautifulSoup(html, 'html.parser')
for a in soup.find_all('a', href=True):
    if 'github.com' in a['href']:
        repos.add(a['href'])
```

**Strategy 2: GitHub API Search**
```python
g = Github(token)
query = f'"{target}" in:readme OR "{target}" in:description'
repos = g.search_repositories(query)
```

**Strategy 3: Explicit Target**
```python
# When --github-target is provided
org = g.get_organization('Commando-X')
repos = org.get_repos()
```

#### Relevance Scoring Algorithm

To avoid scanning unrelated CTFs, tutorials, and demo repos, each repository receives a relevance score (0-100):

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

# Penalize noise keywords
for keyword in ['ctf', 'writeup', 'test', 'example', 'demo', 'tutorial', 'lab']:
    if keyword in repo_name:
        score -= 20

# Clamp to 0-100
score = max(0, min(100, score))
```

**Default threshold:** `GIT_MIN_SCORE=60` (configurable via CLI)

#### Cloning & Scanning

```bash
# Shallow clone (saves bandwidth)
git clone --depth 1 <repo_url>

# Scan with Gitleaks
gitleaks detect --source <repo_path> \
  --report-format json \
  --report-path report.json \
  --no-git --no-banner
```

#### Gitleaks v8+ JSON Parsing

```python
# Handle both v7 (dict) and v8+ (list) formats
if isinstance(data, list):
    findings_list = data
elif isinstance(data, dict):
    findings_list = data.get('Issues', []) or data.get('Report', [])

for finding in findings_list:
    secret = finding.get('Secret', '')
    rule = finding.get('RuleID', 'unknown')
    file = finding.get('File', 'unknown')

    # Truncate secret for safety
    safe_secret = secret[:20] + "..." if len(secret) > 20 else secret
```

**Findings:**
- `LEAKED_SECRET` (CRITICAL)

---

### 1.2 SASTScanner

**Tool:** `trufflehog`
**Purpose:** Deep git history scanning for verified live secrets.

#### Command
```bash
trufflehog filesystem <repos_dir> \
  --json --no-update --only-verified
```

#### Why `--only-verified`?

TruffleHog's verification mode actively tests discovered secrets against provider APIs:

| Without Verification | With Verification |
|---|---|
| Reports all potential secrets | Only reports live, valid secrets |
| High false-positive rate (~80%) | Near-zero false positives |
| Includes rotated/revoked keys | Excludes dead credentials |
| Confidence: MEDIUM | Confidence: CONFIRMED |

#### Output Format (NDJSON)
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
    "DetectorName": "AWS",
    "Verified": true
}
```

**Findings:**
- `DEEP_CODE_SECRET (VERIFIED)` (CRITICAL)

---

### 1.3 SBOMScanner

**Tools:** `trivy`, custom parsers
**Purpose:** Software Bill of Materials and dependency vulnerability scanning.

#### Lock Files Analyzed

| Ecosystem | Lock Files |
|---|---|
| **Node.js** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Python** | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| **Go** | `go.mod`, `go.sum` |
| **Rust** | `Cargo.lock` |
| **Java** | `pom.xml`, `build.gradle` |
| **PHP** | `composer.lock` |
| **Ruby** | `Gemfile.lock` |
| **.NET** | `*.csproj`, `packages.config` |

#### Trivy Command
```bash
trivy fs --scanners vuln --format json <repo_path>
```

#### Custom Vulnerability Patterns

For repositories without lock files, custom regex patterns detect vulnerable versions:

```python
vulnerable_patterns = [
    ('lodash<4.17.21', 'Prototype pollution'),
    ('requests<2.20.0', 'CRLF injection'),
    ('django<3.2', 'Multiple vulnerabilities'),
    ('flask<2.0', 'Security vulnerabilities'),
    ('express<4.17.3', 'Open redirect'),
    ('axios<0.21.1', 'SSRF vulnerability'),
]
```

**Findings:**
- `VULNERABLE_DEPENDENCY` (CRITICAL/HIGH/MEDIUM based on CVE severity)

---

### 1.4 IaCScanner

**Tools:** `checkov`, custom parsers
**Purpose:** Infrastructure as Code security scanning.

#### Checkov Command
```bash
checkov -d <repo_path> --output json --quiet
```

#### JSON Parsing (Multi-Format Support)

```python
# Handle different Checkov output formats
if isinstance(report, dict):
    results = report.get('results', {})
    if isinstance(results, dict):
        failed_checks = results.get('failed_checks', [])
    elif isinstance(results, list):
        failed_checks = results
elif isinstance(report, list):
    failed_checks = report
```

#### Custom Checks (Beyond Checkov)

**Dockerfile Analysis:**
```python
# Missing USER directive → Running as root
if 'USER' not in dockerfile_content:
    # DOCKERFILE_RUNNING_AS_ROOT (MEDIUM)

# Secrets in ENV/ARG
if re.search(r'(PASSWORD|SECRET|API_KEY)', dockerfile_content):
    # DOCKERFILE_SECRET_LEAK (HIGH)
```

**Terraform Analysis:**
```python
# Public S3 bucket
if 'acl = "public"' in terraform_content:
    # TERRAFORM_PUBLIC_S3 (HIGH)

# Open security group
if '0.0.0.0/0' in terraform_content:
    # TERRAFORM_OPEN_SECURITY_GROUP (HIGH)
```

**Kubernetes Analysis:**
```python
# Privileged pod
if 'privileged: true' in k8s_manifest:
    # K8S_PRIVILEGED_POD (HIGH)

# Host filesystem mount
if 'hostPath:' in k8s_manifest:
    # K8S_HOSTPATH_MOUNT (MEDIUM)
```

**Findings:**
- `IAC_MISCONFIGURATION` (HIGH/MEDIUM)
- `DOCKERFILE_RUNNING_AS_ROOT` (MEDIUM)
- `DOCKERFILE_SECRET_LEAK` (HIGH)
- `TERRAFORM_PUBLIC_S3` (HIGH)
- `TERRAFORM_OPEN_SECURITY_GROUP` (HIGH)
- `K8S_PRIVILEGED_POD` (HIGH)
- `K8S_HOSTPATH_MOUNT` (MEDIUM)

---

## 🕵️ 2. OSINT & Monitoring Modules

### 2.1 PasteMonitor

**Tools:** `PyGithub`, Python `requests`
**Purpose:** Monitor paste sites and GitHub for leaked data.

#### Strategy 1: GitHub Code Search

```python
queries = [
    f'"{self.target}"',
    f'"{self.target.split(".")[0]}" password OR secret OR api_key',
    f'"{self.target}" internal OR staging OR dev',
]

for query in queries:
    results = g.search_code(query, sort="indexed", order="desc")
    for code in results[:15]:  # Limit to avoid rate limits
        content = code.decoded_content.decode("utf-8", errors="ignore")[:5000]

        # Check for high-value patterns
        for pattern in HIGH_VALUE_PATTERNS:
            if pattern.search(content):
                # GITHUB_CODE_LEAK (HIGH)
```

#### Strategy 2: GitHub Commit Search

```python
# Search for target-related emails in commit history
query = f'author:{target_base} OR committer:{target_base}'
results = g.search_commits(query, sort="author-date", order="desc")

for commit in results[:30]:
    author_email = commit.commit.author.email
    # Filter out noreply@github.com and privacy proxies
    if target_base.lower() in email.lower():
        # GITHUB_COMMIT_EMAIL (INFO)
```

#### Strategy 3: Paste Site Monitoring

Uses DuckDuckGo HTML search (no API key needed) to find pastes:

```python
search_queries = [
    f'site:pastebin.com "{self.target}"',
    f'site:ghostbin.com "{self.target}"',
    f'site:dpaste.org "{self.target}"',
]

# Extract paste URLs from search results
paste_pattern = re.compile(r'https?://(?:pastebin\.com|ghostbin\.com|dpaste\.org)/[a-zA-Z0-9]+')
```

#### High-Value Patterns

```python
HIGH_VALUE_PATTERNS = [
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),              # AWS Access Key
    re.compile(r"(?i)ghp_[a-zA-Z0-9]{36}"),           # GitHub PAT
    re.compile(r"(?i)(sk_live_|sk_test_)[a-zA-Z0-9]{24,}"),  # Stripe
    re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r'(?i)(DB_PASSWORD|DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*[:=]\s*["\']?[^\s"\']+'),
    re.compile(r"(?i)internal[-.]" + re.escape(target_base)),
]
```

**Findings:**
- `GITHUB_CODE_LEAK` (HIGH)
- `GITHUB_COMMIT_EMAIL` (INFO)
- `PASTE_SITE_LEAK` (HIGH)
- `PASTE_SITE_MENTION` (MEDIUM)

---

### 2.2 EmailOSINT

**Tool:** Python `requests`
**Purpose:** Perform OSINT on discovered email addresses.

#### Username Reuse Detection

Checks 10+ platforms for username reuse:

```python
PLATFORMS = {
    'GitHub': 'https://github.com/{}',
    'Twitter': 'https://twitter.com/{}',
    'LinkedIn': 'https://www.linkedin.com/in/{}',
    'Instagram': 'https://instagram.com/{}',
    'GitLab': 'https://gitlab.com/{}',
    'Bitbucket': 'https://bitbucket.org/{}/',
    'Reddit': 'https://reddit.com/user/{}',
    'Medium': 'https://medium.com/@{}',
    'Dev.to': 'https://dev.to/{}',
    'HackerNews': 'https://news.ycombinator.com/user?id={}',
}

# Try both original and cleaned username
for uname in [username, clean_username]:
    url = url_template.format(uname)
    if self._check_platform(platform, url):
        platforms_found.append(f'{platform} ({uname})')
```

#### Suspicious TLD Detection

```python
suspicious_tlds = ['ru', 'cn', 'top', 'xyz', 'club', 'work']
if any(domain.endswith(f'.{tld}') for tld in suspicious_tlds):
    # SUSPICIOUS_EMAIL_DOMAIN (LOW)
```

**Findings:**
- `USERNAME_REUSE` (INFO)
- `SUSPICIOUS_EMAIL_DOMAIN` (LOW)

---

## 🧠 3. AI-Powered Analysis Modules

MEAT-GRINDER features a **hybrid AI architecture** that combines local privacy (Ollama) with cloud intelligence (Gemini).

### 3.1 AIAnalyzer

**Tool:** Hybrid AI Engine (Local Ollama / Cloud Gemini)
**Purpose:** Analyzes HIGH/CRITICAL findings to append business impact and remediation steps.

#### How It Works

```python
for finding in high_value_findings:
    # Redact secrets before sending to cloud AI
    safe_details = self.ai.redact_secrets(finding["details"])

    prompt = f"""You are an expert application security engineer.

Finding Type: {finding['finding_type']}
Target: {finding['url']}
Context: {safe_details}

Provide EXACTLY two lines:
Business Impact: [one sentence]
Remediation: [one sentence]"""

    # Use LOCAL Ollama (sensitive=True) to protect secrets
    response = self.ai.ask(prompt, sensitive=True, max_tokens=200)

    # Append to finding details
    new_details = f"{finding['details']}\n\n[AI Analysis]\n{response}"
```

#### Secret Redaction

```python
@staticmethod
def redact_secrets(text: str) -> str:
    # Redact long alphanumeric strings (likely keys/tokens)
    text = re.sub(r'[A-Za-z0-9_\-]{32,}', '[REDACTED_SECRET]', text)
    # Redact common secret patterns
    text = re.sub(r'(?i)(AKIA|ghp_|sk_live_|sk_test_)[A-Za-z0-9]{16,}', '[REDACTED_KEY]', text)
    text = re.sub(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END',
                  '[REDACTED_PRIVATE_KEY]-----END', text)
    return text
```

#### Example Output

**Before AI Analysis:**
```
- **[EXPOSED_SENSITIVE_FILE]** `https://vulnbank.org/.env`
  - *Details:* Status: 200, Regex matched potential secrets/config data
```

**After AI Analysis:**
```
- **[EXPOSED_SENSITIVE_FILE]** `https://vulnbank.org/.env`
  - *Details:* Status: 200, Regex matched potential secrets/config data

  [AI Analysis]
  Business Impact: Exposure of environment variables can lead to complete
  database compromise, credential stuffing, and lateral movement within
  the cloud infrastructure.
  Remediation: Immediately rotate all exposed credentials, remove the .env
  file from the web root, and configure the web server to deny access to
  dotfiles.
```

**Findings:** Enhances existing findings (no new finding types created)

---

### 3.2 AIReconHunter

**Tool:** Hybrid AI Engine
**Purpose:** Generates intelligent, context-aware attack surfaces.

#### Phase 1: Context-Aware Wordlist Generation

Traditional wordlists are generic. AI generates **target-specific paths** based on discovered tech stack and industry.

```python
prompt = f"""You are an expert penetration tester performing recon.

TARGET: {context['target']}
TECH STACK: {', '.join(context['tech_stack'])}
KNOWN SUBDOMAINS: {', '.join(context['subdomains'][:10])}
KNOWN ENDPOINTS: {', '.join(context['endpoints'][:10])}
OPEN PORTS: {', '.join(context['ports'])}

Generate exactly 20 HIGH-VALUE paths that are:
1. Specific to this target's industry and tech stack
2. Often missed by generic wordlists
3. Likely to contain sensitive functionality

Return ONLY a JSON array of path strings."""

paths = self.ai.ask_json(prompt, sensitive=False, max_tokens=800)

# Probe AI-generated paths against live endpoints
self._test_ai_paths(paths)
```

**Example AI-generated paths for a bank:**
```json
[
    "/api/internal/debug/vars",
    "/oauth/token",
    "/swift/mt103",
    "/corebanking/admin",
    "/api/v1/transfers/limits",
    "/graphql/introspection",
    "/.well-known/jwks.json",
    "/api/health/detailed"
]
```

**Findings:**
- `AI_GENERATED_ENDPOINT` (HIGH if 200/500, MEDIUM if 401/403/405)

#### Phase 2: Business Logic Attack Suggestions

```python
prompt = f"""You are a senior application security engineer.
Analyze these API endpoints and suggest 5 specific business logic attacks.

TARGET: {context['target']}
API ENDPOINTS: {json.dumps(api_endpoints[:15])}

For each attack, provide:
- name: Short attack name
- endpoint: Target endpoint
- test: Specific parameter manipulation to test
- impact: Expected business impact

Return as JSON array."""

attacks = self.ai.ask_json(prompt, sensitive=False, max_tokens=1200)
```

**Example Output:**
```json
[
    {
        "name": "IDOR on Balance Endpoint",
        "endpoint": "/api/users/{id}/balance",
        "test": "Change {id} to other user IDs",
        "impact": "Unauthorized balance viewing"
    }
]
```

**Findings:**
- `AI_LOGIC_ATTACK_SUGGESTION` (MEDIUM)

#### Phase 3: Attack Path Chaining

The AI analyzes the entire SQLite database and chains isolated findings into realistic attack narratives.

```python
prompt = f"""You are a red team lead. Chain these findings into
realistic attack paths against {context['target']}.

FINDINGS:
{findings_text}

Generate 3 attack paths. For each:
- name: Short path name
- steps: Array of 2-4 concrete steps
- impact: Final business impact
- difficulty: Easy/Medium/Hard

Return as JSON array."""

paths = self.ai.ask_json(prompt, sensitive=False, max_tokens=1500)
```

**Example Attack Path:**
```
Staging_to_Prod_Pivot [Easy]:
1. Discover staging subdomain via TLS SAN
2. Find exposed .env on staging
3. Reuse DB credentials on production
4. Full database compromise

Final Impact: Complete database takeover
```

**Findings:**
- `AI_ATTACK_PATH` (CRITICAL if Easy, HIGH if Medium, MEDIUM if Hard)

---

## 🏗️ 4. Hybrid AI Architecture

### Routing Logic

MEAT-GRINDER intelligently routes AI requests based on data sensitivity:

```python
def ask(self, prompt: str, sensitive: bool = False, max_tokens: int = 1000) -> str:
    if sensitive and self.config.AI_USE_LOCAL_FOR_SECRETS:
        backend = "🟢 Local Ollama"
        return self.ask_local(prompt, max_tokens)
    elif not sensitive and self.config.AI_USE_CLOUD_FOR_REASONING and self.gemini_client:
        backend = "🔵 Cloud Gemini"
        return self.ask_cloud(prompt, max_tokens)
    else:
        backend = "🟢 Local Ollama (Fallback)"
        return self.ask_local(prompt, max_tokens)
```

### Backend Comparison

| Feature | Local Ollama | Cloud Gemini |
|---|---|---|
| **Privacy** | ✅ 100% private | ⚠️ Data sent to Google |
| **Speed** | ⚠️ 5-15 tokens/sec | ✅ 100+ tokens/sec |
| **Reasoning Quality** | ⚠️ Good | ✅ Excellent |
| **Cost** | ✅ Free | ⚠️ API costs |
| **Hardware Required** | ⚠️ 8GB+ RAM | ✅ None |
| **Best For** | Secret analysis | Attack paths, wordlists |

### Configuration Scenarios

#### Scenario 1: Maximum Privacy (Air-gapped)
```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=true
AI_USE_CLOUD_FOR_REASONING=false
GEMINI_API_KEY=
```

#### Scenario 2: Maximum Intelligence (Cloud-only)
```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=false
AI_USE_CLOUD_FOR_REASONING=true
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### Scenario 3: Balanced (Default)
```env
AI_ENABLED=true
AI_USE_LOCAL_FOR_SECRETS=true
AI_USE_CLOUD_FOR_REASONING=true
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Console Output

The engine shows which backend is handling each query:

```text
[*] 🧠 AI Analyzer: Enhancing findings with context...
    [🟢 Local Ollama] You are an expert application security engineer...
    [🟢 Local Ollama] You are an expert application security engineer...
[+] 🧠 AI analysis complete. Enhanced 8 findings.

[*] 🧠 AI Recon Hunter: Generating intelligent attack surface...
    [🔵 Cloud Gemini] You are an expert penetration tester...
[+] 🧠 AI wordlist discovered 3 new accessible paths
    [🔵 Cloud Gemini] You are a red team lead. Chain these findings...
[+] 🧠 AI identified 3 attack paths
```

---

## 📊 Module Summary Table

| # | Module | Tool(s) | Primary Output |
|---|---|---|---|
| 1 | GitScanner | PyGithub, gitleaks | Git secrets |
| 2 | SASTScanner | trufflehog | Verified live secrets |
| 3 | SBOMScanner | trivy, custom parsers | Dependency vulnerabilities |
| 4 | IaCScanner | checkov, custom parsers | IaC misconfigurations |
| 5 | PasteMonitor | PyGithub, requests | Paste site leaks |
| 6 | EmailOSINT | requests | Username reuse |
| 7 | AIAnalyzer | Ollama/Gemini | Enhanced finding context |
| 8 | AIReconHunter | Ollama/Gemini | Smart wordlists, attack paths |

---

## 🔗 Cross-Reference: Modules → Finding Types

| Module | Finding Types Generated |
|---|---|
| `GitScanner` | `LEAKED_SECRET` |
| `SASTScanner` | `DEEP_CODE_SECRET (VERIFIED)` |
| `SBOMScanner` | `VULNERABLE_DEPENDENCY` |
| `IaCScanner` | `IAC_MISCONFIGURATION`, `DOCKERFILE_RUNNING_AS_ROOT`, `DOCKERFILE_SECRET_LEAK`, `TERRAFORM_PUBLIC_S3`, `TERRAFORM_OPEN_SECURITY_GROUP`, `K8S_PRIVILEGED_POD`, `K8S_HOSTPATH_MOUNT` |
| `PasteMonitor` | `GITHUB_CODE_LEAK`, `GITHUB_COMMIT_EMAIL`, `PASTE_SITE_LEAK`, `PASTE_SITE_MENTION` |
| `EmailOSINT` | `USERNAME_REUSE`, `SUSPICIOUS_EMAIL_DOMAIN` |
| `AIAnalyzer` | (Enhances existing findings) |
| `AIReconHunter` | `AI_GENERATED_ENDPOINT`, `AI_LOGIC_ATTACK_SUGGESTION`, `AI_ATTACK_PATH` |

---

## 📌 Key Design Principles

1. **Relevance Filtering:** GitScanner uses a 0-100 scoring algorithm to avoid wasting time on unrelated CTFs and tutorials.
2. **Verification-First:** TruffleHog actively tests secrets to eliminate false positives.
3. **Privacy by Design:** Sensitive data (secrets) processed locally via Ollama; only non-sensitive reasoning uses cloud AI.
4. **Graceful Degradation:** If Gemini API fails, engine falls back to Ollama automatically.
5. **Secret Redaction:** All prompts sent to cloud AI have secrets redacted before transmission.
6. **JSON Robustness:** AI responses are parsed with multiple fallback strategies (direct parse, markdown extraction, regex).
7. **Context-Aware AI:** AI modules receive rich context (tech stack, endpoints, findings) to generate targeted, relevant output.

---

## 🚀 Performance Considerations

### AI Module Performance

| Task | Backend | Typical Latency |
|---|---|---|
| Finding analysis (per finding) | Local Ollama | 3-8 seconds |
| Wordlist generation | Cloud Gemini | 2-4 seconds |
| Attack path chaining | Cloud Gemini | 3-5 seconds |

### Optimization Tips

1. **Limit findings analyzed:** Only CRITICAL/HIGH findings go through AIAnalyzer
2. **Cap wordlist size:** AI generates 20 paths max, probed concurrently
3. **Use smaller Ollama models:** `llama3.2:1b` is 5x faster than `llama3.2`
4. **Enable caching:** Gemini responses can be cached for repeated prompts

### Hardware Requirements

**For Local Ollama:**
- **Minimum:** 8GB RAM, integrated graphics
- **Recommended:** 16GB RAM, dedicated GPU (6GB+ VRAM)
- **Optimal:** 32GB RAM, NVIDIA GPU with CUDA

**For Cloud Gemini:**
- No local hardware requirements
- Requires valid API key
- Free tier: 60 requests/minute

---

*Last Updated: 2026-11-22*
*Total Modules: 8*
*Total AI Finding Types: 3*
*Total Traditional Finding Types: 25+*
