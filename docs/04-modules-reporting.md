# 📊 Reporting & Evidence Modules

This document covers the final phase of MEAT-GRINDER's execution pipeline: filtering, evidence capture, and report
generation. These modules transform raw findings into actionable, stakeholder-ready intelligence.

---

## 📋 Module Categories Overview

| Category                      | Modules | Purpose                                            |
|-------------------------------|---------|----------------------------------------------------|
| **Filtering & Deduplication** | 1       | Remove noise, assign confidence, track occurrences |
| **Evidence Capture**          | 1       | Visual proof via browser screenshots               |
| **Report Generation**         | 2       | Markdown and PDF reports with charts               |

---

## 🔍 1. Filtering & Deduplication Modules

### 1.1 InsightFilter

**Tool:** Python (custom logic)
**Purpose:** Deduplicate findings and assign confidence levels.

#### Deduplication Algorithm

The `InsightFilter` generates a **SHA256 fingerprint** for each finding to prevent duplicate entries in the database:

```python
def generate_fingerprint(finding_type, url, details, file_path, rule_id):
    """Generate a unique fingerprint for deduplication."""
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

**Why truncate to 16 chars?**

- Full SHA256 (64 chars) is overkill for deduplication
- 16 chars (64 bits) provides 18 quintillion unique combinations
- Saves database space and speeds up lookups

#### Confidence Assignment

Each finding type has a default confidence level based on validation rigor:

```python
DEFAULT_CONFIDENCE = {
    # Confirmed via active verification
    'EXPOSED_SENSITIVE_FILE': ConfidenceLevel.CONFIRMED,
    'DEEP_CODE_SECRET': ConfidenceLevel.CONFIRMED,
    'SUBDOMAIN_TAKEOVER_VULNERABLE': ConfidenceLevel.CONFIRMED,

    # High confidence via regex patterns
    'LEAKED_SECRET': ConfidenceLevel.HIGH,
    'HARDCODED_SECRET_IN_WEB_FILE': ConfidenceLevel.HIGH,
    'MISSING_HSTS': ConfidenceLevel.HIGH,

    # Medium confidence via heuristics
    'CLOUD_ASSET_DISCOVERED': ConfidenceLevel.MEDIUM,
    'DANGLING_CNAME': ConfidenceLevel.MEDIUM,

    # Low confidence (informational)
    'HTML_COMMENT_LEAK': ConfidenceLevel.LOW,
    'DOMAIN_WHOIS_INFO': ConfidenceLevel.INFO,
}
```

#### Occurrence Tracking

When a duplicate finding is detected, the filter increments the `occurrences` counter instead of inserting a new row:

```python
if finding_exists(fingerprint):
    # Update existing finding
    UPDATE
    findings
    SET
    occurrences = occurrences + 1, last_seen = CURRENT_TIMESTAMP
    WHERE
    fingerprint = ?
    else:
    # Insert new finding
    INSERT
    INTO
    findings(finding_type, url, details, severity, confidence, fingerprint, source_module)
    VALUES(?, ?, ?, ?, ?, ?, ?)
```

**Benefits:**

- Prevents database bloat from repeated scans
- Tracks finding persistence over time
- Enables `--diff` mode for continuous monitoring

#### Noise Reduction

The filter also applies additional noise reduction logic:

```python
# Skip low-value findings if too many exist
if finding_type == 'HTML_META_TAG' and count > 50:
    continue

# Prioritize verified secrets over potential secrets
if finding_type == 'DEEP_CODE_SECRET' and severity == 'CRITICAL':
    priority = 1
elif finding_type == 'LEAKED_SECRET' and severity == 'CRITICAL':
    priority = 2
else:
    priority = 3
```

**Database Impact:**

- Updates `findings` table: `occurrences`, `last_seen`
- No new tables created

---

## 📸 2. Evidence Capture Modules

### 2.1 BrowserEvidence

**Tool:** `playwright`
**Purpose:** Capture screenshots of high-severity findings for visual proof.

#### Why Playwright?

Traditional screenshot tools (Gowitness, EyeWitness) often fail against modern WAFs and anti-bot measures. Playwright
provides:

- **Stealth mode:** Bypasses basic bot detection
- **Full browser rendering:** JavaScript-heavy SPAs render correctly
- **Custom viewport:** 1920x1080 for consistent screenshots
- **Network idle detection:** Waits for all assets to load

#### Implementation

```python
async def capture_screenshots(self, target_urls: list):
    """Capture screenshots of target URLs using Playwright."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/120.0.0.0 Safari/537.36'
        )

        for i, url in enumerate(target_urls):
            try:
                page = await context.new_page()

                # Navigate with timeout
                await page.goto(url, timeout=30000, wait_until='networkidle')

                # Wait a bit for any lazy-loaded content
                await page.wait_for_timeout(2000)

                # Capture screenshot
                screenshot_path = self.workspace / 'screenshots' / f'screenshot_{i + 1}.png'
                await page.screenshot(path=str(screenshot_path), full_page=True)

                print(f"  ✓ Captured: {url}")

                await page.close()

            except Exception as e:
                print(f"  ✗ Failed to capture {url}: {e}")

        await browser.close()
```

#### Screenshot Selection

Not all findings get screenshots. The module prioritizes:

1. **CRITICAL findings** with HTTP URLs (`.env` files, admin panels)
2. **HIGH findings** with visual impact (exposed dashboards, error pages)
3. **MEDIUM findings** only if explicitly requested

```python
# Filter findings for screenshot capture
screenshot_candidates = [
    f for f in findings
    if f['severity'] in ['CRITICAL', 'HIGH']
       and f['url'].startswith('http')
       and f['finding_type'] in [
           'EXPOSED_SENSITIVE_FILE',
           'ADMIN_PANEL_DISCOVERED',
           'OPENAPI_EXPOSED',
           'NUCLEI_VULN/MISCONFIG'
       ]
]

# Limit to top 20 to avoid excessive capture time
screenshot_urls = [f['url'] for f in screenshot_candidates[:20]]
```

#### Output

Screenshots are saved to:

```text
workspaces/<target>/screenshots/
├── screenshot_1.png
├── screenshot_2.png
└── screenshot_3.png
```

And embedded in the final Markdown report:

```markdown
## 📸 Visual Evidence

### Screenshot 1

![Screenshot 1](screenshots/screenshot_1.png)

### Screenshot 2

![Screenshot 2](screenshots/screenshot_2.png)
```

**Database Impact:**

- No database changes
- Files stored in workspace directory

---

## 📄 3. Report Generation Modules

### 3.1 MarkdownReporter

**Tool:** Python (custom logic)
**Purpose:** Generate clean, severity-grouped Markdown reports.

#### Report Structure

```markdown
# OSINT Insight Report: <target>

**Generated:** <timestamp>

## Executive Summary

- **Actionable Findings:** X
- **Hosts with Open Ports:** Y
- **Live HTTP Endpoints:** Z

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

### CRITICAL Severity (X)

- **[EXPOSED_SENSITIVE_FILE]** `https://www.vulnbank.org/.env`
    - *Details:* Status: 200, Regex matched potential secrets/config data
    - *Confidence:* CONFIRMED
    - *First Seen:* 2026-11-19 10:15:23
    - *Last Seen:* 2026-11-19 10:15:23

### HIGH Severity (Y)

...

### MEDIUM Severity (Z)

...

## 📸 Visual Evidence

![Screenshot 1](screenshots/screenshot_1.png)
```

#### Implementation

```python
def generate(self):
    """Generate Markdown report."""
    findings = self.db.get_all_findings()
    ports = self.db.get_all_ports()
    endpoints = self.db.get_all_endpoints()

    # Group findings by severity
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    high = [f for f in findings if f['severity'] == 'HIGH']
    medium = [f for f in findings if f['severity'] == 'MEDIUM']

    # Build report sections
    report = f"""# OSINT Insight Report: {self.target}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- **Actionable Findings:** {len(findings)}
- **Hosts with Open Ports:** {len(ports)}
- **Live HTTP Endpoints:** {len(endpoints)}

## 🛡️ WAF & Firewall Detection
"""

    # Add WAF table
    report += self._build_waf_table(endpoints)

    # Add infrastructure tables
    report += self._build_infrastructure_tables(ports, endpoints)

    # Add findings by severity
    report += self._build_findings_section(critical, high, medium)

    # Add screenshots
    report += self._build_screenshots_section()

    # Write to file
    report_path = self.workspace / f"REPORT_{self.target}.md"
    with open(report_path, 'w') as f:
        f.write(report)

    print(f"[+] Report generated: {report_path}")
```

#### Diff Mode

When running with `--diff`, the reporter only includes findings discovered since the last scan:

```python
if self.diff_mode and self.last_scan:
    # Get only new findings
    findings = self.db.get_new_findings_since(self.last_scan)

    # Add diff header
    report = f"""# OSINT Insight Report: {self.target} (DIFF MODE)
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Comparing against:** {self.last_scan}

## New Findings Since Last Scan
"""
```

**Database Impact:**

- Reads from `findings`, `ports`, `endpoints` tables
- No writes

---

### 3.2 PDFReporter

**Tools:** `weasyprint`, `matplotlib`, `string.Template`
**Purpose:** Generate stakeholder-ready PDF reports with charts and visual analytics.

#### Architecture

The PDF reporter uses a **template-based approach** to separate logic from presentation:

```text
┌─────────────────────────────────────────────────────────┐
│  PDFReporter (Python)                                   │
│  ├─ Gather data from database                           │
│  ├─ Calculate risk score (0-100)                        │
│  ├─ Generate charts (matplotlib → base64 PNG)           │
│  ├─ Render HTML template (string.Template)              │
│  └─ Convert HTML → PDF (weasyprint)                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  reporting/templates/report.html                        │
│  ├─ Pure HTML/CSS (no Python)                           │
│  ├─ $PLACEHOLDER tokens for dynamic content             │
│  └─ Professional styling with print-optimized CSS       │
└─────────────────────────────────────────────────────────┘
```

#### Risk Score Calculation

The reporter calculates an overall risk score (0-100) based on finding severity:

```python
def _calculate_risk_score(self, findings: list) -> int:
    """Calculate overall risk score 0-100."""
    weights = {
        "CRITICAL": 25,
        "HIGH": 10,
        "MEDIUM": 3,
        "LOW": 1,
        "INFO": 0
    }
    score = sum(weights.get(f["severity"], 0) for f in findings)

    # Bonus for AI-confirmed attack paths
    attack_paths = sum(1 for f in findings if f["finding_type"] == "AI_ATTACK_PATH")
    score += attack_paths * 15

    return min(100, score)


def _risk_level(self, score: int) -> dict:
    """Map score to risk level with color and emoji."""
    if score >= 75:
        return {"level": "CRITICAL", "color": "#dc2626", "emoji": "🔴"}
    if score >= 50:
        return {"level": "HIGH", "color": "#ea580c", "emoji": "🟠"}
    if score >= 25:
        return {"level": "MEDIUM", "color": "#ca8a04", "emoji": "🟡"}
    return {"level": "LOW", "color": "#16a34a", "emoji": "🟢"}
```

#### Chart Generation

The reporter generates two charts using matplotlib:

**1. Severity Distribution Bar Chart**

```python
def _generate_severity_chart(self, findings: list) -> str:
    """Generate a severity distribution bar chart as base64 PNG."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a",
        "INFO": "#2563eb",
    }

    fig, ax = plt.subplots(figsize=(6, 3))
    bars = ax.bar(
        severity_counts.keys(),
        severity_counts.values(),
        color=[colors[k] for k in severity_counts.keys()],
    )
    ax.set_ylabel("Count", fontsize=10)
    ax.set_title("Findings by Severity", fontsize=12, fontweight="bold")

    # Add value labels on bars
    for bar, count in zip(bars, severity_counts.values()):
        if count > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.3,
                str(count),
                ha="center",
                fontsize=10,
                fontweight="bold",
            )

    # Convert to base64
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")
```

**2. Top Finding Types Horizontal Bar Chart**

```python
def _generate_findings_trend(self, findings: list) -> str:
    """Generate a finding-type breakdown chart."""
    type_counts = Counter(f["finding_type"] for f in findings)
    top_10 = type_counts.most_common(10)

    labels = [t[0].replace("_", " ") for t in top_10]
    values = [t[1] for t in top_10]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.barh(labels[::-1], values[::-1], color="#3b82f6")
    ax.set_xlabel("Count", fontsize=10)
    ax.set_title("Top Finding Types", fontsize=12, fontweight="bold")

    # Convert to base64
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")
```

#### HTML Template Rendering

The reporter uses Python's `string.Template` with `$PLACEHOLDER` syntax:

```python
def generate(self):
    """Generate PDF report."""
    # Load template
    template_path = Path(__file__).parent / "templates" / "report.html"
    template = Template(template_path.read_text(encoding="utf-8"))

    # Build context
    context = {
        "TARGET": self.target,
        "GENERATED_AT": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "AI_BACKEND_STATUS": self._determine_ai_status(),
        "RISK_EMOJI": risk["emoji"],
        "RISK_LEVEL": risk["level"],
        "RISK_COLOR": risk["color"],
        "RISK_SCORE": str(risk_score),
        "TOTAL_FINDINGS": str(len(findings)),
        "CRITICAL_COUNT": str(len(critical_findings)),
        # ... more variables ...
        "FINDINGS_HTML": self._render_findings(findings),
        "ATTACK_PATHS_HTML": self._render_attack_paths(findings),
        "CHARTS_HTML": self._render_charts(severity_chart_b64, findings_trend_b64),
    }

    # Render HTML
    html = template.safe_substitute(context)

    # Convert to PDF
    pdf_path = self.workspace / f"REPORT_{self.target}.pdf"
    HTML(string=html).write_pdf(str(pdf_path))
```

#### Template Structure

The HTML template (`reporting/templates/report.html`) includes:

**1. Cover Page**

```html
<div class="cover">
    <h1>🥩 MEAT-GRINDER</h1>
    <div class="target">$TARGET</div>
    <div class="risk-badge">$RISK_EMOJI $RISK_LEVEL RISK • SCORE $RISK_SCORE/100</div>
    <div>Generated: $GENERATED_AT</div>
</div>
```

**2. Executive Summary Metrics**

```html
<div class="metric-grid">
    <div class="metric">
        <div class="value">$TOTAL_FINDINGS</div>
        <div class="label">Total Findings</div>
    </div>
    <div class="metric">
        <div class="value" style="color: #dc2626;">$CRITICAL_COUNT</div>
        <div class="label">Critical</div>
    </div>
    <!-- ... more metrics ... -->
</div>
```

**3. Visual Analytics**

```html
<h1>📈 Visual Analytics</h1>
$CHARTS_HTML
```

**4. AI-Identified Attack Paths**

```html
<h2 style="color: #7c3aed;">🎯 AI-Identified Attack Paths</h2>
$ATTACK_PATHS_HTML
```

**5. Detailed Findings**

```html
<h1>🔍 Detailed Findings</h1>
$FINDINGS_HTML
```

**6. Infrastructure Tables**

```html
<table>
    <tr>
        <th>Host</th>
        <th>IP</th>
        <th>OS</th>
        <th>Open Ports</th>
    </tr>
    $PORTS_TABLE_ROWS
</table>
```

#### PDF Generation with WeasyPrint

```python
from weasyprint import HTML

# Convert HTML to PDF
HTML(string=html).write_pdf(str(pdf_path))
```

**WeasyPrint features:**

- Print-optimized CSS (`@page` rules for A4 size, margins)
- Page numbers and headers/footers
- Automatic page breaks
- Embedded base64 images (charts)
- Professional typography

#### Report Sections

**1. Cover Page**

- Target name
- Risk badge (🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW)
- Risk score (0-100)
- Generation timestamp
- AI backend status

**2. Executive Summary**

- 8 key metrics in a grid:
    - Total findings
    - Critical count
    - Subdomains
    - Live endpoints
    - Hosts with open ports
    - High severity count
    - AI attack paths
    - AI-generated findings

**3. Visual Analytics**

- Severity distribution bar chart
- Top finding types horizontal bar chart

**4. AI-Identified Attack Paths**

- Purple-highlighted section
- Step-by-step attack narratives
- Difficulty ratings (Easy/Medium/Hard)

**5. Infrastructure Overview**

- Hosts & services table
- Web servers & WAFs table

**6. Detailed Findings**

- Grouped by severity (CRITICAL → INFO)
- Color-coded by severity
- Includes AI analysis (business impact + remediation)

**7. Footer**

- Confidentiality notice
- Generation timestamp
- AI backend attribution

**Database Impact:**

- Reads from `findings`, `ports`, `endpoints`, `subdomains` tables
- No writes

---

## 📊 Module Summary Table

| # | Module           | Tool(s)                          | Primary Output         |
|---|------------------|----------------------------------|------------------------|
| 1 | InsightFilter    | Python (custom)                  | Deduplicated findings  |
| 2 | BrowserEvidence  | Playwright                       | PNG screenshots        |
| 3 | MarkdownReporter | Python (custom)                  | Markdown report        |
| 4 | PDFReporter      | WeasyPrint, matplotlib, Template | PDF report with charts |

---

## 🔗 Cross-Reference: Modules → Output

| Module           | Database Writes                             | File Outputs          |
|------------------|---------------------------------------------|-----------------------|
| InsightFilter    | Updates `findings` (occurrences, last_seen) | None                  |
| BrowserEvidence  | None                                        | `screenshots/*.png`   |
| MarkdownReporter | None                                        | `REPORT_<target>.md`  |
| PDFReporter      | None                                        | `REPORT_<target>.pdf` |

---

## 📌 Key Design Principles

1. **Separation of Concerns:** PDF template is pure HTML/CSS, separate from Python logic.
2. **Visual Proof:** Screenshots provide undeniable evidence for stakeholders.
3. **Risk Scoring:** Quantitative risk assessment (0-100) enables quick decision-making.
4. **Deduplication:** SHA256 fingerprints prevent database bloat and enable tracking.
5. **Template-Based:** HTML templates allow designers to customize reports without touching Python.
6. **Chart Integration:** Matplotlib charts embedded as base64 PNG for portability.
7. **AI Attribution:** Reports clearly indicate which AI backend was used (Local Ollama vs Cloud Gemini).

---

## 🎨 PDF Report Features

### Cover Page

- Large, bold target name
- Color-coded risk badge
- Professional branding

### Executive Summary

- 8 key metrics in a clean grid
- Color-coded severity counts
- Quick-glance risk assessment

### Visual Analytics

- Severity distribution bar chart
- Top finding types horizontal bar chart
- Auto-generated from database

### AI Attack Paths

- Purple gradient background
- Step-by-step attack narratives
- Difficulty ratings

### Detailed Findings

- Grouped by severity
- Color-coded borders
- AI-enhanced with business impact and remediation

### Infrastructure Tables

- Hosts, IPs, OS, ports
- Web servers and WAFs
- Clean, readable formatting

### Print Optimization

- A4 page size
- 2cm margins
- Page numbers
- Headers/footers
- Professional typography

---

## 🚀 Performance Considerations

### Screenshot Capture

- **Time:** ~2-5 seconds per screenshot
- **Limit:** Top 20 findings to avoid excessive runtime
- **Optimization:** Use `--no-screenshots` flag for faster scans

### PDF Generation

- **Time:** ~5-15 seconds for typical reports
- **Bottleneck:** WeasyPrint HTML rendering
- **Optimization:** Limit findings to top 50 per severity

### Chart Generation

- **Time:** ~1-2 seconds per chart
- **Optimization:** Charts generated once and reused

---

## 🔒 Security Considerations

### Screenshot Storage

- Screenshots may contain sensitive information
- Store in secure workspace directory
- Delete after report delivery
- Never commit to Git

### Report Distribution

- PDF reports are confidential
- Use encryption for email delivery
- Redact secrets before sharing (`REDACT_SECRETS=true`)
- Track report access

### AI Backend Attribution

- Reports clearly indicate which AI was used
- Stakeholders can assess data privacy implications
- Local Ollama = 100% private
- Cloud Gemini = data sent to Google

---

*Last Updated: 2026-11-22*
*Total Modules: 4*
*Report Formats: 2 (Markdown, PDF)*
*Chart Types: 2 (Severity distribution, Finding types)*
