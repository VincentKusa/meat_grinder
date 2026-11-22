# 🔧 Troubleshooting Guide

This document provides solutions to common errors, edge cases, and diagnostic techniques for MEAT-GRINDER.

---

## 📋 Quick Diagnostic Commands

Before diving into specific issues, run these commands to verify your setup:

```bash
# Check all required tools
python3 main.py example.com --doctor

# Verify Python environment
python3 --version
pip list | grep -E "requests|beautifulsoup4|PyGithub|dnspython|playwright|weasyprint|matplotlib|google-genai"

# Check Ollama status
curl http://localhost:11434/api/tags

# Verify database integrity
sqlite3 workspaces/<target>/recon_data.db "PRAGMA integrity_check;"

# Check disk space
df -h workspaces/

# Monitor resource usage during scan
htop
```

---

## 🚨 Installation Issues

### 1. "httpx: No such option '-l'"

**Problem:** Python `httpx` package is shadowing ProjectDiscovery's `httpx` binary.

**Solution:**

```bash
# Option A: Uninstall Python httpx (if not needed elsewhere)
pip uninstall httpx -y

# Option B: Rename ProjectDiscovery binary (recommended)
# In config.py, change:
HTTPX_BIN = "pdhttpx"

# Then rename the actual binary:
sudo mv $(which httpx) $(which httpx).bak
sudo ln -s /usr/local/bin/httpx /usr/local/bin/pdhttpx
```

**Verification:**

```bash
pdhttpx -version
# Should show ProjectDiscovery httpx version
```

---

### 2. "nuclei: no templates provided"

**Problem:** Nuclei templates not installed or corrupted.

**Solution:**

```bash
# Remove old templates
rm -rf ~/.local/nuclei-templates

# Download fresh templates
wget -qO /tmp/nuclei-templates.zip \
  https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip

# Extract and install
unzip -q /tmp/nuclei-templates.zip -d /tmp/
mkdir -p ~/.local/nuclei-templates
mv /tmp/nuclei-templates-main/* ~/.local/nuclei-templates/

# Verify
nuclei -tl | wc -l
# Should show 10,000+ templates
```

**Alternative:** Let Nuclei auto-download:

```bash
nuclei -update-templates
```

---

### 3. "trivy: Permission denied"

**Problem:** Trivy installed without proper permissions.

**Solution:**

```bash
# Reinstall with sudo
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
  sudo sh -s -- -b /usr/local/bin

# Verify
trivy --version
```

**Alternative:** Install via package manager:

```bash
# Ubuntu/Debian
sudo apt install trivy

# Or use Docker
docker run aquasec/trivy filesystem /path/to/repo
```

---

### 4. "greenlet build failed" (Playwright)

**Problem:** Python 3.14 or incompatible greenlet version.

**Solution:**

```bash
# Update requirements.txt to use flexible version
# Change: playwright==1.40.0
# To:     playwright>=1.45.0

# Reinstall
pip install --upgrade playwright

# Install browser binaries
playwright install chromium
```

**If still failing:**

```bash
# Install system dependencies
sudo apt install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
  libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
  libxrandr2 libgbm1 libasound2

# Reinstall Playwright
pip uninstall playwright -y
pip install playwright
playwright install --with-deps chromium
```

---

### 5. "checkov/mobsfscan dependency conflicts"

**Problem:** Conflicting Python package versions in main environment.

**Solution:** Use `pipx` for isolated installations:

```bash
# Install pipx if not present
sudo apt install pipx
pipx ensurepath

# Install tools in isolated environments
pipx install checkov
pipx install mobsfscan

# Verify
checkov --version
mobsfscan --version
```

**Why this works:** `pipx` creates separate virtual environments for each tool, preventing dependency conflicts with
your main project.

---

### 6. "Gowitness failed" / Headless browser issues

**Problem:** Cloudflare or anti-bot measures blocking headless browsers.

**Solution:** MEAT-GRINDER already uses Playwright (not Gowitness) for browser evidence. If Playwright fails:

```bash
# Use stealth mode (already implemented in BrowserEvidence module)
# If still blocked, disable screenshots:
python3 main.py example.com --no-screenshots
```

---

### 7. "google-genai not found"

**Problem:** AI integration packages not installed.

**Solution:**

```bash
pip install google-genai weasyprint matplotlib

# Verify
python3 -c "from google import genai; print('OK')"
```

---

## ⚙️ Runtime Errors

### 8. "GitHub API rate limit exceeded"

**Problem:** Unauthenticated API calls hitting rate limits (60 requests/hour).

**Solution:**

```bash
# Add GitHub token to .env
echo "GITHUB_TOKEN=ghp_your_token_here" >> .env

# Generate token at: https://github.com/settings/tokens
# Required scope: repo (read-only is sufficient)
```

**Verify:**

```bash
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/rate_limit | grep remaining
```

---

### 9. "TruffleHog returns 0 verified secrets"

**Problem:** This is **normal behavior**, not an error!

**Explanation:** TruffleHog's `--only-verified` flag actively tests discovered secrets against provider APIs. If secrets
have been:

- Rotated/revoked
- Test fixtures/dummy keys
- Already patched

Then TruffleHog correctly reports 0 verified secrets.

**To see unverified secrets (for debugging):**

```python
# In engine/sast_scanner.py, temporarily remove --only-verified
cmd = f"{Config.TRUFFLEHOG_BIN} filesystem '{repos_dir}' --json --no-update"
```

**Warning:** Unverified secrets have high false-positive rates.

---

### 10. "Playwright: OS not officially supported"

**Problem:** Kali Linux not in Playwright's official support list.

**Solution:** **Ignore this warning.** The fallback Ubuntu 24.04 build works perfectly on Kali.

**If screenshots fail:**

```bash
# Install missing dependencies
sudo apt install -y libglib2.0-0 libnss3 libnspr4 libatk1.0-0 \
  libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
  libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2

# Reinstall Playwright browsers
playwright install --with-deps chromium
```

---

### 11. "sqlite3.OperationalError: table has no column named X"

**Problem:** Database schema is outdated (created with older version of MEAT-GRINDER).

**Solution:**

```bash
# Option A: Delete old database (loses historical data)
rm workspaces/<target>/recon_data.db

# Option B: Let auto-migration run (recommended)
# The engine will automatically add missing columns on next run
python3 main.py <target>
```

**Manual migration (if needed):**

```bash
sqlite3 workspaces/<target>/recon_data.db

# Add missing columns
ALTER TABLE endpoints ADD COLUMN title TEXT;
ALTER TABLE endpoints ADD COLUMN waf_detected TEXT;
# ... etc

.quit
```

---

### 12. "Ollama connection refused"

**Problem:** Ollama service not running.

**Solution:**

```bash
# Start Ollama service
sudo systemctl start ollama
sudo systemctl enable ollama

# Verify
curl http://localhost:11434/api/tags

# Check logs
sudo journalctl -u ollama -f
```

**If service won't start:**

```bash
# Check if port 11434 is in use
sudo lsof -i :11434

# Kill conflicting process
sudo kill -9 <PID>

# Restart
sudo systemctl restart ollama
```

---

### 13. "Gemini API key invalid"

**Problem:** Invalid or expired Gemini API key.

**Solution:**

```bash
# Verify key at: https://aistudio.google.com/apikey
# Regenerate if needed

# Test key
python3 -c "
from google import genai
from google.genai import types
client = genai.Client(api_key='YOUR_KEY_HERE')
response = client.models.generate_content(
    model='gemini-2.0-flash-exp',
    contents='Say hello',
    config=types.GenerateContentConfig()
)
print(response.text)
"
```

---

## 🧠 AI Integration Issues

### 14. "AI Analyzer: No AI backend available"

**Problem:** Neither Ollama nor Gemini is configured.

**Solution:**

```bash
# Option A: Enable Ollama (local, private)
sudo systemctl start ollama
ollama pull llama3.2

# Option B: Enable Gemini (cloud, faster)
# Add to .env:
GEMINI_API_KEY=your_key_here
AI_USE_CLOUD_FOR_REASONING=true

# Option C: Disable AI entirely
# In .env:
AI_ENABLED=false
```

---

### 15. "AI responses are slow (10+ seconds per finding)"

**Problem:** Ollama running on CPU without GPU acceleration.

**Solution:**

```bash
# Option A: Use smaller model
# In .env:
OLLAMA_MODEL=llama3.2:1b  # 1B parameter version, much faster

# Option B: Switch to Gemini for all tasks
# In .env:
AI_USE_LOCAL_FOR_SECRETS=false
AI_USE_CLOUD_FOR_REASONING=true

# Option C: Reduce number of findings analyzed
# Only analyze CRITICAL findings (edit engine/ai_analyzer.py):
high_value = [f for f in findings if f["severity"] == "CRITICAL"]
```

**Hardware check:**

```bash
# Check if GPU is being used
ollama ps
# Should show "GPU" in the output if NVIDIA GPU detected
```

---

### 16. "AI generates invalid JSON"

**Problem:** LLM returns malformed JSON, breaking parsing.

**Solution:** The `AIEngine._extract_json()` method already handles this with multiple fallback strategies:

1. Direct JSON parse
2. Extract from markdown code blocks
3. Extract raw JSON arrays/objects

**If still failing:**

```python
# Add debug logging in engine/ai_engine.py
def ask_json(self, prompt: str, ...) -> Any:
    response = self.ask(prompt, ...)
    print(f"[DEBUG] AI Response: {response[:200]}")  # Add this line
    return self._extract_json(response)
```

---

## 📊 PDF & Report Generation Issues

### 17. "WeasyPrint not installed"

**Problem:** PDF generation dependencies missing.

**Solution:**

```bash
pip install weasyprint matplotlib

# Install system dependencies
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

---

### 18. "PDF report is blank or missing charts"

**Problem:** Matplotlib or WeasyPrint rendering issues.

**Solution:**

```bash
# Test chart generation
python3 -c "
import matplotlib.pyplot as plt
import io, base64
fig, ax = plt.subplots()
ax.bar(['A', 'B'], [1, 2])
buf = io.BytesIO()
plt.savefig(buf, format='png')
print('Chart generation OK')
"

# If fails, reinstall matplotlib
pip install --upgrade matplotlib
```

---

### 19. "PDF generation hangs or takes forever"

**Problem:** Large number of findings or screenshots.

**Solution:**

```bash
# Limit findings in report (edit reporting/pdf_reporter.py)
# In _render_findings():
for f in sev_findings[:50]:  # Limit to 50 per severity

# Disable screenshots
python3 main.py example.com --no-screenshots

# Check PDF size
ls -lh workspaces/*/REPORT_*.pdf
# Should be < 50MB for normal scans
```

---

## 🌐 Network & API Issues

### 20. "Shodan API rate limit exceeded"

**Problem:** Free tier Shodan API limit (100 requests/day).

**Solution:**

```bash
# Wait 24 hours for reset
# Or upgrade to paid plan: https://account.shodan.io/billing

# Use passive mode to minimize API calls
python3 main.py example.com --mode passive
```

---

### 21. "VirusTotal API rate limit exceeded"

**Problem:** Free tier limit (4 requests/minute).

**Solution:**

```bash
# Add delays in subdomain_enum.py
import time
time.sleep(15)  # Wait 15 seconds between requests

# Or upgrade to premium: https://www.virustotal.com/gui/pricing
```

---

### 22. "Connection timeout errors"

**Problem:** Slow network or target blocking requests.

**Solution:**

```bash
# Increase timeouts in .env
HTTP_TIMEOUT=30
SCAN_TIMEOUT=600

# Reduce concurrent workers
MAX_WORKERS=20

# Use passive mode
python3 main.py example.com --mode passive
```

---

## 🗄️ Database Issues

### 23. "Database is locked"

**Problem:** Multiple processes trying to write to the same database.

**Solution:**

```bash
# Kill duplicate MEAT-GRINDER processes
ps aux | grep "python3 main.py"
kill -9 <PID>

# Wait for database to unlock
# SQLite automatically releases locks after timeout
```

---

### 24. "Database file is corrupted"

**Problem:** Database file damaged (power loss, disk full, etc.).

**Solution:**

```bash
# Backup corrupted file
mv workspaces/<target>/recon_data.db workspaces/<target>/recon_data.db.bak

# Create fresh database
python3 main.py <target>

# If you need to recover data:
sqlite3 workspaces/<target>/recon_data.db.bak ".dump" > backup.sql
sqlite3 workspaces/<target>/recon_data.db < backup.sql
```

---

### 25. "Database grows too large (> 1GB)"

**Problem:** Accumulated scan data over time.

**Solution:**

```bash
# Clean up old workspaces
find workspaces/ -type d -mtime +30 -exec rm -rf {} \;

# Vacuum database to reclaim space
sqlite3 workspaces/<target>/recon_data.db "VACUUM;"

# Check size
ls -lh workspaces/*/recon_data.db
```

---

## 🚀 Performance Issues

### 26. "Scan takes too long (> 30 minutes)"

**Problem:** Large target or slow network.

**Solution:**

```bash
# Skip heavy modules
python3 main.py example.com \
  --skip-git \
  --no-screenshots \
  --mode passive

# Reduce Git scanning scope
python3 main.py example.com --git-min-score 80

# Limit concurrent workers
# In .env:
MAX_WORKERS=20
```

---

### 27. "High CPU/memory usage"

**Problem:** Too many concurrent operations.

**Solution:**

```bash
# Reduce workers
# In .env:
MAX_WORKERS=10

# Disable AI (uses significant resources)
# In .env:
AI_ENABLED=false

# Monitor in real-time
htop
```

---

### 28. "Disk space running out"

**Problem:** Git repos and screenshots consuming space.

**Solution:**

```bash
# Check disk usage
du -sh workspaces/*

# Clean up Git repos after scan
rm -rf workspaces/*/git_repos/

# Clean up screenshots
rm -rf workspaces/*/screenshots/

# Use shallow clones
# In .env:
GIT_CLONE_DEPTH=1
```

---

## 🔍 Diagnostic Techniques

### Enable Verbose Output

```bash
export PYTHONUNBUFFERED=1
python3 main.py example.com 2>&1 | tee debug.log
```

### Inspect Database Directly

```bash
sqlite3 workspaces/<target>/recon_data.db

# List tables
.tables

# Show schema
.schema findings

# Query critical findings
SELECT finding_type, url, details FROM findings WHERE severity='CRITICAL' ORDER BY last_seen DESC;

# Count findings by type
SELECT finding_type, COUNT(*) as count FROM findings GROUP BY finding_type ORDER BY count DESC;

# Check for duplicates
SELECT fingerprint, COUNT(*) as count FROM findings GROUP BY fingerprint HAVING count > 1;

.quit
```

### Test Individual Modules

```bash
# Test specific module in isolation
python3 -c "
from database import DatabaseManager
from engine.subdomain_enum import SubdomainEnumerator
from pathlib import Path

db = DatabaseManager(Path('test.db'))
SubdomainEnumerator('example.com', db, Path('.')).execute()
print(db.get_all_subdomains())
"
```

### Check Tool Outputs

```bash
# Capture raw tool output
subfinder -d example.com -json -silent > subs.json
naabu -list subs.txt -json -silent > ports.json
httpx -l subs.txt -json -silent > endpoints.json
```

---

## 🎯 Edge Cases

### Target Behind Cloudflare/CDN

**Issue:** WAF blocks scanning.
**Solution:**

```bash
# Use passive mode (no direct requests)
python3 main.py example.com --mode passive

# Disable screenshot capture
python3 main.py example.com --no-screenshots
```

### Very Large Target (1000+ subdomains)

**Issue:** Scan times out or runs out of memory.
**Solution:**

```bash
# Reduce concurrency
# In .env:
MAX_WORKERS=20

# Skip Git scanning
python3 main.py example.com --skip-git

# Increase timeouts
# In .env:
SCAN_TIMEOUT=900
```

### Target Returns 403/429 for All Requests

**Issue:** Target actively blocking.
**Solution:**

```bash
# Use passive mode only
python3 main.py example.com --mode passive

# Add delays between requests (edit modules)
import time
time.sleep(2)  # Add 2-second delay
```

### Unicode/Encoding Errors

**Issue:** Special characters in target data.
**Solution:**

```bash
# Set UTF-8 encoding
export PYTHONIOENCODING=utf-8

# Or handle in code:
with open(file, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()
```

### Git Clone Fails for Private Repos

**Issue:** No authentication for private repos.
**Solution:**

```bash
# Ensure GITHUB_TOKEN has 'repo' scope
# Private repos require explicit permission

# Or skip private repos (only scan public)
# GitScanner already filters by accessibility
```

### Nuclei Finds 0 Templates

**Issue:** Template directory empty or corrupted.
**Solution:**

```bash
# Reinstall templates
nuclei -update-templates

# Verify template count
nuclei -tl | wc -l
# Should be 10,000+
```

---

## 📞 Getting Help

If you encounter an issue not covered here:

1. **Check GitHub Issues:** Search for similar problems
2. **Enable Debug Mode:**
   ```bash
   export PYTHONUNBUFFERED=1
   python3 main.py example.com 2>&1 | tee debug.log
   ```
3. **Collect Diagnostics:**
   ```bash
   python3 main.py example.com --doctor
   python3 --version
   pip list
   sqlite3 workspaces/example.com/recon_data.db ".schema"
   ```
4. **Open an Issue:** Include debug log, error message, and environment details

---

## ✅ Pre-Flight Checklist

Before reporting an issue, verify:

- [ ] All required tools installed (`--doctor` passes)
- [ ] `.env` file configured with API keys
- [ ] Ollama service running (if using AI)
- [ ] Sufficient disk space (`df -h`)
- [ ] Network connectivity (`ping google.com`)
- [ ] Database not corrupted (`PRAGMA integrity_check`)
- [ ] Using latest version of MEAT-GRINDER
- [ ] Target is authorized for scanning

---

*Last Updated: 2026-11-22*
*Version: 1.0*
