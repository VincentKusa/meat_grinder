# 🛠️ Development Guide

This document provides a comprehensive guide for developers contributing to MEAT-GRINDER. It covers how to add new
modules, adhere to code style standards, test changes, and debug effectively.

---

## 📦 Adding a New Module

MEAT-GRINDER is designed with a modular, object-oriented architecture. Adding a new scanning capability requires only a
few steps.

### Step 1: Create the Module File

Create a new Python file in the `engine/` directory (e.g., `engine/my_scanner.py`). Inherit from `BaseReconModule` to
automatically gain access to `self.target`, `self.db`, and `self.workspace`.

```python
"""My Custom Scanner Module."""

import requests
import urllib3
from engine.base import BaseReconModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MyScanner(BaseReconModule):
    def __init__(self, target: str, db, workspace):
        super().__init__(target, db, workspace)
        # Initialize any module-specific variables here

    def execute(self):
        print("[*] Running my custom scanner...")

        # 1. Gather data (e.g., from database or external API)
        endpoints = self.db.get_all_endpoints()

        findings_count = 0
        for ep in endpoints:
            if self._check_something(ep["url"]):
                findings_count += 1

        print(f"[+] My scanner complete. Found {findings_count} insights.")

    def _check_something(self, url: str) -> bool:
        """Internal helper method to check a specific condition."""
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if "sensitive_data" in resp.text:
                # 2. Insert finding into the database
                self.db.insert_finding(
                    f_type="MY_CUSTOM_FINDING",
                    url=url,
                    details="Found sensitive data pattern in response",
                    severity="HIGH",
                    source_module="my_scanner"
                )
                return True
        except Exception as e:
            # Always catch exceptions to prevent the whole engine from crashing
            print(f"[!] Error checking {url}: {e}")

        return False
```

### Step 2: Wire It Into `main.py`

Import your new module at the top of `main.py` and add it to the appropriate phase in the execution pipeline.

```python
# 1. Add import at the top
from engine.my_scanner import MyScanner


# 2. Add to the execution pipeline in main()
def main():
    # ... (previous phases) ...

    # ==========================================
    # 4. Deep Content & Secret Scanning
    # ==========================================
    SensitiveFileScanner(target, db, workspace).execute()
    WebContentScanner(target, db, workspace).execute()

    # ADD YOUR NEW MODULE HERE
    MyScanner(target, db, workspace).execute()

    # ... (subsequent phases) ...
```

### Step 3: Update the Database (If Needed)

If your module needs to store data in a new table or add columns to an existing table, update the `_migrate` method in
`database.py`.

```python
# In database.py, inside the _migrate method:
def _migrate(self):
    with self._get_conn() as conn:
        # ... existing migrations ...

        # Add new table
        conn.execute("""CREATE TABLE IF NOT EXISTS my_custom_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            custom_value TEXT
        )""")

        # Add new column to existing table
        cols = [row[1] for row in conn.execute("PRAGMA table_info(endpoints)").fetchall()]
        if "my_new_column" not in cols:
            conn.execute("ALTER TABLE endpoints ADD COLUMN my_new_column TEXT")
```

### Step 4: Update Documentation

1. Add your module to `docs/02-modules-recon.md` or `docs/03-modules-code-ai.md`.
2. Add your new `f_type` to `docs/06-finding-catalog.md` with its severity and description.

---

## 📐 Code Style & Standards

MEAT-GRINDER enforces strict code quality standards using `pre-commit` hooks. All contributions must pass these checks.

### 1. Formatting (Black)

- Line length: **120 characters**
- Use double quotes for strings by default.
- Run: `black .`

### 2. Import Sorting (isort)

- Imports are automatically grouped and sorted.
- Run: `isort .`

### 3. Linting (flake8)

- No unused imports (`F401`).
- No undefined variables (`F821`).
- No bare `except:` clauses (use `except Exception:`).
- No line length violations (`E501` - handled by Black).
- Run: `flake8 .`

### 4. Type Hinting

All public methods and functions must include type hints for parameters and return values.

```python
# ✅ Good
def _extract_json(text: str) -> Optional[dict]:
    pass


# ❌ Bad
def _extract_json(text):
    pass
```

### 5. Docstrings

Use Google-style docstrings for all classes and public methods.

```python
class MyScanner(BaseReconModule):
    """
    Scans for custom vulnerabilities.

    Attributes:
        target (str): The target domain.
        db (DatabaseManager): Database connection manager.
    """

    def _check_something(self, url: str) -> bool:
        """
        Checks a URL for sensitive data patterns.

        Args:
            url (str): The URL to check.

        Returns:
            bool: True if sensitive data is found, False otherwise.
        """
        pass
```

### 6. Running Pre-Commit

Before committing any code, run the pre-commit hooks to ensure compliance:

```bash
pre-commit run --all-files
```

---

## 🧪 Testing & Debugging

### 1. Pre-Flight Checks

Always verify your environment before running a full scan:

```bash
python3 main.py example.com --doctor
```

### 2. Testing on Known Targets

Use intentionally vulnerable applications to verify your module works correctly without risking unauthorized targets.

```bash
# Test against OWASP Juice Shop
python3 main.py demo.owasp-juice.shop --mode active
```

### 3. Enabling Verbose Output

To see real-time output without Python buffering delays (useful for debugging hangs):

```bash
export PYTHONUNBUFFERED=1
python3 main.py example.com 2>&1 | tee debug.log
```

### 4. Inspecting the Database Directly

If a module runs but findings don't appear in the report, inspect the SQLite database directly.

```bash
# Open the database
sqlite3 workspaces/example.com/recon_data.db

# List all tables
.tables

# View schema of a specific table
.schema findings

# Query recent findings
SELECT id, finding_type, url, severity, source_module
FROM findings
ORDER BY id DESC
LIMIT 10;

# Check for deduplication issues (occurrences > 1)
SELECT finding_type, url, occurrences
FROM findings
WHERE occurrences > 1;

# Exit
.quit
```

### 5. Isolating Module Execution

To test a single module without running the entire pipeline, create a temporary test script:

```python
# test_my_scanner.py
from pathlib import Path
from database import DatabaseManager
from engine.my_scanner import MyScanner

# Setup
target = "example.com"
workspace = Path(f"./workspaces/{target}")
workspace.mkdir(parents=True, exist_ok=True)
db = DatabaseManager(workspace / "recon_data.db")

# Inject some dummy data for the module to process
db.insert_endpoint("https://example.com", 200, "Example", "Apache", 1234, "Apache/2.4", "{}", "None")

# Run module
scanner = MyScanner(target, db, workspace)
scanner.execute()

# Verify results
print("\n--- Findings ---")
for f in db.get_all_findings():
    print(f)
```

### 6. Debugging AI Modules

If the AI engine is returning unexpected results or failing to parse JSON:

```python
# Temporarily add debug prints in engine/ai_engine.py
def ask_json(self, prompt: str, sensitive: bool = False, max_tokens: int = 1000) -> Any:
    response = self.ask(prompt, sensitive=sensitive, max_tokens=max_tokens)
    print(f"[DEBUG] Raw AI Response:\n{response[:500]}...")  # Add this line
    return self._extract_json(response)
```

---

## ⚡ Performance Profiling

If a new module is slowing down the engine, profile it to identify bottlenecks.

### 1. Using `cProfile`

Run the engine with Python's built-in profiler:

```bash
python3 -m cProfile -s cumtime main.py example.com --mode passive > profile.txt
```

Open `profile.txt` and look at the `cumtime` (cumulative time) column to see which functions are taking the longest.

### 2. Optimizing HTTP Requests

- **Always use `ThreadPoolExecutor`** for I/O-bound tasks (HTTP requests, API calls).
- **Set strict timeouts**: `timeout=10` prevents hanging on unresponsive servers.
- **Cap response sizes**: Read only what you need (e.g., `resp.text[:5000]`) to avoid loading 50MB JavaScript bundles
  into memory.

```python
# ✅ Good: Concurrent with timeout and size limit
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(self._check_url, url): url for url in urls}
    for future in as_completed(futures):
        future.result()


def _check_url(self, url: str):
    resp = requests.get(url, timeout=10, verify=False)
    content = resp.text[:10000]  # Cap at 10KB
```

### 3. Database Optimization

- Use `INSERT OR IGNORE` or `UNIQUE` constraints to prevent duplicate row errors.
- Batch inserts if adding thousands of rows (though MEAT-GRINDER's current per-finding insertion is fast enough for
  typical recon scales).

---

## 🔒 Security Considerations for Developers

### 1. Never Hardcode Secrets

- **Do not** commit API keys, tokens, or passwords to the repository.
- Always load sensitive configuration from `os.getenv()` via the `.env` file.

### 2. Command Injection Prevention

When calling external binaries (e.g., `nmap`, `gitleaks`), **never** use string concatenation for user input. Use
list-based `subprocess.run` arguments.

```python
# ❌ BAD: Vulnerable to command injection
cmd = f"nmap -sS {target}"
subprocess.run(cmd, shell=True)

# ✅ GOOD: Safe, list-based execution
subprocess.run(["nmap", "-sS", target], capture_output=True, check=True)
```

### 3. Exception Handling

Always wrap external tool executions and network requests in `try/except Exception` blocks. A single failing endpoint
should not crash the entire reconnaissance pipeline.

```python
try:
    resp = requests.get(url, timeout=10)
except requests.exceptions.RequestException as e:
    print(f"[!] Request failed for {url}: {e}")
    return False
```

### 4. Data Sanitization

When writing data to HTML reports, always escape user-controlled input to prevent Cross-Site Scripting (XSS) in the
generated PDF/Markdown.

```python
# Use the built-in escape method in pdf_reporter.py
safe_url = self._escape_html(finding["url"])
```

---

## 📋 Developer Checklist

Before submitting a Pull Request or merging a new feature, verify:

- [ ] Module inherits from `BaseReconModule`.
- [ ] All public methods have type hints and Google-style docstrings.
- [ ] `pre-commit run --all-files` passes with zero errors.
- [ ] New finding types are documented in `docs/06-finding-catalog.md`.
- [ ] No hardcoded secrets or API keys in the code.
- [ ] External commands use list-based `subprocess.run` (no `shell=True` with user input).
- [ ] Tested on a safe target (e.g., `demo.owasp-juice.shop`).
- [ ] Database migrations are added to `database.py` if new tables/columns are used.

---

*Last Updated: 2026-11-22*
*Version: 1.0*
