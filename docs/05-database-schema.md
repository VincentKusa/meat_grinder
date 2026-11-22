# 🗄️ Database Schema

MEAT-GRINDER uses a local **SQLite** database (`recon_data.db`) stored per-target in `workspaces/<target>/`. This
provides persistent state, crash resilience, and enables continuous monitoring via `--diff` mode.

---

## 📋 Overview

| Table         | Purpose                              | Written By                      |
|---------------|--------------------------------------|---------------------------------|
| `subdomains`  | Discovered subdomains                | SubdomainEnumerator, TLSScanner |
| `endpoints`   | Live HTTP endpoints + metadata       | HTTPProber, HeaderAnalyzer      |
| `ports`       | Open ports and services              | PortScanner                     |
| `findings`    | All security findings (deduplicated) | All modules                     |
| `os_recon`    | Deep OS/service fingerprinting       | OSRecon                         |
| `dns_records` | Raw DNS records                      | DNSScanner                      |
| `tls_info`    | TLS certificate details              | TLSScanner                      |
| `scan_runs`   | Historical scan metadata             | main.py                         |

---

## 📊 Entity Relationship Diagram

```text
                    ┌──────────────┐
                    │  scan_runs   │  (tracks --diff history)
                    └──────────────┘

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  subdomains  │──▶│  endpoints   │──▶│   findings   │◀── (all modules)
  └──────────────┘   └──────────────┘   └──────────────┘
         │                   │                  ▲
         ▼                   ▼                  │
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │    ports     │   │   tls_info   │   │  dns_records │
  └──────────────┘   └──────────────┘   └──────────────┘
         │
         ▼
  ┌──────────────┐
  │   os_recon   │
  └──────────────┘
```

> **Note:** Tables are logically related by `host`/`domain`/`url` but do not enforce foreign keys. The `findings` table
> is the central aggregation point consumed by all reporters.

---

## 🗃️ Table Definitions

### `subdomains`

Stores unique subdomains discovered passively (subfinder) or via TLS SAN extraction.

```sql
CREATE TABLE subdomains
(
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    source TEXT
);
```

| Column   | Type    | Constraints       | Description                                          |
|----------|---------|-------------------|------------------------------------------------------|
| `id`     | INTEGER | PK, AUTOINCREMENT | Unique row ID                                        |
| `domain` | TEXT    | UNIQUE            | Subdomain hostname (e.g., `api.vulnbank.org`)        |
| `source` | TEXT    | —                 | Discovery source (`virustotal`, `censys`, `tls_san`) |

---

### `endpoints`

Stores live HTTP endpoints and their extracted metadata.

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

| Column           | Type    | Constraints       | Description                                         |
|------------------|---------|-------------------|-----------------------------------------------------|
| `id`             | INTEGER | PK, AUTOINCREMENT | Unique row ID                                       |
| `url`            | TEXT    | UNIQUE            | Full endpoint URL                                   |
| `status_code`    | INTEGER | —                 | HTTP status (200, 301, 403, etc.)                   |
| `title`          | TEXT    | —                 | HTML page title                                     |
| `tech_stack`     | TEXT    | —                 | Comma-separated technologies (Wappalyzer)           |
| `content_length` | INTEGER | —                 | Response body size in bytes                         |
| `webserver`      | TEXT    | —                 | Server header (e.g., `cloudflare`, `Apache/2.4.41`) |
| `headers_json`   | TEXT    | —                 | JSON-serialized response headers                    |
| `waf_detected`   | TEXT    | —                 | Detected WAF/firewall name                          |

---

### `ports`

Stores open ports and service data per host.

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

| Column     | Type    | Constraints          | Description                                        |
|------------|---------|----------------------|----------------------------------------------------|
| `id`       | INTEGER | PK, AUTOINCREMENT    | Unique row ID                                      |
| `host`     | TEXT    | UNIQUE(host, source) | Hostname                                           |
| `ip`       | TEXT    | —                    | Resolved IP address                                |
| `ports`    | TEXT    | —                    | JSON array of open ports (e.g., `[80, 443, 8080]`) |
| `source`   | TEXT    | UNIQUE(host, source) | `naabu` (active) or `shodan` (passive)             |
| `os`       | TEXT    | —                    | Detected operating system                          |
| `services` | TEXT    | —                    | JSON object mapping ports to service names         |

---

### `findings`

The central table aggregating all security findings with deduplication and occurrence tracking.

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

| Column          | Type      | Constraints       | Description                                       |
|-----------------|-----------|-------------------|---------------------------------------------------|
| `id`            | INTEGER   | PK, AUTOINCREMENT | Unique row ID                                     |
| `finding_type`  | TEXT      | —                 | Finding category (e.g., `EXPOSED_SENSITIVE_FILE`) |
| `url`           | TEXT      | —                 | Affected URL/resource                             |
| `details`       | TEXT      | —                 | Human-readable details (+ AI analysis if enabled) |
| `severity`      | TEXT      | —                 | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`       |
| `confidence`    | TEXT      | DEFAULT 'MEDIUM'  | `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `INFO`      |
| `fingerprint`   | TEXT      | UNIQUE            | SHA256 dedup hash (first 16 chars)                |
| `first_seen`    | TIMESTAMP | DEFAULT NOW       | First discovery time                              |
| `last_seen`     | TIMESTAMP | DEFAULT NOW       | Most recent discovery time                        |
| `occurrences`   | INTEGER   | DEFAULT 1         | Times this finding was seen                       |
| `source_module` | TEXT      | —                 | Module that generated the finding                 |

#### Deduplication Fingerprint

The `fingerprint` is generated from key finding attributes to prevent duplicates:

```python
components = [
    finding_type,
    url.lower().strip(),
    rule_id or "",
    file_path or "",
    details[:100]
]
fingerprint = hashlib.sha256("|".join(components).encode()).hexdigest()[:16]
```

If a fingerprint already exists, `occurrences` is incremented and `last_seen` updated instead of inserting a duplicate
row.

---

### `os_recon`

Stores deep OS and service fingerprinting results from Nmap.

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

| Column        | Type    | Constraints       | Description                                  |
|---------------|---------|-------------------|----------------------------------------------|
| `id`          | INTEGER | PK, AUTOINCREMENT | Unique row ID                                |
| `host`        | TEXT    | UNIQUE            | Target hostname                              |
| `ip`          | TEXT    | —                 | IP address                                   |
| `os_name`     | TEXT    | —                 | Detected OS (e.g., `Linux 5.4.0-42-generic`) |
| `os_accuracy` | TEXT    | —                 | Nmap OS detection confidence (%)             |
| `hostname`    | TEXT    | —                 | Reverse-DNS hostname                         |
| `open_ports`  | TEXT    | —                 | Ports with service versions                  |

---

### `dns_records`

Stores raw DNS records for infrastructure intelligence.

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

| Column         | Type    | Constraints                 | Description                                    |
|----------------|---------|-----------------------------|------------------------------------------------|
| `id`           | INTEGER | PK, AUTOINCREMENT           | Unique row ID                                  |
| `domain`       | TEXT    | UNIQUE(domain, type, value) | Queried domain                                 |
| `record_type`  | TEXT    | UNIQUE(domain, type, value) | `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA` |
| `record_value` | TEXT    | UNIQUE(domain, type, value) | Record value                                   |
| `ttl`          | INTEGER | —                           | Time-to-live in seconds                        |

---

### `tls_info`

Stores TLS certificate and protocol details.

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

| Column         | Type    | Constraints       | Description                |
|----------------|---------|-------------------|----------------------------|
| `id`           | INTEGER | PK, AUTOINCREMENT | Unique row ID              |
| `host`         | TEXT    | UNIQUE            | Target hostname            |
| `issuer`       | TEXT    | —                 | Certificate issuer (CA)    |
| `subject`      | TEXT    | —                 | Certificate subject        |
| `sans`         | TEXT    | —                 | Subject Alternative Names  |
| `not_before`   | TEXT    | —                 | Certificate validity start |
| `not_after`    | TEXT    | —                 | Certificate expiry date    |
| `tls_versions` | TEXT    | —                 | Supported TLS versions     |
| `cipher_suite` | TEXT    | —                 | Negotiated cipher suite    |

---

### `scan_runs`

Tracks historical scan metadata to power `--diff` mode.

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

| Column           | Type      | Constraints       | Description                  |
|------------------|-----------|-------------------|------------------------------|
| `id`             | INTEGER   | PK, AUTOINCREMENT | Unique row ID                |
| `target`         | TEXT      | —                 | Scanned target domain        |
| `scan_mode`      | TEXT      | —                 | `passive` or `active`        |
| `started_at`     | TIMESTAMP | DEFAULT NOW       | Scan start time              |
| `completed_at`   | TIMESTAMP | —                 | Scan completion time         |
| `total_findings` | INTEGER   | —                 | Total findings at completion |

---

## 🔍 Common Queries

### View all critical findings

```sql
SELECT finding_type, url, details
FROM findings
WHERE severity = 'CRITICAL'
ORDER BY last_seen DESC;
```

### Count findings by severity

```sql
SELECT severity, COUNT(*) AS count
FROM findings
GROUP BY severity
ORDER BY count DESC;
```

### Find recurring findings (seen more than once)

```sql
SELECT finding_type, url, occurrences, first_seen, last_seen
FROM findings
WHERE occurrences > 1
ORDER BY occurrences DESC;
```

### Get new findings since last scan (diff mode)

```sql
SELECT *
FROM findings
WHERE first_seen > (SELECT completed_at
                    FROM scan_runs
                    WHERE target = 'vulnbank.org'
                    ORDER BY completed_at DESC
    LIMIT 1
    );
```

### List all live endpoints with WAF

```sql
SELECT url, status_code, webserver, waf_detected
FROM endpoints
WHERE status_code = 200;
```

### Inspect DNS records

```sql
SELECT record_type, record_value, ttl
FROM dns_records
WHERE domain = 'vulnbank.org'
ORDER BY record_type;
```

---

## 🔄 Schema Migrations

MEAT-GRINDER auto-migrates older databases on startup via the `_migrate()` method in `database.py`. It uses
`PRAGMA table_info()` to detect missing columns and adds them with `ALTER TABLE`, ensuring backward compatibility
without data loss.

**Example migration logic:**

```python
cols = [row[1] for row in conn.execute("PRAGMA table_info(endpoints)").fetchall()]
if "title" not in cols:
    conn.execute("ALTER TABLE endpoints ADD COLUMN title TEXT")
if "waf_detected" not in cols:
    conn.execute("ALTER TABLE endpoints ADD COLUMN waf_detected TEXT")
```

> **Tip:** If a schema becomes corrupted or incompatible, delete `workspaces/<target>/recon_data.db` and re-run the
> scan. The engine recreates a fresh, up-to-date schema automatically.

---

## 💾 Direct Database Access

```bash
# Open the database
sqlite3 workspaces/vulnbank.org/recon_data.db

# Useful commands inside the SQLite shell
.tables                          -- List all tables
.schema findings                 -- Show table schema
.headers on                      -- Show column headers
.mode column                     -- Pretty-print output
SELECT * FROM findings LIMIT 10; -- Query findings
.quit                            -- Exit
```

---

## 📌 Design Notes

1. **No Foreign Keys:** Tables are related logically (by `host`/`url`/`domain`) but do not enforce FK constraints,
   keeping inserts fast and module-independent.
2. **UNIQUE Constraints:** Prevent duplicate subdomains, endpoints, and findings at the database level.
3. **JSON Columns:** `ports`, `services`, and `headers_json` store serialized JSON for flexible, schema-less nested
   data.
4. **Timestamps:** `first_seen` / `last_seen` enable temporal analysis and continuous monitoring.
5. **Central Aggregation:** All modules write to `findings`; reporters read only from it, ensuring a clean separation of
   concerns.
