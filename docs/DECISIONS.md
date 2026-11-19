# Architecture Decision Records (ADR) — AI-Sentinel

## ADR-001: Standard Library CSV Export for Forensics
- **Context:** Security analysts and evaluators need to export incident logs for offline forensic analysis, Excel reporting, or SIEM ingestion.
- **Options Considered:**
  1. JSON export only (`/sentinel/api/events`).
  2. Third-party export libraries (Pandas / OpenPyXL).
  3. Python standard library `csv` module with `io.StringIO`.
- **Decision:** Python `csv` module via `/sentinel/export/csv`.
- **Why:** Zero additional dependencies, deterministic formatting, opens directly in spreadsheet applications, and runs fast in memory without temporary files.
- **Security:** Protected by `_local_only()` (remote IP access blocked with 403 Forbidden). Secrets continue to be masked at insertion time in SQLite.

## ADR-002: Vanilla JavaScript Dashboard Filtering with Pause/Resume Auto-Refresh
- **Context:** In high-speed monitoring, `<meta http-equiv="refresh" content="5">` reloads the page forcefully, clearing any active search or scroll state while an analyst is investigating an incident.
- **Options Considered:**
  1. Full single-page frontend (React / Vue / Vite).
  2. Server-side query parameter filtering (`/sentinel/dashboard?action=block&q=...`).
  3. Client-side vanilla JavaScript filtering with JS-based countdown and pause/resume control.
- **Decision:** Client-side vanilla JS in the single Jinja template.
- **Why:** Works completely offline in the local lab environment, requires zero build step or npm packages, and gives instantaneous instant-search and filter response without extra roundtrips to SQLite. Auto-pauses refresh as soon as the user starts typing in the search box to prevent disruption.

## ADR-003: Isolation Forest for Anomaly Detection
- **Context:** Need an ML model to flag requests that rules miss (obfuscated attacks, zero-day patterns).
- **Options Considered:**
  1. **Isolation Forest** — unsupervised, needs only normal data, fast inference.
  2. **One-Class SVM** — good for small feature spaces but slow on large datasets, sensitive to kernel choice.
  3. **Local Outlier Factor (LOF)** — density-based, but the `novelty=True` mode is less mature and slower at inference.
  4. **Autoencoder (neural network)** — powerful but overkill for 12 features, needs PyTorch/TensorFlow dependency.
- **Decision:** Isolation Forest (`sklearn.ensemble.IsolationForest`).
- **Why:** Unsupervised (no attack labels needed), fast training and inference (~4 ms), built into scikit-learn (no extra dependency), works well with our 12-dimensional feature vector. LOF and One-Class SVM are viable alternatives for future comparison.
- **Trade-off:** Less expressive than a neural autoencoder, but far simpler to understand, debug, and explain in a viva.

## ADR-004: Contamination = 0.01
- **Context:** `IsolationForest(contamination=...)` sets the threshold: what fraction of training data is treated as outlier.
- **Options Considered:**
  1. `0.001` — very strict, fewer false positives but might miss subtle anomalies.
  2. `0.01` — ~1% of normal training data flagged as anomalous.
  3. `0.05` — aggressive, more catches but much higher false-positive rate.
- **Decision:** `contamination=0.01`.
- **Why:** On our synthetic normal data, 0.01 gives ~1% false-alarm rate on held-out normal traffic (acceptable). Going to 0.05 raised FPR to ~5% without meaningfully improving recall. Since ML alone never blocks (policy rule), the cost of a false alert is low.
- **Trade-off:** On real traffic (more diverse than synthetic), FPR will be higher. Tune down to 0.005 if false alerts become noisy.

## ADR-005: Regex-Based Rule Engine (Not OWASP CRS / Coraza)
- **Context:** Need a signature-based detection layer to catch known attack patterns.
- **Options Considered:**
  1. **OWASP ModSecurity CRS + Coraza** — industry standard, 100+ rules, but requires Go binary or C library, complex integration.
  2. **Custom regex rules in Python** — simple, fully understood, easy to explain.
  3. **YARA rules** — designed for malware, not HTTP payloads.
- **Decision:** Custom Python regex rules (~20 rules) in `rules.py`.
- **Why:** Zero external dependencies, every rule is readable and explainable in a viva, normalisation pipeline (decode → strip comments → lowercase) is transparent. The rule set covers the top OWASP categories (SQLi, XSS, path traversal, command injection, scanner UA).
- **Trade-off:** Far fewer rules than CRS. Real-world coverage will be lower. Documented as a limitation; Coraza + CRS integration is listed as a future step.

## ADR-006: SQLite for Event Logging
- **Context:** Need persistent storage for request events (the "Register").
- **Options Considered:**
  1. **SQLite** — file-based, zero-config, built into Python.
  2. **PostgreSQL / MySQL** — full RDBMS, supports concurrent writes, but requires a running server.
  3. **Plain log files** — simplest, but no structured queries for dashboard stats.
- **Decision:** SQLite via `sqlite3` stdlib module.
- **Why:** Single-file database, no server to install, supports SQL queries for dashboard aggregations, sufficient for a single-process demo. Parameterised queries (`?` placeholders) prevent our own logger from being vulnerable to SQL injection.
- **Trade-off:** Single-writer lock means concurrent multi-process deployments would need connection pooling or a move to PostgreSQL.

## ADR-007: Synthetic Normal Traffic for Training (Not Real Data)
- **Context:** Isolation Forest needs "normal" traffic to learn from. Options: real captured traffic, public dataset (CSIC 2010), or synthetic generation.
- **Options Considered:**
  1. **CSIC 2010 dataset** — 36,000 real normal + 25,000 anomalous HTTP requests. Best for evaluation but requires download and parsing.
  2. **Capture from own lab** — realistic but needs a running website with real users.
  3. **Synthetic generation** (`normal_traffic.py`) — fully controlled, deterministic (seed=42), instant.
- **Decision:** Synthetic generation as the starter, with CSIC 2010 recommended for paper results.
- **Why:** Lets the project run out-of-the-box with `python run.py` (model auto-trains on first start). No download step, no data licensing concerns. Deterministic seed ensures reproducible results.
- **Trade-off:** Synthetic traffic is narrow and clean — the model flags anything slightly unusual. This inflates recall (100%) and underestimates real-world FPR. Documented honestly in `docs/LIMITATIONS.md` and `results/`.

## ADR-008: Header and Cookie Inspection Scope
- **Context:** Attackers frequently hide SQLi, XSS, and command injection payloads inside HTTP headers (`Cookie`, `Referer`, `Authorization`, `X-Forwarded-Host`) to bypass naive WAFs that inspect only query strings and form parameters.
- **Decision:** Inspect cookies and high-risk HTTP headers in `app.py:guard()`.
- **Why:** Closes trivial bypass techniques without adding significant latency overhead.

## ADR-009: SQLite-Backed Persistent IP Bans & Unban Capability
- **Context:** In-memory IP bans vanish when the Flask application restarts, allowing brute-force attackers to resume immediate attacks upon restart. SOC operators also require the ability to manually unban misidentified IPs.
- **Decision:** Persist bans with timestamp expiration in a SQLite `bans` table, reload active bans on `Sentinel` initialization, and provide a `/sentinel/api/unban/<ip>` endpoint and dashboard button. Clear `fails` counter on unban to avoid immediate re-triggering.
- **Why:** Maintains security state across restarts while retaining in-memory speed during request evaluation.

## ADR-010: Security Response Headers & Request Correlation IDs
- **Context:** Defensive architecture should protect against browser-side vulnerabilities (MIME sniffing, clickjacking) and enable incident tracking across client, proxy, and database.
- **Decision:** Implement `@app.after_request` adding CSP, X-Frame-Options, X-Content-Type-Options, and a unique 8-character `X-Request-ID` per request that is logged in SQLite.
- **Why:** Comprehensive defence-in-depth adhering to OWASP Secure Headers guidelines.
