# AI-Sentinel — Numbers & Code Facts Cheat Sheet

> **Document Type:** Academic Viva Reference & Empirical Verification  
> **Target:** B.Tech Technical Examination Defense  
> **Source Code Basis:** Verified directly from `sentinel/`, `tests/`, and `eval/`

---

## 1. Machine Learning Features (`sentinel/features.py`)

- **File & Lines:** [`sentinel/features.py:17-21`](../sentinel/features.py#L17-L21) & [`sentinel/features.py:33-55`](../sentinel/features.py#L33-L55)
- **Feature Vector Dimension:** Exactly **12 features** (`FEATURE_NAMES` list):
  1. `path_len`: String length of the HTTP request path.
  2. `n_params`: Total count of extracted query and body parameter values.
  3. `payload_len`: Total character length of all decoded parameter values combined.
  4. `max_value_len`: Length of the longest individual decoded parameter string.
  5. `special_ratio`: Fraction of characters in payload matching `SPECIAL = set("'\"<>;()=\\/-#*|&$`{}[]!")`.
  6. `digit_ratio`: Fraction of payload characters that are digits (`0-9`).
  7. `upper_ratio`: Fraction of payload characters that are uppercase letters (`A-Z`).
  8. `entropy`: Shannon entropy ($-\sum p_i \log_2 p_i$) measuring character randomness/variety.
  9. `pct_count`: Count of URL percent-encoded sequences (`%xx`).
  10. `is_post`: Binary indicator (`1` if HTTP method is `POST`, else `0`).
  11. `rate_10s`: Sliding-window request count from the client's IP in the past 10 seconds.
  12. `failed_logins_60s`: Sliding-window count of failed logins from the client's IP in the past 60 seconds.
- **Is request rate a feature?** **YES.** Feature #11 (`rate_10s`) directly feeds request frequency into the ML input vector.

---

## 2. Regex Rules & Attack Categories (`sentinel/rules.py`)

- **File & Lines:** [`sentinel/rules.py:48-103`](../sentinel/rules.py#L48-L103)
- **Total Rule Count:** Exactly **25 rules** organized into 4 inspection groups:
  - `VALUE_RULES` (22 rules, applied across path and all parameter values, lines 48-85)
  - `PATH_RULES` (1 rule, applied only to URL path, lines 88-91)
  - `UA_RULES` (1 rule, applied only to User-Agent header, lines 94-96)
  - `DECODED_RULES` (1 rule, applied to decoded-only text before normalization, lines 100-102)
- **Attack Categories Covered (12 distinct categories):**
  1. **SQL Injection** (7 rules: `sqli-union-select`, `sqli-tautology`, `sqli-quote-comment`, `sqli-stacked-query`, `sqli-time-based`, `sqli-db-metadata`, `sqli-select-from`)
  2. **Cross-Site Scripting (XSS)** (6 rules: `xss-script-tag`, `xss-event-handler`, `xss-javascript-uri`, `xss-dangerous-tag`, `xss-dom-sink`, `xss-any-html-tag`)
  3. **Command Injection** (2 rules: `cmd-chain`, `cmd-substitution`)
  4. **Path Traversal** (2 rules: `path-dotdot`, `path-sensitive-file`)
  5. **Null Byte Injection** (1 rule: `null-byte`)
  6. **Server-Side Request Forgery (SSRF)** (1 rule: `ssrf-cloud-metadata`)
  7. **Log4Shell** (1 rule: `log4shell-jndi`)
  8. **XML External Entity (XXE)** (1 rule: `xxe-entity`)
  9. **Open Redirect** (1 rule: `open-redirect`)
  10. **Reconnaissance** (1 rule: `recon-sensitive-path`)
  11. **Automated Scanner** (1 rule: `scanner-user-agent`)
  12. **HTTP Response Splitting** (1 rule: `response-splitting`)

---

## 3. Execution Pipeline & Concurrency (`sentinel/app.py` & `sentinel/engine.py`)

- **File & Lines:** [`sentinel/app.py:91-142`](../sentinel/app.py#L91-L142) & [`sentinel/engine.py:78-125`](../sentinel/engine.py#L78-L125)
- **Concurrency Mode:** Strictly **SEQUENTIAL** on the request thread. Rules, ML, rate limiter, and brute force do **not** run in parallel.
- **Exact Execution Sequence:**
  1. **Exemption Check:** Requests starting with `/sentinel/*` bypass inspection (`app.py:93-94`).
  2. **Tracing ID Generation:** Assign `request.request_id = uuid.uuid4().hex[:8]` (`app.py:97`).
  3. **Input Extraction:** Query string, POST/PUT bodies, and headers (`Cookie`, `Referer`, `Authorization`) (`app.py:99-122`).
  4. **Allowlist & Active Ban Check:** Check `ip in ALLOWLIST`; if `st.banned_until > now`, immediately return `block` (`engine.py:82-88`).
  5. **Stateful Window Maintenance:** Prune timestamps and compute `rate` (10s window) and `fails` (60s window) (`engine.py:89-93`).
  6. **Regex Rule Scan:** Run `rules.scan()` over normalized strings $\rightarrow$ aggregates `rule_score` (capped at 10) and `top_category` (`engine.py:95-97`).
  7. **ML Anomaly Scoring:** Run `features.extract()` $\rightarrow$ `detector.score(vec)` $\rightarrow$ produces `ml_score` and `ml_flag` (`engine.py:100-103`).
  8. **Policy Decision:** `policy.decide(rule_score, top_category, ml_flag, rate, fails)` evaluates priority ladder (`engine.py:106`).
  9. **Dynamic IP Ban Check:** If blocked, record block; if `d.ban` or blocks $\ge 5$, set `banned_until = now + 60` and save to SQLite (`engine.py:110-123`).
  10. **Audit Log & Dispatch:** Commit to SQLite via `db.log_event()` (`app.py:129`), attach security headers (`app.py:148-163`), return HTTP 200/403/429.

---

## 4. Policy Decision Hierarchy & Configuration Thresholds

- **File & Lines:** [`sentinel/policy.py:20-33`](../sentinel/policy.py#L20-L33) & [`sentinel/config.py:27-35`](../sentinel/config.py#L27-L35)
- **Decision Ladder (Top-to-Bottom First Match):**
  1. `fails >= config.MAX_FAILED_LOGINS` ($\ge 5$):
     - **Action:** `block` | **Reason:** `"brute force: too many failed logins"` | **Ban:** `True` | **Category:** `"Brute Force"`
  2. `rule_score >= config.BLOCK_SCORE` ($\ge 5$):
     - **Action:** `block` | **Reason:** `"high-severity rule match"` | **Ban:** `False` | **Category:** `top_category`
  3. `rule_score > 0 and ml_flag`:
     - **Action:** `block` | **Reason:** `"rule match + ML anomaly agree"` | **Ban:** `False` | **Category:** `top_category`
  4. `rate > config.RATE_LIMIT` ($> 20$):
     - **Action:** `rate_limit` | **Reason:** `"too many requests in a short time"` | **Ban:** `False` | **Category:** `"Rate Limit"` (HTTP 429)
  5. `rule_score > 0` ($< 5$):
     - **Action:** `alert` | **Reason:** `"low-severity rule match"` | **Ban:** `False` | **Category:** `top_category`
  6. `ml_flag` alone:
     - **Action:** `alert` | **Reason:** `"ML anomaly only (ML alone never blocks)"` | **Ban:** `False` | **Category:** `"Anomaly (ML)"`
  7. Default / Clean:
     - **Action:** `allow` | **Reason:** `"clean"` | **Ban:** `False` | **Category:** `""`
- **Config Constants:**
  - `BLOCK_SCORE = 5` (`config.py:27`)
  - `RATE_LIMIT = 20` requests (`config.py:28`)
  - `RATE_WINDOW = 10` seconds (`config.py:29`)
  - `MAX_FAILED_LOGINS = 5` attempts (`config.py:30`)
  - `LOGIN_WINDOW = 60` seconds (`config.py:31`)
  - `BAN_AFTER_BLOCKS = 5` blocks (`config.py:32`)
  - `BAN_WINDOW = 60` seconds (`config.py:33`)
  - `BAN_SECONDS = 60` seconds ban duration (`config.py:34`)

---

## 5. Training Dataset Composition & Leakage Prevention

- **File & Lines:** [`train.py:24`](../train.py#L24), [`sentinel/ml.py:23-50`](../sentinel/ml.py#L23-L50), [`sentinel/config.py:19`](../sentinel/config.py#L19)
- **Dataset Composition:**
  - CSIC 2010 Normal Requests: **28,000 samples** (`data/csic_2010/normalTrafficTraining.txt` parsed via `iter_csic_requests()`).
  - Synthetic Target App Requests: **5,000 samples** (`make_normal_request` with RNG `seed=42`).
  - Total Training Set: **33,000 samples** ($28,000 + 5,000$).
- **Is any test data in training?** **NO (Zero Data Leakage).**
  - CSIC Benchmark: Split at the dataset file level. Training strictly ingests `normalTrafficTraining.txt`; anomaly evaluations use `anomalousTrafficTest.txt` or holdouts.
  - Synthetic Traffic: Training uses RNG `seed=42` ($n=5,000$), while evaluation in `evaluate.py:110` uses RNG `seed=7` ($n=400$) plus separate hand-crafted payloads that are never passed to `ml.train()`.

---

## 6. Obfuscation Benchmark Analysis (62% $\rightarrow$ 92% & 50% $\rightarrow$ 67%)

- **File & Lines:** [`evaluate.py:20-73`](../evaluate.py#L20-L73), [`evaluate.py:101-118`](../evaluate.py#L101-L118), [`results/evaluation_2026-11-22_csic.md:16-28`](../results/evaluation_2026-11-22_csic.md#L16-L28)
- **Payload Distribution per Category (Injected across 3 endpoints: `GET /search`, `GET /product`, `POST /login`):**
  - **SQL Injection (SQLi):**
    - Plain: 11 payloads $\times$ 3 endpoints = **33 test requests** ($n=33$). Rules only: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
    - Obfuscated: 8 payloads $\times$ 3 endpoints = **24 test requests** ($n=24$). Rules only: **$62\%$** ($15/24$) $\rightarrow$ Rules + ML: **$92\%$** ($22/24$).
  - **Command Injection (Cmd):**
    - Plain: 6 payloads $\times$ 3 endpoints = **18 test requests** ($n=18$). Rules only: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
    - Obfuscated: 2 payloads $\times$ 3 endpoints = **6 test requests** ($n=6$). Rules only: **$50\%$** ($3/6$) $\rightarrow$ Rules + ML: **$67\%$** ($4/6$).
  - **Path Traversal (Path):**
    - Plain: 3 payloads $\times$ 3 endpoints = **9 requests** ($n=9$). Rules: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
    - Obfuscated: 3 payloads $\times$ 3 endpoints = **9 requests** ($n=9$). Rules: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
  - **XSS:**
    - Plain: 7 payloads $\times$ 3 endpoints = **21 requests** ($n=21$). Rules: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
    - Obfuscated: 6 payloads $\times$ 3 endpoints = **18 requests** ($n=18$). Rules: $100\%$ $\rightarrow$ Rules + ML: $100\%$.
  - **Total Attacks Tested:** 46 distinct payloads $\times$ 3 injection points = **138 attack test requests**.
- **How were obfuscated payloads generated?**
  Hand-crafted using evasion techniques observed in penetration testing:
  - SQLi: Case alternating (`1 UnIoN SeLeCt 1,2,3`), comment splitting (`1/**/UNION/**/SELECT/**/1,2`), double URL encoding (`%2527%2520OR%25201%253D1`), hex literals (`1 OR 0x31=0x31`), arithmetic tautologies (`' or 2>1 --`), MySQL version comments (`/*!50000UNION*/`), newline injection (`1%0aUNION%0aSELECT%0a1,2`).
  - Cmd: Newline URL encoding (`127.0.0.1%0Acat%20/etc/hosts`), shell environment whitespace evasion (`$IFS$9cat$IFS/etc/passwd`).
- **Overlap with training data:** **ZERO.** The Isolation Forest was trained strictly on 100% benign traffic (learning the shape of normal web requests). Attack payloads were never exposed during training.

---

## 7. False Positive Benchmark Results (30 Challenging Benign Cases)

- **File & Lines:** [`eval/false_positive_results.json:1-6`](../eval/false_positive_results.json#L1-L6) & [`eval/results.md:46-60`](../eval/results.md#L46-L60)
- **Total Tested:** 30 challenging benign queries (e.g. `O'Brien`, `select a plan`, `union station`, `drop me a message`, `<3 love`, JSON login, C++, multilingual Hindi text `नमस्ते दुनिया`).
- **WAF Decision Breakdown:**
  - **Blocks:** **0** (False Positive Block Rate = **0.0%**; zero legitimate requests blocked).
  - **ML Alerts:** **14** (Triggered strictly by `ml_flag=True` due to length/symbol/entropy density; converted to audit alerts via the "ML alone never blocks" policy).
  - **Rule Alerts:** **0** (Regex signatures produced zero false matches).
  - **Allows:** **16** (Completely clean traffic passing with zero alerts).

---

## 8. Request ID Format & Block Page Presentation

- **File & Lines:** [`sentinel/app.py:97`](../sentinel/app.py#L97), [`sentinel/app.py:137`](../sentinel/app.py#L137), [`sentinel/app.py:160-163`](../sentinel/app.py#L160-L163), [`sentinel/app.py:657`](../sentinel/app.py#L657)
- **Exact Format:**
  - **Internal & Tracing Header:** 8-character lowercase hexadecimal string generated by `uuid.uuid4().hex[:8]` (e.g. `e4a2b91c`, `7f8e9a0b`).
  - **HTTP Response Header:** `X-Request-ID: e4a2b91c`
  - **Block Page HTTP Body:**
    ```text
    403 Forbidden - blocked by AI-Sentinel (incident #50)
    ```
    (where `50` is the autoincrement primary key integer from the SQLite database).
  - **SOC Dashboard Presentation:** Correlates both identifiers side-by-side (`#50` and `<code>e4a2b91c</code>`).

---

## 9. Automated Test Suite Metrics

- **File & Lines:** [`tests/test_basic.py:1-263`](../tests/test_basic.py#L1-L263)
- **Total Test Count:** Exactly **30 automated tests**.
  - `WebsiteTests`: 24 tests (normal routing, SQLi, XSS, Path Traversal, POST bodies, brute-force bans, rate limiting, Request ID tracing, security headers, unban endpoint, CSV export, HTML escaping, health checks).
  - `EngineTests`: 6 tests (scanner UA alert, ML alone never blocks, repeated blocks ban IP, dry-run mode, double encoding decoding, ban persistence across restarts).
- **Execution Command:** `python -m unittest tests.test_basic -v`
- **Execution Time:** ~0.74 seconds (All 30 tests PASS).

---

## 10. Numbers I Must Memorize (10-Line Viva Cheat Sheet)

1. **Features:** **12 features** extracted per request; request rate **is** a feature (`rate_10s` at index 10).
2. **Rules:** **25 regex rules** across **12 attack categories**; max score capped at **10**.
3. **Execution:** Strictly **sequential** (Exemptions $\rightarrow$ Active Ban $\rightarrow$ Rules $\rightarrow$ ML $\rightarrow$ Policy $\rightarrow$ Dynamic Ban $\rightarrow$ SQLite Log).
4. **Rate Limit:** **$>20$ requests in $10\text{ seconds}$** triggers HTTP **429 Too Many Requests**.
5. **Brute Force & Ban:** **$\ge 5$ failed logins in $60\text{ seconds}$** triggers immediate **$60\text{-second}$ IP Ban**.
6. **Training Data:** **$33,000$ normal samples** ($28,000$ CSIC 2010 + $5,000$ synthetic); **$0\%$ test data in training**.
7. **Obfuscation Detection:** Adding ML boosts obfuscated SQLi from **$62\% \rightarrow 92\%$** and obfuscated Command Injection from **$50\% \rightarrow 67\%$**.
8. **False Positive Block Rate:** **$0.0\%$ block rate** on 30 tricky queries; 14 alerts raised by ML, but **zero** blocked.
9. **Latency:** Baseline app = **$1.02\text{ ms}$**; End-to-End with WAF = **$7.67\text{ ms}$ mean** ($8.53\text{ ms}$ p95); Net overhead $\approx \mathbf{6.65\text{ ms}}$.
10. **Test Suite & Tracing:** Exactly **30 automated unit tests**; Request ID is an **8-character hex string** (`uuid.uuid4().hex[:8]`).
