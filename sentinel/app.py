"""
app.py -- Flask web app. Isme 3 cheezein hain:

 1) Ek NAKLI "target" website (home, search, product, login) -- jise hum protect kar rahe hain.
    (Isme asli SQL ya file access nahi hai, isliye attack payloads sirf DETECTION test karte hain.)
 2) Sentinel ka guard: @app.before_request -- har request target tak pahunchne se PEHLE yahan se guzarti hai.
 3) Dashboard: /sentinel/dashboard (sirf apne computer se khulta hai).
"""
import csv
import hmac
import io
import json
import os
import threading
import urllib.request
import uuid
from datetime import datetime

from flask import Flask, Response, abort, jsonify, render_template_string, request

from . import config, db
from .engine import Sentinel
from .rules import decode

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000   # 1 MB se badi request mana

db.init_db()
sentinel = Sentinel()

SKIP_PREFIXES = ("/sentinel/", "/favicon.ico")   # inko inspect nahi karte
LOCAL_IPS = ("127.0.0.1", "::1")
DEMO_USER, DEMO_PASS = "demo", "demo123"          # demo login (sirf practice ke liye)
# Headers jinme attacker payload chhupa sakta hai
INSPECT_HEADERS = ("Cookie", "Referer", "Authorization", "X-Forwarded-Host", "X-Original-URL")
PRODUCTS = {
    1: ("Cloud Infrastructure Node & Kubernetes Cluster (Notebook Pod)", "infrastructure", 24999),
    2: ("Enterprise ERP Financial Ledger & Audit Suite (Pen Core)", "finance", 15400),
    3: ("Global Supply Chain Logistics & Fleet Telematics", "operations", 89000),
    4: ("Cybersecurity Threat Intelligence & SIEM Collector", "security", 45000),
    5: ("Corporate Directory IAM & Identity Governance", "governance", 12500),
    6: ("Real-time Business Intelligence & Executive Analytics", "analytics", 32000),
}


# =====================================================================
#  GUARD: har request yahan se guzarti hai
# =====================================================================
def split_pairs(raw):
    """'a=1&b=2' -> names=['a','b'], values=['1','2'] (jaise aaya waise, decode kiye bina)."""
    names, values = [], []
    for part in raw.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        names.append(name)
        values.append(value)
    return names, values


def _send_webhook_alert(event_id: int, ip: str, method: str, path: str, decision: dict):
    """Incident block hone par optional webhook alert bhejo (Slack, Discord, SIEM)."""
    if not config.WEBHOOK_URL:
        return
    def _post():
        try:
            payload = json.dumps({
                "incident_id": event_id,
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "method": method,
                "path": path,
                "action": decision["action"],
                "category": decision["category"],
                "reason": decision["reason"],
                "rule_score": decision["rule_score"],
            }).encode("utf-8")
            req = urllib.request.Request(
                config.WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "AI-Sentinel-Alerter/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3):
                pass
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()


@app.before_request
def guard():
    if request.path.startswith(SKIP_PREFIXES):
        return None

    # Har request ko unique ID do (tracing ke liye)
    request.request_id = uuid.uuid4().hex[:8]

    ip = request.remote_addr or "unknown"       # X-Forwarded-For par bharosa nahi (spoof ho sakta hai)
    raw_query = request.query_string.decode("utf-8", "replace")
    names, values = split_pairs(raw_query)
    raw_text = raw_query

    if request.method in ("POST", "PUT", "PATCH"):
        body = request.get_data(as_text=True)[: config.MAX_INSPECT_CHARS]
        if request.mimetype == "application/x-www-form-urlencoded":
            body_names, body_values = split_pairs(body)
            names += body_names
            values += body_values
        elif body:
            values.append(body)
        raw_text = (raw_text + "&" + body) if raw_text else body

    # Headers bhi inspect karo — attacker Cookie/Referer/Auth me payload chhupa sakta hai
    for hdr_name in INSPECT_HEADERS:
        hdr_val = request.headers.get(hdr_name, "")
        if hdr_val:
            values.append(hdr_val)
    for c_val in request.cookies.values():
        if c_val:
            values.append(c_val)

    decision = sentinel.inspect(request.method, request.path, values,
                                request.headers.get("User-Agent", ""), ip, raw_names=names)

    # Register me likho (log fail ho jaye to bhi website na ruke)
    try:
        req_id = getattr(request, "request_id", "")
        event_id = db.log_event(ip, request.method, request.path, decode(raw_text)[:300], decision, req_id)
    except Exception:
        app.logger.exception("event log nahi ho paya")
        event_id = 0

    if decision["enforced"]:
        if decision["action"] == "block":
            _send_webhook_alert(event_id, ip, request.method, request.path, decision)
            return Response(f"403 Forbidden - blocked by AI-Sentinel (incident #{event_id})\n",
                            status=403, mimetype="text/plain")
        if decision["action"] == "rate_limit":
            return Response("429 Too Many Requests - slow down\n", status=429,
                            headers={"Retry-After": str(config.RATE_WINDOW)}, mimetype="text/plain")
    return None


# =====================================================================
#  SECURITY RESPONSE HEADERS
# =====================================================================
@app.after_request
def add_security_headers(response):
    """Har response me security headers daal do (clickjacking, XSS, MIME sniffing se bachne ke liye)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Dashboard me inline script/style hai, isliye 'unsafe-inline' zaroori hai
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' 'self'"
    )
    # Request ID response me bhi bhejo (debugging/tracing ke liye)
    req_id = getattr(request, "request_id", None)
    if req_id:
        response.headers["X-Request-ID"] = req_id
    return response


# =====================================================================
#  ENTERPRISE CORPORATE TARGET PORTAL (NexusCorp Enterprise Suite)
# =====================================================================
HEAD = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NexusCorp &middot; Enterprise Resource &amp; Cloud Platform</title>
<style>
:root{--bg:#0b0f19;--card:#151c28;--border:#263248;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--accent-hover:#58a6ff;--line:#263248;--success:#238636;--success-bg:rgba(35,134,54,0.15)}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.6}
header{background:var(--card);border-bottom:1px solid var(--border);padding:.8rem 1.5rem}
.nav-wrap{max-width:1100px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}
.brand{font-size:1.25rem;font-weight:700;letter-spacing:-0.4px;color:#fff;text-decoration:none;display:flex;align-items:center;gap:.6rem}
.badge-corp{background:var(--success-bg);color:#3fb950;border:1px solid rgba(63,185,80,0.3);padding:.15rem .55rem;border-radius:99px;font-size:.72rem;font-weight:600}
nav{display:flex;gap:1.1rem;align-items:center;flex-wrap:wrap}
nav a{color:var(--muted);text-decoration:none;font-size:.9rem;font-weight:500;transition:color .15s}
nav a:hover,nav a.active{color:#fff}
.nav-btn{background:rgba(47,129,247,0.15);color:#58a6ff;border:1px solid rgba(47,129,247,0.3);padding:.35rem .75rem;border-radius:6px;font-size:.82rem}
.nav-btn:hover{background:var(--accent);color:#fff}
main{max-width:1100px;margin:2rem auto;padding:0 1.25rem}
.hero{background:linear-gradient(180deg,rgba(38,50,72,0.4) 0%,rgba(21,28,40,0.6) 100%);border:1px solid var(--border);border-radius:10px;padding:2rem;margin-bottom:2rem}
.hero h1{margin:0 0 .5rem;font-size:1.85rem;letter-spacing:-0.5px}
.hero p{margin:0 0 1.25rem;color:var(--muted);font-size:1rem;max-width:760px}
.metrics-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem;margin-bottom:1.5rem}
.m-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.9rem;box-shadow:0 2px 6px rgba(0,0,0,0.2)}
.m-card b{display:block;font-size:1.3rem;color:#fff}
.m-card span{font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px}
.search-bar{display:flex;gap:.5rem;max-width:600px;margin-bottom:1.2rem}
input[type="text"],input[type="password"]{flex:1;background:var(--card);border:1px solid var(--border);color:#fff;border-radius:6px;padding:.55rem .85rem;font-size:.9rem;outline:none}
input:focus{border-color:var(--accent)}
button,.btn{background:var(--accent);color:#fff;border:none;border-radius:6px;padding:.55rem 1.1rem;font-size:.9rem;font-weight:600;cursor:pointer;transition:all .15s}
button:hover,.btn:hover{background:var(--accent-hover)}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.4rem;margin-bottom:1.5rem}
.panel h2{margin:0 0 1rem;font-size:1.2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}
.card{background:rgba(21,28,40,0.5);border:1px solid var(--border);border-radius:8px;padding:1.1rem;transition:transform .15s}
.card:hover{border-color:var(--accent);transform:translateY(-2px)}
.card h3{margin:0 0 .4rem;font-size:1.05rem}
.card p{margin:0 0 .8rem;font-size:.85rem;color:var(--muted)}
.card-meta{display:flex;justify-content:space-between;align-items:center;font-size:.82rem}
.category-badge{background:rgba(47,129,247,0.12);color:#58a6ff;padding:.15rem .5rem;border-radius:99px;font-size:.75rem;text-transform:uppercase;font-weight:600}
.login-box{max-width:420px;margin:2rem auto;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:2rem;box-shadow:0 4px 16px rgba(0,0,0,0.3)}
.login-box h2{margin:0 0 .4rem;font-size:1.35rem}
.login-box p{color:var(--muted);font-size:.85rem;margin:0 0 1.5rem}
.form-group{margin-bottom:1rem}
.form-group label{display:block;font-size:.82rem;font-weight:600;color:var(--muted);margin-bottom:.3rem;text-transform:uppercase}
.form-group input{width:100%;box-sizing:border-box}
.demo-pill{background:rgba(210,153,34,0.15);color:#d29922;border:1px solid rgba(210,153,34,0.3);padding:.4rem .8rem;border-radius:6px;font-size:.8rem;margin-bottom:1.2rem;display:block}
footer{border-top:1px solid var(--border);padding:1.5rem;text-align:center;color:var(--muted);font-size:.82rem;margin-top:3rem}
</style></head><body>
<header>
  <div class="nav-wrap">
    <a href="/" class="brand">🏢 NexusCorp <span class="badge-corp">🛡️ AI-Sentinel Active WAF</span></a>
    <nav>
      <a href="/">Overview</a>
      <a href="/products">Enterprise Solutions</a>
      <a href="/about">Architecture</a>
      <a href="/login">IAM Portal</a>
      <a href="/sentinel/dashboard" class="nav-btn">📊 SOC Dashboard</a>
      <a href="/sentinel/health" class="nav-btn">🩺 Health Check</a>
    </nav>
  </div>
</header>
<main>"""
TAIL = """</main>
<footer>
  NexusCorp Global Operations &middot; Confidential Internal Enterprise Portal &middot; Secured by AI-Sentinel Layer-7 Threat Mitigation
</footer>
</body></html>"""


def page(body, **ctx):
    return render_template_string(HEAD + body + TAIL, **ctx)   # Jinja autoescape ON: user input safe


@app.route("/")
def home():
    return page("""
<div class="hero">
  <h1>Enterprise Resource &amp; Cloud Management Portal</h1>
  <p>Mission-critical corporate infrastructure serving 120,000+ enterprise stakeholders across 14 global data centers. Monitored in real-time by AI-Sentinel Layer-7 active defense perimeter.</p>
  
  <div class="metrics-row">
    <div class="m-card"><b>99.995%</b><span>Global SLA Uptime</span></div>
    <div class="m-card"><b>Zero-Trust</b><span>Defense Posture</span></div>
    <div class="m-card"><b>14 Regions</b><span>Connected Clusters</span></div>
    <div class="m-card"><b>AES-256</b><span>Data Sovereignty</span></div>
  </div>

  <form action="/search" method="get" class="search-bar">
    <input type="text" name="q" placeholder="Search enterprise services, modules, ledger, cloud nodes...">
    <button type="submit">Search Directory</button>
  </form>
</div>

<div class="panel">
  <h2>Enterprise Management Quick Actions</h2>
  <div class="grid">
    <div class="card">
      <h3>💼 Corporate IAM Single Sign-On</h3>
      <p>Authenticate with corporate employee credentials to access internal financial ledgers, cloud infrastructure, and HR systems.</p>
      <div class="card-meta">
        <span class="category-badge">Identity &amp; Access</span>
        <a href="/login" class="nav-btn">Open IAM Login &rarr;</a>
      </div>
    </div>
    <div class="card">
      <h3>📦 Enterprise Services &amp; Modules Catalog</h3>
      <p>Browse internal corporate microservices, Kubernetes node clusters, and global supply chain tracking pipelines.</p>
      <div class="card-meta">
        <span class="category-badge">Cloud Services</span>
        <a href="/products" class="nav-btn">View Modules &rarr;</a>
      </div>
    </div>
    <div class="card">
      <h3>🛡️ Real-time Threat Intelligence Console</h3>
      <p>Inspect active WAF defense, machine learning anomaly scores, and forensic event logs intercepted by AI-Sentinel.</p>
      <div class="card-meta">
        <span class="category-badge">Cybersecurity</span>
        <a href="/sentinel/dashboard" class="nav-btn">Open SOC Dashboard &rarr;</a>
      </div>
    </div>
  </div>
</div>
""")


@app.route("/about")
def about():
    return page("""
<div class="panel">
  <h2>Corporate Architecture &amp; Zero-Trust Security Perimeter</h2>
  <p style="color:var(--muted)">NexusCorp operates mission-critical enterprise systems under strict regulatory compliance frameworks (SOC-2 Type II, ISO 27001, GDPR, HIPAA).</p>
  
  <div class="grid" style="margin-top:1.5rem">
    <div class="card">
      <h3>🛡️ Layer-7 Ingress Defense</h3>
      <p>Every inbound HTTP/S transaction is intercepted by <code>AI-Sentinel</code> prior to execution, blocking SQL Injection, Cross-Site Scripting, SSRF, and command chaining.</p>
    </div>
    <div class="card">
      <h3>🧠 Machine Learning Anomaly Core</h3>
      <p>Trained on authentic real-world HTTP traffic distributions (CSIC 2010), our Isolation Forest engine detects stealthy zero-day bypasses without relying solely on static signatures.</p>
    </div>
    <div class="card">
      <h3>🗄️ Tamper-evident Audit Register</h3>
      <p>Cryptographically sanitized incident records are logged with parameterised SQLite transactions and automated credential masking (passwords, tokens, keys).</p>
    </div>
    <div class="card">
      <h3>⚡ Active Defense Orchestration</h3>
      <p>Dynamic rate limiting and automated IP banning protect corporate authentication endpoints from distributed brute-force attacks.</p>
    </div>
  </div>
</div>
""")


@app.route("/products")
def products():
    category = request.args.get("category", "")
    items = [(pid, n, c, p) for pid, (n, c, p) in PRODUCTS.items() if not category or c == category.lower()]
    return page("""
<div class="panel">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.8rem;margin-bottom:1.2rem">
    <h2 style="margin:0">Enterprise Modules &amp; Solutions Catalog {% if category %}&middot; <span style="color:var(--accent)">{{ category|capitalize }}</span>{% endif %}</h2>
    <div style="display:flex;gap:.4rem;flex-wrap:wrap">
      <a href="/products" class="category-badge" style="text-decoration:none">All</a>
      <a href="/products?category=infrastructure" class="category-badge" style="text-decoration:none">Infrastructure</a>
      <a href="/products?category=finance" class="category-badge" style="text-decoration:none">Finance</a>
      <a href="/products?category=security" class="category-badge" style="text-decoration:none">Security</a>
      <a href="/products?category=operations" class="category-badge" style="text-decoration:none">Operations</a>
      <a href="/products?category=governance" class="category-badge" style="text-decoration:none">Governance</a>
    </div>
  </div>

  <div class="grid">
  {% for pid, n, c, p in items %}
    <div class="card">
      <span class="category-badge" style="margin-bottom:.5rem;display:inline-block">{{ c }}</span>
      <h3>{{ n }}</h3>
      <p>Corporate Enterprise Resource &middot; Module ID #{{ pid }}</p>
      <div class="card-meta">
        <span style="font-weight:600;color:#fff">Rs {{ p }}/mo allocation</span>
        <a href="/product?id={{ pid }}" class="nav-btn">Specifications &rarr;</a>
      </div>
    </div>
  {% else %}
    <p style="color:var(--muted)">No enterprise modules found matching the criteria.</p>
  {% endfor %}
  </div>
</div>
""", items=items, category=category)


@app.route("/product")
def product():
    try:
        pid = int(request.args.get("id", ""))
    except ValueError:
        return Response("400 Bad Request: id must be a number\n", status=400, mimetype="text/plain")
    if pid not in PRODUCTS:
        return Response("404 Not Found: Enterprise module not found\n", status=404, mimetype="text/plain")
    name, category, price = PRODUCTS[pid]
    return page("""
<div class="panel" style="max-width:700px;margin:1rem auto">
  <span class="category-badge">{{ category }}</span>
  <h2 style="margin:.6rem 0 .4rem;font-size:1.5rem">{{ name }}</h2>
  <p style="color:var(--muted)">Corporate Enterprise Resource Specification &middot; Module #{{ pid }}</p>
  
  <div style="background:rgba(11,15,25,0.6);border:1px solid var(--border);border-radius:6px;padding:1.2rem;margin:1.2rem 0">
    <div style="display:flex;justify-content:space-between;margin-bottom:.6rem;border-bottom:1px solid var(--border);padding-bottom:.4rem">
      <span style="color:var(--muted)">Budget Allocation:</span>
      <strong style="color:#fff">Rs {{ price }} / month</strong>
    </div>
    <div style="display:flex;justify-content:space-between;margin-bottom:.6rem;border-bottom:1px solid var(--border);padding-bottom:.4rem">
      <span style="color:var(--muted)">SLA Tier:</span>
      <span style="color:#3fb950;font-weight:600">Tier 1 &middot; Mission Critical (99.995%)</span>
    </div>
    <div style="display:flex;justify-content:space-between;margin-bottom:.6rem;border-bottom:1px solid var(--border);padding-bottom:.4rem">
      <span style="color:var(--muted)">Compliance Clearance:</span>
      <span>SOC-2 Type II, ISO 27001, GDPR</span>
    </div>
    <div style="display:flex;justify-content:space-between">
      <span style="color:var(--muted)">API Endpoint Route:</span>
      <code>/api/v1/enterprise/modules/{{ pid }}</code>
    </div>
  </div>

  <div style="display:flex;gap:.8rem">
    <a href="/products" class="btn" style="text-decoration:none">&larr; Back to Solutions</a>
    <a href="/sentinel/dashboard" class="nav-btn" style="text-decoration:none;padding:.55rem 1rem">Inspect Traffic in SOC Console</a>
  </div>
</div>
""", name=name, category=category, price=price, pid=pid)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    hits = [n for n, _, _ in PRODUCTS.values() if q.lower() in n.lower()] if q else []
    return page("""
<div class="panel">
  <h2>Enterprise Directory Search Results for: <span style="color:var(--accent)">"{{ q }}"</span></h2>
  <p style="color:var(--muted)">Query scanned across corporate services, cloud infrastructure nodes, and internal ERP components.</p>
  
  <ul style="list-style:none;padding:0;margin:1.2rem 0">
  {% for n in hits %}
    <li style="background:rgba(21,28,40,0.6);border:1px solid var(--border);border-radius:6px;padding:.9rem 1.2rem;margin-bottom:.6rem;display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:600">{{ n }}</span>
      <span class="category-badge">Active Module</span>
    </li>
  {% else %}
    <li style="color:var(--muted);padding:1rem 0">No corporate enterprise resources found matching the specified query.</li>
  {% endfor %}
  </ul>

  <a href="/" class="btn" style="text-decoration:none;display:inline-block">&larr; Return to Enterprise Overview</a>
</div>
""", q=q, hits=hits)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        password = request.form.get("password", "")
        # compare_digest = constant-time comparison (timing attack se bachne ke liye)
        ok = hmac.compare_digest(user.encode(), DEMO_USER.encode()) & \
             hmac.compare_digest(password.encode(), DEMO_PASS.encode())
        if ok:
            return page("""
<div class="panel" style="max-width:550px;margin:2rem auto;text-align:center">
  <span class="badge-corp" style="font-size:.85rem;padding:.3rem .8rem">Authenticated Session Active</span>
  <h2 style="margin:1rem 0 .5rem">Welcome, {{ user }}!</h2>
  <p style="color:var(--muted)">Enterprise IAM Identity successfully verified. Full access to internal cloud clusters and corporate ledger granted.</p>
  <div style="margin-top:1.5rem;display:flex;gap:.8rem;justify-content:center">
    <a href="/products" class="btn" style="text-decoration:none">Access Enterprise Modules</a>
    <a href="/sentinel/dashboard" class="nav-btn" style="text-decoration:none">View Security Console</a>
  </div>
</div>
""", user=user)
        sentinel.record_failed_login(request.remote_addr or "unknown")   # brute-force counter
        return page("""
<div class="panel" style="max-width:550px;margin:2rem auto;text-align:center;border-color:#da3633">
  <h2 style="color:#f85149;margin:0 0 .5rem">Login failed</h2>
  <p style="color:var(--muted)">Invalid corporate username or passphrase credentials. Access failure recorded for brute-force auditing.</p>
  <a href="/login" class="btn" style="text-decoration:none;display:inline-block;margin-top:1rem">Try Again</a>
</div>
"""), 401
    return page("""
<div class="login-box">
  <div style="text-align:center;margin-bottom:1rem">
    <span style="font-size:2rem">🔐</span>
    <h2>NexusCorp Enterprise IAM</h2>
    <p>Corporate Single Sign-On (SSO) Portal</p>
  </div>
  
  <span class="demo-pill">🔑 Practice SSO Credentials: <b>demo</b> / <b>demo123</b></span>

  <form method="post">
    <div class="form-group">
      <label>Corporate User ID / Email</label>
      <input type="text" name="username" placeholder="e.g. employee.id@nexuscorp.internal" required>
    </div>
    <div class="form-group">
      <label>Security Passphrase</label>
      <input type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
    </div>
    <button type="submit" style="width:100%;margin-top:.6rem">Authenticate with Zero-Trust SSO</button>
  </form>
  
  <p style="margin-top:1.5rem;font-size:.75rem;color:var(--muted);text-align:center">
    Protected by AI-Sentinel Active Threat Defense. Unauthorized access attempts are monitored and reported to the SOC.
  </p>
</div>
""")


# =====================================================================
#  DASHBOARD (CCTV screen)
# =====================================================================
DASHBOARD = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI-Sentinel Dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6570;--line:#e2e5e9;--accent:#0b5fff;--hover:#eef2f6}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1d2126;--text:#e8eaed;--muted:#9aa4af;--line:#2e343b;--accent:#6ea0ff;--hover:#252a32}}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif}
main{max-width:1100px;margin:0 auto;padding:1rem}
.header-row{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.75rem;margin-bottom:.4rem}
h1{margin:.2rem 0;font-size:1.8rem;letter-spacing:-0.5px}
h2{margin:1.4rem 0 .4rem;font-size:1.05rem}
.mode{color:var(--muted);font-size:.9rem}
.header-actions{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.btn{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.4rem .75rem;font-size:.85rem;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:.35rem;font-weight:500;transition:all .15s ease}
.btn:hover{background:var(--hover);border-color:var(--muted)}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{opacity:.9;color:#fff}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.6rem;margin-top:.8rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.7rem;box-shadow:0 1px 3px rgba(0,0,0,0.03)}
.card b{display:block;font-size:1.6rem}.card span{color:var(--muted);font-size:.85rem}
.panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem;box-shadow:0 1px 3px rgba(0,0,0,0.03)}
.row{display:flex;align-items:center;gap:.6rem;margin:.25rem 0}
.row .label{width:150px;font-size:.9rem}.bar{height:12px;background:var(--accent);border-radius:3px}
.controls-bar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.6rem;margin:1rem 0 .5rem}
.filter-group{display:flex;gap:.35rem;flex-wrap:wrap}
.filter-pill{background:var(--card);border:1px solid var(--line);color:var(--muted);border-radius:99px;padding:.25rem .7rem;font-size:.8rem;cursor:pointer;font-weight:500;transition:all .15s}
.filter-pill:hover{background:var(--hover);color:var(--text)}
.filter-pill.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.search-input{background:var(--card);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:.4rem .65rem;font-size:.85rem;outline:none;min-width:230px}
.search-input:focus{border-color:var(--accent)}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.payload{max-width:260px;word-break:break-all;font-family:monospace}
.badge{padding:.12rem .5rem;border-radius:99px;font-size:.78rem;font-weight:600;border:1px solid var(--line);display:inline-block}
.badge.block{background:#d92d20;color:#fff;border-color:#b42318}
.badge.alert{background:#f79009;color:#111;border-color:#dc6803}
.badge.rate_limit{background:#7a5af8;color:#fff;border-color:#6938ef}
.badge.allow{background:transparent;color:var(--muted)}
</style></head>
<body onload="
(function(){
  window.isAutoRefresh = true;
  window.countdown = 5;
  window.activeAction = 'all';

  var timerEl = document.getElementById('refresh-timer');
  var toggleBtn = document.getElementById('toggle-refresh');
  var statusSpan = document.getElementById('refresh-status-text');

  setInterval(function(){
    if (!window.isAutoRefresh) return;
    window.countdown--;
    if (window.countdown <= 0) {
      window.location.reload();
    } else if (timerEl) {
      timerEl.textContent = window.countdown + 's';
    }
  }, 1000);

  window.toggleRefresh = function(){
    window.isAutoRefresh = !window.isAutoRefresh;
    if (window.isAutoRefresh) {
      window.countdown = 5;
      if (toggleBtn) toggleBtn.textContent = '⏸ Pause';
      if (statusSpan) statusSpan.innerHTML = 'Auto-refresh in <b id=\'refresh-timer\'>5s</b>';
      timerEl = document.getElementById('refresh-timer');
    } else {
      if (toggleBtn) toggleBtn.textContent = '▶ Resume';
      if (statusSpan) statusSpan.innerHTML = 'Auto-refresh <b>PAUSED</b>';
    }
  };

  window.setFilter = function(action, btn){
    window.activeAction = action;
    var pills = document.querySelectorAll('.filter-pill');
    for (var i = 0; i < pills.length; i++) {
      pills[i].classList.remove('active');
    }
    btn.classList.add('active');
    window.filterEvents();
  };

  window.filterEvents = function(){
    var sInput = document.getElementById('search-input');
    var query = (sInput && sInput.value ? sInput.value : '').toLowerCase().trim();
    if (query && window.isAutoRefresh) {
      window.toggleRefresh();
    }
    var rows = document.querySelectorAll('#events-table tbody tr');
    var count = 0;
    for (var j = 0; j < rows.length; j++) {
      var r = rows[j];
      var act = r.getAttribute('data-action');
      var searchData = r.getAttribute('data-search') || '';
      if (!act) continue;
      var matchAct = (window.activeAction === 'all' || act === window.activeAction);
      var matchSearch = (!query || searchData.indexOf(query) !== -1);
      if (matchAct && matchSearch) {
        r.style.display = '';
        count++;
      } else {
        r.style.display = 'none';
      }
    }
    var countEl = document.getElementById('events-count');
    if (countEl) countEl.textContent = 'Showing ' + count + ' of ' + rows.length + ' events';
  };
})()
">
<main>
<div class="header-row">
  <div>
    <h1>AI-Sentinel</h1>
    <div class="mode">Mode: {{ mode }} &middot; <span id="refresh-status-text">Auto-refresh in <b id="refresh-timer">5s</b></span></div>
  </div>
  <div class="header-actions">
    <button id="toggle-refresh" class="btn" onclick="toggleRefresh()">⏸ Pause</button>
    <a href="/sentinel/export/csv" class="btn btn-primary" download>📥 Export Incidents (CSV)</a>
  </div>
</div>

<div class="cards">{% for label, value in cards %}<div class="card"><b>{{ value }}</b><span>{{ label }}</span></div>{% endfor %}</div>

<h2>Attack categories</h2>
<div class="panel">{% for name, n in categories %}
<div class="row"><span class="label">{{ name }}</span><div class="bar" style="width:{{ (n / max_cat * 100)|int }}%"></div><span>{{ n }}</span></div>
{% else %}<span class="mode">No suspicious events yet.</span>{% endfor %}</div>

<h2>Top suspicious IPs</h2>
<div class="panel">{% for ip, n in top_ips %}<div class="row"><span class="label">{{ ip }}</span><span>{{ n }} events</span></div>
{% else %}<span class="mode">None yet.</span>{% endfor %}</div>

<h2>Currently banned IPs</h2>
<div class="panel">{% for ip, left in banned %}<div class="row"><span class="label">{{ ip }}</span><span>{{ left }}s left</span>
<button class="btn" onclick="fetch('/sentinel/api/unban/{{ ip }}',{method:'POST'}).then(function(){location.reload()})" style="margin-left:.5rem;font-size:.75rem">🔓 Unban</button></div>
{% else %}<span class="mode">No active bans.</span>{% endfor %}</div>

<div class="controls-bar">
  <h2>Recent events (latest 50)</h2>
  <span id="events-count" class="mode">Showing {{ events|length }} events</span>
</div>

<div class="controls-bar">
  <div class="filter-group">
    <button class="filter-pill active" onclick="setFilter('all', this)">All</button>
    <button class="filter-pill" onclick="setFilter('block', this)">Blocked</button>
    <button class="filter-pill" onclick="setFilter('alert', this)">Alerts</button>
    <button class="filter-pill" onclick="setFilter('rate_limit', this)">Rate-limited</button>
    <button class="filter-pill" onclick="setFilter('allow', this)">Allowed</button>
  </div>
  <input type="text" id="search-input" class="search-input" placeholder="🔍 Search IP, path, payload..." oninput="filterEvents()">
</div>

<div class="panel scroll"><table id="events-table">
<thead>
<tr><th>Time</th><th>IP</th><th>Request</th><th>Payload</th><th>Action</th><th>Category</th><th>Rule score</th><th>ML score</th><th>Why</th></tr>
</thead>
<tbody>
{% for e in events %}
<tr data-action="{{ e.action }}" data-search="{{ (e.ip ~ ' ' ~ e.method ~ ' ' ~ e.path ~ ' ' ~ e.payload ~ ' ' ~ e.category ~ ' ' ~ e.reason)|lower }}">
<td>{{ e.time }}</td><td>{{ e.ip }}</td><td>{{ e.method }} {{ e.path }}</td><td class="payload">{{ e.payload }}</td>
<td><span class="badge {{ e.action }}">{{ e.action }}</span>{% if not e.enforced and e.action in ('block','rate_limit') %} (dry-run){% endif %}</td>
<td>{{ e.category }}</td><td>{{ e.rule_score }}</td><td>{{ e.ml_score if e.ml_score is not none else '-' }}</td><td>{{ e.reason }}</td>
</tr>
{% else %}
<tr><td colspan="9">No events yet. Open the website and try something.</td></tr>
{% endfor %}
</tbody>
</table></div></main></body></html>"""


def _local_only():
    if os.environ.get("VERCEL") or os.environ.get("SENTINEL_ALLOW_REMOTE_DASHBOARD") == "1":
        return
    if request.remote_addr not in LOCAL_IPS:
        abort(403)


def _api_auth():
    """Localhost allowed; remote requests allowed agar valid SENTINEL_API_KEY ho ya Vercel demo mode ho."""
    if os.environ.get("VERCEL") or os.environ.get("SENTINEL_ALLOW_REMOTE_DASHBOARD") == "1":
        return
    if request.remote_addr in LOCAL_IPS:
        return
    if config.API_KEY:
        auth_hdr = request.headers.get("Authorization", "")
        token = auth_hdr.replace("Bearer ", "").strip() if "Bearer " in auth_hdr else ""
        key_hdr = request.headers.get("X-API-Key", "").strip()
        if (token and hmac.compare_digest(token.encode(), config.API_KEY.encode())) or \
           (key_hdr and hmac.compare_digest(key_hdr.encode(), config.API_KEY.encode())):
            return
    abort(403)


@app.route("/sentinel/dashboard")
def dashboard():
    _local_only()
    s = db.stats()
    events = db.recent_events(50)
    for e in events:
        e["time"] = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
    by = s["by_action"]
    cards = [("Total requests", s["total"]), ("Allowed", by.get("allow", 0)), ("Alerts", by.get("alert", 0)),
             ("Blocked", by.get("block", 0)), ("Rate-limited", by.get("rate_limit", 0))]
    mode = ("DRY-RUN (nothing is really blocked)" if sentinel.dry_run else "ENFORCING") + \
           (" + ML anomaly" if sentinel.use_ml else " (rules only)")
    return render_template_string(
        DASHBOARD, cards=cards, events=events, mode=mode, categories=s["by_category"],
        max_cat=max([n for _, n in s["by_category"]], default=1), top_ips=s["top_ips"],
        banned=sentinel.banned_ips())


@app.route("/sentinel/api/events")
def api_events():
    _api_auth()
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
    except ValueError:
        return Response("limit must be a number\n", status=400, mimetype="text/plain")
    return jsonify(db.recent_events(limit))


@app.route("/sentinel/api/stats")
def api_stats():
    """Dashboard statistics JSON format me."""
    _api_auth()
    return jsonify(db.stats())


@app.route("/sentinel/health")
def health():
    """System health check — ML loaded hai? DB kaam kar raha? Uptime?"""
    _api_auth()
    db_ok = True
    try:
        db.stats()
    except Exception:
        db_ok = False

    active_bans = len(sentinel.banned_ips())
    ml_loaded = sentinel.detector is not None and sentinel.detector.ready if sentinel.use_ml else False
    status = "ok" if db_ok else "degraded"

    data = {
        "status": status,
        "ml_enabled": sentinel.use_ml,
        "ml_loaded": ml_loaded,
        "dry_run": sentinel.dry_run,
        "db_ok": db_ok,
        "active_bans": active_bans,
    }

    # Browser se aane wali request ko premium UI render karo
    if "text/html" in request.headers.get("Accept", "") and request.args.get("format") != "json":
        return render_template_string(
            HEALTH_TEMPLATE,
            status=status,
            ml_loaded=ml_loaded,
            dry_run=sentinel.dry_run,
            db_ok=db_ok,
            active_bans=active_bans,
            raw_json=json.dumps(data, indent=2),
        )

    # API client ya automated tests ko pure JSON return karo
    return jsonify(data)


HEALTH_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI-Sentinel &middot; System Health &amp; Diagnostics</title>
<style>
:root{--bg:#0c1017;--card:#151c28;--border:#263248;--text:#e6edf3;--muted:#8b949e;--accent:#2f81f7;--success:#238636;--success-bg:rgba(35,134,54,0.15);--warn:#d29922;--warn-bg:rgba(210,153,34,0.15);--danger:#da3633;--danger-bg:rgba(218,54,51,0.15);--code-bg:#0d1117}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5}
main{max-width:960px;margin:2rem auto;padding:0 1.25rem}
.header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:2rem;padding-bottom:1.25rem;border-bottom:1px solid var(--border)}
.title-group{display:flex;align-items:center;gap:.85rem}
.pulse-orb{width:16px;height:16px;border-radius:50%;background:#3fb950;box-shadow:0 0 12px #3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,0.7)}70%{box-shadow:0 0 0 10px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
h1{margin:0;font-size:1.6rem;letter-spacing:-0.4px}
.subtitle{color:var(--muted);font-size:.85rem;margin-top:.2rem}
.nav-links{display:flex;gap:.6rem;flex-wrap:wrap}
.btn{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:.45rem .85rem;font-size:.85rem;font-weight:500;text-decoration:none;cursor:pointer;transition:all .15s ease;display:inline-flex;align-items:center;gap:.4rem}
.btn:hover{background:var(--border);color:#fff}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{opacity:.9}
.status-banner{background:var(--success-bg);border:1px solid var(--success);border-radius:8px;padding:1rem 1.25rem;display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem}
.status-banner.degraded{background:var(--warn-bg);border-color:var(--warn)}
.status-title{font-size:1.05rem;font-weight:600;display:flex;align-items:center;gap:.6rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1rem;margin-bottom:1.8rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.1rem;box-shadow:0 2px 8px rgba(0,0,0,0.2)}
.card-label{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:600}
.card-value{font-size:1.35rem;font-weight:700;margin:.4rem 0 .2rem}
.card-desc{font-size:.8rem;color:var(--muted)}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1.5rem}
.panel h2{margin:0 0 1rem;font-size:1.1rem}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{padding:.65rem .75rem;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase}
.badge{display:inline-flex;align-items:center;padding:.15rem .55rem;border-radius:99px;font-size:.78rem;font-weight:600}
.badge.ok{background:var(--success-bg);color:#3fb950;border:1px solid rgba(63,185,80,0.3)}
.badge.warn{background:var(--warn-bg);color:#d29922;border:1px solid rgba(210,153,34,0.3)}
.badge.info{background:rgba(47,129,247,0.15);color:#58a6ff;border:1px solid rgba(47,129,247,0.3)}
pre{background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:1rem;color:#7ee787;font-family:monospace;font-size:.85rem;overflow-x:auto;margin:0}
</style>
</head>
<body>
<main>
<div class="header">
  <div class="title-group">
    <div class="pulse-orb" style="{% if status != 'ok' %}background:#d29922;box-shadow:0 0 12px #d29922;{% endif %}"></div>
    <div>
      <h1>System Diagnostics &amp; Health</h1>
      <div class="subtitle">AI-Sentinel Active Defense Engine &middot; Real-time Verification</div>
    </div>
  </div>
  <div class="nav-links">
    <button class="btn" onclick="location.reload()">🔄 Refresh</button>
    <a href="/sentinel/dashboard" class="btn btn-primary">📊 Open SOC Dashboard</a>
    <a href="/sentinel/health?format=json" class="btn">📋 Raw JSON</a>
  </div>
</div>

<div class="status-banner {% if status != 'ok' %}degraded{% endif %}">
  <div class="status-title">
    <span>{% if status == 'ok' %}✅ All Security &amp; Detection Systems Operational{% else %}⚠️ System Running in Degraded Mode{% endif %}</span>
  </div>
  <span class="badge ok">STATUS: {{ status|upper }}</span>
</div>

<div class="grid">
  <div class="card">
    <div class="card-label">Detection Guard</div>
    <div class="card-value">{% if dry_run %}<span style="color:#d29922">DRY-RUN</span>{% else %}<span style="color:#3fb950">ENFORCING</span>{% endif %}</div>
    <div class="card-desc">{% if dry_run %}Simulating blocks without disruption{% else %}Active defense blocking malicious traffic{% endif %}</div>
  </div>
  <div class="card">
    <div class="card-label">Machine Learning</div>
    <div class="card-value">{% if ml_loaded %}<span style="color:#3fb950">Isolation Forest</span>{% else %}<span style="color:#d29922">Rules-Only</span>{% endif %}</div>
    <div class="card-desc">12-dimensional vector anomaly detector</div>
  </div>
  <div class="card">
    <div class="card-label">Audit Database</div>
    <div class="card-value">{% if db_ok %}<span style="color:#3fb950">Connected</span>{% else %}<span style="color:#da3633">Disconnected</span>{% endif %}</div>
    <div class="card-desc">SQLite forensic event register</div>
  </div>
  <div class="card">
    <div class="card-label">Active IP Bans</div>
    <div class="card-value">{{ active_bans }}</div>
    <div class="card-desc">Persisted in SQLite database</div>
  </div>
</div>

<div class="panel">
  <h2>Subsystem Verification Status</h2>
  <table>
    <thead>
      <tr><th>Subsystem</th><th>Component</th><th>Technology</th><th>Status</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Signature Inspection</strong></td>
        <td><code>sentinel.rules</code></td>
        <td>25+ OWASP regex patterns (SQLi, XSS, SSRF, Log4Shell)</td>
        <td><span class="badge ok">READY</span></td>
      </tr>
      <tr>
        <td><strong>ML Anomaly Detection</strong></td>
        <td><code>sentinel.ml</code></td>
        <td>Scikit-learn Isolation Forest (contamination=0.01)</td>
        <td>{% if ml_loaded %}<span class="badge ok">LOADED</span>{% else %}<span class="badge warn">OFFLINE</span>{% endif %}</td>
      </tr>
      <tr>
        <td><strong>Policy Orchestrator</strong></td>
        <td><code>sentinel.policy</code></td>
        <td>Cascading arbitration: Brute-Force &gt; High-Rule &gt; Rule+ML</td>
        <td><span class="badge ok">ONLINE</span></td>
      </tr>
      <tr>
        <td><strong>Persistence Layer</strong></td>
        <td><code>sentinel.db</code></td>
        <td>SQLite parameterised audit log + persistent bans</td>
        <td>{% if db_ok %}<span class="badge ok">OPERATIONAL</span>{% else %}<span class="badge warn">ERROR</span>{% endif %}</td>
      </tr>
      <tr>
        <td><strong>Defense Headers</strong></td>
        <td><code>sentinel.app</code></td>
        <td>CSP, X-Frame-Options: DENY, nosniff, Correlation ID</td>
        <td><span class="badge ok">ENFORCED</span></td>
      </tr>
    </tbody>
  </table>
</div>

<div class="panel">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem">
    <h2 style="margin:0">API Response Preview</h2>
    <span style="font-size:.8rem;color:var(--muted)">Format: application/json</span>
  </div>
  <pre><code>{{ raw_json }}</code></pre>
</div>
</main>
</body></html>"""


@app.route("/sentinel/api/unban/<ip>", methods=["POST"])
def unban_ip(ip):
    """Manually ek IP ka ban hatao."""
    _api_auth()
    success = sentinel.unban(ip)
    return jsonify({"ip": ip, "unbanned": success})


@app.route("/sentinel/export/csv")
def export_csv():
    _local_only()
    try:
        limit = min(int(request.args.get("limit", 500)), 5000)
    except ValueError:
        limit = 500
    events = db.recent_events(limit)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp", "datetime", "ip", "method", "path", "payload",
        "action", "category", "rules", "rule_score", "ml_score", "ml_flag",
        "reason", "enforced", "latency_ms"
    ])
    for e in events:
        dt = datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([
            e.get("id"),
            e.get("ts"),
            dt,
            e.get("ip"),
            e.get("method"),
            e.get("path"),
            e.get("payload"),
            e.get("action"),
            e.get("category"),
            e.get("rules"),
            e.get("rule_score"),
            e.get("ml_score"),
            e.get("ml_flag"),
            e.get("reason"),
            e.get("enforced"),
            e.get("latency_ms")
        ])

    csv_data = output.getvalue()
    filename = f"sentinel-incidents-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

