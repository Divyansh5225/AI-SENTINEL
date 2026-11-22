"""
demo/healthcheck.py -- Comprehensive Health & Endpoint Verification Suite
Verifies all portal pages, SOC dashboard, health UIs, APIs, and WAF attack interception.
"""
import sys
import time
import urllib.request
import urllib.parse
from urllib.error import HTTPError, URLError

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"

ENDPOINTS = [
    # (Category, Method, Path, Params, Form/Data, Expected Status, Description)
    ("Portal UI", "GET", "/", None, None, 200, "Enterprise Portal Home Page"),
    ("Portal UI", "GET", "/about", None, None, 200, "Corporate Zero-Trust Architecture"),
    ("Portal UI", "GET", "/products", None, None, 200, "Enterprise Catalog Directory"),
    ("Portal UI", "GET", "/product", {"id": 2}, None, 200, "Single Module Specification (ERP)"),
    ("Portal UI", "GET", "/search", {"q": "cloud"}, None, 200, "Benign Search Query"),
    ("Portal UI", "GET", "/login", None, None, 200, "IAM Corporate Login Page"),
    ("Portal UI", "POST", "/login", None, {"username": "demo", "password": "demo123"}, 200, "IAM Valid Authentication"),
    ("SOC Monitor", "GET", "/sentinel/dashboard", None, None, 200, "Real-Time SOC Dashboard HTML"),
    ("SOC Monitor", "GET", "/sentinel/health", None, None, 200, "Interactive Health Check HTML UI"),
    ("SOC Monitor", "GET", "/sentinel/health", {"format": "json"}, None, 200, "System Health JSON Endpoint"),
    ("SOC Monitor", "GET", "/sentinel/api/stats", None, None, 200, "Aggregated Incident Statistics API"),
    ("SOC Monitor", "GET", "/sentinel/api/events", {"limit": 5}, None, 200, "Recent Security Events JSON API"),
    ("SOC Monitor", "GET", "/sentinel/export/csv", None, None, 200, "Incident History CSV Export"),
    ("SOC Monitor", "POST", "/sentinel/api/unban/127.0.0.1", None, None, 200, "Manual IP Unban Endpoint"),
    ("WAF Defense", "GET", "/search", {"q": "' OR 1=1 --"}, None, 403, "WAF Intercept: SQL Injection"),
    ("WAF Defense", "GET", "/search", {"q": "<script>alert(1)</script>"}, None, 403, "WAF Intercept: Cross-Site Scripting"),
]

def run_healthcheck():
    print("=" * 88)
    print(f"AI-SENTINEL SYSTEM HEALTH & ENDPOINT VERIFICATION ({BASE_URL})")
    print("=" * 88)
    print(f"{'Category':<13} | {'Method':<6} | {'Target Endpoint':<38} | {'Status':<7} | {'Latency':<8} | {'Result'}")
    print("-" * 88)

    all_passed = True
    total_latency = 0.0

    for category, method, path, params, form, expected, desc in ENDPOINTS:
        url = BASE_URL + path + ("?" + urllib.parse.urlencode(params) if params else "")
        data = urllib.parse.urlencode(form).encode() if form else None
        req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "AI-Sentinel-HealthCheck/1.0"})
        
        t0 = time.perf_counter()
        status = 0
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                status = r.status
        except HTTPError as e:
            status = e.code
        except URLError as e:
            status = 0
            err_msg = str(e.reason)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        total_latency += dt_ms

        passed = (status == expected)
        if not passed:
            all_passed = False
        tag = "[OK]  " if passed else "[FAIL]"
        display_path = path if not params else f"{path}?{urllib.parse.urlencode(params)[:20]}"

        print(f"{category:<13} | {method:<6} | {display_path:<38} | {status:<7} | {dt_ms:>6.2f}ms | {tag} ({desc})")

    print("-" * 88)
    avg_latency = total_latency / len(ENDPOINTS)
    print(f"Total Endpoints Checked: {len(ENDPOINTS)} | Average Latency: {avg_latency:.2f}ms")
    if all_passed:
        print("RESULT: ALL ENDPOINTS HEALTHY AND FUNCTIONING PROPERLY (100% PASS)")
    else:
        print("RESULT: ONE OR MORE ENDPOINTS FAILED VERIFICATION")
    print("=" * 88)
    return all_passed

if __name__ == "__main__":
    success = run_healthcheck()
    sys.exit(0 if success else 1)
