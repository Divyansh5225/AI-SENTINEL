"""
eval/test_false_positives.py -- Task B: False Positive Analysis for AI-Sentinel WAF

Evaluates 30 realistic, diverse benign requests that look like potential attacks
to naive regex or ML systems (SQL-like keywords, apostrophes, math inequalities,
unicode, base64 cookies, long queries, technical terms, etc.).

For each request:
  - Prints HTTP status code
  - If blocked or alerted, details the rule, score, and ML anomaly flag
  - Summarizes "X of 30 blocked"
"""
import json
import os
import shutil
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel import config

# Step 1: Isolation
temp_dir = tempfile.mkdtemp(prefix="sentinel_fp_")
temp_db = os.path.join(temp_dir, "temp_fp.db")
config.DB_PATH = temp_db

temp_model = os.path.join(temp_dir, "temp_model.joblib")
if os.path.exists(config.MODEL_PATH):
    shutil.copyfile(config.MODEL_PATH, temp_model)
    config.MODEL_PATH = temp_model

from sentinel import db
db.init_db()

from sentinel.app import app, sentinel

TEST_CASES = [
    {
        "id": 1,
        "name": "Apostrophe in Irish Name",
        "method": "GET",
        "path": "/search",
        "params": {"q": "O'Brien"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 2,
        "name": "SQL Keyword 'select' in Natural Prose",
        "method": "GET",
        "path": "/search",
        "params": {"q": "select a plan"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 3,
        "name": "SQL Keyword 'union' in Location Name",
        "method": "GET",
        "path": "/search",
        "params": {"q": "union station timetable"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 4,
        "name": "SQL Keyword 'drop' in Natural Prose",
        "method": "GET",
        "path": "/search",
        "params": {"q": "drop me a message"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 5,
        "name": "Emoticon with Angle Bracket (<3 love)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "<3 love"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 6,
        "name": "Legitimate JSON Login Body",
        "method": "POST",
        "path": "/login",
        "params": None,
        "data": json.dumps({"username": "corporate.analyst@company.com", "password": "SecurePassword123!"}),
        "headers": {"Content-Type": "application/json"},
        "cookies": {},
    },
    {
        "id": 7,
        "name": "Long Benign Business Query String (>110 chars)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "comprehensive quarterly financial audit report for fiscal year 2026 enterprise cloud infrastructure and security metrics"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 8,
        "name": "Email Address with Plus Sign (+)",
        "method": "POST",
        "path": "/login",
        "params": None,
        "data": {"username": "user+updates@example.com", "password": "ValidPassword123"},
        "headers": {},
        "cookies": {},
    },
    {
        "id": 9,
        "name": "Hindi / Unicode Multilingual Text",
        "method": "GET",
        "path": "/search",
        "params": {"q": "नमस्ते दुनिया सुरक्षा ऑडिट रिपोर्ट"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 10,
        "name": "Four-Segment Legitimate Route Path",
        "method": "GET",
        "path": "/about/company/team/careers",
        "params": None,
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 11,
        "name": "Base64 JWT-like Value in Cookie",
        "method": "GET",
        "path": "/",
        "params": None,
        "data": None,
        "headers": {},
        "cookies": {"session": "eyJ1c2VyX2lkIjogNDIsICJyb2xlIjogImFkbWluIn0="},
    },
    {
        "id": 12,
        "name": "Mathematical Inequality with Angle Brackets",
        "method": "GET",
        "path": "/search",
        "params": {"q": "x < 5 and y > 10"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 13,
        "name": "Full HTTPS URL in Search Field",
        "method": "GET",
        "path": "/search",
        "params": {"q": "https://google.com/search?hl=en"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 14,
        "name": "Literal Double Quotes in Search Query",
        "method": "GET",
        "path": "/search",
        "params": {"q": '"annual executive review"'},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 15,
        "name": "Parentheses in Query",
        "method": "GET",
        "path": "/search",
        "params": {"q": "Python (programming language)"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 16,
        "name": "Ampersand and Slash in Department Name",
        "method": "GET",
        "path": "/search",
        "params": {"q": "R&D / Innovation Department"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 17,
        "name": "Currency Amount with Dollar and Commas",
        "method": "GET",
        "path": "/search",
        "params": {"q": "budget $50,000 to $100,000"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 18,
        "name": "Date Range Filter Syntax with Dots",
        "method": "GET",
        "path": "/search",
        "params": {"q": "date:2026-01-01..2026-12-31"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 19,
        "name": "SQL Keyword 'update' in News Search",
        "method": "GET",
        "path": "/search",
        "params": {"q": "update on the latest company news"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 20,
        "name": "SQL Keyword 'insert' in Instructional Search",
        "method": "GET",
        "path": "/search",
        "params": {"q": "insert your card into the reader"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 21,
        "name": "SQL Keyword 'delete' in Archive Search",
        "method": "GET",
        "path": "/search",
        "params": {"q": "delete old drafts from archive"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 22,
        "name": "Programming Plus Signs (C++)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "c++ template metaprogramming tutorial"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 23,
        "name": "Unix Command 'chmod' in Help Search",
        "method": "GET",
        "path": "/search",
        "params": {"q": "chmod 755 permission settings"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 24,
        "name": "Document File Extension (.pdf)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "quarterly_financial_report.pdf"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 25,
        "name": "XML Syntax Discussion in Prose",
        "method": "GET",
        "path": "/search",
        "params": {"q": "how to write valid xml elements in python"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 26,
        "name": "Markdown Syntax in Query (*bold* _italic_)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "**bold** and _italic_ markdown guide"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 27,
        "name": "Customer Feedback with Exclamation and Slash",
        "method": "POST",
        "path": "/login",
        "params": None,
        "data": {"username": "demo", "password": "demo123", "notes": "Great service! Fast & reliable 10/10"},
        "headers": {},
        "cookies": {},
    },
    {
        "id": 28,
        "name": "Street Address with Number Sign (#4B)",
        "method": "GET",
        "path": "/search",
        "params": {"q": "123 Main St, Apt #4B, Springfield"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 29,
        "name": "Structured Filter Query with Equals and Ampersand",
        "method": "GET",
        "path": "/search",
        "params": {"q": "ERP ledger status=active&sort=desc"},
        "data": None,
        "headers": {},
        "cookies": {},
    },
    {
        "id": 30,
        "name": "Standard Mobile Device User-Agent",
        "method": "GET",
        "path": "/",
        "params": None,
        "data": None,
        "headers": {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"},
        "cookies": {},
    },
]

def run_false_positive_tests():
    client = app.test_client()
    
    # Intercept decision to capture full WAF internals
    captured_decisions = []
    orig_inspect = sentinel.inspect
    def capturing_inspect(*args, **kwargs):
        res = orig_inspect(*args, **kwargs)
        captured_decisions.append(res)
        return res
    sentinel.inspect = capturing_inspect

    print("=" * 80)
    print("TASK B: FALSE POSITIVE ANALYSIS (30 Challenging Benign Requests)")
    print("=" * 80)

    results = []
    blocked_count = 0
    alert_count = 0

    for idx, tc in enumerate(TEST_CASES):
        captured_decisions.clear()
        ip = f"10.1.{idx // 256}.{idx % 256}"
        env = {"REMOTE_ADDR": ip}
        
        # Apply cookies if present
        for c_k, c_v in tc["cookies"].items():
            client.set_cookie(c_k, c_v)

        if tc["method"] == "GET":
            response = client.get(tc["path"], query_string=tc["params"], headers=tc["headers"], environ_overrides=env)
        else:
            response = client.post(tc["path"], data=tc["data"], headers=tc["headers"], environ_overrides=env)

        status_code = response.status_code
        dec = captured_decisions[-1] if captured_decisions else {
            "action": "unknown", "rules": [], "rule_score": 0, "ml_score": 0.0, "ml_flag": False, "reason": ""
        }

        is_blocked = (status_code == 403 or dec["action"] == "block")
        is_alert = (dec["action"] == "alert")
        if is_blocked:
            blocked_count += 1
        if is_alert:
            alert_count += 1

        rec = {
            "id": tc["id"],
            "name": tc["name"],
            "method": tc["method"],
            "path": tc["path"],
            "status_code": status_code,
            "waf_action": dec["action"],
            "is_blocked": is_blocked,
            "rules_hit": dec["rules"],
            "rule_score": dec["rule_score"],
            "ml_score": dec["ml_score"],
            "ml_flag": dec["ml_flag"],
            "reason": dec["reason"],
        }
        results.append(rec)

        tag = "BLOCKED [FP!]" if is_blocked else ("ALERT   " if is_alert else "PASS    ")
        detail = ""
        if is_blocked or is_alert:
            detail = f" | Rules: {dec['rules']} (Score: {dec['rule_score']}), ML Flag: {dec['ml_flag']} ({dec['ml_score']}), Reason: {dec['reason']}"
        print(f"[{tag}] #{tc['id']:02d}: {tc['name']:<50} -> HTTP {status_code}{detail}")

    print("-" * 80)
    print(f"SUMMARY: {blocked_count} of 30 blocked (False Positive Rate on challenging set = {blocked_count / 30 * 100:.1f}%)")
    print(f"ALERTS:  {alert_count} of 30 alerted (allowed through with audit flag)")
    print("=" * 80)

    # Cleanup temp dir
    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

    return {
        "total_tested": len(TEST_CASES),
        "blocked_count": blocked_count,
        "alert_count": alert_count,
        "false_positive_rate_pct": round(blocked_count / 30 * 100, 2),
        "cases": results,
    }

if __name__ == "__main__":
    fp_results = run_false_positive_tests()
    out_path = os.path.join(os.path.dirname(__file__), "false_positive_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(fp_results, f, indent=2, ensure_ascii=False)
    print(f"Saved false positive results to {out_path}")
