"""
demo/verify_dashboards.py -- Verify SOC Dashboard and Health UI data populations
"""
import urllib.request
import json
import re

BASE = "http://127.0.0.1:5000"

def verify():
    print("=" * 80)
    print("VERIFYING DASHBOARDS CONTENT & DATA POPULATION")
    print("=" * 80)

    # 1. Health JSON
    h_url = f"{BASE}/sentinel/health?format=json"
    with urllib.request.urlopen(h_url) as r:
        h_data = json.loads(r.read().decode())
    print("1. Health Endpoint API Data:")
    for k, v in h_data.items():
        print(f"   - {k}: {v}")
    assert h_data.get("db_ok") is True, "Database health failure!"
    assert h_data.get("ml_loaded") is True, "ML model not loaded!"

    # 2. Stats API
    s_url = f"{BASE}/sentinel/api/stats"
    with urllib.request.urlopen(s_url) as r:
        s_data = json.loads(r.read().decode())
    print("\n2. Aggregated Incident Statistics (API):")
    print(f"   - Total Events Logged: {s_data.get('total')}")
    print(f"   - Decisions by Action: {s_data.get('by_action')}")
    print(f"   - Top Attack Categories: {s_data.get('by_category')}")
    print(f"   - Top Attacking IPs: {s_data.get('top_ips')}")
    assert s_data.get("total", 0) > 0, "No events found in database!"

    # 3. SOC Dashboard HTML
    d_url = f"{BASE}/sentinel/dashboard"
    with urllib.request.urlopen(d_url) as r:
        d_html = r.read().decode()
    print("\n3. SOC Dashboard HTML Inspection:")
    
    # Check for Request IDs in HTML table
    req_ids = re.findall(r"<code>([0-9a-f]{8})</code>", d_html)
    print(f"   - Correlated Request IDs found in table: {len(req_ids)} (Sample: {req_ids[:5]})")
    assert len(req_ids) > 0, "No Request IDs rendered in dashboard table!"

    # Check for Action badges
    has_block_badge = 'class="badge block"' in d_html
    has_allow_badge = 'class="badge allow"' in d_html
    print(f"   - Block & Allow Badges Rendered: Block={has_block_badge}, Allow={has_allow_badge}")
    assert has_block_badge and has_allow_badge, "Action badges missing!"

    # Check for Latency column
    has_latency = "Latency" in d_html and "ms" in d_html
    print(f"   - Latency Metrics Column Rendered: {has_latency}")
    assert has_latency, "Latency column missing!"

    # Check for Unban / Bans section
    has_bans_section = "Currently banned IPs" in d_html
    print(f"   - Active Bans Section Present: {has_bans_section}")
    assert has_bans_section, "Bans section missing!"

    # 4. Enterprise Portal UI
    p_url = f"{BASE}/"
    with urllib.request.urlopen(p_url) as r:
        p_html = r.read().decode()
    print("\n4. Enterprise Portal Home Inspection:")
    has_portal_title = "NexusCorp" in p_html
    has_hero = "Enterprise Resource" in p_html and "Cloud Management Portal" in p_html
    print(f"   - Portal Branding Active: {has_portal_title}")
    print(f"   - Enterprise Hero & Quick Actions Rendered: {has_hero}")
    assert has_portal_title and has_hero, "Portal content missing!"

    # 5. Products Catalog
    prod_url = f"{BASE}/products"
    with urllib.request.urlopen(prod_url) as r:
        prod_html = r.read().decode()
    print("\n5. Enterprise Modules Catalog Inspection:")
    has_modules = "Cloud Infrastructure" in prod_html and "Enterprise ERP Financial" in prod_html
    print(f"   - Enterprise Modules Catalog Rendered: {has_modules}")
    assert has_modules, "Catalog modules missing!"

    print("\n" + "=" * 80)
    print("ALL THREE UIs VERIFIED FULLY OPERATIONAL WITH REAL POPULATED DATA")
    print("=" * 80)

if __name__ == "__main__":
    verify()
