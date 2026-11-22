import urllib.request
import urllib.error
import time

BASE = "http://127.0.0.1:5000"

print("1. Fetching SOC Dashboard at T=0...")
with urllib.request.urlopen(f"{BASE}/sentinel/dashboard") as r:
    t0_html = r.read().decode()

test_payload = "sqli_autorefresh_probe_99"
print(f"   Dashboard at T=0 contains '{test_payload}': {test_payload in t0_html}")

print("\n2. Sending SQLi attack request to WAF...")
attack_url = f"{BASE}/search?q=%27+UNION+SELECT+1,{test_payload}--"
try:
    urllib.request.urlopen(attack_url)
    print("   [!] Request was not blocked (unexpected)")
except urllib.error.HTTPError as e:
    print(f"   [OK] Intercepted by WAF: HTTP {e.code}")
    print(f"        Response: {e.read().decode().strip()}")
    print(f"        X-Request-ID: {e.headers.get('X-Request-ID')}")

print("\n3. Waiting 10 seconds (simulating user keeping dashboard open without reloading)...")
for s in range(10, 0, -1):
    print(f"   Waiting... {s}s", end="\r")
    time.sleep(1)
print("\n   10 seconds elapsed.")

print("\n4. Checking SOC Dashboard (simulating the auto-refresh triggered by setInterval window.location.reload())...")
with urllib.request.urlopen(f"{BASE}/sentinel/dashboard") as r:
    t10_html = r.read().decode()

appears = test_payload in t10_html
print(f"   Dashboard at T=10 contains '{test_payload}': {appears}")
if appears:
    print("\nSUCCESS: Attack incident appears on the SOC dashboard automatically!")
else:
    print("\nFAILURE: Attack incident did NOT appear on the SOC dashboard!")
