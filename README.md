# AI-Sentinel — starter project (simple Python)

Ek chhota, **chalta hua** prototype jo tumhare paper ke architecture ko implement karta hai:
request inspect karo → rules + ML se check karo → faisla lo → register me likho → dashboard pe dikhao.

> Ye ek active WAF + ML anomaly prototype hai jo enterprise business portal ("NexusCorp Enterprise Suite") ko protect karta hai.
> Sab kuch sirf **tumhare apne computer (localhost)** par chalta hai.

---

## 1. Yaad rakhne ka formula: "Restaurant ka gate"

Socho ek restaurant hai (tumhari website). Gate pe 5 cheezein hain. Naam yaad rakho: **G-N-M-R-C**
(*Guard, Naak, Manager, Register, CCTV*).

| # | Kaun | Kya karta hai | File | Paper section |
|---|------|---------------|------|---------------|
| G | **Guard** | Haath me "wanted list" hai. Jo pehchaana hua badmaash dikhe, roko. | `rules.py` | 5.1 WAF |
| N | **Naak** (gut feeling) | "Kuch ajeeb lag raha hai" — naye/chhupe hue tareeke pakadta hai | `features.py`, `ml.py` | 5.3 ML |
| M | **Manager** | Guard + Naak ki baat sunke faisla: jaane do / alert / roko | `policy.py`, `engine.py` | 5.5 Active Defense |
| R | **Register** | Har aane-wale ka record (kaun, kab, kya maanga, kya hua) | `db.py` | 5.4 Logging |
| C | **CCTV screen** | Manager aur owner ko sab live dikhta hai | dashboard in `app.py` | 5.6 Dashboard |

```
Request ──> [Guard: rules] ──┐
                             ├──> [Manager: policy] ──> allow / alert / 429 / 403 ──> [Register: SQLite] ──> [CCTV: dashboard]
        ──> [Naak: ML score] ┘
```

**Manager ka sabse zaroori niyam (viva me zaroor bolna):** *ML akela kabhi block nahi karta.*
Block tab hota hai jab rule pakka bole, ya rule + ML dono sahmat hon. ML akela ho to sirf **alert**.

Manager ke faisle (`policy.py`, upar se neeche pehla match):

1. 5 galat login 60s me → **block + IP ban**
2. Rule score ≥ 5 → **block**
3. Rule score > 0 **aur** ML ko ajeeb laga → **block**
4. 10 sec me 20 se zyada requests → **429 rate limit**
5. Rule score > 0 (chhota) → **alert**
6. Sirf ML ko ajeeb laga → **alert**
7. Baaki sab → **allow**

---

## 2. Chalane ke 3 steps

Python 3.10 ya naya chahiye (maine Python 3.13 par test kiya hai).

```bash
pip install -r requirements.txt     # Windows me kabhi "py -m pip install -r requirements.txt"
python run.py                       # server chalu: http://127.0.0.1:5000
```

Dusra terminal kholo:

```bash
python demo.py                      # normal + attacks + rate limit + brute force ka live demo (~20 sec)
```

Browser me kholo:
- Website: http://127.0.0.1:5000  (demo login: `demo` / `demo123`)
- Dashboard: http://127.0.0.1:5000/sentinel/dashboard  (5 sec me auto-refresh)

> Demo ke baad tumhara IP **60 second ke liye ban** ho jaata hai (brute force pakda gaya). Ye feature hai.
> Turant dobara try karna ho to `python run.py` restart karo.

Pehli baar chalane par ML model khud train ho jaata hai (`data/model.joblib`, 2-3 second).

### Baaki commands

| Command | Kaam |
|---|---|
| `python -m unittest tests.test_basic -v` | 30 automatic checks (attacks, headers, brute force, unban, persistent bans, health, CSV export) |
| `python evaluate.py` | Paper ke Section 8 ke numbers (precision, recall, FPR, latency) |
| `python train.py` | ML model dobara train |
| `SENTINEL_DRY_RUN=1 python run.py` | **Dry-run**: kuch block nahi hota, sirf dashboard me dikhta hai "kya block hota" |
| `SENTINEL_USE_ML=0 python run.py` | Sirf rules (ML band) — comparison ke liye |

(Windows CMD me `SENTINEL_DRY_RUN=1` ki jagah pehle `set SENTINEL_DRY_RUN=1` likho, phir `python run.py`.)

---

## 3. Code ke 4 asli ideas (inhe samajh liya to sab samajh liya)

**(a) Rule = ek pattern.** `rules.py` me:
```python
_rule("sqli-union-select", "SQL Injection", 5, r"\bunion\b[\s(]*(?:all\b[\s(]*)?select\b")
```
Matlab: agar text me `union ... select` mile to "SQL Injection", score 5. Pehle text ko saaf karte hain
(`%27` → `'`, chhote-bade akshar ek jaise, `/**/` hataana), taaki chhupaana mushkil ho.

**(b) ML ko numbers chahiye.** `features.py` har request ko 12 numbers me badalta hai
(kitni lambi, kitne special characters `' " < > ;`, entropy, kitni requests aa chuki hain ...).

**(c) Isolation Forest.** `ml.py` me:
```python
model = IsolationForest(n_estimators=100, contamination=0.01)
model.fit(X)                      # sirf NORMAL traffic dikhao
model.decision_function([vec])    # negative = "ajeeb"
```
Idea: random cuts lagao. Ajeeb cheez jaldi alag ho jaati hai, normal bheed me rehta hai.

**(d) Sab kuch SQL me `?` se.** `db.py` me hum SQL string jodte nahi, `?` use karte hain —
warna hamara apna logger hi SQL Injection ka shikaar ban jaata. Password log me `***` ban ke jaata hai.

---

## 4. Evaluation — mere run ke numbers (aur unka sach)

`python evaluate.py` (138 attack requests + 414 legit requests, jisme 14 haath se banaye mushkil-legit hain):

| Config | Precision | Recall (alert ya block) | Recall (sirf block) | False-positive rate | Latency (engine) |
|---|---|---|---|---|---|
| A: sirf rules | 99.2% | 91.3% | 84.8% | 0.2% (1 request) | ~0.03 ms |
| B: rules + ML | 94.5% | 100% | 88.4% | 1.9% (8 requests) | ~8 ms |

Chhupaaye (obfuscated) attacks me: SQLi 62% → 100%, Command injection 50% → 100%.

**Ye numbers ko paper me aise mat likhna ki "humara system 100% pakadta hai". Sach ye hai:**

- **Data nakli hai.** ML ko sikhane wala "normal traffic" computer ne banaya hai, isliye bahut saaf aur narrow hai.
  Isliye har "ajeeb-sa" cheez ML ko ajeeb lagti hai. Isi wajah se 100% recall aaya.
- **False alarms asli duniya me zyada honge.** Haath se banayi 14 sahi requests me se ML ne 3 ko flag kiya
  (`women's shoes (size 7) - black` aur do login jinke username/password me `'`, `@`, `#`, `!` jaise special characters the)
  — jabki nakli normal data par sirf ~1%.
  Real traffic par ye farq aur badhega.
- **ML ke extra catches sirf ALERT hain, block nahi** (policy ka niyam). Isliye "sirf block" wala recall 88.4% hai.
- **Attacks aur rules dono ek hi insaan ne likhe** (tumhare liye, Claude ne). Isliye rules ka 91.3% optimistic hai.
  Kisi aur ke attack list par kam aayega.
- **ML ~8 ms per request add karta hai** (rules ke 0.03 ms ke muqable). Chhote project ke liye theek, bade traffic ke liye nahi.

Paper me **apne run ka** table do, aur ye limitations "Limitations" section me likho — examiner ko ye honesty pasand aayegi.
Asli data ke liye: **CSIC 2010** dataset (36,000 normal + 25,000+ anomalous requests) download karke
`normal_traffic.py` ki jagah uska normal part se train karo.

---

## 5. Jaldi seekhne ka plan (7 din, roz 2-3 ghante)

| Din | Kya karo | Goal |
|---|---|---|
| 1 | Project chalao (section 2). `demo.py` chalao, dashboard dekho. Python refresher: list, dict, function, `if/for`. | "Ye chalta kaise dikhta hai" |
| 2 | `app.py` padho: `@app.route`, `before_request`. Ek naya page add karke dekho. | Flask me request ka safar |
| 3 | `rules.py` padho. https://regex101.com par 3 rules paste karke test karo. Ek naya rule likho. | Regex samajhna |
| 4 | `features.py` + `ml.py`. `python train.py`. `CONTAMINATION` badal ke dekho (0.01 → 0.05), kya badla? | ML ka idea |
| 5 | `policy.py`, `engine.py`, `db.py`. `SENTINEL_DRY_RUN=1` se chalao. | Faisla + logging |
| 6 | `python evaluate.py`. Numbers + limitations paper me likho. Tests chalao. | Results section |
| 7 | Neeche ke viva sawal bol-bol ke practice. Demo ek baar poora rehearse. | Presentation |

---

## 6. Viva ke sawal (jawab 2-3 line me)

1. **Ye WAF scratch se banaya?** — Ye ek chhota rule-engine hai, concept dikhane ke liye. Production me OWASP Core Rule Set + Coraza use karte hain; ye next step hai.
2. **ML kyun, rules kaafi nahi?** — Rules sirf jaane-pehchaane pattern pakadte hain. Chhupaaye hue attacks (case badalna, encoding, comments) me ML "ajeeb lag raha hai" pakad sakta hai.
3. **Isolation Forest hi kyun?** — Ye unsupervised hai: sirf normal data chahiye, attack labels nahi. Tez hai aur scikit-learn me ready hai. LOF aur One-Class SVM bhi compare kiye ja sakte hain.
4. **ML akela block kyun nahi karta?** — Anomaly detection me false positives zyada hote hain (NIST SP 800-94 bhi yahi kehta hai). Isliye ML sirf alert deta hai; block tab jab rule bhi sahmat ho.
5. **False positive aur false negative?** — FP = sahi user ko galat roka. FN = attack ko jaane diya. Ek kam karo to doosra badhta hai.
6. **Dry-run mode kya hai?** — Kuch block nahi hota, sirf record hota hai "kya block hota". Naya system lagate waqt safe tareeka (NIST ke "simulation mode" jaisa).
7. **Brute force kaise pakadte ho?** — Har IP ke galat logins 60 second ke window me gino. 5 ke baad block + 60 sec ban.
8. **Limitations?** — Nakli training data, sirf apni demo site protect karta hai, state memory me hai (restart par saaf), sirf URL/form/UA inspect karta hai (cookies/headers nahi), ML ~8 ms add karta hai.

---

## 7. Aage kya (agar time mile)

1. **Reverse-proxy mode:** abhi guard Flask ke andar hai. Isko DVWA / Juice Shop ke aage proxy bana do (Docker me chalte hain).
2. **Coraza + OWASP CRS** ko rules ki jagah lagao, aur apna ML uske upar rakho.
3. **CSIC 2010** par train/test karke asli numbers lo.
4. Dashboard me chart/React, alerts me email.
5. `X-Forwarded-For` ka sahi handling (abhi jaan-bujhkar ignore hai, kyunki spoof ho sakta hai).

## Safety

- Server sirf `127.0.0.1` par sunta hai. Internet par expose mat karna.
- `demo.py` localhost ke alawa kisi address par chalne se mana karta hai.
- Attack strings textbook wale hain, apne hi nakli target par detection test karne ke liye.
  **Kisi aur ki website par bina likhit permission ke test karna illegal hai.**
