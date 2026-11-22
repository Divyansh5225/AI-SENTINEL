"""
rules.py -- WAF ka "Guard".

Idea (bahut simple):
  Request aayi -> uske path + values ko saaf karo (decode, lowercase)
  -> ek list ke patterns (regex) se match karo.
  Pattern mila to us rule ka 'score' judta hai. Score jitna zyada = attack utna pakka.

Ye CHHOTA demo rule-set hai (~20 rules). Asli duniya me OWASP Core Rule Set
(CRS) hota hai jisme sainkdon rules hain -- next step me use Coraza + CRS se badal sakte ho.
"""
import re
from urllib.parse import unquote_plus

MAX_VALUE_CHARS = 2000   # bahut lambi string par regex dheemi na ho
MAX_VALUES = 50


def decode(text: str) -> str:
    """%27 jaise URL-encoding ko wapas normal text banata hai.
    3 baar tak karta hai, taaki double-encoding (%2527) bhi pakad me aaye."""
    text = str(text)[:MAX_VALUE_CHARS]
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_SPACES = re.compile(r"\s+")


def normalize(text: str) -> str:
    """decode + SQL comment hatao (UN/**/ION trick) + spaces ek karo + lowercase."""
    text = decode(text)
    text = _COMMENT.sub(" ", text)
    text = _SPACES.sub(" ", text)
    return text.strip().lower()


def _rule(name, category, score, pattern):
    return (name, category, score, re.compile(pattern))


# Ye rules path + saari values par lagte hain
VALUE_RULES = [
    # ---------- SQL Injection ----------
    _rule("sqli-union-select", "SQL Injection", 5, r"\bunion\b[\s(]*(?:all\b[\s(]*)?select\b"),
    # ' or 1=1  /  ' or 'a'='a  (dono taraf same cheez = hamesha true)
    _rule("sqli-tautology", "SQL Injection", 5, r"\b(?:or|and)\b\s*['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b"),
    _rule("sqli-quote-comment", "SQL Injection", 5, r"['\"]\s*(?:--|#|/\*|;)"),
    _rule("sqli-stacked-query", "SQL Injection", 5, r";\s*(?:drop|insert|update|delete|create|alter|truncate|exec|shutdown)\b"),
    _rule("sqli-time-based", "SQL Injection", 5, r"\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay"),
    _rule("sqli-db-metadata", "SQL Injection", 5, r"information_schema|@@version|\bload_file\s*\(|into\s+(?:out|dump)file|xp_cmdshell"),
    _rule("sqli-select-from", "SQL Injection", 3, r"\bselect\b.{1,100}?\bfrom\b"),
    # ---------- XSS ----------
    _rule("xss-script-tag", "XSS", 5, r"<\s*/?\s*script"),
    _rule("xss-event-handler", "XSS", 4, r"\bon[a-z]{3,20}\s*="),
    _rule("xss-javascript-uri", "XSS", 4, r"javascript\s*:"),
    _rule("xss-dangerous-tag", "XSS", 4, r"<\s*(?:iframe|object|embed|svg|math|meta|link|base|form)\b"),
    _rule("xss-dom-sink", "XSS", 3, r"document\s*\.\s*(?:cookie|location|write)|\b(?:alert|eval|prompt|confirm)\s*\("),
    _rule("xss-any-html-tag", "XSS", 2, r"<\s*/?\s*[a-z][^<>]{0,200}>"),
    # ---------- Command Injection ----------
    # (Path rules se PEHLE rakha hai: "; cat /etc/passwd" dono se match hota hai, score barabar hai,
    #  aur dashboard me category wahi dikhti hai jo list me pehle aaye.)
    _rule("cmd-chain", "Command Injection", 5, r"[;&|`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|powershell|cmd|ping|rm)\b"),
    _rule("cmd-substitution", "Command Injection", 4, r"\$\([^)]*\)|`[^`]+`"),
    # ---------- Path Traversal ----------
    _rule("path-dotdot", "Path Traversal", 5, r"\.\.[/\\]"),
    _rule("path-sensitive-file", "Path Traversal", 5, r"/etc/(?:passwd|shadow)|boot\.ini|win\.ini|c:\\windows"),
    # ---------- Null Byte Injection ----------
    _rule("null-byte", "Null Byte Injection", 5, r"\x00"),
    # ---------- SSRF / Cloud Metadata ----------
    _rule("ssrf-cloud-metadata", "SSRF", 5,
          r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"),
    # ---------- Log4Shell ----------
    _rule("log4shell-jndi", "Log4Shell", 5, r"\$\{(?:jndi|lower|upper|env|sys|java)\b"),
    # ---------- XXE ----------
    _rule("xxe-entity", "XXE", 5, r"<\s*!(?:entity|doctype)\b"),
    # ---------- Open Redirect ----------
    _rule("open-redirect", "Open Redirect", 3,
          r"(?:url|redirect|next|return|goto)\s*=\s*(?:https?:)?//"),
]

# Ye sirf URL path par lagte hain
PATH_RULES = [
    _rule("recon-sensitive-path", "Recon", 3,
          r"/\.(?:env|git|svn|htaccess|ds_store)|/(?:wp-admin|wp-login|phpmyadmin|xmlrpc\.php|admin\.php|config\.php)"),
]

# Ye sirf User-Agent header par lagte hain
UA_RULES = [
    _rule("scanner-user-agent", "Scanner", 3, r"sqlmap|nikto|nmap|acunetix|dirbuster|masscan|wpscan|nuclei|havij"),
]

# Ye rules decoded (par normalized nahi) text par lagte hain.
# normalize() CRLF ko space bana deta hai, isliye CRLF check yahan hai.
DECODED_RULES = [
    _rule("response-splitting", "Response Splitting", 5, r"\r\n"),
]


def scan(path: str, values: list[str], user_agent: str = "") -> list[dict]:
    """Request ko rules se milao. Return: hits ki list (score ke hisaab se bade se chhota)."""
    found = {}
    path_text = normalize(path)
    texts = [path_text] + [normalize(v) for v in list(values)[:MAX_VALUES]]
    for text in texts:
        for rule in VALUE_RULES:
            if rule[0] not in found and rule[3].search(text):
                found[rule[0]] = rule
    # Decoded-only rules (normalize destroys CRLF etc.)
    decoded_texts = [decode(path)] + [decode(v) for v in list(values)[:MAX_VALUES]]
    for text in decoded_texts:
        for rule in DECODED_RULES:
            if rule[0] not in found and rule[3].search(text):
                found[rule[0]] = rule
    for rule in PATH_RULES:
        if rule[0] not in found and rule[3].search(path_text):
            found[rule[0]] = rule
    ua = str(user_agent).lower()[:300]
    for rule in UA_RULES:
        if rule[0] not in found and rule[3].search(ua):
            found[rule[0]] = rule
    hits = [{"rule": n, "category": c, "score": s} for (n, c, s, _) in found.values()]
    hits.sort(key=lambda h: -h["score"])
    return hits
