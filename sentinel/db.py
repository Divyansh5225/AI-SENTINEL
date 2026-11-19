"""
db.py -- "Register": har request ka record SQLite me (ek simple file, koi server nahi chahiye).

Dhyan do: hum SQL me hamesha '?' wale parameters use karte hain, string jod ke nahi --
warna hamara apna logger SQL Injection ka shikaar ho sakta tha.
"""
import os
import re
import sqlite3
import time

from . import config

_SECRET = re.compile(r"(?i)(password|passwd|pwd|token|secret)([\"'\s:=]+)([^&\"',\s}]+)")


def mask_secrets(text: str) -> str:
    """password=abc123 -> password=***  (log me password kabhi save nahi karte)."""
    return _SECRET.sub(lambda m: m.group(1) + m.group(2) + "***", text)


def _connect():
    con = sqlite3.connect(config.DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    con = _connect()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, ip TEXT, method TEXT, path TEXT, payload TEXT,
                action TEXT, category TEXT, rules TEXT, rule_score INTEGER,
                ml_score REAL, ml_flag INTEGER, reason TEXT, enforced INTEGER,
                latency_ms REAL, request_id TEXT
            )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                banned_until REAL,
                reason TEXT
            )""")
        # Purane DB me request_id column nahi hoga — safely add karo
        try:
            con.execute("ALTER TABLE events ADD COLUMN request_id TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        con.commit()
    finally:
        con.close()


def log_event(ip: str, method: str, path: str, payload: str, d: dict, request_id: str = "") -> int:
    """Ek event save karo. d = engine ka decision dict. Return: event id."""
    con = _connect()
    try:
        cur = con.execute(
            "INSERT INTO events (ts, ip, method, path, payload, action, category, rules, rule_score,"
            " ml_score, ml_flag, reason, enforced, latency_ms, request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), ip, method, path[:200], mask_secrets(payload)[:300], d["action"], d["category"],
             ",".join(d["rules"]), d["rule_score"], d["ml_score"], 1 if d["ml_flag"] else 0,
             d["reason"], 1 if d["enforced"] else 0, d["latency_ms"], request_id))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def recent_events(limit: int = 50) -> list[dict]:
    con = _connect()
    try:
        rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def stats() -> dict:
    """Dashboard ke counters."""
    con = _connect()
    try:
        total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_action = {r[0]: r[1] for r in con.execute("SELECT action, COUNT(*) FROM events GROUP BY action")}
        by_category = [(r[0], r[1]) for r in con.execute(
            "SELECT category, COUNT(*) c FROM events WHERE category != '' AND action != 'allow' "
            "GROUP BY category ORDER BY c DESC")]
        top_ips = [(r[0], r[1]) for r in con.execute(
            "SELECT ip, COUNT(*) c FROM events WHERE action != 'allow' GROUP BY ip ORDER BY c DESC LIMIT 5")]
        return {"total": total, "by_action": by_action, "by_category": by_category, "top_ips": top_ips}
    finally:
        con.close()


# ---------- IP Ban persistence ----------

def save_ban(ip: str, banned_until: float, reason: str = "") -> None:
    """Ban ko DB me save karo (restart ke baad bhi rahe)."""
    con = _connect()
    try:
        con.execute("INSERT OR REPLACE INTO bans (ip, banned_until, reason) VALUES (?,?,?)",
                     (ip, banned_until, reason))
        con.commit()
    finally:
        con.close()


def load_active_bans() -> dict[str, float]:
    """DB se active (expire nahi hue) bans load karo."""
    now = time.time()
    con = _connect()
    try:
        rows = con.execute("SELECT ip, banned_until FROM bans WHERE banned_until > ?", (now,)).fetchall()
        return {r["ip"]: r["banned_until"] for r in rows}
    finally:
        con.close()


def remove_ban(ip: str) -> bool:
    """Ek IP ka ban hatao. Return True agar ban tha."""
    con = _connect()
    try:
        cur = con.execute("DELETE FROM bans WHERE ip = ?", (ip,))
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def cleanup_expired_bans() -> int:
    """Expire ho chuke bans DB se saaf karo."""
    con = _connect()
    try:
        cur = con.execute("DELETE FROM bans WHERE banned_until <= ?", (time.time(),))
        con.commit()
        return cur.rowcount
    finally:
        con.close()
