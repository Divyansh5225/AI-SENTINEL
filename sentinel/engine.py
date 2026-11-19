"""
engine.py -- poora pipeline ek jagah jodta hai.

Request -> (banned?) -> rules -> features -> ML -> policy -> decision

Ye class Flask se alag hai, isliye evaluate.py bina server chalaye ise seedha test kar sakta hai.
"""
import threading
import time
from collections import deque

from . import config, features, ml, policy, rules


class _IPState:
    """Har IP ke baare me thodi yaaddasht (memory me)."""
    __slots__ = ("times", "fails", "blocks", "banned_until")

    def __init__(self):
        self.times = deque()      # pichhli requests ka time (rate nikalne ke liye)
        self.fails = deque()      # galat login ka time
        self.blocks = deque()     # pichhle blocks ka time
        self.banned_until = 0.0


def _prune(dq, cutoff):
    while dq and dq[0] < cutoff:
        dq.popleft()


class Sentinel:
    def __init__(self, use_ml: bool | None = None, dry_run: bool | None = None) -> None:
        self.use_ml = config.USE_ML if use_ml is None else use_ml
        self.dry_run = config.DRY_RUN if dry_run is None else dry_run
        self.detector = ml.Detector() if self.use_ml else None
        self._state = {}
        self._lock = threading.Lock()
        self._load_persisted_bans()

    def _load_persisted_bans(self):
        """Restart ke baad DB se active bans wapas load karo."""
        try:
            from . import db
            bans = db.load_active_bans()
            for ip, until in bans.items():
                st = self._state.setdefault(ip, _IPState())
                st.banned_until = until
        except Exception:
            pass  # DB not ready (e.g. evaluate.py headless mode)

    # ---------- IP ki yaaddasht ----------
    def _get(self, ip, now):
        st = self._state.get(ip)
        if st is None:
            if len(self._state) > 10000:          # memory na bhare
                self._cleanup(now)
            st = self._state[ip] = _IPState()
        return st

    def _cleanup(self, now):
        stale = [ip for ip, s in self._state.items()
                 if (not s.times or now - s.times[-1] > 600) and s.banned_until < now]
        for ip in stale:
            del self._state[ip]

    def record_failed_login(self, ip: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._get(ip, now).fails.append(now)

    def banned_ips(self, now: float | None = None) -> list[tuple[str, int]]:
        now = time.time() if now is None else now
        with self._lock:
            return sorted((ip, int(s.banned_until - now)) for ip, s in self._state.items()
                          if s.banned_until > now)

    # ---------- main kaam ----------
    def inspect(self, method: str, path: str, raw_values: list[str], user_agent: str, ip: str, raw_names: tuple[str, ...] = (), now: float | None = None) -> dict:
        t0 = time.perf_counter()
        now = time.time() if now is None else now

        if ip in config.ALLOWLIST:
            return self._result("allow", "allowlisted IP", "", [], 0, None, False, t0, 0, 0)

        with self._lock:
            st = self._get(ip, now)
            if st.banned_until > now:
                return self._result("block", "IP temporarily banned", "Banned IP", [], 0, None, False, t0, 0, 0)
            st.times.append(now)
            _prune(st.times, now - config.RATE_WINDOW)
            _prune(st.fails, now - config.LOGIN_WINDOW)
            rate, fails = len(st.times), len(st.fails)

        # 1) Guard: rules
        hits = rules.scan(path, list(raw_values) + list(raw_names), user_agent)
        rule_score = min(10, sum(h["score"] for h in hits))
        top_category = hits[0]["category"] if hits else ""

        # 2) Gut feeling: ML
        ml_score, ml_flag = None, False
        if self.detector is not None and self.detector.ready:
            vec = features.to_vector(features.extract(method, path, raw_values, rate, fails))
            ml_score, ml_flag = self.detector.score(vec)

        # 3) Manager: policy
        d = policy.decide(rule_score, top_category, ml_flag, rate, fails)

        # 4) Block hua to yaad rakho; baar baar ya brute force par IP ban
        reason = d.reason
        if d.action == "block":
            with self._lock:
                st.blocks.append(now)
                _prune(st.blocks, now - config.BAN_WINDOW)
                if d.ban or len(st.blocks) >= config.BAN_AFTER_BLOCKS:
                    st.banned_until = now + config.BAN_SECONDS
                    reason += f" -> IP banned for {config.BAN_SECONDS}s"
                    # Ban DB me bhi save karo (restart ke baad bhi rahe)
                    try:
                        from . import db
                        db.save_ban(ip, st.banned_until, reason)
                    except Exception:
                        pass

        return self._result(d.action, reason, d.category, [h["rule"] for h in hits],
                            rule_score, ml_score, ml_flag, t0, rate, fails)

    def _result(self, action, reason, category, rule_names, rule_score, ml_score, ml_flag, t0, rate, fails):
        return {
            "action": action,
            "reason": reason,
            "category": category,
            "rules": rule_names,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "ml_flag": ml_flag,
            "enforced": not self.dry_run,     # dry-run me block "hota" nahi, sirf likha jaata hai
            "rate": rate,
            "fails": fails,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    def unban(self, ip: str) -> bool:
        """Manually ek IP ka ban hatao. Dashboard ya API se use hota hai."""
        with self._lock:
            st = self._state.get(ip)
            if st and st.banned_until > 0:
                st.banned_until = 0.0
                st.fails.clear()
                st.blocks.clear()
                try:
                    from . import db
                    db.remove_ban(ip)
                except Exception:
                    pass
                return True
        return False
