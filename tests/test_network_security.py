"""Інтеграційні тести WAF / Rate Limiting (ЛР №4).

Перевіряють реальні HTTP-відповіді 403/429, заголовки Retry-After,
Greylist, журнал інцидентів і лабораторний Reset.

Запуск:
    python -m unittest tests.test_network_security -v
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.config import Config


class NetworkSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab4-"))
        test_config = type(
            "Lab4Config",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab4-secret-key",
                "JWT_SECRET_KEY": "lab4-jwt-secret-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab4.db"),
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": True,
                "RATE_LIMIT_ENABLED": True,
                "RATE_LIMIT_LOGIN_LIMIT": 5,
                "RATE_LIMIT_LOGIN_WINDOW": 60,
                "RATE_LIMIT_API_LIMIT": 10,
                "RATE_LIMIT_API_WINDOW": 60,
                "RATE_LIMIT_WEB_LIMIT": 20,
                "RATE_LIMIT_WEB_WINDOW": 60,
                "WAF_GREYLIST_SECONDS": 60,
                "WAF_LAB_ALLOW_RESET": True,
            },
        )
        cls.app = create_app(test_config)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.client = self.app.test_client()
        self.app.extensions["network_guard"].reset()

    # ------------------------------------------------------------------
    # Допоміжні
    # ------------------------------------------------------------------

    def _csrf_token(self, path: str = "/waf-lab") -> str:
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def _login(self):
        return self.client.post(
            "/api/v1/auth/login",
            json={"username": "probe", "password": "wrong-password"},
        )

    # ------------------------------------------------------------------
    # Сторінка та журнал
    # ------------------------------------------------------------------

    def test_waf_lab_page_renders(self):
        response = self.client.get("/waf-lab")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Sentinel", body)
        self.assertIn("Sliding Window Log", body)
        self.assertIn("waf-1001", body)
        self.assertIn("Стрес-тест login", body)

    def test_events_endpoint_returns_json(self):
        self._login()
        response = self.client.get("/waf-lab/events")
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("stats", data)
        self.assertIn("incidents", data)
        self.assertIn("rules", data)
        self.assertEqual(data["stats"]["rate_limiter"]["total_allowed"], 1)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def test_login_rate_limit_returns_429_with_retry_after(self):
        for _ in range(5):
            self.assertEqual(self._login().status_code, 401)

        response = self._login()
        self.assertEqual(response.status_code, 429)
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 1)
        self.assertEqual(response.headers["X-RateLimit-Remaining"], "0")
        self.assertEqual(response.headers["X-RateLimit-Rule"], "auth_login")

        payload = response.get_json()
        self.assertEqual(payload["error"]["code"], "rate_limited")
        self.assertIn("retry_after", payload["error"])

        guard = self.app.extensions["network_guard"]
        kinds = [item["kind"] for item in guard.incidents.recent(10)]
        self.assertIn("rate_limit", kinds)

    def test_api_rate_limit_returns_429(self):
        for _ in range(10):
            self.assertEqual(self.client.get("/api/v1/health").status_code, 200)

        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["X-RateLimit-Rule"], "api_general")

    def test_success_response_has_rate_limit_headers(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-RateLimit-Limit"], "10")
        self.assertEqual(response.headers["X-RateLimit-Remaining"], "9")
        self.assertEqual(response.headers["X-RateLimit-Rule"], "api_general")

    def test_login_limit_does_not_consume_api_limit(self):
        for _ in range(5):
            self._login()
        self.assertEqual(self._login().status_code, 429)
        self.assertEqual(self.client.get("/api/v1/health").status_code, 200)

    def test_html_rate_limit_returns_styled_429(self):
        for _ in range(20):
            self.assertEqual(self.client.get("/login").status_code, 200)

        response = self.client.get("/login")
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertIn("Забагато запитів", response.get_data(as_text=True))

    # ------------------------------------------------------------------
    # WAF
    # ------------------------------------------------------------------

    def test_path_traversal_is_blocked_and_ip_greylisted(self):
        response = self.client.get("/api/v1/user/profile?file=../../etc/passwd")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["X-WAF-Rule"], "waf-1001")
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 1)

        payload = response.get_json()
        self.assertEqual(payload["error"]["code"], "waf_blocked")
        self.assertEqual(payload["error"]["rule"], "waf-1001")
        self.assertEqual(payload["error"]["location"], "query")

        follow_up = self.client.get("/api/v1/health")
        self.assertEqual(follow_up.status_code, 403)
        self.assertEqual(follow_up.get_json()["error"]["code"], "ip_greylisted")

    def test_sqli_is_blocked(self):
        response = self.client.get(
            "/api/v1/user/profile?q=%27%20OR%20%271%27%3D%271"
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["X-WAF-Rule"], "waf-1003")

    def test_command_injection_is_blocked(self):
        response = self.client.get(
            "/api/v1/user/profile?cmd=%3B%20%2Fbin%2Fsh%20-c%20id"
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(response.headers["X-WAF-Rule"].startswith("waf-2"))
        self.assertEqual(response.get_json()["error"]["location"], "query")

    def test_xss_signature_is_blocked_on_api(self):
        response = self.client.get(
            "/api/v1/user/profile?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["X-WAF-Rule"], "waf-3001")

    def test_sqli_in_json_body_is_blocked(self):
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "x' OR '1'='1", "password": "x"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["X-WAF-Rule"], "waf-1003")
        self.assertEqual(response.get_json()["error"]["location"], "body")

    def test_waf_blocks_html_route_with_styled_page(self):
        response = self.client.get("/dashboard?next=../../etc/passwd")
        self.assertEqual(response.status_code, 403)
        body = response.get_data(as_text=True)
        self.assertIn("WAF заблокував запит", body)
        self.assertIn("waf-1001", body)

    def test_client_lab_is_exempt_from_waf(self):
        page = self.client.get("/client-lab")
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match)

        response = self.client.post(
            "/client-lab/sanitize",
            data={
                "csrf_token": match.group(1),
                "filename": "contract<img src=x onerror=alert(1)>.pdf",
                "description": "<script>alert('XSS')</script>Опис",
                "comment": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("contract.pdf", response.get_data(as_text=True))

    def test_security_lab_is_exempt_from_waf(self):
        response = self.client.get("/security-lab?payload=../../etc/passwd")
        self.assertNotEqual(response.status_code, 403)

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def test_reset_requires_csrf(self):
        response = self.client.post("/waf-lab/reset")
        self.assertEqual(response.status_code, 400)

    def test_reset_clears_greylist_and_counters(self):
        self.client.get("/api/v1/user/profile?file=../../etc/passwd")
        self.assertEqual(self.client.get("/api/v1/health").status_code, 403)

        token = self._csrf_token()
        reset = self.client.post(
            "/waf-lab/reset",
            data={"csrf_token": token},
            headers={"X-Requested-With": "fetch"},
        )
        self.assertEqual(reset.status_code, 200)
        self.assertTrue(reset.get_json()["ok"])

        self.assertEqual(self.client.get("/api/v1/health").status_code, 200)
        self.assertEqual(self.app.extensions["network_guard"].incidents.total(), 0)

    def test_reset_can_be_disabled(self):
        self.app.config["WAF_LAB_ALLOW_RESET"] = False
        try:
            token = self._csrf_token("/client-lab")
            response = self.client.post(
                "/waf-lab/reset",
                data={"csrf_token": token},
                headers={"X-Requested-With": "fetch"},
            )
            self.assertEqual(response.status_code, 403)
        finally:
            self.app.config["WAF_LAB_ALLOW_RESET"] = True


if __name__ == "__main__":
    unittest.main()
