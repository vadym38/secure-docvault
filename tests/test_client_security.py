"""Інтеграційні тести клієнтського захисту (ЛР №3).

Перевіряють реальні HTTP-заголовки, CORS-політику, атрибути cookie,
CSRF-захист лабораторії та відсутність відображеного XSS.

Запуск:
    python -m unittest tests.test_client_security -v
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.config import Config
from app.database import get_db, list_client_notes


class ClientSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab3-"))
        cls.db_path = cls.temp_dir / "lab3.db"

        test_config = type(
            "Lab3Config",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "lab3-secret-key",
                "JWT_SECRET_KEY": "lab3-jwt-secret-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.db_path),
                "BCRYPT_ROUNDS": 4,
                "SESSION_COOKIE_SECURE": True,
                "SESSION_COOKIE_SAMESITE": "Strict",
                "CORS_ALLOWED_ORIGINS": ["https://app.example", "http://localhost:5000"],
                "CLIENT_LAB_MAX_TEXT": 500,
            },
        )
        cls.app = create_app(test_config)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM client_notes")
            db.commit()

    def _csrf_token(self) -> str:
        page = self.client.get("/client-lab")
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match, "CSRF-поле відсутнє у формі")
        return match.group(1)

    # ------------------------------------------------------------------
    # Маршрути та заголовки
    # ------------------------------------------------------------------

    def test_all_client_lab_pages_render(self):
        for route in (
            "/client-lab",
            "/client-lab/csp",
            "/client-lab/cookies",
            "/client-lab/headers",
            "/client-lab/cors",
        ):
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 200)
                self.assertGreater(len(response.data), 1000)

    def test_csp_has_self_scripts_and_no_unsafe_inline(self):
        response = self.client.get("/client-lab")
        csp = response.headers["Content-Security-Policy"]

        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("report-uri /client-lab/csp-report", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("*", csp)

    def test_required_security_headers_are_present(self):
        response = self.client.get("/client-lab/headers")

        self.assertEqual(
            response.headers["Strict-Transport-Security"],
            "max-age=31536000; includeSubDomains",
        )
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Referrer-Policy"],
            "strict-origin-when-cross-origin",
        )
        self.assertIn("camera=()", response.headers["Permissions-Policy"])

    def test_security_headers_apply_to_api_responses(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    def test_allowed_origin_is_echoed(self):
        response = self.client.get(
            "/api/v1/health",
            headers={"Origin": "https://app.example"},
        )
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"],
            "https://app.example",
        )
        self.assertEqual(
            response.headers["Access-Control-Allow-Credentials"],
            "true",
        )
        self.assertIn("Origin", response.headers["Vary"])

    def test_foreign_origin_gets_no_allow_origin_header(self):
        response = self.client.get(
            "/api/v1/health",
            headers={"Origin": "https://evil.example"},
        )
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)
        self.assertIn("Origin", response.headers["Vary"])

    def test_cors_page_lists_configured_origins(self):
        response = self.client.get("/client-lab/cors")
        body = response.get_data(as_text=True)

        self.assertIn("https://app.example", body)
        self.assertIn("http://localhost:5000", body)
        self.assertIn(">CORS_ALLOWED_ORIGINS<", body)
        self.assertIn("заборонено", body)

    def test_wildcard_origin_is_never_returned(self):
        for origin in ("*", "null", "https://evil.example"):
            with self.subTest(origin=origin):
                response = self.client.get(
                    "/api/v1/health",
                    headers={"Origin": origin},
                )
                self.assertNotEqual(
                    response.headers.get("Access-Control-Allow-Origin"),
                    "*",
                )

    def test_preflight_for_allowed_origin(self):
        response = self.client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "https://app.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, authorization",
            },
        )
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"],
            "https://app.example",
        )
        self.assertIn("POST", response.headers["Access-Control-Allow-Methods"])
        self.assertIn(
            "Authorization",
            response.headers["Access-Control-Allow-Headers"],
        )

    # ------------------------------------------------------------------
    # Cookie
    # ------------------------------------------------------------------

    def test_session_cookie_flags(self):
        response = self.client.get("/client-lab")
        session_cookie = next(
            header
            for header in response.headers.getlist("Set-Cookie")
            if header.startswith("docvault_session=")
        )

        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("Secure", session_cookie)
        self.assertIn("SameSite=Strict", session_cookie)

    def test_demo_cookies_have_full_flag_set(self):
        response = self.client.get("/client-lab/cookies")
        cookies = response.headers.getlist("Set-Cookie")
        joined = "\n".join(cookies)

        self.assertIn("docvault_demo_session=", joined)
        self.assertIn("docvault_demo_csrf=", joined)
        self.assertIn("HttpOnly", joined)
        self.assertIn("Secure", joined)
        self.assertIn("SameSite=Strict", joined)

        csrf_cookie = next(
            header
            for header in cookies
            if header.startswith("docvault_demo_csrf=")
        )
        self.assertNotIn("HttpOnly", csrf_cookie)

    def test_cookie_page_does_not_cache(self):
        response = self.client.get("/client-lab/cookies")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    # ------------------------------------------------------------------
    # Санітизація та CSRF
    # ------------------------------------------------------------------

    def test_sanitize_post_stores_clean_text(self):
        token = self._csrf_token()
        response = self.client.post(
            "/client-lab/sanitize",
            data={
                "csrf_token": token,
                "filename": "contract<img src=x onerror=alert(1)>.pdf",
                "description": "<script>alert('XSS')</script>Опис документа",
                "comment": '"><svg onload=alert(1)>Коментар',
            },
        )
        self.assertEqual(response.status_code, 200)

        body = response.get_data(as_text=True)
        self.assertNotIn("<script>alert('XSS')</script>", body)
        self.assertNotIn("<img src=x onerror", body)
        self.assertNotIn("<svg onload", body)

        with self.app.app_context():
            notes = list_client_notes(limit=1)

        self.assertEqual(len(notes), 1)
        note = notes[0]
        self.assertEqual(note["filename"], "contract.pdf")
        self.assertNotIn("<script", note["description"].lower())
        self.assertNotIn("<svg", note["description"].lower())
        self.assertIn("script", note["blocked_vectors"].lower())

    def test_sanitize_post_without_csrf_is_rejected(self):
        response = self.client.post(
            "/client-lab/sanitize",
            data={"filename": "test.pdf", "description": "x"},
        )
        self.assertEqual(response.status_code, 400)

    def test_csp_report_endpoint_accepts_json(self):
        response = self.client.post(
            "/client-lab/csp-report",
            json={"csp-report": {"violated-directive": "script-src 'self'"}},
        )
        self.assertEqual(response.status_code, 204)

    def test_reflected_payload_is_html_escaped(self):
        token = self._csrf_token()
        response = self.client.post(
            "/client-lab/sanitize",
            data={
                "csrf_token": token,
                "filename": "x.pdf",
                "description": '<img src=x onerror="alert(1)">',
                "comment": "",
            },
        )
        body = response.get_data(as_text=True)
        # Оригінал показується лише як екранований текст.
        self.assertIn("&lt;img", body)
        self.assertNotIn('<img src=x onerror="alert(1)">', body)


if __name__ == "__main__":
    unittest.main()
