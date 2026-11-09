"""End-to-end тести клієнтського захисту (ЛР №3).

Стек: unittest + Selenium WebDriver (Microsoft Edge, headless).
Перевіряють реальне блокування CSP у браузері, атрибути cookie та
санітизацію XSS-пейлоада через форму.

Запуск:
    python -m unittest tests.test_client_security_e2e -v
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from werkzeug.serving import make_server

from app import create_app
from app.config import Config
from app.database import get_db


class ClientSecurityE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab3-e2e-"))
        cls.db_path = cls.temp_dir / "lab3-e2e.db"

        test_config = type(
            "Lab3E2EConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "lab3-e2e-secret-key",
                "JWT_SECRET_KEY": "lab3-e2e-jwt-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.db_path),
                "BCRYPT_ROUNDS": 4,
                "SESSION_COOKIE_SECURE": True,
                "SESSION_COOKIE_SAMESITE": "Strict",
                "CORS_ALLOWED_ORIGINS": ["http://127.0.0.1:5000"],
            },
        )

        cls.app = create_app(test_config)
        cls.server = make_server("127.0.0.1", 0, cls.app, threaded=True)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1100")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

        try:
            cls.driver = webdriver.Edge(options=options)
        except Exception as exc:  # pragma: no cover - залежить від середовища
            cls.server.shutdown()
            cls.thread.join(timeout=5)
            shutil.rmtree(cls.temp_dir, ignore_errors=True)
            raise unittest.SkipTest(f"Microsoft Edge WebDriver недоступний: {exc}")

        cls.driver.set_page_load_timeout(15)
        cls.wait = WebDriverWait(cls.driver, 10)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "driver", None):
            cls.driver.quit()
        if getattr(cls, "server", None):
            cls.server.shutdown()
        if getattr(cls, "thread", None):
            cls.thread.join(timeout=5)
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.driver.delete_all_cookies()
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM client_notes")
            db.commit()

    # ------------------------------------------------------------------
    # CSP
    # ------------------------------------------------------------------

    def test_browser_blocks_inline_script(self):
        self.driver.get(self.base_url + "/client-lab/csp")
        time.sleep(0.6)

        # Інлайн-скрипт не повинен виконатися.
        self.assertIsNone(
            self.driver.execute_script("return window.__xssExecuted === true ? true : null")
        )

        statuses = {
            element.get_attribute("id"): element.text
            for element in self.driver.find_elements(
                By.CSS_SELECTOR, ".attack-status strong"
            )
        }
        self.assertEqual(statuses.get("inline-status"), "BLOCKED")
        self.assertEqual(statuses.get("handler-status"), "BLOCKED")

    def test_browser_console_reports_csp_violation(self):
        self.driver.get(self.base_url + "/client-lab/csp")
        time.sleep(0.8)

        logs = self.driver.get_log("browser")
        text = "\n".join(entry.get("message", "") for entry in logs)

        self.assertTrue(
            "Content Security Policy" in text or "Refused to execute" in text,
            f"У консолі немає CSP-помилки. Отримано: {text[:800]}",
        )
        self.assertIn("script-src", text)

    def test_dom_injection_is_blocked(self):
        self.driver.get(self.base_url + "/client-lab/csp")
        self.driver.find_element(By.ID, "btn-dom-xss").click()

        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.ID, "dom-status"), "BLOCKED"
            )
        )
        self.assertIsNone(
            self.driver.execute_script("return window.__xssExecuted === true ? true : null")
        )

    # ------------------------------------------------------------------
    # Cookies
    # ------------------------------------------------------------------

    def test_demo_cookie_has_httponly_secure_samesite(self):
        self.driver.get(self.base_url + "/client-lab/cookies")
        cookies = {cookie["name"]: cookie for cookie in self.driver.get_cookies()}

        self.assertIn("docvault_demo_session", cookies)
        session_cookie = cookies["docvault_demo_session"]
        self.assertTrue(session_cookie["httpOnly"])
        self.assertTrue(session_cookie["secure"])
        self.assertEqual(session_cookie["sameSite"], "Strict")

    def test_document_cookie_does_not_expose_httponly_session(self):
        self.driver.get(self.base_url + "/client-lab/cookies")
        visible = self.driver.execute_script("return document.cookie || ''")

        self.assertNotIn("docvault_session", visible)
        self.assertNotIn("docvault_demo_session", visible)
        # Публічний CSRF-токен навпаки має бути видимим.
        self.assertIn("docvault_demo_csrf", visible)

    # ------------------------------------------------------------------
    # Санітизація через форму
    # ------------------------------------------------------------------

    def test_form_sanitizes_xss_payload(self):
        self.driver.get(self.base_url + "/client-lab")

        filename = self.driver.find_element(
            By.CSS_SELECTOR, 'input[name="filename"]'
        )
        filename.clear()
        filename.send_keys("contract<img src=x onerror=alert(1)>.pdf")

        description = self.driver.find_element(
            By.CSS_SELECTOR, 'textarea[name="description"]'
        )
        description.send_keys("<script>alert('XSS')</script>Опис документа")

        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()

        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".result-value"))
        )

        values = [
            element.text
            for element in self.driver.find_elements(By.CSS_SELECTOR, ".result-value")
        ]
        joined = "\n".join(values)

        self.assertIn("contract.pdf", joined)
        self.assertNotIn("<script", joined.lower())
        self.assertNotIn("onerror", joined.lower())
        self.assertIsNone(
            self.driver.execute_script("return window.__xssExecuted === true ? true : null")
        )

        with self.app.app_context():
            row = get_db().execute(
                "SELECT filename, description FROM client_notes ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(row["filename"], "contract.pdf")
        self.assertNotIn("<script", row["description"].lower())


if __name__ == "__main__":
    unittest.main()
