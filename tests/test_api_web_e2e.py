"""E2E-тест JWT API-лабораторії у справжньому браузері (unittest + Selenium)."""

from __future__ import annotations

import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from werkzeug.serving import make_server

from app import create_app
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user

PASSWORD = "Vault#2026!"


class ApiLabE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-api-e2e-"))
        test_config = type(
            "ApiE2EConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "api-e2e-session-secret",
                "JWT_SECRET_KEY": "api-e2e-jwt-secret-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "api-e2e.db"),
                "BCRYPT_ROUNDS": 4,
                "SESSION_COOKIE_SECURE": False,
            },
        )
        cls.app = create_app(test_config)
        with cls.app.app_context():
            digest, salt = hash_password(PASSWORD, rounds=4)
            create_user("o.kravets", "o.kravets@docvault.local", digest, salt)

        cls.server = make_server("127.0.0.1", 0, cls.app, threaded=True)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1500,1200")

        try:
            cls.driver = webdriver.Edge(options=options)
        except Exception as exc:  # pragma: no cover - залежить від середовища
            cls.server.shutdown()
            cls.thread.join(timeout=5)
            shutil.rmtree(cls.temp_dir, ignore_errors=True)
            raise unittest.SkipTest(f"Microsoft Edge WebDriver недоступний: {exc}")

        cls.driver.set_page_load_timeout(15)
        cls.wait = WebDriverWait(cls.driver, 12)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "driver", None):
            cls.driver.quit()
        if getattr(cls, "server", None):
            cls.server.shutdown()
        if getattr(cls, "thread", None):
            cls.thread.join(timeout=5)
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _text(self, element_id: str) -> str:
        return self.driver.find_element(By.ID, element_id).text

    def _wait_status(self, code: str) -> None:
        self.wait.until(
            lambda d: d.find_element(By.ID, "response-status").text.startswith(code)
        )

    def test_full_jwt_protocol(self):
        self.driver.get(self.base_url + "/api-lab")
        self.wait.until(EC.element_to_be_clickable((By.ID, "btn-login")))

        self.driver.find_element(By.ID, "btn-login").click()
        self._wait_status("200")
        self.assertNotEqual(self._text("access-preview"), "—")
        self.assertNotEqual(self._text("refresh-preview"), "—")
        self.assertIn('"type": "access"', self._text("jwt-payload"))
        self.assertIn("signature valid", self._text("signature-state"))

        self.driver.find_element(By.ID, "btn-profile").click()
        self._wait_status("200")
        self.assertEqual(self._text("response-path"), "/api/v1/user/profile")
        self.assertIn('"username": "o.kravets"', self._text("response-body"))

        self.driver.find_element(By.ID, "btn-no-token").click()
        self._wait_status("401")
        self.assertIn('"code": "missing_token"', self._text("response-body"))

        self.driver.find_element(By.ID, "btn-tamper").click()
        self._wait_status("401")
        self.assertIn('"code": "invalid_signature"', self._text("response-body"))
        self.assertIn("INVALID", self._text("signature-state"))
        self.assertIn('"role": "admin"', self._text("jwt-payload"))

        self.driver.find_element(By.ID, "btn-refresh").click()
        self._wait_status("200")
        self.assertIn('"rotated": true', self._text("response-body"))

        self.driver.find_element(By.ID, "btn-reuse").click()
        self._wait_status("401")
        self.assertIn('"code": "refresh_token_reuse"', self._text("response-body"))
        self.assertIn("revoked", self._text("signature-state"))


if __name__ == "__main__":
    unittest.main()
