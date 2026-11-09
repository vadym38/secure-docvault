"""End-to-end тести веб-інтерфейсу.

Стек тестування: unittest + Selenium WebDriver (Microsoft Edge, headless).
Це навмисно інший стек, ніж pytest + fastapi.testclient/httpx/requests.

Запуск:
    python -m unittest tests.test_web_e2e -v
"""

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
from app.database import create_user, get_db


class WebE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-e2e-"))
        cls.db_path = cls.temp_dir / "e2e.db"

        test_config = type(
            "E2EConfig",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "e2e-secret-key",
                "DATABASE": str(cls.db_path),
                "BCRYPT_ROUNDS": 12,
                "SESSION_COOKIE_SECURE": False,
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
            db.execute("DELETE FROM users")
            db.commit()

        self.driver.get(self.base_url + "/login")

    # ------------------------------------------------------------------
    # Допоміжні методи
    # ------------------------------------------------------------------

    def _wait_flash(self, category: str | None = None) -> str:
        selector = f".flash--{category}" if category else ".flash"
        flash_text = self.wait.until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, f"{selector} .flash__text")
            )
        )
        # textContent не залежить від візуальної видимості й стабільніший
        # за .text у headless-режимі.
        return (flash_text.get_attribute("textContent") or "").strip()

    def _fill_login(self, username: str, password: str) -> None:
        field = self.driver.find_element(By.ID, "username")
        field.clear()
        field.send_keys(username)

        field = self.driver.find_element(By.ID, "password")
        field.clear()
        field.send_keys(password)

        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()

    def _register(
        self,
        username: str = "o.kravets",
        email: str = "o.kravets@example.com",
        password: str = "Vault#2026",
        confirm: str | None = None,
    ) -> None:
        confirm = password if confirm is None else confirm

        self.driver.get(self.base_url + "/register")
        self.driver.find_element(By.ID, "username").send_keys(username)
        self.driver.find_element(By.ID, "email").send_keys(email)
        self.driver.find_element(By.ID, "password").send_keys(password)
        self.driver.find_element(By.ID, "confirm_password").send_keys(confirm)
        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()

    def _create_user_in_db(
        self,
        username: str = "o.kravets",
        email: str = "o.kravets@example.com",
        password: str = "Vault#2026",
    ) -> int:
        with self.app.app_context():
            password_hash, salt = hash_password(password, rounds=12)
            return create_user(username, email, password_hash, salt)

    # ------------------------------------------------------------------
    # Тести
    # ------------------------------------------------------------------

    def test_register_rejects_weak_password(self):
        self._register(password="weakpass", confirm="weakpass")
        self._wait_flash("error")

        self.assertIn("/register", self.driver.current_url)

        with self.app.app_context():
            total = get_db().execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        self.assertEqual(total, 0)

    def test_register_creates_hashed_user(self):
        self._register()

        self.wait.until(lambda driver: "/login" in driver.current_url)
        self.assertIn("Акаунт створено", self._wait_flash("success"))

        with self.app.app_context():
            user = get_db().execute(
                "SELECT * FROM users WHERE username = ?", ("o.kravets",)
            ).fetchone()

        self.assertIsNotNone(user)
        self.assertTrue(user["password_hash"].startswith("$2b$12$"))
        self.assertTrue(user["salt"].startswith("$2b$12$"))
        self.assertNotIn("Vault#2026", user["password_hash"])

    def test_login_with_correct_password_opens_dashboard(self):
        self._create_user_in_db()

        self._fill_login("o.kravets", "Vault#2026")
        self.wait.until(lambda driver: "/dashboard" in driver.current_url)

        self.assertIn("o.kravets", self.driver.find_element(By.CSS_SELECTOR, "h1").text)

        cookies = {cookie["name"]: cookie for cookie in self.driver.get_cookies()}
        self.assertIn("docvault_session", cookies)

    def test_login_with_wrong_password_shows_generic_error(self):
        self._create_user_in_db()

        self._fill_login("o.kravets", "Wrong#2026")
        self.assertIn("Невірне ім'я користувача або пароль.", self._wait_flash("error"))
        self.assertIn("/login", self.driver.current_url)

    def test_sql_injection_in_login_is_blocked(self):
        self._create_user_in_db(username="admin", email="admin@example.com")

        self._fill_login("' OR '1'='1", "anything")
        self.assertIn("Невірне ім'я користувача або пароль.", self._wait_flash("error"))
        self.assertIn("/login", self.driver.current_url)
        self.assertNotIn("/dashboard", self.driver.current_url)

    def test_security_lab_blocks_payload(self):
        self.driver.get(self.base_url + "/security-lab")

        textarea = self.driver.find_element(By.ID, "payload")
        textarea.clear()
        textarea.send_keys("' OR '1'='1")
        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()

        terminal = self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".terminal__ok"))
        )
        self.assertIn("rows returned: 0", terminal.text)
        self.assertIn(
            "заблоковано",
            self.driver.find_element(By.CSS_SELECTOR, ".lab-result strong").text,
        )

    def test_dashboard_requires_login(self):
        self.driver.get(self.base_url + "/dashboard")
        self.wait.until(lambda driver: "/login" in driver.current_url)

        self.assertIn("увійдіть", self._wait_flash("warning").lower())

    def test_password_visibility_toggle(self):
        self.driver.get(self.base_url + "/register")

        password = self.driver.find_element(By.ID, "password")
        self.assertEqual(password.get_attribute("type"), "password")

        self.driver.find_element(By.CSS_SELECTOR, '[data-reveal="password"]').click()
        self.assertEqual(password.get_attribute("type"), "text")

    def test_csrf_token_is_required(self):
        self.driver.get(self.base_url + "/login")
        self.driver.execute_script(
            "document.querySelector('input[name=csrf_token]').remove();"
        )

        self.driver.find_element(By.ID, "username").send_keys("o.kravets")
        self.driver.find_element(By.ID, "password").send_keys("Vault#2026")
        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()

        error_code = self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".error-code"))
        )
        self.assertEqual(error_code.text, "400")


if __name__ == "__main__":
    unittest.main()
