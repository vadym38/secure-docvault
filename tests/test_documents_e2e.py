"""End-to-end тести Cipher Vault у браузері (ЛР №5).

Стек: unittest + Selenium WebDriver (Microsoft Edge, headless).
Перевіряють вхід, завантаження файлу через UI, detail-сторінку з hexdump,
відмову для недозволеного розширення та видалення контейнера.

Запуск:
    python -m unittest tests.test_documents_e2e -v
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

PASSWORD = "Vault#2026!"


class CipherVaultE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab5-e2e-"))
        cls.storage_dir = cls.temp_dir / "vault"
        cls.sample_file = cls.temp_dir / "quarterly-report.txt"
        cls.sample_file.write_text(
            "CONFIDENTIAL FINANCIAL REPORT - SECURE DOCVAULT 2026\n",
            encoding="utf-8",
        )
        cls.bad_file = cls.temp_dir / "malware.exe"
        cls.bad_file.write_bytes(b"MZ-not-allowed")

        test_config = type(
            "Lab5E2EConfig",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab5-e2e-secret-key",
                "JWT_SECRET_KEY": "lab5-e2e-jwt-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab5-e2e.db"),
                "DOCUMENT_STORAGE_DIR": str(cls.storage_dir),
                "FILE_ENCRYPTION_KEY": "44" * 32,
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "MAX_DOCUMENT_BYTES": 1024 * 1024,
            },
        )
        cls.app = create_app(test_config)

        with cls.app.app_context():
            digest, salt = hash_password(PASSWORD, rounds=4)
            create_user(
                "vault.user",
                "vault.user@example.com",
                digest,
                salt,
                role="user",
            )

        cls.server = make_server("127.0.0.1", 0, cls.app, threaded=True)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1500")

        try:
            cls.driver = webdriver.Edge(options=options)
        except Exception as exc:  # pragma: no cover - залежить від середовища
            cls.server.shutdown()
            cls.thread.join(timeout=5)
            shutil.rmtree(cls.temp_dir, ignore_errors=True)
            raise unittest.SkipTest(f"Microsoft Edge WebDriver недоступний: {exc}")

        cls.driver.set_page_load_timeout(20)
        cls.wait = WebDriverWait(cls.driver, 20)

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
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM documents")
            db.commit()
        for path in self.storage_dir.glob("*.enc"):
            path.unlink(missing_ok=True)
        self.driver.delete_all_cookies()
        self._login()

    def _login(self) -> None:
        self.driver.get(self.base_url + "/login")
        self.driver.find_element(By.ID, "username").send_keys("vault.user")
        self.driver.find_element(By.ID, "password").send_keys(PASSWORD)
        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        self.wait.until(lambda driver: "/dashboard" in driver.current_url)

    def _upload(self, path: Path) -> None:
        self.driver.get(self.base_url + "/vault")
        field = self.driver.find_element(By.ID, "document-file")
        field.send_keys(str(path))
        self.driver.find_element(
            By.CSS_SELECTOR, ".vault-upload button[type=submit]"
        ).click()

    def test_vault_requires_login(self):
        self.driver.delete_all_cookies()
        self.driver.get(self.base_url + "/vault")
        self.wait.until(lambda driver: "/login" in driver.current_url)

    def test_upload_opens_encrypted_detail_page(self):
        self._upload(self.sample_file)

        self.wait.until(lambda driver: "/vault/" in driver.current_url)
        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".hexdump__line"))
        )

        body = self.driver.find_element(By.TAG_NAME, "body").text
        lowered = body.lower()
        self.assertIn("quarterly-report.txt", body)
        self.assertIn("aes-256-gcm", lowered)
        self.assertIn("iv / nonce", lowered)
        self.assertIn("auth tag", lowered)

        lines = self.driver.find_elements(By.CSS_SELECTOR, ".hexdump__line")
        self.assertGreaterEqual(len(lines), 2)

    def test_disallowed_extension_shows_error(self):
        self._upload(self.bad_file)

        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".flash--error"))
        )
        flash = self.driver.find_element(By.CSS_SELECTOR, ".flash--error .flash__text")
        text = flash.get_attribute("textContent") or ""
        self.assertIn("не дозволено", text)

    def test_delete_removes_document(self):
        self._upload(self.sample_file)
        self.wait.until(lambda driver: "/vault/" in driver.current_url)

        self.driver.find_element(
            By.CSS_SELECTOR, ".vault-delete-form button[type=submit]"
        ).click()
        self.wait.until(EC.alert_is_present())
        self.driver.switch_to.alert.accept()

        self.wait.until(lambda driver: driver.current_url.rstrip("/").endswith("/vault"))
        body = self.driver.find_element(By.TAG_NAME, "body").text
        self.assertIn("Сховище порожнє", body)


if __name__ == "__main__":
    unittest.main()
