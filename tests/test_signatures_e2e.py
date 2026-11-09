"""End-to-end тести Signature Lab і підписання документа (ЛР №6).

Стек: unittest + Selenium WebDriver (Microsoft Edge, headless).
Перевіряють генерацію ключа через UI, PEM-панель, підписання документа,
статус Signed & Verified у списку та відмову при хибній парольній фразі.

Запуск:
    python -m unittest tests.test_signatures_e2e -v
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
PASSPHRASE = "Sigil#2026!"


class DigitalSignatureE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab6-e2e-"))
        cls.storage_dir = cls.temp_dir / "vault"
        cls.sample_file = cls.temp_dir / "board-resolution.txt"
        cls.sample_file.write_text(
            "OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n",
            encoding="utf-8",
        )

        test_config = type(
            "Lab6E2EConfig",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab6-e2e-secret-key",
                "JWT_SECRET_KEY": "lab6-e2e-jwt-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab6-e2e.db"),
                "DOCUMENT_STORAGE_DIR": str(cls.storage_dir),
                "FILE_ENCRYPTION_KEY": "99" * 32,
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "MAX_DOCUMENT_BYTES": 1024 * 1024,
            },
        )
        cls.app = create_app(test_config)
        with cls.app.app_context():
            digest, salt = hash_password(PASSWORD, rounds=4)
            cls.user_id = create_user(
                "sig.user",
                "sig.user@example.com",
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
            db.execute("DELETE FROM document_signatures")
            db.execute("DELETE FROM user_signing_keys")
            db.execute("DELETE FROM documents")
            db.commit()
            self.app.extensions["document_service"].generate_signing_key(
                {
                    "id": self.user_id,
                    "username": "sig.user",
                    "role": "user",
                },
                PASSPHRASE,
            )
        for path in self.storage_dir.glob("*.enc"):
            path.unlink(missing_ok=True)
        self.driver.delete_all_cookies()
        self._login()

    def _login(self) -> None:
        self.driver.get(self.base_url + "/login")
        self.driver.find_element(By.ID, "username").send_keys("sig.user")
        self.driver.find_element(By.ID, "password").send_keys(PASSWORD)
        self.driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        self.wait.until(lambda driver: "/dashboard" in driver.current_url)

    def _upload(self) -> None:
        self.driver.get(self.base_url + "/vault")
        self.driver.find_element(By.ID, "document-file").send_keys(
            str(self.sample_file)
        )
        self.driver.find_element(
            By.CSS_SELECTOR, ".vault-upload button[type=submit]"
        ).click()
        self.wait.until(lambda driver: "/vault/" in driver.current_url)
        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".signature-panel"))
        )

    def _sign(self, passphrase: str = PASSPHRASE) -> None:
        field = self.driver.find_element(
            By.CSS_SELECTOR, ".signature-panel input[name=passphrase]"
        )
        field.send_keys(passphrase)
        self.driver.find_element(
            By.CSS_SELECTOR, ".signature-panel button[type=submit]"
        ).click()

    def test_signature_lab_shows_public_and_encrypted_private_pem(self):
        self.driver.get(self.base_url + "/signature-lab")
        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".pem-block"))
        )
        body = self.driver.find_element(By.TAG_NAME, "body").text
        self.assertIn("BEGIN PUBLIC KEY", body)
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", body)
        self.assertIn("RSA-PSS 2048", body)

    def test_generate_key_through_ui(self):
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM user_signing_keys")
            db.commit()

        self.driver.get(self.base_url + "/signature-lab")
        self.driver.find_element(
            By.CSS_SELECTOR, "input[name=passphrase]"
        ).send_keys(PASSPHRASE)
        self.driver.find_element(
            By.CSS_SELECTOR, "input[name=confirm]"
        ).send_keys(PASSPHRASE)
        self.driver.find_element(
            By.CSS_SELECTOR, "form button[type=submit]"
        ).click()

        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".pem-block"))
        )
        body = self.driver.find_element(By.TAG_NAME, "body").text
        self.assertIn("BEGIN PUBLIC KEY", body)

    def test_ui_sign_document_and_vault_badge(self):
        self._upload()
        self._sign()

        self.wait.until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, ".signature-badge--verified")
            )
        )
        body = self.driver.find_element(By.TAG_NAME, "body").text
        self.assertIn("Signed & Verified", body)
        self.assertIn("RSA-PSS-2048-SHA256", body)

        self.driver.get(self.base_url + "/vault")
        self.wait.until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, ".signature-badge--verified")
            )
        )

    def test_wrong_passphrase_shows_error(self):
        self._upload()
        self._sign("Wrong#2026!")

        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".flash--error"))
        )
        flash = self.driver.find_element(By.CSS_SELECTOR, ".flash--error .flash__text")
        text = flash.get_attribute("textContent") or ""
        self.assertIn("Невірна", text)

        badge = self.driver.find_element(By.CSS_SELECTOR, ".signature-badge")
        self.assertIn("Unsigned", badge.get_attribute("textContent") or "")


if __name__ == "__main__":
    unittest.main()
