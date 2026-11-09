"""End-to-end тести WAF / Rate Limiting у браузері (ЛР №4).

Стек: unittest + Selenium WebDriver (Microsoft Edge, headless).
Перевіряють реальний JS-сценарій на `/waf-lab`: 10 запитів → 429,
WAF-атаку → 403 + Greylist, журнал інцидентів і лабораторний Reset.

Запуск:
    python -m unittest tests.test_network_security_e2e -v
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


class NetworkSecurityE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab4-e2e-"))
        test_config = type(
            "Lab4E2EConfig",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab4-e2e-secret-key",
                "JWT_SECRET_KEY": "lab4-e2e-jwt-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab4-e2e.db"),
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": True,
                "RATE_LIMIT_ENABLED": True,
                "RATE_LIMIT_LOGIN_LIMIT": 5,
                "RATE_LIMIT_API_LIMIT": 60,
                "RATE_LIMIT_WEB_LIMIT": 120,
                "WAF_GREYLIST_SECONDS": 60,
                "WAF_LAB_ALLOW_RESET": True,
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
        options.add_argument("--window-size=1440,1400")

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
        self.app.extensions["network_guard"].reset()
        self.driver.delete_all_cookies()

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def test_burst_ui_shows_401_then_429_with_retry_after(self):
        self.driver.get(self.base_url + "/waf-lab")
        self.driver.find_element(By.ID, "btn-burst").click()

        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.ID, "burst-status"), "429"
            )
        )

        rows = self.driver.find_elements(By.CSS_SELECTOR, "#burst-results tr")
        self.assertEqual(len(rows), 10)

        statuses = [
            row.find_elements(By.TAG_NAME, "td")[1].text for row in rows
        ]
        self.assertEqual(statuses[:5], ["HTTP 401"] * 5)
        self.assertEqual(statuses[5:], ["HTTP 429"] * 5)

        retry_after = [
            row.find_elements(By.TAG_NAME, "td")[2].text for row in rows
        ]
        self.assertTrue(all(value == "—" for value in retry_after[:5]))
        self.assertTrue(all(value.isdigit() for value in retry_after[5:]))

        status = self.driver.find_element(By.ID, "burst-status")
        self.assertEqual(status.get_attribute("data-state"), "error")

    # ------------------------------------------------------------------
    # WAF
    # ------------------------------------------------------------------

    def test_waf_attack_ui_blocks_and_greylists(self):
        self.driver.get(self.base_url + "/waf-lab")
        self.driver.find_element(By.CSS_SELECTOR, '[data-attack="path"]').click()

        pre = self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#waf-result pre"))
        )
        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "#waf-result pre"), "HTTP: 403"
            )
        )
        self.assertIn("waf-1001", pre.text)
        self.assertIn("waf_blocked", pre.text)

        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.ID, "incident-body"), "waf_block"
            )
        )

        self.driver.find_element(By.ID, "btn-check-greylist").click()
        self.wait.until(
            lambda driver: "greylist probe"
            in driver.find_element(
                By.CSS_SELECTOR, "#waf-result .attack-result__label"
            ).text.lower()
        )
        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "#waf-result pre"), "ip_greylisted"
            )
        )

    def test_sqli_attack_ui_is_blocked(self):
        self.driver.get(self.base_url + "/waf-lab")
        self.driver.find_element(By.CSS_SELECTOR, '[data-attack="sqli"]').click()

        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "#waf-result pre"), "HTTP: 403"
            )
        )
        pre = self.driver.find_element(By.CSS_SELECTOR, "#waf-result pre")
        self.assertIn("waf-1003", pre.text)

    def test_command_attack_ui_is_blocked(self):
        self.driver.get(self.base_url + "/waf-lab")
        self.driver.find_element(By.CSS_SELECTOR, '[data-attack="cmd"]').click()

        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "#waf-result pre"), "HTTP: 403"
            )
        )
        pre = self.driver.find_element(By.CSS_SELECTOR, "#waf-result pre")
        self.assertIn("waf-2", pre.text)

    # ------------------------------------------------------------------
    # Reset та сумісність із ЛР №3
    # ------------------------------------------------------------------

    def test_reset_button_clears_greylist(self):
        self.driver.get(self.base_url + "/waf-lab")
        self.driver.find_element(By.CSS_SELECTOR, '[data-attack="path"]').click()
        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.CSS_SELECTOR, "#waf-result pre"), "HTTP: 403"
            )
        )

        self.driver.find_element(By.ID, "btn-reset").click()
        self.wait.until(
            EC.text_to_be_present_in_element(
                (By.ID, "greylist-count"), "0"
            )
        )

    def test_client_lab_sanitizer_still_works_under_waf(self):
        self.driver.get(self.base_url + "/client-lab")
        self.driver.execute_script(
            """
            document.querySelector('input[name="filename"]').value =
              'contract<img src=x onerror=alert(1)>.pdf';
            document.querySelector('textarea[name="description"]').value =
              "<script>alert('XSS')</script>Опис";
            document.querySelector('.sanitizer-form button[type="submit"]').click();
            """
        )

        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".result-value"))
        )
        values = "\n".join(
            item.text
            for item in self.driver.find_elements(By.CSS_SELECTOR, ".result-value")
        )
        self.assertIn("contract.pdf", values)
        self.assertIsNone(
            self.driver.execute_script(
                "return window.__xssExecuted === true ? true : null"
            )
        )


if __name__ == "__main__":
    unittest.main()
