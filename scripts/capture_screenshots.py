"""Автоматично створює скриншоти протоколу тестування для звіту.

Запуск:
    python scripts/capture_screenshots.py

Потрібен Microsoft Edge (Selenium Manager сам підбере драйвер).
Скриншоти зберігаються у docs/screenshots/.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

# Демонстраційна БД, щоб не змішувати скриншоти з робочою instance/docvault.db.
DEMO_DB = ROOT / "instance" / "demo.db"
os.environ["DOCVAULT_DB"] = str(DEMO_DB)
os.environ["SECRET_KEY"] = "screenshot-demo-secret-key"
os.environ["BCRYPT_ROUNDS"] = "12"
os.environ["SESSION_COOKIE_SECURE"] = "0"

from selenium import webdriver  # noqa: E402
from selenium.webdriver.common.by import By  # noqa: E402
from selenium.webdriver.edge.options import Options  # noqa: E402
from selenium.webdriver.support import expected_conditions as EC  # noqa: E402
from selenium.webdriver.support.ui import WebDriverWait  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from app import create_app  # noqa: E402
from app.auth_security import hash_password  # noqa: E402
from app.database import create_user, find_user_by_username  # noqa: E402

try:
    from scripts.db_snapshot import generate_snapshot
except ImportError:  # запуск як python scripts/capture_screenshots.py
    from db_snapshot import generate_snapshot  # type: ignore


SCREENSHOTS = ROOT / "docs" / "screenshots"
DB_SNAPSHOT = ROOT / "docs" / "db_snapshot.html"
ARCH_HTML = ROOT / "docs" / "architecture.html"
DEMO_PASSWORD = "Vault#2026!"


def _remove_demo_db() -> None:
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DEMO_DB) + suffix)
        if path.exists():
            path.unlink()


def _seed_users(app) -> None:
    with app.app_context():
        for username, email, role in (
            ("admin", "admin@docvault.local", "admin"),
            ("s.koval", "s.koval@docvault.local", "user"),
        ):
            if find_user_by_username(username) is None:
                digest, salt = hash_password(DEMO_PASSWORD)
                create_user(username, email, digest, salt, role=role)


def _wait_flash(driver, wait, category: str) -> str:
    element = wait.until(
        EC.presence_of_element_located(
            (By.CSS_SELECTOR, f".flash--{category} .flash__text")
        )
    )
    return (element.get_attribute("textContent") or "").strip()


def _fill_login(driver, username: str, password: str) -> None:
    field = driver.find_element(By.ID, "username")
    field.clear()
    field.send_keys(username)

    field = driver.find_element(By.ID, "password")
    field.clear()
    field.send_keys(password)

    driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()


def main() -> int:
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    _remove_demo_db()

    app = create_app()
    _seed_users(app)

    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1500,1200")

    driver = webdriver.Edge(options=options)
    driver.set_page_load_timeout(15)
    driver.set_window_size(1500, 1200)
    wait = WebDriverWait(driver, 12)

    try:
        # 00. Оглядова сторінка входу
        driver.get(base_url + "/login")
        driver.save_screenshot(str(SCREENSHOTS / "00-login.png"))

        # 01. Реєстрація: заповнена форма з надійним паролем
        driver.get(base_url + "/register")
        driver.find_element(By.ID, "username").send_keys("o.kravets")
        driver.find_element(By.ID, "email").send_keys("o.kravets@docvault.local")
        driver.find_element(By.ID, "password").send_keys(DEMO_PASSWORD)
        driver.find_element(By.ID, "confirm_password").send_keys(DEMO_PASSWORD)
        wait.until(
            lambda d: d.find_element(By.CSS_SELECTOR, "[data-strength]").get_attribute(
                "data-level"
            )
            == "4"
        )
        driver.save_screenshot(str(SCREENSHOTS / "01-register-validation.png"))

        # 02. Успішна реєстрація -> flash на сторінці входу
        driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        wait.until(lambda d: "/login" in d.current_url)
        _wait_flash(driver, wait, "success")
        driver.save_screenshot(str(SCREENSHOTS / "02-register-success.png"))

        # 03. Помилка входу з хибним паролем
        _fill_login(driver, "o.kravets", "Wrong#2026!")
        _wait_flash(driver, wait, "error")
        driver.save_screenshot(str(SCREENSHOTS / "03-login-error.png"))

        # 04. Успішний вхід -> кабінет
        driver.get(base_url + "/login")
        _fill_login(driver, "o.kravets", DEMO_PASSWORD)
        wait.until(lambda d: "/dashboard" in d.current_url)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".stat-grid")))
        driver.save_screenshot(str(SCREENSHOTS / "04-dashboard.png"))

        # 05. SQL-ін'єкція у формі входу
        driver.delete_all_cookies()
        driver.get(base_url + "/login")
        _fill_login(driver, "' OR '1'='1", "anything")
        _wait_flash(driver, wait, "error")
        driver.save_screenshot(str(SCREENSHOTS / "05-sqli-login.png"))

        # 06. SQLi-лабораторія: параметризований запит повертає 0 рядків
        driver.set_window_size(1500, 1400)
        driver.get(base_url + "/security-lab")
        textarea = driver.find_element(By.ID, "payload")
        textarea.clear()
        textarea.send_keys("' OR '1'='1")
        driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".terminal__ok")))
        driver.save_screenshot(str(SCREENSHOTS / "06-security-lab.png"))

        # 07. Знімок таблиці users
        driver.set_window_size(1500, 1400)
        generate_snapshot(DEMO_DB, DB_SNAPSHOT)
        driver.get(DB_SNAPSHOT.as_uri())
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
        driver.save_screenshot(str(SCREENSHOTS / "07-users-table.png"))

        # 08. Архітектурна схема реєстрації/входу
        driver.set_window_size(1500, 1400)
        driver.get(ARCH_HTML.as_uri())
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".flow-grid")))
        driver.save_screenshot(str(SCREENSHOTS / "08-auth-flow.png"))

    finally:
        driver.quit()
        server.shutdown()
        thread.join(timeout=5)

    print("[+] Скриншоти збережено:")
    for path in sorted(SCREENSHOTS.glob("*.png")):
        print(f"    - {path.relative_to(ROOT)}")
    print(f"[+] HTML-знімок БД: {DB_SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
