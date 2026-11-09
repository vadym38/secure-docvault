"""Скриншоти протоколу ЛР №2: JWT REST API.

Запуск:
    python scripts/capture_screenshots_lab2.py

Потрібен Microsoft Edge (Selenium Manager підбере драйвер).
Результат: docs/screenshots 2/*.png, docs/jwt_db_snapshot.html.
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

DEMO_DB = ROOT / "instance" / "lab2_demo.db"
os.environ["DOCVAULT_DB"] = str(DEMO_DB)
os.environ["SECRET_KEY"] = "lab2-screenshot-session-secret"
os.environ["JWT_SECRET_KEY"] = "lab2-screenshot-jwt-secret-0123456789abcdef0123456789"
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
    from scripts.jwt_db_snapshot import generate_snapshot
except ImportError:  # запуск як python scripts/capture_screenshots_lab2.py
    from jwt_db_snapshot import generate_snapshot  # type: ignore


SCREENSHOTS = ROOT / "docs" / "screenshots 2"
DB_SNAPSHOT = ROOT / "docs" / "jwt_db_snapshot.html"
ARCH_HTML = ROOT / "docs" / "jwt_architecture.html"
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
            ("o.kravets", "o.kravets@docvault.local", "user"),
        ):
            if find_user_by_username(username) is None:
                digest, salt = hash_password(DEMO_PASSWORD, rounds=12)
                create_user(username, email, digest, salt, role=role)


def _wait_status(driver, wait, code: str, path: str) -> None:
    wait.until(
        lambda d: d.find_element(By.ID, "response-status").text.startswith(code)
        and d.find_element(By.ID, "response-path").text == path
    )


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
    wait = WebDriverWait(driver, 15)

    try:
        # 00. Оглядова сторінка JWT-стенда
        driver.get(base_url + "/api-lab")
        wait.until(EC.element_to_be_clickable((By.ID, "btn-login")))
        driver.save_screenshot(str(SCREENSHOTS / "00-api-lab-overview.png"))

        # 01. Успішний login: пара access + refresh
        driver.find_element(By.ID, "btn-login").click()
        _wait_status(driver, wait, "200", "/api/v1/auth/login")
        wait.until(lambda d: d.find_element(By.ID, "access-preview").text != "—")
        driver.save_screenshot(str(SCREENSHOTS / "01-jwt-login.png"))

        # 02. Доступ до захищеного профілю з Bearer
        driver.find_element(By.ID, "btn-profile").click()
        _wait_status(driver, wait, "200", "/api/v1/user/profile")
        driver.save_screenshot(str(SCREENSHOTS / "02-profile-authorized.png"))

        # 03. Запит без токена -> 401
        driver.find_element(By.ID, "btn-no-token").click()
        _wait_status(driver, wait, "401", "/api/v1/user/profile")
        driver.save_screenshot(str(SCREENSHOTS / "03-profile-no-token.png"))

        # 04. Підміна role=admin -> invalid signature
        driver.set_window_size(1500, 1500)
        driver.find_element(By.ID, "btn-tamper").click()
        _wait_status(driver, wait, "401", "/api/v1/user/profile")
        wait.until(
            lambda d: "INVALID" in d.find_element(By.ID, "signature-state").text
        )
        driver.execute_script(
            "document.getElementById('jwt-inspector').scrollIntoView({block:'center'});"
        )
        driver.save_screenshot(str(SCREENSHOTS / "04-tampered-token.png"))

        # 05. Ротація Refresh-токена
        driver.set_window_size(1500, 1200)
        driver.execute_script("window.scrollTo(0, 0);")
        driver.find_element(By.ID, "btn-refresh").click()
        _wait_status(driver, wait, "200", "/api/v1/auth/refresh")
        wait.until(lambda d: '"rotated": true' in d.find_element(By.ID, "response-body").text)
        driver.save_screenshot(str(SCREENSHOTS / "05-refresh-rotation.png"))

        # 06. Повторне використання старого Refresh -> 401 + revoke family
        driver.find_element(By.ID, "btn-reuse").click()
        _wait_status(driver, wait, "401", "/api/v1/auth/refresh")
        wait.until(
            lambda d: "revoked" in d.find_element(By.ID, "signature-state").text
        )
        driver.save_screenshot(str(SCREENSHOTS / "06-refresh-reuse.png"))

        # 07. Декодована структура JWT (Header / Payload / Signature)
        driver.find_element(By.ID, "btn-login").click()
        _wait_status(driver, wait, "200", "/api/v1/auth/login")
        driver.set_window_size(1500, 840)
        driver.execute_script(
            "document.getElementById('jwt-inspector').scrollIntoView({block:'center'});"
        )
        driver.save_screenshot(str(SCREENSHOTS / "07-jwt-structure.png"))

        # 08. Архітектурна схема обміну токенами
        driver.set_window_size(1500, 1060)
        driver.get(ARCH_HTML.as_uri())
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".lane")))
        driver.save_screenshot(str(SCREENSHOTS / "08-jwt-flow.png"))

        # 09. Журнал refresh_tokens: rotation + reuse detection
        driver.set_window_size(1500, 620)
        generate_snapshot(DEMO_DB, DB_SNAPSHOT)
        driver.get(DB_SNAPSHOT.as_uri())
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "table")))
        driver.save_screenshot(str(SCREENSHOTS / "09-refresh-token-table.png"))

    finally:
        driver.quit()
        server.shutdown()
        thread.join(timeout=5)

    print("[+] Скриншоти ЛР №2 збережено:")
    for path in sorted(SCREENSHOTS.glob("*.png")):
        print(f"    - {path.relative_to(ROOT)}")
    print(f"[+] HTML-знімок refresh_tokens: {DB_SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
