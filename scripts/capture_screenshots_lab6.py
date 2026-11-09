"""Генерація скриншотів для звіту з ЛР №6.

Сценарій:
1. піднімає Flask-сервер із тимчасовою БД та vault/;
2. виконує реальний API-протокол keygen → upload → sign → download;
3. запускає tamper-тест (документ/підпис/контейнер);
4. у Edge headless проходить UI: ключі PEM, завантаження, підпис, vault;
5. генерує HTML-знімок `document_signatures` і скриншоти.

Запуск:
    python scripts/capture_screenshots_lab6.py
"""

from __future__ import annotations

import base64
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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


OUTPUT_DIR = PROJECT_ROOT / "docs" / "screenshots 6"
TEMP_DIR = Path(tempfile.mkdtemp(prefix="docvault-lab6-shots-"))
DB_PATH = TEMP_DIR / "lab6-demo.db"
STORAGE_DIR = TEMP_DIR / "vault"


def screenshot_clip(driver, clip: dict, path: Path, scale: int = 1) -> None:
    result = driver.execute_cdp_cmd(
        "Page.captureScreenshot",
        {
            "format": "png",
            "captureBeyondViewport": True,
            "clip": {
                "x": max(0.0, float(clip["x"])),
                "y": max(0.0, float(clip["y"])),
                "width": max(1.0, float(clip["width"])),
                "height": max(1.0, float(clip["height"])),
                "scale": scale,
            },
        },
    )
    path.write_bytes(base64.b64decode(result["data"]))
    print(f"  saved {path.name}")


def element_clip(driver, selector: str, pad: int = 8) -> dict:
    return driver.execute_script(
        """
        const el = document.querySelector(arguments[0]);
        if (!el) { throw new Error('Element not found: ' + arguments[0]); }
        const r = el.getBoundingClientRect();
        return {
          x: r.x + window.scrollX - arguments[1],
          y: r.y + window.scrollY - arguments[1],
          width: r.width + arguments[1] * 2,
          height: r.height + arguments[1] * 2,
        };
        """,
        selector,
        pad,
    )


def shot_element(
    driver, selector: str, name: str, pad: int = 8, scale: int = 1
) -> None:
    screenshot_clip(
        driver,
        element_clip(driver, selector, pad),
        OUTPUT_DIR / name,
        scale=scale,
    )


def shot_full(driver, name: str) -> None:
    metrics = driver.execute_cdp_cmd("Page.getLayoutMetrics", {})
    size = metrics.get("cssContentSize") or metrics["contentSize"]
    screenshot_clip(
        driver,
        {"x": 0, "y": 0, "width": size["width"], "height": size["height"]},
        OUTPUT_DIR / name,
    )


def shot_viewport(driver, name: str) -> None:
    driver.save_screenshot(str(OUTPUT_DIR / name))
    print(f"  saved {name}")


def wait_css(driver, selector: str, timeout: int = 20):
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
    )


def _colorize_line(line: str) -> str:
    escaped = html.escape(line.expandtabs(2), quote=False)
    lowered = line.lower()
    if "invalid" in lowered or "409" in lowered or "помилка" in lowered:
        css = "line line--rose"
    elif "signed & verified" in lowered or "http 200" in lowered or "http 201" in lowered:
        css = "line line--mint"
    elif any(
        marker in lowered
        for marker in ("rsa-pss", "public key", "private key", "fingerprint", "signature")
    ):
        css = "line line--violet"
    elif "sha-256" in lowered or "verify" in lowered:
        css = "line line--gold"
    else:
        css = "line"
    return f'<span class="{css}">{escaped}</span>'


def render_terminal(
    *,
    title: str,
    subtitle: str,
    command: str,
    output: str,
    filename: str,
) -> Path:
    lines = "\n".join(_colorize_line(line) for line in output.splitlines())
    document = f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0b1218; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --muted:#647a83; --violet:#b49cff; --gold:#ffd07a;
    --mint:#72f2c6; --rose:#ff7c91; --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;padding:38px;background:
    radial-gradient(900px 480px at 82% -10%,rgba(180,156,255,.15),transparent 60%),
    radial-gradient(760px 420px at 2% 12%,rgba(255,208,122,.07),transparent 58%),var(--bg);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif}}
  #shot{{max-width:1180px;margin:0 auto}}
  .head{{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:18px}}
  .eyebrow{{margin:0 0 8px;color:var(--violet);font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase}}
  h1{{margin:0;font-size:29px;letter-spacing:-.035em}}
  .hint{{color:var(--muted);font-family:var(--mono);font-size:11px;text-align:right;line-height:1.5}}
  .term{{border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--panel);box-shadow:0 30px 80px rgba(0,0,0,.5)}}
  .bar{{display:flex;align-items:center;gap:8px;padding:12px 15px;border-bottom:1px solid var(--line);background:rgba(255,255,255,.03)}}
  .dot{{width:10px;height:10px;border-radius:50%}}
  .dot:nth-child(1){{background:#ff6b6b}} .dot:nth-child(2){{background:#ffd166}} .dot:nth-child(3){{background:#4ade80}}
  .bar em{{margin-left:8px;color:var(--muted);font-family:var(--mono);font-size:11px;font-style:normal}}
  pre{{margin:0;padding:20px 22px 24px;overflow:auto;font-family:var(--mono);font-size:12px;line-height:1.6;white-space:pre}}
  .line{{display:block;color:#c3d4d8}}
  .line--mint{{color:var(--mint)}} .line--violet{{color:var(--violet)}}
  .line--gold{{color:var(--gold)}} .line--rose{{color:var(--rose)}}
  .prompt{{color:var(--mint)}} .cmd{{color:var(--text)}}
  .note{{margin:14px auto 0;color:var(--muted);font-family:var(--mono);font-size:10.5px;text-align:center}}
</style></head>
<body>
  <main id="shot">
    <div class="head">
      <div>
        <p class="eyebrow">{html.escape(subtitle)}</p>
        <h1>{html.escape(title)}</h1>
      </div>
      <div class="hint">Secure DocVault<br>ЛР №6 · реальний вивід</div>
    </div>
    <div class="term">
      <div class="bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><em>PowerShell · {html.escape(command)}</em></div>
      <pre><span class="prompt">PS D:\\TZIR\\secure-docvault&gt;</span> <span class="cmd">{html.escape(command)}</span>
{lines}</pre>
    </div>
    <p class="note">Дані отримані під час роботи реального Flask-сервера та RSA-PSS сервісу.</p>
  </main>
</body></html>"""
    path = TEMP_DIR / filename
    path.write_text(document, encoding="utf-8")
    return path


def run_script(args: list[str], timeout: int = 180) -> tuple[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        cwd=str(PROJECT_ROOT),
        check=False,
    )
    output = completed.stdout or completed.stderr or "Скрипт не повернув вивід."
    command = "python " + " ".join(args)
    return command, output


def seed_user(app) -> None:
    with app.app_context():
        digest, salt = hash_password("Vault#2026!", rounds=4)
        create_user(
            "lab6.demo",
            "lab6.demo@example.com",
            digest,
            salt,
            role="user",
        )


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT_DIR.glob("*.png"):
        old.unlink()

    test_config = type(
        "Lab6CaptureConfig",
        (Config,),
        {
            "TESTING": True,
            "SECRET_KEY": "lab6-capture-secret-key",
            "JWT_SECRET_KEY": "lab6-capture-jwt-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(DB_PATH),
            "DOCUMENT_STORAGE_DIR": str(STORAGE_DIR),
            "FILE_ENCRYPTION_KEY": "bb" * 32,
            "BCRYPT_ROUNDS": 4,
            "WAF_ENABLED": True,
            "RATE_LIMIT_ENABLED": True,
            "MAX_DOCUMENT_BYTES": 5 * 1024 * 1024,
        },
    )
    app = create_app(test_config)
    seed_user(app)

    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    driver = None
    try:
        print("01. API: keygen → upload → sign → download")
        api_command, api_output = run_script(
            ["scripts/demo_lab6_signature.py", "--base-url", base_url]
        )
        api_page = render_terminal(
            title="API-протокол ЕЦП документа",
            subtitle="Keygen / sign / download",
            command=api_command,
            output=api_output,
            filename="_lab6_api.html",
        )

        print("02. Tamper test")
        tamper_command, tamper_output = run_script(
            ["scripts/signature_tamper_lab6.py"]
        )
        tamper_page = render_terminal(
            title="Фальсифікація документа та підпису",
            subtitle="RSA-PSS / InvalidSignature",
            command=tamper_command,
            output=tamper_output,
            filename="_lab6_tamper.html",
        )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1200")
        options.add_argument("--force-device-scale-factor=1")
        driver = webdriver.Edge(options=options)
        driver.set_page_load_timeout(20)
        driver.execute_cdp_cmd(
            "Emulation.setEmulatedMedia",
            {"features": [{"name": "prefers-reduced-motion", "value": "reduce"}]},
        )

        print("03. Термінал API")
        driver.get(api_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, "#shot", "03-api-signed-download.png", pad=0)

        print("04. Термінал tamper")
        driver.get(tamper_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, "#shot", "04-tamper-signature.png", pad=0)

        print("05. UI: вхід і Signature Lab")
        driver.get(base_url + "/login")
        driver.find_element(By.ID, "username").send_keys("lab6.demo")
        driver.find_element(By.ID, "password").send_keys("Vault#2026!")
        driver.find_element(By.CSS_SELECTOR, "button[type=submit]").click()
        WebDriverWait(driver, 15).until(
            lambda d: "/dashboard" in d.current_url
        )
        driver.get(base_url + "/signature-lab")
        wait_css(driver, "#signature-key-panel")
        time.sleep(0.4)
        shot_viewport(driver, "00-signature-lab-overview.png")
        shot_element(
            driver,
            "#signature-key-panel",
            "01-keypair-pem.png",
            pad=6,
            scale=2,
        )

        print("06. UI: завантаження та підпис документа")
        sample = TEMP_DIR / "board-resolution.txt"
        sample.write_text(
            "OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n"
            "Secure DocVault · board resolution #2026-06\n",
            encoding="utf-8",
        )
        driver.get(base_url + "/vault")
        driver.find_element(By.ID, "document-file").send_keys(str(sample))
        driver.find_element(
            By.CSS_SELECTOR, ".vault-upload button[type=submit]"
        ).click()
        WebDriverWait(driver, 20).until(
            lambda d: "/vault/" in d.current_url
        )
        wait_css(driver, ".signature-panel")
        driver.find_element(
            By.CSS_SELECTOR, ".signature-panel input[name=passphrase]"
        ).send_keys("Sigil#2026!")
        driver.find_element(
            By.CSS_SELECTOR, ".signature-panel button[type=submit]"
        ).click()
        wait_css(driver, ".signature-badge--verified")
        time.sleep(0.4)
        shot_full(driver, "02-document-signed.png")

        print("07. UI: список підписаних документів")
        driver.get(base_url + "/vault")
        wait_css(driver, "#vault-documents")
        time.sleep(0.3)
        shot_element(
            driver, "#vault-documents", "06-vault-signed-documents.png",
            pad=6, scale=2
        )

        print("08. DB snapshot document_signatures")
        snapshot_path = PROJECT_ROOT / "docs" / "signature_db_snapshot.html"
        snapshot_command, snapshot_output = run_script(
            [
                "scripts/signature_db_snapshot.py",
                "--db",
                str(DB_PATH),
                "--output",
                str(snapshot_path),
            ]
        )
        print("  " + snapshot_output.strip())
        driver.get(snapshot_path.as_uri())
        time.sleep(0.4)
        shot_full(driver, "05-signature-db.png")

        print("09. Архітектурна схема")
        architecture = PROJECT_ROOT / "docs" / "digital_signature_architecture.html"
        driver.get(architecture.as_uri())
        time.sleep(0.4)
        shot_full(driver, "07-signature-architecture.png")

        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "base_url": base_url,
            "api_output": api_output,
            "tamper_output": tamper_output,
            "db_snapshot": snapshot_output,
            "files": sorted(path.name for path in OUTPUT_DIR.glob("*.png")),
        }
        (OUTPUT_DIR / "_capture_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\nГотово: {OUTPUT_DIR}")
        print(f"Файлів: {len(summary['files'])}")
    finally:
        if driver is not None:
            driver.quit()
        server.shutdown()
        thread.join(timeout=5)
        shutil.rmtree(TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
