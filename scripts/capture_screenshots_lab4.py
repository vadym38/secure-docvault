"""Генерація скриншотів для звіту з ЛР №4.

Сценарій:
1. піднімає Flask-сервер із увімкненими WAF/Rate Limiting;
2. запускає реальний `scripts/stress_test_lab4.py` (10 запитів → 429);
3. перехоплює реальні записи `app.logger` / Werkzeug;
4. у Edge headless проходить UI-сценарії: стрес-тест, Path Traversal,
   SQLi, Command Injection, Greylist, журнал інцидентів;
5. зберігає PNG у `docs/screenshots 4/`.

Запуск:
    python scripts/capture_screenshots_lab4.py
"""

from __future__ import annotations

import base64
import html
import json
import logging
import os
import re
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
from app.config import Config


OUTPUT_DIR = PROJECT_ROOT / "docs" / "screenshots 4"
TEMP_DIR = Path(tempfile.mkdtemp(prefix="docvault-lab4-shots-"))
DB_PATH = TEMP_DIR / "lab4-demo.db"


class ListHandler(logging.Handler):
    """Збирає логи сервера для термінального скриншота."""

    def __init__(self, sink: list[str]) -> None:
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.append(self.format(record))
        except Exception:  # pragma: no cover - logging не має ламати сервер
            pass


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


def wait_css(driver, selector: str, timeout: int = 15):
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
    )


def wait_text(driver, selector: str, text: str, timeout: int = 15) -> None:
    WebDriverWait(driver, timeout).until(
        EC.text_to_be_present_in_element((By.CSS_SELECTOR, selector), text)
    )


def _colorize_line(line: str) -> str:
    escaped = html.escape(line.expandtabs(2), quote=False)
    lowered = line.lower()
    if "http 403" in lowered or "http 429" in lowered or "waf_block" in lowered:
        css = "line line--rose"
    elif "waf-" in lowered or "retry-after" in lowered or "greylist" in lowered:
        css = "line line--amber"
    elif "http 401" in lowered or "rate_limit" in lowered:
        css = "line line--amber"
    elif "http 200" in lowered:
        css = "line line--mint"
    else:
        css = "line"
    return f'<span class="{css}">{escaped}</span>'


def render_terminal(
    *,
    title: str,
    subtitle: str,
    command: str,
    output: str,
    accent: str,
    filename: str,
) -> Path:
    lines = "\n".join(_colorize_line(line) for line in output.splitlines())
    document = f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0b1218; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --muted:#8aa1a9; --amber:#ffb86b; --rose:#ff7c91;
    --mint:#72f2c6; --blue:#7ab8ff; --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;padding:38px;background:
    radial-gradient(900px 480px at 82% -10%,rgba(255,184,107,.13),transparent 60%),
    radial-gradient(760px 420px at 2% 12%,rgba(255,124,145,.07),transparent 58%),var(--bg);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif}}
  #shot{{max-width:1180px;margin:0 auto}}
  .head{{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:18px}}
  .eyebrow{{margin:0 0 8px;color:{accent};font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase}}
  h1{{margin:0;font-size:29px;letter-spacing:-.035em}}
  .hint{{color:var(--muted);font-family:var(--mono);font-size:11px;text-align:right;line-height:1.5}}
  .term{{border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--panel);box-shadow:0 30px 80px rgba(0,0,0,.5)}}
  .bar{{display:flex;align-items:center;gap:8px;padding:12px 15px;border-bottom:1px solid var(--line);background:rgba(255,255,255,.03)}}
  .dot{{width:10px;height:10px;border-radius:50%}}
  .dot:nth-child(1){{background:#ff6b6b}} .dot:nth-child(2){{background:#ffd166}} .dot:nth-child(3){{background:#4ade80}}
  .bar em{{margin-left:8px;color:var(--muted);font-family:var(--mono);font-size:11px;font-style:normal}}
  pre{{margin:0;padding:20px 22px 24px;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.65;white-space:pre-wrap}}
  .line{{display:block;color:#c3d4d8}}
  .line--mint{{color:var(--mint)}} .line--amber{{color:var(--amber)}} .line--rose{{color:var(--rose)}}
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
      <div class="hint">Secure DocVault<br>ЛР №4 · реальний вивід</div>
    </div>
    <div class="term">
      <div class="bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><em>PowerShell · {html.escape(command)}</em></div>
      <pre><span class="prompt">PS D:\\TZIR\\secure-docvault&gt;</span> <span class="cmd">{html.escape(command)}</span>
{lines}</pre>
    </div>
    <p class="note">Дані отримані під час роботи реального Flask-сервера та middleware.</p>
  </main>
</body></html>"""
    path = TEMP_DIR / filename
    path.write_text(document, encoding="utf-8")
    return path


def run_stress_script(base_url: str) -> tuple[str, str]:
    command = (
        f'{sys.executable} scripts/stress_test_lab4.py '
        f'--base-url {base_url} --requests 10'
    )
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "stress_test_lab4.py"),
            "--base-url",
            base_url,
            "--requests",
            "10",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        cwd=str(PROJECT_ROOT),
        check=False,
    )
    output = completed.stdout or completed.stderr or "Скрипт не повернув вивід."
    return command, output


def reset_guard(app) -> None:
    app.extensions["network_guard"].reset()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT_DIR.glob("*.png"):
        old.unlink()

    test_config = type(
        "Lab4CaptureConfig",
        (Config,),
        {
            "TESTING": True,
            "SECRET_KEY": "lab4-capture-secret-key",
            "JWT_SECRET_KEY": "lab4-capture-jwt-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(DB_PATH),
            "BCRYPT_ROUNDS": 4,
            "WAF_ENABLED": True,
            "RATE_LIMIT_ENABLED": True,
            "RATE_LIMIT_LOGIN_LIMIT": 5,
            "RATE_LIMIT_LOGIN_WINDOW": 60,
            "RATE_LIMIT_API_LIMIT": 60,
            "RATE_LIMIT_API_WINDOW": 60,
            "RATE_LIMIT_WEB_LIMIT": 120,
            "RATE_LIMIT_WEB_WINDOW": 60,
            "WAF_GREYLIST_SECONDS": 120,
            "WAF_LAB_ALLOW_RESET": True,
        },
    )
    app = create_app(test_config)

    captured: list[str] = []
    handler = ListHandler(captured)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.addHandler(handler)
    werkzeug_logger.setLevel(logging.INFO)

    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    driver = None
    try:
        print("01. Стрес-тест скриптом")
        command, stress_output = run_stress_script(base_url)
        stress_page = render_terminal(
            title="Стрес-тест WAF / Rate Limiting",
            subtitle="Rate limiter / 10 login attempts",
            command=command,
            output=stress_output,
            accent="#ffb86b",
            filename="_lab4_stress.html",
        )

        print("02. Журнал сервера")
        time.sleep(0.3)
        log_output = "\n".join(captured[-40:]) or "Записів не захоплено."
        log_page = render_terminal(
            title="Журнал сервера · network_guard",
            subtitle="Server log / rate limit + WAF + greylist",
            command="tail -n 40 server.log",
            output=log_output,
            accent="#72f2c6",
            filename="_lab4_server_log.html",
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

        print("03. Термінал стрес-тесту")
        driver.get(stress_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, "#shot", "01-stress-test-429.png", pad=0)

        print("04. Термінал журналу сервера")
        driver.get(log_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, "#shot", "02-server-log-rate-limit.png", pad=0)

        print("05. Огляд /waf-lab")
        reset_guard(app)
        driver.get(base_url + "/waf-lab")
        wait_css(driver, "#btn-burst")
        time.sleep(0.4)
        shot_viewport(driver, "00-waf-lab-overview.png")

        print("06. UI: стрес-тест 401 → 429")
        reset_guard(app)
        driver.get(base_url + "/waf-lab")
        wait_css(driver, "#btn-burst")
        driver.find_element(By.ID, "btn-burst").click()
        wait_text(driver, "#burst-status", "429", timeout=20)
        time.sleep(0.4)
        shot_element(
            driver, "#rate-limit-panel", "03-rate-limit-ui.png", pad=6, scale=2
        )

        print("07. UI: Path Traversal 403")
        reset_guard(app)
        driver.get(base_url + "/waf-lab")
        driver.find_element(By.CSS_SELECTOR, '[data-attack="path"]').click()
        wait_text(driver, "#waf-result pre", "HTTP: 403")
        wait_text(driver, "#waf-result pre", "waf-1001")
        shot_element(
            driver, "#waf-attack-panel", "04-path-traversal-403.png", pad=6, scale=2
        )

        print("08. UI: Greylist після WAF")
        driver.find_element(By.ID, "btn-check-greylist").click()
        wait_text(driver, "#waf-result pre", "ip_greylisted")
        shot_element(driver, "#waf-result", "07-greylist-block.png", pad=4, scale=2)

        print("09. UI: журнал інцидентів")
        wait_text(driver, "#incident-body", "waf_block")
        shot_element(driver, "#incidents", "08-incident-log.png", pad=6, scale=2)

        print("10. UI: SQL Injection 403")
        reset_guard(app)
        driver.get(base_url + "/waf-lab")
        driver.find_element(By.CSS_SELECTOR, '[data-attack="sqli"]').click()
        wait_text(driver, "#waf-result pre", "HTTP: 403")
        wait_text(driver, "#waf-result pre", "waf-1003")
        shot_element(
            driver, "#waf-attack-panel", "05-sqli-403.png", pad=6, scale=2
        )

        print("11. UI: Command Injection 403")
        reset_guard(app)
        driver.get(base_url + "/waf-lab")
        driver.find_element(By.CSS_SELECTOR, '[data-attack="cmd"]').click()
        wait_text(driver, "#waf-result pre", "HTTP: 403")
        wait_text(driver, "#waf-result pre", "waf-2")
        shot_element(
            driver, "#waf-attack-panel", "06-command-injection-403.png", pad=6, scale=2
        )

        print("12. UI: правила та сигнатури")
        driver.get(base_url + "/waf-lab")
        wait_css(driver, "#rules")
        shot_element(driver, "#rules", "09-rate-limit-rules.png", pad=6, scale=2)
        shot_element(
            driver, "#signatures", "10-waf-signatures.png", pad=6, scale=1
        )

        print("13. Архітектурна схема")
        architecture = PROJECT_ROOT / "docs" / "network_security_architecture.html"
        driver.get(architecture.as_uri())
        time.sleep(0.4)
        shot_full(driver, "11-sentinel-architecture.png")

        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "base_url": base_url,
            "stress_output": stress_output,
            "server_log": log_output,
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
        app.logger.removeHandler(handler)
        werkzeug_logger.removeHandler(handler)
        shutil.rmtree(TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
