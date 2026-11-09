"""Генерація скриншотів для звіту з ЛР №3.

Скрипт:
1. піднімає реальний Flask-сервер на тимчасовій БД;
2. виконує справжній `curl -I` і рендерить його вивід у термінальному стилі;
3. відкриває сторінки `/client-lab/*` у Edge headless;
4. збирає реальний browser log для CSP та реальні cookie через Selenium;
5. зберігає PNG у `docs/screenshots 3/`.

Запуск:
    python scripts/capture_screenshots_lab3.py
"""

from __future__ import annotations

import base64
import html
import json
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
from app.database import create_client_note, get_db


OUTPUT_DIR = PROJECT_ROOT / "docs" / "screenshots 3"
TEMP_DIR = Path(tempfile.mkdtemp(prefix="docvault-lab3-shots-"))
DB_PATH = TEMP_DIR / "lab3-demo.db"

PAYLOAD_FILENAME = "contract<img src=x onerror=alert(1)>.pdf"
PAYLOAD_DESCRIPTION = "<script>alert('XSS')</script>Опис документа зі шкідливим скриптом"
PAYLOAD_COMMENT = '"><svg onload=alert(1)>Коментар до документа'


# ---------------------------------------------------------------------------
# Допоміжні функції
# ---------------------------------------------------------------------------

def eur(value: object) -> str:
    return html.escape(str(value), quote=True)


def screenshot_clip(driver, clip: dict, path: Path, scale: int = 1) -> None:
    """Знімок довільної області документа через CDP (працює за межами viewport)."""

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


def wait_css(driver, selector: str, timeout: int = 12):
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
    )


def wait_text(driver, selector: str, text: str, timeout: int = 12) -> None:
    WebDriverWait(driver, timeout).until(
        EC.text_to_be_present_in_element((By.CSS_SELECTOR, selector), text)
    )


def seed_notes(app) -> None:
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM client_notes")
        db.commit()

        for author, filename, description in (
            ("admin", "contract-2026.pdf", "Договір оренди приміщення №14, підписаний 12.10.2026."),
            ("s.koval", "audit-report-q3.pdf", "Звіт внутрішнього аудиту за III квартал 2026 року."),
            ("o.kravets", "policy-update.docx", "Оновлена політика паролів і доступів до сховища."),
        ):
            create_client_note(author, filename, description, "—")


# ---------------------------------------------------------------------------
# curl -I
# ---------------------------------------------------------------------------

def collect_curl_headers(url: str) -> tuple[str, str]:
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        raise RuntimeError("curl не знайдено в PATH")

    command = [curl, "-sS", "-I", url]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    output = completed.stdout or completed.stderr or "curl не повернув вивід"
    return f"curl -I {url}", output


def render_curl_terminal(command: str, output: str) -> Path:
    lines: list[str] = []
    for line in output.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        if ":" in line and not line.lower().startswith("http/"):
            name, value = line.split(":", 1)
            lines.append(
                f'<span class="hdr">{eur(name)}</span>: '
                f'<span class="val">{eur(value.strip())}</span>'
            )
        elif line.lower().startswith("http/"):
            lines.append(f'<span class="status">{eur(line)}</span>')
        else:
            lines.append(eur(line))

    document = f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>curl -I · Secure DocVault</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0b1218; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --muted:#8aa1a9; --mint:#72f2c6; --blue:#7ab8ff;
    --rose:#ff7c91; --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;padding:40px;background:
    radial-gradient(900px 480px at 80% -10%,rgba(122,184,255,.12),transparent 60%),
    radial-gradient(760px 420px at 2% 12%,rgba(114,242,198,.07),transparent 58%),var(--bg);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif}}
  #shot{{max-width:1180px;margin:0 auto}}
  .head{{max-width:1180px;margin:0 auto 20px;display:flex;align-items:flex-end;justify-content:space-between;gap:20px}}
  .eyebrow{{margin:0 0 8px;color:var(--mint);font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase}}
  h1{{margin:0;font-size:30px;letter-spacing:-.035em}}
  .hint{{color:var(--muted);font-family:var(--mono);font-size:11px;text-align:right;line-height:1.5}}
  .term{{max-width:1180px;margin:0 auto;border:1px solid var(--line);border-radius:16px;overflow:hidden;background:var(--panel);box-shadow:0 30px 80px rgba(0,0,0,.5)}}
  .bar{{display:flex;align-items:center;gap:8px;padding:12px 15px;border-bottom:1px solid var(--line);background:rgba(255,255,255,.03)}}
  .dot{{width:10px;height:10px;border-radius:50%}}
  .dot:nth-child(1){{background:#ff6b6b}} .dot:nth-child(2){{background:#ffd166}} .dot:nth-child(3){{background:#4ade80}}
  .bar em{{margin-left:8px;color:var(--muted);font-family:var(--mono);font-size:11px;font-style:normal}}
  pre{{margin:0;padding:22px 24px 26px;overflow:auto;font-family:var(--mono);font-size:13px;line-height:1.75;white-space:pre-wrap}}
  .prompt{{color:var(--mint)}} .cmd{{color:#e9f3f3}}
  .status{{color:var(--mint);font-weight:700}} .hdr{{color:var(--blue)}} .val{{color:#c3d4d8}}
  .note{{max-width:1180px;margin:16px auto 0;color:var(--muted);font-family:var(--mono);font-size:11px;text-align:center}}
</style></head>
<body>
  <main id="shot">
  <div class="head">
    <div>
      <p class="eyebrow">Response headers / server hardening</p>
      <h1>curl -I · Secure DocVault</h1>
    </div>
    <div class="hint">HEAD /client-lab<br>реальний вивід curl.exe</div>
  </div>
  <div class="term">
    <div class="bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><em>PowerShell · {eur(command)}</em></div>
    <pre><span class="prompt">PS D:\\TZIR\\secure-docvault&gt;</span> <span class="cmd">{eur(command)}</span>
{chr(10).join(lines)}</pre>
  </div>
  <p class="note">Усі заголовки додані middleware `app/security.py` до кожної відповіді.</p>
  </main>
</body></html>"""
    path = TEMP_DIR / "_lab3_curl.html"
    path.write_text(document, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# DevTools Application → Cookies
# ---------------------------------------------------------------------------

def render_devtools_cookies(cookies: list[dict], origin: str) -> Path:
    rows = []
    for cookie in cookies:
        expiry = cookie.get("expiry")
        expires = (
            datetime.fromtimestamp(expiry, tz=timezone.utc).strftime("%d.%m.%Y, %H:%M:%S")
            if expiry
            else "Session"
        )
        size = len(cookie.get("name", "")) + len(cookie.get("value", ""))
        same_site = cookie.get("sameSite") or "—"
        rows.append(
            "<tr>"
            f'<td class="name">{eur(cookie.get("name", ""))}</td>'
            f'<td class="value">{eur(cookie.get("value", "")[:72])}{"…" if len(cookie.get("value", "")) > 72 else ""}</td>'
            f'<td>{eur(cookie.get("domain", ""))}</td>'
            f'<td>{eur(cookie.get("path", "/"))}</td>'
            f'<td>{eur(expires)}</td>'
            f'<td>{size}</td>'
            f'<td class="yes">{eur("✓" if cookie.get("httpOnly") else "—")}</td>'
            f'<td class="yes">{eur("✓" if cookie.get("secure") else "—")}</td>'
            f'<td class="same">{eur(same_site)}</td>'
            "</tr>"
        )

    document = f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>DevTools · Application · Cookies</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0c141b; --panel2:#101b24; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --muted:#8aa1a9; --mint:#72f2c6; --blue:#7ab8ff;
    --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif}}
  .devtools{{max-width:1380px;margin:0 auto;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--panel);box-shadow:0 30px 90px rgba(0,0,0,.55)}}
  .tabs{{display:flex;align-items:center;gap:18px;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--panel2);color:var(--muted);font-size:12px}}
  .tabs .brand{{display:flex;gap:7px;align-items:center;margin-right:8px}}
  .logo{{width:13px;height:13px;border-radius:3px;background:linear-gradient(135deg,var(--mint),var(--blue))}}
  .tabs span{{padding:4px 2px;cursor:default}}
  .tabs .active{{color:var(--text);border-bottom:2px solid var(--mint)}}
  .crumbs{{display:flex;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid var(--line);color:var(--muted);font-family:var(--mono);font-size:11px}}
  .crumbs b{{color:var(--text);font-weight:600}}
  .layout{{display:grid;grid-template-columns:270px minmax(0,1fr);min-height:560px}}
  .side{{border-right:1px solid var(--line);padding:12px 10px;background:rgba(255,255,255,.015)}}
  .side h3{{margin:6px 10px 8px;color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase}}
  .side ul{{margin:0;padding:0;list-style:none}}
  .side li{{padding:7px 10px;border-radius:7px;color:#c3d4d8;font-size:12px}}
  .side li.sub{{padding-left:26px;color:var(--muted);font-family:var(--mono);font-size:11px}}
  .side li.on{{background:rgba(114,242,198,.11);color:var(--mint)}}
  .main{{padding:18px 20px}}
  .main h2{{margin:0 0 4px;font-size:16px}}
  .domain{{margin:0 0 14px;color:var(--muted);font-family:var(--mono);font-size:11px}}
  .toolbar{{display:flex;gap:10px;align-items:center;margin-bottom:12px}}
  .filter{{flex:1;padding:8px 11px;border:1px solid var(--line);border-radius:7px;color:var(--muted);font-family:var(--mono);font-size:11px;background:rgba(4,8,11,.5)}}
  .badge{{padding:5px 9px;border:1px solid rgba(114,242,198,.32);border-radius:999px;color:var(--mint);font-family:var(--mono);font-size:10px;white-space:nowrap}}
  table{{width:100%;border-collapse:collapse;font-size:11px}}
  th,td{{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}
  th{{color:var(--muted);font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;background:rgba(255,255,255,.025)}}
  td{{color:#c3d4d8}}
  td.name{{color:var(--mint);font-family:var(--mono)}}
  td.value{{color:var(--muted);font-family:var(--mono);max-width:260px;overflow:hidden;text-overflow:ellipsis}}
  td.yes{{color:var(--mint);font-weight:700;text-align:center}}
  td.same{{color:var(--blue);font-family:var(--mono)}}
  .legend{{display:flex;gap:14px;margin-top:14px;color:var(--muted);font-family:var(--mono);font-size:10px}}
  .legend b{{color:var(--mint)}}
  .foot{{padding:12px 20px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
</style></head>
<body>
  <div class="devtools">
    <div class="tabs">
      <span class="brand"><span class="logo"></span>DevTools</span>
      <span>Elements</span><span>Console</span><span>Sources</span><span>Network</span>
      <span class="active">Application</span><span>Security</span><span>Lighthouse</span>
    </div>
    <div class="crumbs">Application <span>›</span> Storage <span>›</span> <b>Cookies</b> <span>›</span> {eur(origin)}</div>
    <div class="layout">
      <aside class="side">
        <h3>Application</h3>
        <ul>
          <li>Manifest</li>
          <li>Service Workers</li>
          <li>Storage</li>
          <li class="sub">Local Storage</li>
          <li class="sub">Session Storage</li>
          <li class="sub on">Cookies</li>
          <li class="sub">IndexedDB</li>
          <li class="sub">Cache Storage</li>
          <li>Background Services</li>
          <li>Frames</li>
        </ul>
      </aside>
      <section class="main">
        <h2>Cookies</h2>
        <p class="domain">http://127.0.0.1 · {eur(origin)}</p>
        <div class="toolbar">
          <div class="filter">Filter cookies…</div>
          <span class="badge">HttpOnly &amp; Secure &amp; SameSite=Strict</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Value</th><th>Domain</th><th>Path</th>
              <th>Expires</th><th>Size</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows) or '<tr><td colspan="9">No cookies</td></tr>'}
          </tbody>
        </table>
        <div class="legend">
          <span><b>✓</b> HttpOnly — недоступно з JavaScript</span>
          <span><b>✓</b> Secure — лише HTTPS / trustworthy localhost</span>
          <span><b>Strict</b> — без cross-site відправки</span>
        </div>
      </section>
    </div>
    <div class="foot">Дані отримано через Selenium `driver.get_cookies()` після відкриття /client-lab/cookies.</div>
  </div>
</body></html>"""
    path = TEMP_DIR / "_lab3_devtools_cookies.html"
    path.write_text(document, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Основний сценарій
# ---------------------------------------------------------------------------

def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT_DIR.glob("*.png"):
        old.unlink()

    test_config = type(
        "Lab3CaptureConfig",
        (Config,),
        {
            "TESTING": True,
            "SECRET_KEY": "lab3-capture-secret-key",
            "JWT_SECRET_KEY": "lab3-capture-jwt-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(DB_PATH),
            "BCRYPT_ROUNDS": 4,
            # Для скриншота Secure-cookie браузер вважає 127.0.0.1 trustworthy.
            "SESSION_COOKIE_SECURE": True,
            "SESSION_COOKIE_SAMESITE": "Strict",
        },
    )
    app = create_app(test_config)

    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"
    app.config["CORS_ALLOWED_ORIGINS"] = [
        base_url,
        "http://localhost:5000",
        "https://app.example",
    ]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    seed_notes(app)

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1440,1200")
    options.add_argument("--force-device-scale-factor=1")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    driver = webdriver.Edge(options=options)
    driver.set_page_load_timeout(20)
    driver.execute_cdp_cmd(
        "Emulation.setEmulatedMedia",
        {"features": [{"name": "prefers-reduced-motion", "value": "reduce"}]},
    )

    try:
        print("01. Огляд /client-lab")
        driver.get(base_url + "/client-lab")
        wait_css(driver, ".note-card")
        shot_viewport(driver, "00-client-lab-overview.png")

        print("02. curl -I")
        command, output = collect_curl_headers(base_url + "/client-lab")
        curl_page = render_curl_terminal(command, output)
        driver.get(curl_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, "#shot", "01-curl-headers.png", pad=0)

        print("03. CSP: console log")
        driver.get(base_url + "/client-lab/csp")
        time.sleep(1.0)
        logs = driver.get_log("browser")
        csp_messages: list[str] = []
        for entry in logs:
            message = entry.get("message", "")
            if "Content Security Policy" in message or "Refused to" in message:
                cleaned = message.strip()
                if cleaned not in csp_messages:
                    csp_messages.append(cleaned)
        if csp_messages:
            driver.execute_script(
                "window.__lab3.renderBrowserLogs(arguments[0]);",
                csp_messages,
            )
        wait_css(driver, ".console-panel")
        shot_element(driver, ".console-panel", "02-csp-console.png", pad=4, scale=2)

        print("04. CSP: статуси BLOCKED")
        driver.find_element(By.ID, "btn-dom-xss").click()
        try:
            wait_text(driver, "#dom-status", "BLOCKED", timeout=6)
        except Exception:
            time.sleep(0.5)
        shot_element(driver, ".attack-panel", "03-csp-blocked-status.png", pad=4, scale=2)

        print("05. DevTools: cookies")
        driver.get(base_url + "/client-lab/cookies")
        wait_text(driver, "#cookie-visible", "docvault_demo_csrf", timeout=8)
        cookies = driver.get_cookies()
        devtools_page = render_devtools_cookies(cookies, base_url)
        driver.get(devtools_page.as_uri())
        time.sleep(0.4)
        shot_element(driver, ".devtools", "04-cookies-devtools.png", pad=0)

        print("06. document.cookie")
        driver.get(base_url + "/client-lab/cookies")
        wait_text(driver, "#cookie-visible", "docvault_demo_csrf", timeout=8)
        shot_element(driver, "#cookie-js-panel", "05-document-cookie.png", pad=4, scale=2)

        print("07. Санітизація XSS-пейлоада")
        driver.get(base_url + "/client-lab")
        wait_css(driver, ".sanitizer-form")
        driver.execute_script(
            """
            document.querySelector('input[name="filename"]').value = arguments[0];
            document.querySelector('textarea[name="description"]').value = arguments[1];
            document.querySelector('textarea[name="comment"]').value = arguments[2];
            document.querySelector('.sanitizer-form button[type="submit"]').click();
            """,
            PAYLOAD_FILENAME,
            PAYLOAD_DESCRIPTION,
            PAYLOAD_COMMENT,
        )
        wait_css(driver, ".result-value", timeout=12)
        driver.execute_script(
            """
            document.querySelector('input[name="filename"]').value = arguments[0];
            document.querySelector('textarea[name="description"]').value = arguments[1];
            document.querySelector('textarea[name="comment"]').value = arguments[2];
            window.scrollTo(0, 0);
            """,
            PAYLOAD_FILENAME,
            PAYLOAD_DESCRIPTION,
            PAYLOAD_COMMENT,
        )
        time.sleep(0.3)
        shot_element(driver, ".client-grid", "06-sanitized-xss.png", pad=10)

        print("08. Збережений очищений опис")
        shot_element(driver, ".notes-panel", "07-sanitized-stored-note.png", pad=6, scale=2)

        print("09. Матриця заголовків")
        driver.get(base_url + "/client-lab/headers")
        wait_css(driver, ".code-block--headers")
        shot_full(driver, "08-headers-matrix.png")

        print("10. CORS: allowed / denied")
        driver.get(base_url + "/client-lab/cors")
        wait_css(driver, "#cors-compare")
        shot_element(driver, "#cors-compare", "09-cors-allowed-denied.png", pad=6, scale=2)

        print("11. CORS: preflight")
        shot_element(driver, "#cors-preflight", "10-cors-preflight.png", pad=6, scale=2)

        print("12. CORS: whitelist")
        shot_element(driver, "#cors-config", "11-cors-whitelist.png", pad=6, scale=2)

        print("13. Архітектурна схема")
        architecture = PROJECT_ROOT / "docs" / "client_security_architecture.html"
        driver.get(architecture.as_uri())
        time.sleep(0.4)
        shot_full(driver, "12-client-security-architecture.png")

        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "base_url": base_url,
            "curl_command": command,
            "csp_messages": csp_messages,
            "cookies": [
                {
                    "name": c["name"],
                    "httpOnly": c["httpOnly"],
                    "secure": c["secure"],
                    "sameSite": c.get("sameSite"),
                }
                for c in cookies
            ],
            "files": sorted(path.name for path in OUTPUT_DIR.glob("*.png")),
        }
        (OUTPUT_DIR / "_capture_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\nГотово: {OUTPUT_DIR}")
        print(f"Файлів: {len(summary['files'])}")
    finally:
        driver.quit()
        server.shutdown()
        thread.join(timeout=5)
        shutil.rmtree(TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
