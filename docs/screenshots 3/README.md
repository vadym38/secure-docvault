# Скриншоти ЛР №3 — Secure DocVault

Усі файли згенеровані скриптом `scripts/capture_screenshots_lab3.py` з
реального Flask-сервера, реального `curl -I`, browser log Edge та
`driver.get_cookies()`.

| Заголовок для звіту | Файл |
|---|---|
| Оглядова сторінка клієнтського захисту | `00-client-lab-overview.png` |
| `curl -I` з усіма захисними заголовками | `01-curl-headers.png` |
| Консоль браузера: блокування inline-скрипта політикою CSP | `02-csp-console.png` |
| Статуси CSP: inline script / onerror / DOM injection — BLOCKED | `03-csp-blocked-status.png` |
| DevTools → Application → Cookies: HttpOnly, Secure, SameSite=Strict | `04-cookies-devtools.png` |
| `document.cookie` без HttpOnly-сесії | `05-document-cookie.png` |
| Санітизація XSS-пейлоада у формі вводу | `06-sanitized-xss.png` |
| Збережений очищений опис у `client_notes` | `07-sanitized-stored-note.png` |
| Матриця та фактичні захисні HTTP-заголовки | `08-headers-matrix.png` |
| CORS: дозволений Origin vs сторонній Origin | `09-cors-allowed-denied.png` |
| CORS: preflight OPTIONS | `10-cors-preflight.png` |
| CORS: whitelist `CORS_ALLOWED_ORIGINS` без `*` | `11-cors-whitelist.png` |
| Архітектурна схема ешелонованого захисту | `12-client-security-architecture.png` |

`_capture_summary.json` містить службові дані: реальний `curl`-вивід,
CSP-повідомлення browser log і атрибути cookie.
