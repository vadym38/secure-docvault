# Скриншоти ЛР №4 — Secure DocVault

Усі файли згенеровані скриптом `scripts/capture_screenshots_lab4.py` з
реального Flask-сервера з увімкненими WAF/Rate Limiting, реального
стрес-скрипта та browser UI у Edge headless.

| Заголовок для звіту | Файл |
|---|---|
| Оглядова сторінка Sentinel Gate `/waf-lab` | `00-waf-lab-overview.png` |
| Стрес-тест: 5×401 → 5×429 та `Retry-After` | `01-stress-test-429.png` |
| Журнал сервера: IP, `[RATE_LIMIT]`, `[WAF_BLOCK]`, `[GREYLIST]` | `02-server-log-rate-limit.png` |
| UI-таблиця 10 запитів: статуси та `Retry-After` | `03-rate-limit-ui.png` |
| Path Traversal → `403`, `waf-1001`, Greylist | `04-path-traversal-403.png` |
| SQL Injection → `403`, `waf-1003` | `05-sqli-403.png` |
| Command Injection → `403`, `waf-2001` | `06-command-injection-403.png` |
| Повторний запит → `403 ip_greylisted` | `07-greylist-block.png` |
| Журнал інцидентів + активний Greylist | `08-incident-log.png` |
| Правила Rate Limiting | `09-rate-limit-rules.png` |
| 13 сигнатур WAF | `10-waf-signatures.png` |
| Архітектурна схема WAF / Rate Limiter | `11-sentinel-architecture.png` |

`_capture_summary.json` містить реальний вивід стрес-скрипта та
захоплений журнал сервера.
