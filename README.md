# Secure DocVault — етап 5: AES-256-GCM шифрування файлів

Навчальний проєкт до лабораторних робіт №1–5 з дисципліни
**«Технології захисту інформаційних ресурсів»**.

Реалізовано п'ять шарів захисту корпоративного порталу **Secure DocVault**:

1. **ЛР №1 — автентифікація та захист БД:** реєстрація, вхід, безпечне
   зберігання паролів у SQLite, захист від SQL-ін'єкцій, CSRF і session
   fixation.
2. **ЛР №2 — безсесійний REST API на JWT:** випуск пари Access/Refresh
   токенів із підписом HS256, криптографічна валідація кожного запиту,
   Refresh Token Rotation, виявлення повторного використання (reuse) та
   захищений маршрут `/api/v1/user/profile`.
3. **ЛР №3 — клієнтський захист:** санітизація вводу через Bleach,
   контекстне екранування виводу, CSP без `unsafe-inline`, безпечні
   cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), HSTS, `nosniff`,
   `X-Frame-Options: DENY` та CORS із явним whitelist Origin.
4. **ЛР №4 — мережевий захист рівня застосунку:** сигнатурний WAF,
   Greylist для IP, Sliding Window Rate Limiting із диференційованими
   лімітами для login/API/HTML, коректні `403`/`429` та журнал інцидентів.
5. **ЛР №5 — шифрування даних у стані спокою:** AES-256-GCM,
   унікальний 96-бітний IV, контейнер `[12 B IV][16 B Tag][Ciphertext]`,
   завантаження/скачування з перевіркою прав, `InvalidTag` при зміні
   одного байта.

Замість десктопного PyQt-інтерфейсу з прикладу зроблено **веб-інтерфейс
на Flask + Jinja2** з авторським темним дизайном «Obsidian Vault»,
інтерактивними стендами `/api-lab`, `/client-lab`, `/waf-lab` і
Cipher Vault `/vault`.

> **Статус:** виконано ЛР №1 (тег `v0.1-auth-db`), ЛР №2
> (тег `v0.2-jwt-api`), ЛР №3 (тег `v0.3-client-security`), ЛР №4
> (тег `v0.4-waf-ratelimit`) і ЛР №5 (тег `v0.5-file-encryption`).
> Цифрові підписи з наступного етапу навмисно не додані.

---

## 1. Що демонструє проєкт

### ЛР №5 — AES-256-GCM шифрування файлів

| Вимога ЛР | Реалізація |
|---|---|
| AES-256-GCM | `app/file_crypto.py`: `FileCipher`, `cryptography` 50.0.2 |
| Унікальний IV 96 біт | `os.urandom(12)` для кожної операції |
| Формат контейнера | `[12 B IV][16 B Auth Tag][Ciphertext]` |
| UUID замість прямих ID | `uuid.uuid4()` для `id` і `<uuid>.enc` |
| Upload endpoint | `POST /api/v1/documents/upload` + `Authorization: Bearer` |
| Download endpoint | `GET /api/v1/documents/<id>/download` |
| Перевірка прав / IDOR | owner або admin; `AAD = docvault\|file\|v1\|id\|owner` |
| Цілісність | `InvalidTag` → `409 integrity_error`; додатково SHA-256 plaintext |
| Веб-інтерфейс | `/vault`, `/vault/<id>`, hexdump контейнера |
| Тести | 41 новий: 20 unit crypto, 17 інтеграційних, 4 Selenium E2E |
| Звіт | `docs/screenshots 5/`, `docs/file_encryption_architecture.html` |

### ЛР №4 — WAF і Rate Limiting

| Вимога ЛР | Реалізація |
|---|---|
| Sliding Window Rate Limiter | `app/rate_limiter.py`: `deque` міток часу, потокобезпечний `check()` |
| Ліміт login 5/хв | `POST /api/v1/auth/login`, `POST /login` → `auth_login` |
| Загальний API 60/хв | `/api/v1/*` → `api_general` |
| HTML-сторінки | 120/хв → `web_general` |
| `429 Too Many Requests` | JSON/HTML + `Retry-After`, `X-RateLimit-*` |
| Журнал інцидентів | `app/security_events.py` + `app.logger.warning` + `/waf-lab` |
| Path Traversal | сигнатура `waf-1001` + `403` + Greylist |
| SQL-ін'єкції | `waf-1002`/`1003`/`1004`/`1005` (`UNION SELECT`, tautology, DROP, `xp_cmdshell`) |
| Командні ін'єкції | `waf-2001`…`2004` (`; /bin/sh`, `cmd.exe`, `system(`, `cmd=`) |
| XSS-сигнатури | `waf-3001`…`3004` |
| Блокування IP (Greylist) | `app/waf_filter.py`: `Greylist`, `WAF_GREYLIST_SECONDS` |
| Стрес-тест | `scripts/stress_test_lab4.py` (10 запитів, stdlib `urllib`) |
| Тести | 66 нових: 9 unit Rate Limiter, 33 unit WAF, 18 інтеграційних, 6 Selenium E2E |
| Звіт | `docs/screenshots 4/`, `docs/network_security_architecture.html` |

### ЛР №3 — клієнтський захист і безпечний вебсервер

| Вимога ЛР | Реалізація |
|---|---|
| Санітизація вводу (Stored/Reflected XSS) | `app/sanitizer.py`: Bleach 6.4, політика без HTML-тегів, окремі правила для тексту й імені файлу |
| Контекстне екранування виводу | Jinja2 autoescape + `escape_text()`; санітизований текст зберігається в `client_notes` |
| `HttpOnly` | `SESSION_COOKIE_HTTPONLY = True`, демонстраційні cookie через `set_cookie(httponly=True)` |
| `Secure` | `SESSION_COOKIE_SECURE` (env), demo-cookie завжди `Secure`; перевірено в Edge на `127.0.0.1` |
| `SameSite=Strict` | `SESSION_COOKIE_SAMESITE = "Strict"` для сесії та demo-cookie |
| CSP без `unsafe-inline`, `script-src 'self'` | `app/security.py`: `CSP_POLICY`, `report-uri /client-lab/csp-report` |
| HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| `nosniff` | `X-Content-Type-Options: nosniff` |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| CORS без `*` | `CORS_ALLOWED_ORIGINS` — явний whitelist Origin, `Vary: Origin` |
| Тестування | 44 нові тести: 22 unit (санітизатор), 16 інтеграційних, 6 Selenium E2E |
| Звіт | `docs/screenshots 3/`, `docs/client_security_architecture.html` |

### ЛР №2 — JWT та Stateless API

| Вимога ЛР | Реалізація |
|---|---|
| Підпис HS256, ключ ≥ 256 біт | `app/jwt_service.py`, `JWT_SECRET_KEY` ≥ 32 байти, fail-closed перевірка на старті |
| Access Token TTL 15 хв | `JWT_ACCESS_TTL_SECONDS=900` |
| Refresh Token TTL 7 діб | `JWT_REFRESH_TTL_SECONDS=604800` |
| `Authorization: Bearer` | декоратор `require_access_token` у `app/api.py` |
| Валідація підпису, `exp`, `alg:none` | `decode_token()`: явна перевірка header + PyJWT `algorithms=["HS256"]` |
| Refresh Token Rotation | таблиця `refresh_tokens`, атомарний `rotate_refresh_token()` |
| Blacklist / revoke-список | `revoked_at`, `revoked_reason`, `access_token_revocations` |
| Reuse detection | повторний `jti` → `401` + відкликання всієї `family_id` |
| Захищений `/api/v1/user/profile` | доступний лише з валідним Access Token |
| Тести | 62 тести (`unittest` + Selenium), з них 28 нових для JWT/API |
| Звіт | `docs/screenshots 2/`, `docs/jwt_architecture.html`, `docs/jwt_db_snapshot.html` |

### ЛР №1 — автентифікація та захист БД

| Вимога ЛР | Реалізація |
|---|---|
| Структура проєкту, venv, Git | `app/`, `tests/`, `scripts/`, `venv/`, тег `v0.1-auth-db` |
| Схема `users` | `id`, `username`, `email`, `password_hash`, `salt`, `role`, `created_at`, `is_active` |
| Повільне хешування + сіль | `bcrypt` із `rounds=12`, окрема сіль для кожного запису |
| Prepared Statements | Усі запити в `app/database.py` — тільки `?` + кортеж параметрів |
| Реєстрація та вхід | Веб-форми `/register`, `/login` із серверною валідацією |
| Валідація пароля | ≥ 8 символів, великі/малі літери, цифра, спецсимвол, ≤ 72 байти |
| SQLi-тест | Стенд `/security-lab` + E2E-тест із payload `' OR '1'='1` |
| Звіт | `docs/REPORT.md`, `docs/screenshots/` |

---

## 2. Технології

- **Python 3.10+** (перевірено на Python 3.14.7)
- **Flask 3.1** + Jinja2 — серверний рендеринг і REST API
- **PyJWT 2.15** — підпис та валідація JWT (HS256)
- **Bleach 6.4** — санітизація HTML/JS-векторів у користувацькому вводі
- **cryptography 50.0.2** — AES-256-GCM (AEAD) для файлів у стані спокою
- **SQLite** — локальна реляційна БД, режим WAL
- **bcrypt 5.0** — хешування паролів, work factor 12
- **HTML/CSS/vanilla JS** — адаптивний інтерфейс без зовнішніх CDN
- **unittest + Selenium WebDriver** — тестування (Edge headless)
- **stdlib `urllib`** — окремий стрес-скрипт ЛР №4 без зовнішніх залежностей

> У тестах **не використовуються** `pytest`, `fastapi.testclient.TestClient`,
> `httpx` або `requests`. Тестовий стек побудований на `unittest` і
> `selenium`, який працює з реальним браузером. Стрес-скрипт ЛР №4
> навмисно використовує лише стандартну бібліотеку `urllib`.

---

## 3. Структура

```text
secure-docvault/
├── app/
│   ├── __init__.py              # application factory, JWT fail-closed, error handlers
│   ├── auth.py                  # веб-маршрути, CSRF, сесії, SQLi-стенд, /api-lab
│   ├── auth_security.py         # bcrypt, валідація пароля/username/email
│   ├── api.py                   # REST API v1: login, refresh, logout, profile
│   ├── client_security.py       # ЛР №3: стенд /client-lab (XSS, CSP, cookies, CORS)
│   ├── sanitizer.py             # ЛР №3: Bleach-санітизація та звіт про вектори
│   ├── security.py              # ЛР №3: CSP, HSTS, nosniff, XFO, CORS-middleware
│   ├── network_guard.py         # ЛР №4: before_request WAF + Rate Limiter + Greylist
│   ├── network_lab.py           # ЛР №4: стенд /waf-lab, /events, /reset
│   ├── rate_limiter.py          # ЛР №4: Sliding Window Log
│   ├── security_events.py       # ЛР №4: кільцевий журнал інцидентів
│   ├── waf_filter.py            # ЛР №4: сигнатури атак і Greylist
│   ├── file_crypto.py           # ЛР №5: AES-256-GCM, IV+Tag+Ciphertext
│   ├── documents.py             # ЛР №5: сервіс сховища, IDOR, integrity
│   ├── documents_api.py         # ЛР №5: /api/v1/documents/*
│   ├── vault.py                 # ЛР №5: веб-інтерфейс /vault
│   ├── jwt_service.py           # випуск/декодування JWT, заборона alg:none
│   ├── config.py                # конфігурація з .env (сесії, JWT, CORS, WAF, AES)
│   ├── database.py              # users, refresh_tokens, client_notes, documents
│   ├── static/
│   │   ├── css/app.css          # тема «Obsidian Vault»
│   │   ├── js/app.js            # strength meter, показ пароля, flash
│   │   ├── js/api_lab.js        # fetch-протокол JWT, декодер, tamper, rotation
│   │   ├── js/client_lab.js     # швидкі XSS-payload у формі санітизатора
│   │   ├── js/client_lab_csp.js # securitypolicyviolation → консоль/таблиця
│   │   ├── js/client_lab_cookies.js # демонстрація document.cookie
│   │   ├── js/waf_lab.js        # стрес-тест, WAF-атаки, журнал, Reset
│   │   └── js/vault.js          # ім'я файлу, confirm видалення
│   └── templates/
│       ├── _brand.html
│       ├── _client_nav.html
│       ├── _icons.html
│       ├── api_lab.html         # інтерактивний JWT-стенд
│       ├── client_lab.html      # санітизатор і збережені описи
│       ├── client_lab_csp.html  # навмисні inline-вектори для CSP
│       ├── client_lab_cookies.html
│       ├── client_lab_headers.html
│       ├── client_lab_cors.html
│       ├── network_block.html   # стилізовані 403/429
│       ├── waf_lab.html         # панель WAF / Rate Limiting
│       ├── vault.html           # Cipher Vault: список і завантаження
│       ├── vault_document.html  # detail + hexdump контейнера
│       ├── auth_base.html
│       ├── base.html
│       ├── dashboard.html
│       ├── error.html
│       ├── login.html
│       ├── register.html
│       └── security_lab.html
├── docs/
│   ├── screenshots/             # 9 скриншотів ЛР №1
│   ├── screenshots 2/           # 10 скриншотів ЛР №2
│   ├── screenshots 3/           # скриншоти ЛР №3
│   ├── screenshots 4/           # скриншоти ЛР №4
│   ├── screenshots 5/           # скриншоти ЛР №5
│   ├── file_encryption_architecture.html # схема AES-GCM
│   ├── network_security_architecture.html # схема WAF / Rate Limiter
│   ├── client_security_architecture.html # схема ешелонованого захисту
│   ├── jwt_architecture.html    # схема обміну токенами
│   ├── jwt_db_snapshot.html     # HTML-знімок refresh_tokens
│   ├── architecture.html        # схема входу ЛР №1
│   └── REPORT.md                # звіт ЛР №1
├── scripts/
│   ├── capture_screenshots.py   # скриншоти ЛР №1
│   ├── capture_screenshots_lab2.py  # скриншоти ЛР №2
│   ├── capture_screenshots_lab3.py  # скриншоти ЛР №3
│   ├── capture_screenshots_lab4.py  # скриншоти ЛР №4
│   ├── capture_screenshots_lab5.py  # скриншоти ЛР №5
│   ├── stress_test_lab4.py      # стрес-тест 10 запитів + WAF
│   ├── demo_lab5_api.py         # login → upload → download
│   ├── integrity_test_lab5.py   # hexdump + InvalidTag
│   ├── jwt_db_snapshot.py       # HTML-знімок refresh_tokens
│   ├── db_snapshot.py           # HTML-знімок users
│   └── seed_demo.py             # створення демо-користувача
├── tests/
│   ├── test_security.py         # 17 юніт-тестів ЛР №1
│   ├── test_database.py         # 8 тестів схеми та SQLi
│   ├── test_web_e2e.py          # 9 E2E-тестів ЛР №1
│   ├── test_jwt_service.py      # 8 юніт-тестів JWT
│   ├── test_api.py              # 19 інтеграційних тестів API
│   ├── test_api_web_e2e.py      # 1 E2E-тест JWT-стенда
│   ├── test_sanitizer.py        # 22 юніт-тести ЛР №3
│   ├── test_client_security.py  # 16 інтеграційних тестів ЛР №3
│   ├── test_client_security_e2e.py # 6 Selenium E2E-тестів ЛР №3
│   ├── test_rate_limiter.py     # 9 юніт-тестів Rate Limiter
│   ├── test_waf_filter.py       # 33 юніт-тести WAF / Greylist
│   ├── test_network_security.py # 18 інтеграційних тестів ЛР №4
│   ├── test_network_security_e2e.py # 6 Selenium E2E-тестів ЛР №4
│   ├── test_file_crypto.py      # 20 юніт-тестів AES-GCM
│   ├── test_documents.py        # 17 інтеграційних тестів сховища
│   └── test_documents_e2e.py    # 4 Selenium E2E-тести Cipher Vault
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── requirements-dev.txt
└── run.py
```

---

## 4. Швидкий старт

### Windows (PowerShell)

```powershell
cd D:\TZIR\secure-docvault
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# відредагуйте .env: SECRET_KEY, JWT_SECRET_KEY, FILE_ENCRYPTION_KEY
python run.py
```

### Linux / macOS

```bash
cd secure-docvault
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# відредагуйте .env: SECRET_KEY, JWT_SECRET_KEY, FILE_ENCRYPTION_KEY
python run.py
```

Після запуску відкрийте <http://127.0.0.1:5000>.
Інтерактивний JWT-стенд: <http://127.0.0.1:5000/api-lab>.

Згенерувати безпечні ключі (кожен окремо):

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Приклад `.env`:

```dotenv
SECRET_KEY=<64 hex-символи>
JWT_SECRET_KEY=<інші 64 hex-символи>
JWT_ACCESS_TTL_SECONDS=900
JWT_REFRESH_TTL_SECONDS=604800
JWT_LEEWAY_SECONDS=5
DOCVAULT_DB=instance/docvault.db
BCRYPT_ROUNDS=12
SESSION_COOKIE_SECURE=0
FLASK_DEBUG=0
HOST=127.0.0.1
PORT=5000
```

> **Fail-closed:** якщо `JWT_SECRET_KEY` відсутній або коротший за
> 32 байти, застосунок не запускається. Це навмисно: жодного
> «секрету за замовчуванням» у коді немає.

База даних створюється автоматично у `instance/docvault.db`.
Каталог `instance/` та файли `*.db` додані до `.gitignore`.

---

## 5. Маршрути

### Веб-інтерфейс (ЛР №1)

| Метод | Маршрут | Призначення |
|---|---|---|
| GET | `/` | редірект на `/dashboard` або `/login` |
| GET/POST | `/register` | реєстрація з серверною валідацією |
| GET/POST | `/login` | перевірка автентичності |
| POST | `/logout` | завершення сесії (тільки POST + CSRF) |
| GET | `/dashboard` | закритий кабінет користувача |
| GET/POST | `/security-lab` | навчальний read-only SQLi-стенд |
| GET | `/api-lab` | інтерактивний стенд JWT (ЛР №2) |
| GET | `/healthz` | службовий JSON health-check |

### Клієнтський захист (ЛР №3)

| Метод | Маршрут | Призначення |
|---|---|---|
| GET | `/client-lab` | огляд, форма санітизатора, збережені описи |
| POST | `/client-lab/sanitize` | санітизація XSS-payload + запис у `client_notes` |
| GET | `/client-lab/csp` | навмисні inline-вектори та журнал порушень CSP |
| POST | `/client-lab/csp-report` | приймальник `report-uri` (204 No Content) |
| GET | `/client-lab/cookies` | інспектор `HttpOnly` / `Secure` / `SameSite` |
| GET | `/client-lab/headers` | матриця та фактичні заголовки відповіді |
| GET | `/client-lab/cors` | дозволений, сторонній Origin і preflight |

### Мережевий захист (ЛР №4)

| Метод | Маршрут | Призначення |
|---|---|---|
| GET | `/waf-lab` | панель WAF, Rate Limiter, Greylist і журналу |
| GET | `/waf-lab/events` | JSON для живого оновлення журналу |
| POST | `/waf-lab/reset` | лабораторний скид стану (CSRF + config-прапорець) |

### Зашифроване сховище (ЛР №5)

| Метод | Маршрут | Доступ | Призначення |
|---|---|---|---|
| GET | `/vault` | сесія | список документів і форма завантаження |
| POST | `/vault/upload` | сесія + CSRF | шифрування та збереження файлу |
| GET | `/vault/<id>` | власник/admin | метадані, IV/Tag/Ciphertext, hexdump |
| GET | `/vault/<id>/download` | власник/admin | дешифрування та видача файлу |
| POST | `/vault/<id>/delete` | власник/admin | видалення метаданих і `.enc` |
| POST | `/api/v1/documents/upload` | Bearer | upload + AES-256-GCM |
| GET | `/api/v1/documents` | Bearer | список своїх документів |
| GET | `/api/v1/documents/<id>` | Bearer | метадані + hex-прев'ю |
| GET | `/api/v1/documents/<id>/download` | Bearer | decrypt + `InvalidTag` → 409 |
| DELETE | `/api/v1/documents/<id>` | Bearer | видалення документа |

### REST API v1 (ЛР №2)

| Метод | Маршрут | Доступ | Призначення |
|---|---|---|---|
| POST | `/api/v1/auth/login` | публічний | перевірка пароля, видача пари токенів |
| POST | `/api/v1/auth/refresh` | refresh token | ротація пари, reuse detection |
| POST | `/api/v1/auth/logout` | access token | blacklist access + revoke refresh family |
| GET | `/api/v1/user/profile` | access token | захищений профіль користувача |
| GET | `/api/v1/health` | публічний | статус API, алгоритм підпису |

Усі помилки API мають єдиний формат:

```json
{
  "error": {
    "code": "invalid_signature",
    "message": "Підпис JWT недійсний. Токен змінено або підписано іншим ключем."
  }
}
```

Відповіді API містять `Cache-Control: no-store` та `Pragma: no-cache`;
на `401` додається `WWW-Authenticate: Bearer realm="secure-docvault"`.

---

## 6. Схема БД

### `users` (ЛР №1)

```sql
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    email         TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
                          CHECK (role IN ('user', 'admin')),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_active     INTEGER NOT NULL DEFAULT 1
                          CHECK (is_active IN (0, 1))
);
```

### `refresh_tokens` (ЛР №2)

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    jti             TEXT    NOT NULL UNIQUE,
    family_id       TEXT    NOT NULL,
    user_id         INTEGER NOT NULL,
    issued_at       TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    revoked_at      TEXT,
    revoked_reason  TEXT    CHECK (
                        revoked_reason IS NULL OR revoked_reason IN (
                            'rotated', 'logout', 'reuse_detected', 'expired'
                        )
                    ),
    replaced_by_jti TEXT,
    user_agent      TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
```

Кожен Refresh-токен — окремий рядок зі станом:

- `revoked_at IS NULL` — токен ще можна обміняти;
- `revoked_reason='rotated'` — токен уже використано один раз;
- `revoked_reason='reuse_detected'` — зафіксовано повторне використання;
- `replaced_by_jti` — нащадок у ланцюжку ротації.

### `access_token_revocations` (ЛР №2)

```sql
CREATE TABLE IF NOT EXISTS access_token_revocations (
    jti        TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at TEXT    NOT NULL,
    revoked_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reason     TEXT    NOT NULL DEFAULT 'logout',
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
```

Це blacklist для Access-токенів після logout: запис живе до їхнього
природного `exp`, після чого токен і так недійсний.

### `client_notes` (ЛР №3)

```sql
CREATE TABLE IF NOT EXISTS client_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    author          TEXT    NOT NULL DEFAULT 'guest',
    filename        TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    blocked_vectors TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

У `description` і `filename` записується **уже санітизований** текст.
Поле `blocked_vectors` зберігає перелік нейтралізованих тегів/обробників
для навчального протоколу; сирий HTML у БД не потрапляє.

### `documents` (ЛР №5)

```sql
CREATE TABLE IF NOT EXISTS documents (
    id                TEXT    PRIMARY KEY,
    owner_id          INTEGER NOT NULL,
    original_filename TEXT    NOT NULL,
    stored_filename   TEXT    NOT NULL UNIQUE,
    content_type      TEXT    NOT NULL DEFAULT 'application/octet-stream',
    original_size     INTEGER NOT NULL,
    encrypted_size    INTEGER NOT NULL,
    sha256            TEXT    NOT NULL,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);
```

`id` — випадковий UUID4, `stored_filename` — `<uuid>.enc`. Сам вміст
лежить у каталозі `instance/vault/`, а не в SQLite. `sha256` — хеш
**відкритого** тексту для додаткової перевірки після GCM-дешифрування.

---

## 7. Механізми захисту

### 7.1. bcrypt + унікальна сіль (ЛР №1)

```python
salt = bcrypt.gensalt(rounds=12)
digest = bcrypt.hashpw(password.encode("utf-8"), salt)
```

- work factor 12 означає `2^12` ітерацій; підбір пароля стає значно
  дорожчим, ніж для MD5/SHA;
- сіль генерується криптографічно стійким генератором для **кожного**
  пароля, тому однакові паролі дають різні хеші;
- сіль не є секретом, її можна зберігати поряд із хешем; секретом є
  лише сам пароль;
- перевірка виконується через `bcrypt.checkpw` у constant-time режимі.

### 7.2. Prepared Statements (ЛР №1)

Усі запити мають вигляд:

```python
cursor.execute(
    "SELECT id, username, role FROM users WHERE username = ?",
    (username,),
)
```

Навіть payload `' OR '1'='1` передається як **значення параметра**, а не
як частина SQL-синтаксису. Конкатенація, f-рядки та `%`-форматування в SQL
у проєкті відсутні.

### 7.3. JWT: підпис і валідація (ЛР №2)

Access Token містить клейми:

```json
{
  "iss": "secure-docvault",
  "aud": "secure-docvault-api",
  "sub": "3",
  "type": "access",
  "jti": "унікальний-ідентифікатор",
  "iat": 1794226219,
  "nbf": 1794226219,
  "exp": 1794227119,
  "username": "o.kravets",
  "role": "user"
}
```

Refresh Token додатково містить `family`, а `type` дорівнює `refresh`.
TTL: Access — 900 с (15 хв), Refresh — 604800 с (7 діб).

Під час кожного запиту `decode_token()`:

1. читає header **без** довіри до підпису;
2. явно відхиляє будь-який `alg`, крім `HS256` (це закриває `alg:none`
   та algorithm confusion навіть за зміни поведінки бібліотеки);
3. викликає `jwt.decode(..., algorithms=["HS256"])` з перевіркою
   `exp`, `iat`, `nbf`, `iss`, `aud` і обов'язкових клеймів;
4. перевіряє, що `sub` — додатне число, а `type` — `access` або `refresh`;
5. для захищених маршрутів додатково звіряє `jti` з blacklist.

Підпис обчислюється HMAC-SHA256 від `base64url(header).base64url(payload)`
із секретним ключем сервера. Зміна будь-якого символу Payload або
Signature дає `401 invalid_signature` до виконання бізнес-логіки.

### 7.4. Refresh Token Rotation (ЛР №2)

1. Клієнт надсилає `refresh_token` на `/api/v1/auth/refresh`.
2. Сервер перевіряє підпис, тип, `exp` і наявність `jti` у БД.
3. `rotate_refresh_token()` в одній транзакції:
   - ставить старому `jti` `revoked_at`, `revoked_reason='rotated'`,
     `replaced_by_jti=<новий jti>`;
   - вставляє новий Refresh-токен у тій самій `family_id`;
   - якщо старий уже було відкликано — `rowcount != 1`, операція
     відкочується.
4. Клієнт отримує нову пару Access + Refresh.

### 7.5. Reuse detection (ЛР №2)

Якщо надходить Refresh-токен, у якого `revoked_reason='rotated'`, це
означає, що токен уже використали (можлива крадіжка). Сервер:

- повертає `401 refresh_token_reuse`;
- викликає `revoke_refresh_family(family_id, reason='reuse_detected')`;
- відкликає **усі** активні токени цієї родини, включно з новим.

Після цього жоден токен родини не можна обміняти — потрібен повторний
вхід.

### 7.6. Logout і revoke-список (ЛР №2)

`POST /api/v1/auth/logout`:

- додає `jti` поточного Access-токена до `access_token_revocations`;
- відкликає Refresh-родину, передану в тілі, або всі активні
  Refresh-токени користувача (logout everywhere).

Access-токен після logout відхиляється з `401 token_revoked`, навіть
якщо його `exp` ще не минув.

### 7.7. Додаткові рівні (ЛР №1)

- CSRF-токен у кожній POST-формі, перевірка через `hmac.compare_digest`;
- `session.clear()` після входу — захист від session fixation;
- cookie: `HttpOnly`, `SameSite=Strict` (ЛР №3), `Secure` вмикається через `.env`;
- єдине повідомлення про помилку входу — не розкриває, чи існує акаунт;
- dummy bcrypt-перевірка для неіснуючого користувача — вирівнює час
  відповіді та ускладнює user enumeration;
- security headers: `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`;
- пароль не логується і не повертається у відповідях API.

### 7.8. Санітизація вводу (ЛР №3)

`app/sanitizer.py` розділяє три контексти:

```python
def sanitize_text(text, *, max_length=2000, strip_blocks=False):
    value = _normalize(text)                 # NFC + видалення control chars
    if strip_blocks:
        value = DANGEROUS_BLOCK_RE.sub(" ", value)  # script/style/svg...
    value = _plain_text(value)               # bleach.clean(tags=[], strip=True)
    return html.unescape(value).strip()[:max_length]
```

- **Текст (описи, коментарі):** Bleach забороняє всі HTML-теги,
  `strip=True` прибирає розмітку, але залишає безпечний текстовий вміст.
- **Ім'я файлу:** додатково видаляються небезпечні контейнери разом із
  вмістом, відсікаються шляхи (`../`, `C:\`), заборонені символи
  замінюються на `_`, а зарезервовані імена Windows (`CON`, `PRN`, ...)
  отримують префікс `_`.
- **Оцінка загроз:** `inspect_sanitization()` повертає `removed_tags`,
  `removed_handlers`, `blocked_protocols` — саме це показує сторінка
  `/client-lab` після надсилання payload.
- **Екранування виводу:** Jinja2 autoescape перетворює залишкові
  `<`, `>`, `&` на сутності; для не-HTML контекстів є `escape_text()`.

### 7.9. CSP без `unsafe-inline` (ЛР №3)

```
default-src 'self'; base-uri 'self'; object-src 'none';
frame-ancestors 'none'; form-action 'self';
script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self';
report-uri /client-lab/csp-report
```

Увесь JavaScript винесено у `app/static/js/*.js`; inline-скрипти та
inline-обробники `on*` не виконуються. Сторінка `/client-lab/csp`
навмисно містить `<script>` і `<img onerror>` — браузер блокує їх і
надсилає звіт на `report-uri`, а консоль фіксує
`Refused to execute inline script because it violates CSP`.

### 7.10. Безпечні cookie (ЛР №3)

| Атрибут | Значення | Що блокує |
|---|---|---|
| `HttpOnly` | увімкнено | читання сесії через `document.cookie` при XSS |
| `Secure` | увімкнено (env/demo) | передачу cookie через відкритий HTTP |
| `SameSite=Strict` | увімкнено | cross-site відправку cookie → CSRF |
| `Path=/` | явно | надмірне розширення області дії |

`/client-lab/cookies` встановлює `docvault_demo_session` (HttpOnly) і
`docvault_demo_csrf` (публічний, без HttpOnly) та показує різницю між
серверним сховищем і `document.cookie`.

### 7.11. Захисні заголовки (ЛР №3)

| Заголовок | Значення | Загроза |
|---|---|---|
| `Content-Security-Policy` | див. 7.9 | XSS, inline-код, `data:`-скрипти |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | SSL-stripping / downgrade |
| `X-Content-Type-Options` | `nosniff` | MIME-sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | витік URL із токенами |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | доступ до пристроїв |
| `X-Permitted-Cross-Domain-Policies` | `none` | cross-domain policy-файли |

Заголовки додаються в `after_request`-middleware (`app/security.py`) до
**кожної** відповіді, включно з REST API та сторінками помилок.

### 7.12. CORS із явним whitelist (ЛР №3)

- `CORS_ALLOWED_ORIGINS` — список конкретних Origin; `*` не
  підтримується і ніколи не повертається.
- Для дозволеного Origin сервер повертає `Access-Control-Allow-Origin`
  з його точним значенням, `Allow-Credentials: true`, `Allow-Methods`,
  `Allow-Headers`, `Max-Age: 600`.
- Для стороннього Origin `Access-Control-Allow-Origin` **не
  встановлюється**, тому браузер не віддає тіло відповіді скрипту.
- `Vary: Origin` додається завжди, щоб проміжні кеші не змішували
  відповіді для різних Origin.

### 7.13. Sliding Window Rate Limiter (ЛР №4)

`app/rate_limiter.py` зберігає для кожного ключа `IP:rule` `deque`
міток часу в межах вікна:

```python
def check(self, client_ip, rule, *, now=None):
    current = time.monotonic() if now is None else now
    key = f"{client_ip}:{rule.name}"
    with self._lock:
        bucket = self._events[key]
        cutoff = current - rule.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= rule.limit:
            oldest = bucket[0]
            retry = max(1, math.ceil(rule.window_seconds - (current - oldest)))
            return RateDecision(False, ..., retry_after=retry)
        bucket.append(current)
        return RateDecision(True, ..., remaining=rule.limit - len(bucket))
```

Правила:

| Група | Ліміт | Маршрути |
|---|---|---|
| `auth_login` | 5 / 60 с | `POST /api/v1/auth/login`, `POST /login` |
| `api_general` | 60 / 60 с | `/api/v1/*` |
| `web_general` | 120 / 60 с | решта HTML-маршрутів |

Переваги Sliding Window Log: немає подвійного сплеску `2 × limit` на межі
хвилини; `Retry-After` обчислюється точно за найстарішою міткою. Пам'ять
на ключ обмежена лімітом, а `RATE_LIMIT_MAX_KEYS` + `RATE_LIMIT_KEY_TTL_SECONDS`
захищають від Memory Exhaustion DoS.

### 7.14. Сигнатурний WAF і Greylist (ЛР №4)

`app/waf_filter.py` перевіряє **path → query → body** після подвійного
URL-декодування та NFKC-нормалізації. Сигнатури згруповані:

- Path Traversal — `../`, `..\`, зокрема `%2e%2e%2f`;
- SQL Injection — `UNION SELECT`, tautology `' OR '1'='1`, `DROP TABLE`,
  `INSERT INTO`, `EXEC xp_`, `xp_cmdshell`;
- Command Injection — `; /bin/sh`, `| bash`, `cmd.exe`, `system(`, `exec(`,
  `?cmd=`;
- XSS — `<script>`, `javascript:`, `onerror=`, `<svg>`.

При спрацюванні:

1. IP додається до `Greylist` на `WAF_GREYLIST_SECONDS` (за замовчуванням
   300 с);
2. повертається `403 Forbidden` із `X-WAF-Rule`, `X-WAF-Action`,
   `Retry-After`;
3. подія пишеться в `IncidentLog` і `app.logger.warning`;
4. усі наступні запити з цієї IP блокуються до завершення інтервалу.

Лабораторні сторінки `/client-lab` і `/security-lab` навмисно виключені
з WAF, щоб демонструвати санітизацію та параметризовані запити; їхній
захист забезпечують шари ЛР №1 і ЛР №3.

### 7.15. Коректна HTTP-семантика 403/429 (ЛР №4)

- `403 Forbidden` — WAF/Greylist; API отримує JSON `error.code` =
  `waf_blocked` або `ip_greylisted`, HTML — стилізовану сторінку.
- `429 Too Many Requests` — перевищення ліміту; заголовок `Retry-After`
  повідомляє, через скільки секунд можна повторити запит.
- Успішні відповіді містять `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Window`, `X-RateLimit-Rule`.
- Журнал інцидентів доступний на `/waf-lab` і через `/waf-lab/events`.

### 7.16. Лабораторний стенд `/waf-lab` (ЛР №4)

Сторінка показує:

- статус WAF, Rate Limiter, кількість активних Greylist-записів;
- кнопку стрес-тесту (10 запитів → 401…429);
- кнопки Path Traversal / SQLi / Command Injection / XSS;
- журнал інцидентів із IP, маршрутом, деталями, дією та HTTP-кодом;
- таблицю правил і сигнатур;
- `Reset` для очищення лічильників, Greylist і журналу.

`/waf-lab` і `/waf-lab/*` виключені з Greylist/лімітів, щоб консоль
залишалася доступною під час демонстрації. У production цю консоль
потрібно закрити авторизацією або вимкнути (`WAF_LAB_ALLOW_RESET=0`,
окремий admin-маршрут).

### 7.17. AES-256-GCM і формат контейнера (ЛР №5)

```python
ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
container = nonce + tag + ciphertext          # [12 B][16 B][N B]
```

- `nonce = os.urandom(12)` — новий 96-бітний IV для кожного файлу;
- `tag` — 16-байтний Authentication Tag, який перевіряється **до**
  повернення plaintext;
- `AAD = b"docvault|file|v1|<document_id>|<owner_id>"` — прив'язує
  контейнер до метаданих і власника;
- неправильний ключ, IV, tag, ciphertext або AAD → `InvalidTag`.

### 7.18. Завантаження та скачування (ЛР №5)

`POST /api/v1/documents/upload`:

1. JWT Bearer, перевірка активної сесії;
2. санітизація імені, allowlist розширень, ліміт `MAX_DOCUMENT_BYTES`;
3. `uuid.uuid4()` для `document_id` і `<uuid>.enc`;
4. AES-GCM-шифрування, атомарний `os.replace()`;
5. запис метаданих у SQLite; при помилці БД файл видаляється.

`GET /api/v1/documents/<id>/download`:

1. перевірка власника або ролі `admin` (IDOR захист);
2. читання `.enc`, відновлення AAD із метаданих;
3. `AESGCM.decrypt()` → `InvalidTag` → `409 integrity_error`;
4. додаткова перевірка SHA-256 plaintext;
5. `send_file(..., as_attachment=True)` із `X-Content-SHA256`.

### 7.19. Керування ключем і ротація (ЛР №5)

- `FILE_ENCRYPTION_KEY` — 32-байтний AES-256 ключ у hex (64 символи);
- у production `FILE_ENCRYPTION_KEY_REQUIRED=1` — старт без ключа
  завершується помилкою;
- `FILE_ENCRYPTION_KEY_OLD` — список старих ключів через кому; сервіс
  пробує поточний, потім старі (ротація без втрати старих файлів);
- відбиток ключа (`SHA-256` перші 16 hex) показується в UI, але сам
  ключ ніколи не логується й не віддається клієнту;
- ключ зберігається окремо від диска з файлами (env/секрет-менеджер).

### 7.20. Цілісність і IDOR (ЛР №5)

- `InvalidTag` при зміні одного байта IV/tag/ciphertext;
- SHA-256 plaintext у БД — друга незалежна перевірка;
- UUID4 + перевірка `owner_id`/`admin` замість прямих ID;
- AAD не дає переставити контейнер між документами або власниками;
- `X-Content-Type-Options: nosniff` + `Content-Disposition: attachment`
  для скачування;
- HTML/JS/SVG-розширення не входять до allowlist, щоб сховище не стало
  XSS-репозиторієм.

---

## 8. Приклади запитів до API

> Демо-користувач: `o.kravets` / `Vault#2026!` (створюється
> `scripts/seed_demo.py`).

### 8.1. Login — отримати пару токенів

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"o.kravets","password":"Vault#2026!"}'
```

Відповідь `200 OK`:

```json
{
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 900,
  "refresh_expires_in": 604800,
  "access_expires_at": "2026-11-09T12:23:47.394865Z",
  "refresh_expires_at": "2026-11-16T12:08:47.396105Z",
  "user": {
    "id": 3,
    "username": "o.kravets",
    "email": "o.kravets@docvault.local",
    "role": "user",
    "is_active": true
  }
}
```

### 8.2. Захищений профіль

```bash
curl -s http://127.0.0.1:5000/api/v1/user/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Без заголовка — `401 missing_token`; із підробленим Payload —
`401 invalid_signature`; із `alg:none` — `401 invalid_algorithm`.

### 8.3. Ротація Refresh-токена

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

Відповідь містить `"rotated": true`, `"previous_refresh_revoked": true`
та нову пару. Повторний запит із тим самим Refresh-токеном дає
`401 refresh_token_reuse` і відкликає всю родину.

### 8.4. Logout

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/auth/logout \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

---

## 9. Тестування

Встановіть dev-залежності:

```bash
pip install -r requirements-dev.txt
```

### Повний прогін

```bash
python -m unittest discover -v
```

**Результат на момент здачі:**

```text
Ran 213 tests in 56.0s
OK
```

| Файл | Тестів | Що перевіряє |
|---|---|---|
| `test_security.py` | 17 | політика пароля, bcrypt, username/email |
| `test_database.py` | 8 | схема `users`, унікальність, SQLi |
| `test_web_e2e.py` | 9 | реєстрація, вхід, CSRF, dashboard, SQLi-стенд |
| `test_jwt_service.py` | 8 | клейми, TTL, підпис, `alg:none`, чужий ключ, fail-closed |
| `test_api.py` | 19 | login, profile, tamper, rotation, reuse, logout, кеш |
| `test_api_web_e2e.py` | 1 | повний JWT-протокол у Edge headless |
| `test_sanitizer.py` | 22 | Bleach, небезпечні теги, шляхи, reserved names, звіт |
| `test_client_security.py` | 16 | CSP, HSTS, XFO, CORS, cookie flags, CSRF, sanitize POST |
| `test_client_security_e2e.py` | 6 | CSP-блокування в Edge, document.cookie, cookie flags, форма |
| `test_rate_limiter.py` | 9 | Sliding Window, ліміти, Retry-After, ізоляція ключів, prune |
| `test_waf_filter.py` | 33 | Path Traversal, SQLi, command injection, XSS, false positives, Greylist |
| `test_network_security.py` | 18 | 401→429, 403, Greylist, журнал, CSRF Reset, виключення лабів |
| `test_network_security_e2e.py` | 6 | реальний браузерний стрес-тест, WAF-атаки, Greylist, Reset |
| `test_file_crypto.py` | 20 | IV, Tag, roundtrip, tamper, AAD, key rotation, короткий контейнер |
| `test_documents.py` | 17 | upload/download, IDOR, admin, 409 InvalidTag, валідація, UI |
| `test_documents_e2e.py` | 4 | UI upload, detail/hexdump, заборонене розширення, delete |

Окремі групи:

```bash
python -m unittest tests.test_security tests.test_database -v
python -m unittest tests.test_web_e2e -v
python -m unittest tests.test_jwt_service tests.test_api -v
python -m unittest tests.test_api_web_e2e -v
python -m unittest tests.test_sanitizer tests.test_client_security -v
python -m unittest tests.test_client_security_e2e -v
python -m unittest tests.test_rate_limiter tests.test_waf_filter -v
python -m unittest tests.test_network_security -v
python -m unittest tests.test_network_security_e2e -v
python -m unittest tests.test_file_crypto tests.test_documents -v
python -m unittest tests.test_documents_e2e -v
```

### Ручна перевірка JWT-протоколу

1. Запустіть `python run.py`.
2. Відкрийте `/api-lab`.
3. Натисніть **Login** — отримайте пару токенів і побачите декодовані
   Header / Payload / Signature.
4. **Profile** — `200` із профілем користувача.
5. **No token** — `401 missing_token`.
6. **Tamper** — роль змінено на `admin`, сервер відповідає
   `401 invalid_signature`, бейдж показує `INVALID · payload змінено`.
7. **Refresh** — `200`, `rotated: true`, нові токени.
8. **Reuse** — повторне використання старого Refresh-токена:
   `401 refresh_token_reuse`, родину відкликано.

### Ручна перевірка клієнтського захисту

1. Запустіть `python run.py` і відкрийте `/client-lab`.
2. У формі санітизатора введіть `<script>alert('XSS')</script>` та
   `<img src=x onerror=alert(1)>` — результат покаже очищений текст і
   перелік нейтралізованих векторів; alert не з'явиться.
3. Відкрийте `/client-lab/csp` — DevTools Console містить
   `Executing inline script violates ... script-src 'self'`.
4. Відкрийте `/client-lab/cookies` → DevTools → Application → Cookies:
   `docvault_session` і `docvault_demo_session` мають `HttpOnly`,
   `Secure`, `SameSite=Strict`.
5. Виконайте `curl -I http://127.0.0.1:5000/client-lab` — у відповіді
   будуть CSP, HSTS, `nosniff`, `X-Frame-Options: DENY`,
   `Referrer-Policy`.
6. Відкрийте `/client-lab/cors` — дозволений Origin отримує
   `Access-Control-Allow-Origin`, сторонній — ні.

### Ручна перевірка WAF / Rate Limiting

1. Запустіть `python run.py` і відкрийте `/waf-lab`.
2. Натисніть **«Надіслати 10 запитів»** — перші 5 відповідей `401`,
   наступні 5 — `429` із `Retry-After`.
3. Натисніть **Path Traversal** — відповідь `403`, `X-WAF-Rule: waf-1001`,
   IP з'являється в Greylist.
4. Натисніть **«Перевірити Greylist»** — `/api/v1/health` повертає `403`
   `ip_greylisted` до завершення інтервалу.
5. Відкрийте журнал інцидентів — там є IP, маршрут, деталі, дія та
   HTTP-код.
6. Натисніть **Reset** — лічильники, Greylist і журнал очищуються.
7. Для термінального протоколу:
   `python scripts/stress_test_lab4.py --base-url http://127.0.0.1:5000`.

### Ручна перевірка шифрування файлів

1. Запустіть `python run.py`, увійдіть і відкрийте `/vault`.
2. Завантажте `.txt`/`.pdf` — відкриється detail-сторінка з IV, Tag,
   Ciphertext і hexdump.
3. Перевірте диск: `instance/vault/<uuid>.enc` не містить plaintext.
4. Натисніть **«Розшифрувати та скачати»** — файл повертається з
   `X-Content-SHA256`.
5. Для API-протоколу:
   `python scripts/demo_lab5_api.py --base-url http://127.0.0.1:5000`
   (потрібен користувач `lab5.demo` або змініть `--username/--password`).
6. Для тесту цілісності:
   `python scripts/integrity_test_lab5.py --mode all`.

---

## 10. Скриншоти та звіт

### ЛР №5 — `docs/screenshots 5/`

Автоматично згенерувати всі скриншоти:

```bash
python scripts/capture_screenshots_lab5.py
```

Скрипт піднімає сервер, виконує реальний API-протокол, запускає
integrity-тест із hexdump та проходить UI Cipher Vault в Edge headless.

| Файл | Що демонструє |
|---|---|
| `00-vault-overview.png` | оглядова сторінка `/vault`, статус AES-256-GCM |
| `01-api-upload-download.png` | login → upload 201 → metadata → download 200, SHA-256 match |
| `02-stored-container-hexdump.png` | hexdump `.enc`-файлу, plaintext marker: ABSENT |
| `03-integrity-invalidtag.png` | зміна 1 байта → `InvalidTag` → `409 integrity_error` |
| `04-vault-upload-detail.png` | UI-завантаження, IV/Tag/Ciphertext і hexdump |
| `05-vault-documents.png` | список зашифрованих документів |
| `06-file-encryption-architecture.png` | схема контейнера, AEAD і потоків |

Додатковий матеріал: `docs/file_encryption_architecture.html` — схема
AES-GCM, порівняння ECB/CBC/CTR/GCM і модель загроз.

### ЛР №4 — `docs/screenshots 4/`

Автоматично згенерувати всі скриншоти:

```bash
python scripts/capture_screenshots_lab4.py
```

Скрипт піднімає сервер із увімкненими WAF/Rate Limiting, запускає
`scripts/stress_test_lab4.py`, перехоплює реальні логи, проходить
UI-сценарії в Edge headless і зберігає PNG.

| Файл | Що демонструє |
|---|---|
| `00-waf-lab-overview.png` | оглядова сторінка `/waf-lab`: статуси, ліміти, кнопки |
| `01-stress-test-429.png` | реальний стрес-тест: 5×401 → 5×429 + `Retry-After` |
| `02-server-log-rate-limit.png` | журнал сервера: IP, `[RATE_LIMIT]`, `[WAF_BLOCK]`, `[GREYLIST]` |
| `03-rate-limit-ui.png` | UI-таблиця 10 запитів: усі статуси та `Retry-After` |
| `04-path-traversal-403.png` | Path Traversal → `403`, `waf-1001`, Greylist |
| `05-sqli-403.png` | SQL Injection → `403`, `waf-1003` |
| `06-command-injection-403.png` | Command Injection → `403`, `waf-2001` |
| `07-greylist-block.png` | повторний запит → `403 ip_greylisted` |
| `08-incident-log.png` | журнал інцидентів + активний Greylist |
| `09-rate-limit-rules.png` | правила `auth_login` / `api_general` / `web_general` |
| `10-waf-signatures.png` | 13 сигнатур WAF із прикладами |
| `11-sentinel-architecture.png` | схема конвеєра WAF / Rate Limiter |

Додатковий матеріал: `docs/network_security_architecture.html` — схема
Sliding Window, сигнатур і HTTP-відповідей.

### ЛР №3 — `docs/screenshots 3/`

Автоматично згенерувати всі скриншоти:

```bash
python scripts/capture_screenshots_lab3.py
```

Скрипт піднімає сервер на тимчасовій БД, виконує реальний `curl -I`,
відкриває сторінки в Edge headless, збирає browser log і `get_cookies()`,
після чого зберігає PNG.

| Файл | Що демонструє |
|---|---|
| `00-client-lab-overview.png` | оглядова сторінка `/client-lab` |
| `01-curl-headers.png` | реальний `curl -I` з CSP, HSTS, nosniff, XFO, Referrer-Policy |
| `02-csp-console.png` | DevTools Console: `Refused to execute inline script` і таблиця порушень |
| `03-csp-blocked-status.png` | статуси `BLOCKED` для inline script / onerror / DOM injection |
| `04-cookies-devtools.png` | DevTools Application → Cookies: HttpOnly, Secure, SameSite=Strict |
| `05-document-cookie.png` | `document.cookie` без HttpOnly-сесії |
| `06-sanitized-xss.png` | XSS-payload у формі та очищений результат Bleach |
| `07-sanitized-stored-note.png` | збережений опис у `client_notes` без HTML |
| `08-headers-matrix.png` | матриця заголовків і фактична відповідь API |
| `09-cors-allowed-denied.png` | дозволений Origin vs сторонній Origin |
| `10-cors-preflight.png` | preflight OPTIONS із дозволеними методами/заголовками |
| `11-cors-whitelist.png` | налаштування `CORS_ALLOWED_ORIGINS` без `*` |
| `12-client-security-architecture.png` | схема ешелонованого захисту |

Додатковий матеріал: `docs/client_security_architecture.html` — схема
чотирьох рівнів (sanitize → escape → CSP → cookie/CORS).

### ЛР №2 — `docs/screenshots 2/`

Автоматично згенерувати всі скриншоти:

```bash
python scripts/capture_screenshots_lab2.py
```

Скрипт створює тимчасову БД `instance/lab2_demo.db`, піднімає сервер,
проходить протокол у Edge headless і зберігає PNG.

| Файл | Що демонструє |
|---|---|
| `00-api-lab-overview.png` | оглядова сторінка JWT-стенда `/api-lab` |
| `01-jwt-login.png` | успішний `POST /auth/login`, пара access + refresh |
| `02-profile-authorized.png` | `GET /user/profile` із `Authorization: Bearer` → `200` |
| `03-profile-no-token.png` | запит без токена → `401 missing_token` |
| `04-tampered-token.png` | підміна `role=admin` → `401 invalid_signature`, Payload змінено |
| `05-refresh-rotation.png` | ротація Refresh-токена → `200`, `rotated: true` |
| `06-refresh-reuse.png` | повторне використання → `401 refresh_token_reuse`, family revoked |
| `07-jwt-structure.png` | декодовані Header / Payload / Signature |
| `08-jwt-flow.png` | архітектурна схема обміну токенами |
| `09-refresh-token-table.png` | журнал `refresh_tokens`: ROTATED / REUSE DETECTED / ACTIVE |

Додаткові матеріали:

- `docs/jwt_architecture.html` — схема двох потоків (видача/доступ та
  ротація/reuse);
- `docs/jwt_db_snapshot.html` — HTML-знімок таблиці `refresh_tokens`
  (генерується `scripts/jwt_db_snapshot.py`).

### ЛР №1 — `docs/screenshots/`

```bash
python scripts/capture_screenshots.py
```

| Файл | Що демонструє |
|---|---|
| `00-login.png` | оглядова сторінка входу |
| `01-register-validation.png` | реєстрація з надійним паролем і зеленим strength meter |
| `02-register-success.png` | успішна реєстрація |
| `03-login-error.png` | помилка входу з хибним паролем |
| `04-dashboard.png` | успішний вхід і кабінет |
| `05-sqli-login.png` | SQLi-payload у формі входу та відмова |
| `06-security-lab.png` | параметризований запит повертає 0 рядків |
| `07-users-table.png` | таблиця `users` із хешами та унікальними солями |
| `08-auth-flow.png` | архітектурна схема реєстрації/входу |

Повний звіт ЛР №1: [`docs/REPORT.md`](docs/REPORT.md).

---

## 11. Git

```bash
git tag
# v0.1-auth-db
# v0.2-jwt-api
# v0.3-client-security
# v0.4-waf-ratelimit
# v0.5-file-encryption
```

Перевірити історію:

```bash
git log --oneline --decorate
```

Для здачі викладачеві достатньо додати remote та виконати:

```bash
git remote add origin <URL-вашого-репозиторію>
git push -u origin main --tags
```

---

## 12. Корисні команди

```bash
# створити демо-користувача
python scripts/seed_demo.py

# HTML-знімок таблиці users (ЛР №1)
python scripts/db_snapshot.py

# HTML-знімок refresh_tokens (ЛР №2)
python scripts/jwt_db_snapshot.py --db instance/lab2_demo.db

# скриншоти ЛР №3
python scripts/capture_screenshots_lab3.py

# скриншоти ЛР №4
python scripts/capture_screenshots_lab4.py

# стрес-тест WAF / Rate Limiting (10 запитів)
python scripts/stress_test_lab4.py --base-url http://127.0.0.1:5000

# скриншоти ЛР №5
python scripts/capture_screenshots_lab5.py

# API-протокол і integrity-тест AES-GCM
python scripts/demo_lab5_api.py --base-url http://127.0.0.1:5000
python scripts/integrity_test_lab5.py --mode all

# перевірити health-check
http://127.0.0.1:5000/healthz
http://127.0.0.1:5000/api/v1/health

# скинути локальну БД
# зупиніть сервер і видаліть instance/docvault.db
```

---

## 13. Обмеження поточного етапу

- WAF і Rate Limiter — навчальні, не замінюють ModSecurity/CRS і
  розподілений Redis-лічильник; сигнатурний аналіз має False Positives;
- `/waf-lab` є відкритою лабораторною консоллю; у production її треба
  закрити авторизацією або вимкнути (`WAF_LAB_ALLOW_RESET=0`);
- WAF навмисно виключає `/client-lab` і `/security-lab`, щоб зберегти
  демонстрації ЛР №1 та ЛР №3;
- ключ AES-256 зберігається в env для навчального стенда; у production
  потрібен KMS/HSM/secret manager, аудит доступу та планова ротація;
- файли читаються в пам'ять повністю (ліміт 5 МБ); для великих файлів
  потрібне потокове/chunked-шифрування;
- немає цифрових підписів — ЛР №6;
- JWT зберігаються на клієнті в пам'яті стенда; у production-фронтенді
  Refresh-токен варто тримати в `HttpOnly Secure SameSite=Strict` cookie;
- `Secure`-cookie та HSTS повноцінно працюють лише за HTTPS; на
  `localhost`/`127.0.0.1` браузер вважає Origin trustworthy, тому
  демонстраційні Secure-cookie зберігаються і без TLS;
- SQLite обрано для локального навчального стенда; для production
  передбачається PostgreSQL/MySQL із тими самими параметризованими
  запитами та спільним revoke-сховищем (Redis).

---

## 14. Висновок до ЛР №3

Клієнтський захист Secure DocVault побудовано за принципом Defense in
Depth: санітизація Bleach нейтралізує XSS-вектори ще до запису в
`client_notes`, Jinja2 autoescape страхує вивід, CSP із `script-src
'self'` без `unsafe-inline` не дає браузеру виконати ні inline-скрипт,
ні атрибут `onerror` навіть за наявності вразливого поля, а
`HttpOnly` + `Secure` + `SameSite=Strict` закривають викрадення сесії та
CSRF. Додаткові HSTS, `nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy` і CORS-whitelist усувають downgrade, MIME-sniffing,
Clickjacking і несанкціоноване міжсайтове читання API. Тести (22 unit,
16 інтеграційних, 6 Selenium E2E) підтверджують, що кожен рівень працює
незалежно, тому компрометація одного механізму не відкриває весь
периметр.

---

## 15. Висновок до ЛР №4

Активний мережевий периметр Secure DocVault побудовано як конвеєр
«IP → Greylist → WAF → Rate Limiter → Flask route»: сигнатурний фільтр
`app/waf_filter.py` блокує Path Traversal, SQLi, командні ін'єкції та XSS
ще до виконання маршруту, додає IP до Greylist і повертає коректний
`403` із `X-WAF-Rule` та `Retry-After`, а `app/rate_limiter.py` реалізує
Sliding Window Log із диференційованими лімітами 5/60 с для login,
60/60 с для API і 120/60 с для HTML, повертаючи `429` із `Retry-After`
та `X-RateLimit-*`. Кільцевий журнал інцидентів і сторінка `/waf-lab`
дають змогу побачити IP, маршрут, сигнатуру, дію та статус, а
лабораторний Reset дозволяє повторювати сценарії. Тести (9 unit Rate
Limiter, 33 unit WAF, 18 інтеграційних і 6 Selenium E2E) підтверджують
перехід `401 → 429`, блокування Path Traversal/SQLi/Command Injection,
роботу Greylist і коректну сумісність із ЛР №1–3; при цьому WAF
залишається додатковим шаром, а не заміною параметризованих запитів,
санітизації та CSP, і потребує налаштування правил для зменшення
False Positives.

---

## 16. Висновок до ЛР №5

Шифрування файлів у Secure DocVault реалізовано як AES-256-GCM із
контейнером `[12 B IV][16 B Tag][Ciphertext]`, унікальним
`os.urandom(12)` для кожного файлу та AAD, що прив'язує контейнер до
UUID документа й власника. Завантаження шифрує дані до запису на диск,
метадані та SHA-256 plaintext зберігаються окремо в SQLite, а скачування
перевіряє права owner/admin, GCM tag і хеш; зміна одного байта IV, tag
або ciphertext викликає `InvalidTag` і `409 integrity_error`, не
повертаючи жодного байта plaintext. Такий підхід забезпечує
конфіденційність навіть при викраденні диска/бекапу та цілісність при
пошкодженні чи підміні файлу, а UUID4 і перевірка власника закривають
IDOR. Водночас ключ потребує окремого захищеного зберігання й ротації
(`FILE_ENCRYPTION_KEY_OLD`), а для великих файлів у production варто
перейти на потокове шифрування; тести (20 unit crypto, 17 інтеграційних
і 4 Selenium E2E) підтверджують roundtrip, унікальність IV, виявлення
модифікацій, IDOR і коректну роботу UI.

---

## 17. Ліцензія

Навчальний проєкт. Використовуйте лише для освітніх цілей.
