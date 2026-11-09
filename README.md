# Secure DocVault — етап 1: автентифікація та захист БД

Навчальний проєкт до лабораторної роботи №1 з дисципліни
**«Технології захисту інформаційних ресурсів»**.

Реалізовано перший шар IAM корпоративного порталу **Secure DocVault**:
реєстрація, вхід, безпечне зберігання паролів у SQLite та захист від
SQL-ін'єкцій. Замість десктопного PyQt-інтерфейсу з прикладу зроблено
**веб-інтерфейс на Flask + Jinja2** з авторським темним дизайном
«Obsidian Vault».

> **Статус:** виконано лише ЛР №1. JWT, WAF, шифрування файлів та цифрові
> підписи з наступних етапів навмисно не додані.

---

## 1. Що демонструє проєкт

| Вимога ЛР | Реалізація |
|---|---|
| Структура проєкту, venv, Git | `app/`, `tests/`, `scripts/`, `venv/`, локальний Git-репозиторій, тег `v0.1-auth-db` |
| Схема `users` | `id`, `username`, `email`, `password_hash`, `salt`, `role`, `created_at`, `is_active` |
| Повільне хешування + сіль | `bcrypt` із `rounds=12`, окрема сіль для кожного запису |
| Prepared Statements | Усі запити в `app/database.py` — тільки `?` + кортеж параметрів |
| Реєстрація та вхід | Веб-форми `/register`, `/login` із серверною валідацією |
| Валідація пароля | ≥ 8 символів, великі/малі літери, цифра, спецсимвол, ≤ 72 байти |
| SQLi-тест | Стенд `/security-lab` + E2E-тест із payload `' OR '1'='1` |
| Звіт | `docs/REPORT.md`, `docs/Звіт_ЛР1_Secure_DocVault.docx`, скриншоти в `docs/screenshots/` |

---

## 2. Технології

- **Python 3.10+** (перевірено на Python 3.14.7)
- **Flask 3.1** + Jinja2 — серверний рендеринг сторінок
- **SQLite** — локальна реляційна БД, режим WAL
- **bcrypt 5.0** — хешування паролів, work factor 12
- **HTML/CSS/vanilla JS** — адаптивний інтерфейс без зовнішніх CDN
- **unittest + Selenium WebDriver** — тестування (Edge headless)

> У проєкті **не використовуються** `pytest`, `fastapi.testclient.TestClient`,
> `httpx`, `requests` або `urllib.request` для тестування. Це вимога до
> нашого варіанта роботи: тестовий стек побудований на `unittest` і
> `selenium`, який працює з реальним браузером.

---

## 3. Структура

```text
secure-docvault/
├── app/
│   ├── __init__.py              # application factory, security headers, error handlers
│   ├── auth.py                  # маршрути, CSRF, сесії, SQLi-стенд
│   ├── auth_security.py         # bcrypt, валідація пароля/username/email
│   ├── config.py                # конфігурація з .env
│   ├── database.py              # схема users і параметризовані запити
│   ├── static/
│   │   ├── css/app.css          # тема «Obsidian Vault»
│   │   ├── js/app.js            # strength meter, показ пароля, flash
│   │   └── favicon.svg
│   └── templates/
│       ├── _brand.html
│       ├── _icons.html
│       ├── auth_base.html
│       ├── base.html
│       ├── dashboard.html
│       ├── error.html
│       ├── login.html
│       ├── register.html
│       └── security_lab.html
├── docs/
│   ├── screenshots/             # 9 скриншотів протоколу тестування
│   ├── architecture.html        # схема потоку реєстрації/входу
│   ├── db_snapshot.html         # локальний HTML-знімок таблиці users
│   └── REPORT.md                # звіт у Markdown
├── scripts/
│   ├── capture_screenshots.py   # автоматичне створення скриншотів
│   ├── db_snapshot.py           # HTML-знімок БД
│   └── seed_demo.py             # створення демо-користувача
├── tests/
│   ├── test_security.py         # 17 юніт-тестів
│   ├── test_database.py         # 8 тестів схеми та SQLi
│   └── test_web_e2e.py          # 9 E2E-тестів у Selenium
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
# відредагуйте .env і задайте власний SECRET_KEY
python run.py
```

### Linux / macOS

```bash
cd secure-docvault
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# відредагуйте .env і задайте власний SECRET_KEY
python run.py
```

Після запуску відкрийте <http://127.0.0.1:5000>.

Згенерувати безпечний `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

База даних створюється автоматично у `instance/docvault.db`.
Каталог `instance/` та файли `*.db` додані до `.gitignore`.

---

## 5. Маршрути

| Метод | Маршрут | Призначення |
|---|---|---|
| GET | `/` | редірект на `/dashboard` або `/login` |
| GET/POST | `/register` | реєстрація з серверною валідацією |
| GET/POST | `/login` | перевірка автентичності |
| POST | `/logout` | завершення сесії (тільки POST + CSRF) |
| GET | `/dashboard` | закритий кабінет користувача |
| GET/POST | `/security-lab` | навчальний read-only SQLi-стенд |
| GET | `/healthz` | службовий JSON health-check |

---

## 6. Схема БД

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

Особливості:

- `username` та `email` унікальні без урахування регістру (`COLLATE NOCASE`);
- `password_hash` містить повний bcrypt-рядок `$2b$12$...`;
- `salt` зберігається окремо, щоб явно показати унікальність солі в звіті;
  вона також вбудована в bcrypt-хеш;
- `created_at` — UTC-час у ISO-подібному форматі;
- `is_active` дозволяє вимкнути акаунт без фізичного видалення.

---

## 7. Механізми захисту

### 7.1. bcrypt + унікальна сіль

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
- перевірка виконується через `bcrypt.checkpw`, який працює у
  constant-time режимі.

### 7.2. Prepared Statements

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

### 7.3. Додаткові рівні

- CSRF-токен у кожній POST-формі, перевірка через `hmac.compare_digest`;
- `session.clear()` після входу — захист від session fixation;
- cookie: `HttpOnly`, `SameSite=Lax`, `Secure` вмикається через `.env`;
- єдине повідомлення про помилку входу — не розкриває, чи існує акаунт;
- dummy bcrypt-перевірка для неіснуючого користувача — вирівнює час
  відповіді та ускладнює user enumeration;
- security headers: `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`;
- пароль не логується і не повертається у відповідях.

---

## 8. Тестування

Встановіть dev-залежності:

```bash
pip install -r requirements-dev.txt
```

### Юніт- та інтеграційні тести

```bash
python -m unittest tests.test_security tests.test_database -v
```

Перевіряється:

- політика складності пароля;
- формат bcrypt `$2b$12$`;
- унікальність солей для однакових паролів;
- коректна/хибна перевірка пароля;
- наявність усіх полів схеми `users`;
- унікальність username/email без урахування регістру;
- SQLi-payload не повертає користувача та не змінює кількість записів.

### E2E-тести у браузері

```bash
python -m unittest tests.test_web_e2e -v
```

Використовується `unittest` + `selenium` + Microsoft Edge headless.
Перевіряються реальні кліки по формах, flash-повідомлення, dashboard,
блокування SQLi, CSRF та перемикач показу пароля.

**Результат на момент здачі:**

```text
Ran 25 tests ... OK   (security + database)
Ran 9 tests ... OK    (web E2E)
```

### SQLi-демонстрація вручну

1. Запустіть `python run.py`.
2. Відкрийте `/login`.
3. У поле «Ім'я користувача» введіть:

   ```text
   ' OR '1'='1
   ```

4. Пароль — будь-який.
5. Очікуваний результат: повідомлення
   «Невірне ім'я користувача або пароль.», редірект на `/login` відсутній,
   доступ до `/dashboard` не надається.

Додатково відкрийте `/security-lab`: стенд покаже `rows returned: 0` та
`injection blocked: true`.

---

## 9. Скриншоти та звіт

Автоматично згенерувати всі скриншоти:

```bash
python scripts/capture_screenshots.py
```

Файли з'являться у `docs/screenshots/`:

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

Повний звіт: [`docs/REPORT.md`](docs/REPORT.md).
Готова версія DOCX: `docs/Звіт_ЛР1_Secure_DocVault.docx`.

---

## 10. Git

Репозиторій ініціалізовано локально, перший стабільний коміт позначено тегом:

```bash
git tag
# v0.1-auth-db
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

## 11. Корисні команди

```bash
# створити демо-користувача
python scripts/seed_demo.py

# зробити HTML-знімок таблиці users
python scripts/db_snapshot.py

# перевірити health-check
# (у браузері або будь-яким HTTP-клієнтом)
http://127.0.0.1:5000/healthz

# скинути локальну БД
# зупиніть сервер і видаліть instance/docvault.db
```

---

## 12. Обмеження етапу 1

- немає JWT — це завдання ЛР №2;
- немає rate limiting / WAF — ЛР №4;
- немає шифрування файлів — ЛР №5;
- немає цифрових підписів — ЛР №6;
- SQLite обрано для локального навчального стенда; для production
  передбачається PostgreSQL/MySQL із тими самими параметризованими запитами.

---

## 13. Ліцензія

Навчальний проєкт. Використовуйте лише для освітніх цілей.
