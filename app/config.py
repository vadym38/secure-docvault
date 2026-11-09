"""Конфігурація застосунку Secure DocVault (етап 4).

Усі секрети та шляхи читаються зі змінних оточення. Для локального запуску
використовуйте файл .env (див. .env.example). У виробничому середовищі
обов'язково задайте власні SECRET_KEY і JWT_SECRET_KEY, увімкніть
SESSION_COOKIE_SECURE, обмежте CORS_ALLOWED_ORIGINS та налаштуйте
WAF/rate limiting під реальний профіль трафіку.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Базова конфігурація для локального середовища та навчального проєкту."""

    # Секретний ключ підписує сесійну cookie. Значення за замовчуванням
    # призначене ВИКЛЮЧНО для локального запуску; у .env його треба замінити.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key")

    # Шлях до SQLite-бази. За замовчуванням — instance/docvault.db.
    DATABASE = os.environ.get(
        "DOCVAULT_DB",
        str(BASE_DIR / "instance" / "docvault.db"),
    )

    # Вартість bcrypt (work factor). 12 — безпечний мінімум для 2026 року.
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

    # Безпека сесійної cookie (ЛР №3).
    SESSION_COOKIE_NAME = "docvault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ------------------------------------------------------------------
    # Клієнтський захист / CORS (ЛР №3)
    # ------------------------------------------------------------------

    # Явний whitelist Origin. Wildcard '*' навмисно не підтримується.
    CORS_ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.environ.get(
            "CORS_ALLOWED_ORIGINS",
            "http://127.0.0.1:5000,http://localhost:5000,"
            "https://127.0.0.1:5000,https://localhost:5000",
        ).split(",")
        if origin.strip()
    ]

    # Обмеження довжини текстових полів лабораторії санітизації.
    CLIENT_LAB_MAX_TEXT = int(os.environ.get("CLIENT_LAB_MAX_TEXT", "2000"))

    # Обмеження розміру запиту: форми автентифікації не потребують великих тіл.
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    # ------------------------------------------------------------------
    # WAF та Rate Limiting (ЛР №4)
    # ------------------------------------------------------------------

    # Головні вимикачі. У тестах вони вимикаються, щоб не впливати на
    # сценарії ЛР №1–3; Lab 4-тести вмикають їх явно.
    WAF_ENABLED = os.environ.get("WAF_ENABLED", "1") == "1"
    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1") == "1"

    # Диференційовані ліміти (Sliding Window Log).
    RATE_LIMIT_LOGIN_LIMIT = int(os.environ.get("RATE_LIMIT_LOGIN_LIMIT", "5"))
    RATE_LIMIT_LOGIN_WINDOW = int(os.environ.get("RATE_LIMIT_LOGIN_WINDOW", "60"))
    RATE_LIMIT_API_LIMIT = int(os.environ.get("RATE_LIMIT_API_LIMIT", "60"))
    RATE_LIMIT_API_WINDOW = int(os.environ.get("RATE_LIMIT_API_WINDOW", "60"))
    RATE_LIMIT_WEB_LIMIT = int(os.environ.get("RATE_LIMIT_WEB_LIMIT", "120"))
    RATE_LIMIT_WEB_WINDOW = int(os.environ.get("RATE_LIMIT_WEB_WINDOW", "60"))

    # Захист пам'яті лічильників від Memory Exhaustion DoS.
    RATE_LIMIT_MAX_KEYS = int(os.environ.get("RATE_LIMIT_MAX_KEYS", "10000"))
    RATE_LIMIT_KEY_TTL_SECONDS = int(
        os.environ.get("RATE_LIMIT_KEY_TTL_SECONDS", "600")
    )

    # WAF.
    WAF_GREYLIST_SECONDS = int(os.environ.get("WAF_GREYLIST_SECONDS", "300"))
    WAF_MAX_BODY_INSPECT = int(
        os.environ.get("WAF_MAX_BODY_INSPECT", str(64 * 1024))
    )
    SECURITY_LOG_CAPACITY = int(os.environ.get("SECURITY_LOG_CAPACITY", "200"))

    # Довіряти X-Forwarded-For можна лише за довіреним reverse-proxy.
    # Інакше клієнт підробить IP і обійде ліміт.
    TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "0") == "1"

    # Лабораторна кнопка Reset для /waf-lab. У production — False.
    WAF_LAB_ALLOW_RESET = os.environ.get("WAF_LAB_ALLOW_RESET", "1") == "1"

    # ------------------------------------------------------------------
    # JWT / Stateless API (ЛР №2)
    # ------------------------------------------------------------------

    # Ключ підпису JWT. Мінімум 256 біт (32 байти). Порожнє значення
    # змушує застосунок завершитися з помилкою — секрет не має fallback.
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
    JWT_ALGORITHM = "HS256"
    JWT_ISSUER = "secure-docvault"
    JWT_AUDIENCE = "secure-docvault-api"
    JWT_ACCESS_TTL_SECONDS = int(os.environ.get("JWT_ACCESS_TTL_SECONDS", "900"))
    JWT_REFRESH_TTL_SECONDS = int(
        os.environ.get("JWT_REFRESH_TTL_SECONDS", str(7 * 24 * 60 * 60))
    )
    JWT_LEEWAY_SECONDS = int(os.environ.get("JWT_LEEWAY_SECONDS", "5"))

    TEMPLATES_AUTO_RELOAD = True
