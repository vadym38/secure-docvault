"""Конфігурація застосунку Secure DocVault (етап 2).

Усі секрети та шляхи читаються зі змінних оточення. Для локального запуску
використовуйте файл .env (див. .env.example). У виробничому середовищі
обов'язково задайте власні SECRET_KEY і JWT_SECRET_KEY та увімкніть
SESSION_COOKIE_SECURE.
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

    # Безпека сесійної cookie.
    SESSION_COOKIE_NAME = "docvault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Обмеження розміру запиту: форми автентифікації не потребують великих тіл.
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

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
