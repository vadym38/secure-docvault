"""Конфігурація застосунку Secure DocVault (етап 1).

Усі секрети та шляхи читаються зі змінних оточення. Для локального запуску
використовуйте файл .env (див. .env.example). У виробничому середовищі
обов'язково задайте власний SECRET_KEY і увімкніть SESSION_COOKIE_SECURE.
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

    TEMPLATES_AUTO_RELOAD = True
