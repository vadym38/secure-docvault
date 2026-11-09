"""Робота з реляційною базою даних SQLite.

Ключовий принцип безпеки: жоден SQL-запит не будується конкатенацією або
f-рядком. Усі значення передаються окремим кортежем параметрів, тому СУБД
сприймає їх виключно як літерали (Prepared Statements).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app, g

# Схема повністю відповідає вимогам ЛР №1: id, username, email,
# password_hash, salt, role, created_at, is_active.
SCHEMA = """
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

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users (email);
"""


def get_db() -> sqlite3.Connection:
    """Повертає одне з'єднання на поточний контекст Flask."""

    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(str(db_path), timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        g.db = connection

    return g.db


def close_db(_exception: BaseException | None = None) -> None:
    """Закриває з'єднання після завершення запиту."""

    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    """Створює таблицю users та індекси, якщо їх ще немає."""

    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app) -> None:
    """Реєструє обробники життєвого циклу БД у Flask-застосунку."""

    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()


def create_user(
    username: str,
    email: str,
    password_hash: str,
    salt: str,
    role: str = "user",
) -> int:
    """Додає користувача через параметризований INSERT.

    Знаки питання — це місця для bound parameters. SQLite не інтерпретує
    вміст кортежу як SQL-код, навіть якщо там є лапки, коментарі чи UNION.
    """

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO users (username, email, password_hash, salt, role)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, password_hash, salt, role),
    )
    db.commit()
    return int(cursor.lastrowid)


def find_user_by_username(username: str) -> sqlite3.Row | None:
    """Шукає користувача за іменем через Prepared Statement.

    Саме цей запит використовується і для входу, і для демонстрації SQLi:
    payload ' OR '1'='1 ніколи не стане частиною SQL-синтаксису.
    """

    return get_db().execute(
        """
        SELECT id, username, email, password_hash, salt, role, created_at, is_active
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def find_user_by_id(user_id: int) -> sqlite3.Row | None:
    """Повертає користувача за первинним ключем (для відновлення сесії)."""

    return get_db().execute(
        """
        SELECT id, username, email, password_hash, salt, role, created_at, is_active
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def count_users() -> int:
    """Кількість зареєстрованих акаунтів (для службових сторінок)."""

    row = get_db().execute("SELECT COUNT(*) AS total FROM users").fetchone()
    return int(row["total"]) if row else 0
