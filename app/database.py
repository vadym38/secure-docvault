"""Робота з реляційною базою даних SQLite.

Ключовий принцип безпеки: жоден SQL-запит не будується конкатенацією або
f-рядком. Усі значення передаються окремим кортежем параметрів, тому СУБД
сприймає їх виключно як літерали (Prepared Statements).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g

# Схема повністю відповідає вимогам ЛР №1: id, username, email,
# password_hash, salt, role, created_at, is_active.
#
# Таблиці refresh_tokens і access_token_revocations додані у ЛР №2.
# Refresh-токени зберігаються як стан із життєвим циклом: active ->
# rotated / logout / reuse_detected. Саме це дозволяє реалізувати
# Refresh Token Rotation та виявляти повторне використання токена.
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

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_jti     ON refresh_tokens (jti);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family  ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user    ON refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS access_token_revocations (
    jti        TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at TEXT    NOT NULL,
    revoked_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reason     TEXT    NOT NULL DEFAULT 'logout',
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_revocations_user
    ON access_token_revocations (user_id);
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


# ---------------------------------------------------------------------------
# Стан Refresh-токенів та blacklist Access-токенів (ЛР №2)
# ---------------------------------------------------------------------------

def utc_iso(value: datetime | None = None) -> str:
    """Повертає UTC-час у форматі, який зберігається в SQLite."""

    value = value or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc(value: str) -> datetime:
    """Розбирає ISO-8601 UTC-рядок із бази у timezone-aware datetime."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def store_refresh_token(
    jti: str,
    family_id: str,
    user_id: int,
    issued_at: str,
    expires_at: str,
    user_agent: str | None = None,
) -> None:
    """Зберігає виданий Refresh-токен у стані active."""

    db = get_db()
    db.execute(
        """
        INSERT INTO refresh_tokens
            (jti, family_id, user_id, issued_at, expires_at, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (jti, family_id, user_id, issued_at, expires_at, user_agent),
    )
    db.commit()


def find_refresh_token(jti: str) -> sqlite3.Row | None:
    """Знаходить Refresh-токен за унікальним ідентифікатором jti."""

    return get_db().execute(
        """
        SELECT id, jti, family_id, user_id, issued_at, expires_at,
               revoked_at, revoked_reason, replaced_by_jti, user_agent
        FROM refresh_tokens
        WHERE jti = ?
        """,
        (jti,),
    ).fetchone()


def rotate_refresh_token(
    old_jti: str,
    new_jti: str,
    family_id: str,
    user_id: int,
    issued_at: str,
    expires_at: str,
    user_agent: str | None = None,
) -> bool:
    """Атомарно відкликає старий і зберігає новий Refresh-токен.

    Повертає False, якщо старий токен уже було використано/відкликано.
    Саме ця операція реалізує Refresh Token Rotation: один Refresh-токен
    може бути обміняний на нову пару рівно один раз.
    """

    db = get_db()
    revoked_at = utc_iso()

    try:
        with db:
            cursor = db.execute(
                """
                UPDATE refresh_tokens
                SET revoked_at = ?,
                    revoked_reason = 'rotated',
                    replaced_by_jti = ?
                WHERE jti = ? AND revoked_at IS NULL
                """,
                (revoked_at, new_jti, old_jti),
            )
            if cursor.rowcount != 1:
                return False

            db.execute(
                """
                INSERT INTO refresh_tokens
                    (jti, family_id, user_id, issued_at, expires_at, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (new_jti, family_id, user_id, issued_at, expires_at, user_agent),
            )
        return True
    except sqlite3.IntegrityError:
        # Колізія jti або інша проблема цілісності — транзакція відкотилась.
        return False


def revoke_refresh_token(
    jti: str,
    reason: str = "logout",
) -> int:
    """Відкликає один Refresh-токен, якщо він ще активний."""

    db = get_db()
    cursor = db.execute(
        """
        UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
        WHERE jti = ? AND revoked_at IS NULL
        """,
        (utc_iso(), reason, jti),
    )
    db.commit()
    return int(cursor.rowcount)


def revoke_refresh_family(family_id: str, reason: str = "reuse_detected") -> int:
    """Відкликає всі активні токени однієї родини.

    Викликається, коли виявлено повторне використання вже ротованого
    Refresh-токена: усі нащадки цієї родини вважаються скомпрометованими.
    """

    db = get_db()
    cursor = db.execute(
        """
        UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
        WHERE family_id = ? AND revoked_at IS NULL
        """,
        (utc_iso(), reason, family_id),
    )
    db.commit()
    return int(cursor.rowcount)


def revoke_all_user_refresh_tokens(user_id: int, reason: str = "logout") -> int:
    """Відкликає всі активні Refresh-токени користувача (logout everywhere)."""

    db = get_db()
    cursor = db.execute(
        """
        UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (utc_iso(), reason, user_id),
    )
    db.commit()
    return int(cursor.rowcount)


def revoke_access_token(
    jti: str,
    user_id: int,
    expires_at: str,
    reason: str = "logout",
) -> None:
    """Додає Access-токен до blacklist до моменту його природного exp."""

    db = get_db()
    db.execute(
        """
        INSERT OR REPLACE INTO access_token_revocations
            (jti, user_id, expires_at, reason)
        VALUES (?, ?, ?, ?)
        """,
        (jti, user_id, expires_at, reason),
    )
    db.commit()


def is_access_token_revoked(jti: str) -> bool:
    """Перевіряє, чи Access-токен уже відкликано (logout)."""

    row = get_db().execute(
        "SELECT 1 FROM access_token_revocations WHERE jti = ?",
        (jti,),
    ).fetchone()
    return row is not None


def list_refresh_tokens(limit: int = 20) -> list[sqlite3.Row]:
    """Повертає останні Refresh-токени для навчального знімка БД."""

    return list(
        get_db().execute(
            """
            SELECT rt.id, rt.jti, rt.family_id, rt.user_id, u.username,
                   rt.issued_at, rt.expires_at, rt.revoked_at,
                   rt.revoked_reason, rt.replaced_by_jti
            FROM refresh_tokens AS rt
            LEFT JOIN users AS u ON u.id = rt.user_id
            ORDER BY rt.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    )

