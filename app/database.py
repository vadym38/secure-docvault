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

-- ЛР №3: безпечні нотатки/описи документів. У поле description потрапляє
-- вже санітизований текст; сирий HTML не зберігається.
CREATE TABLE IF NOT EXISTS client_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    author          TEXT    NOT NULL DEFAULT 'guest',
    filename        TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    blocked_vectors TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_client_notes_created
    ON client_notes (created_at DESC);

-- ЛР №5: метадані зашифрованих документів. Сам вміст лежить на диску
-- у бінарному контейнері <uuid>.enc; у БД зберігаються лише метадані
-- та SHA-256 відкритого тексту для додаткової перевірки цілісності.
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

CREATE INDEX IF NOT EXISTS idx_documents_owner
    ON documents (owner_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_documents_created
    ON documents (created_at DESC);

-- ЛР №6: ключі підпису користувача. Приватний ключ зберігається лише
-- як PKCS#8 PEM, зашифрований парольною фразою користувача.
CREATE TABLE IF NOT EXISTS user_signing_keys (
    key_id                  TEXT    PRIMARY KEY,
    user_id                 INTEGER NOT NULL,
    algorithm               TEXT    NOT NULL,
    public_key_pem          TEXT    NOT NULL,
    private_key_pem_encrypted TEXT  NOT NULL,
    fingerprint             TEXT    NOT NULL,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_active               INTEGER NOT NULL DEFAULT 1
                            CHECK (is_active IN (0, 1)),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_user
    ON user_signing_keys (user_id, is_active);

-- ЛР №6: ЕЦП документа. Один підпис на документ; key_id дозволяє
-- перевірити старі підписи після ротації ключа.
CREATE TABLE IF NOT EXISTS document_signatures (
    document_id       TEXT    PRIMARY KEY,
    signer_id         INTEGER NOT NULL,
    key_id            TEXT    NOT NULL,
    algorithm         TEXT    NOT NULL,
    document_sha256   TEXT    NOT NULL,
    signature_b64     TEXT    NOT NULL,
    signed_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    verified_at       TEXT,
    status            TEXT    NOT NULL DEFAULT 'signed'
                      CHECK (status IN ('signed', 'verified', 'invalid')),
    FOREIGN KEY (document_id) REFERENCES documents (id) ON DELETE CASCADE,
    FOREIGN KEY (signer_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (key_id) REFERENCES user_signing_keys (key_id)
);
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


# ---------------------------------------------------------------------------
# Санітизовані нотатки клієнтської лабораторії (ЛР №3)
# ---------------------------------------------------------------------------

def create_client_note(
    author: str,
    filename: str,
    description: str,
    blocked_vectors: str = "",
) -> int:
    """Зберігає вже санітизований опис документа."""

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO client_notes (author, filename, description, blocked_vectors)
        VALUES (?, ?, ?, ?)
        """,
        (author, filename, description, blocked_vectors),
    )
    db.commit()
    return int(cursor.lastrowid)


def list_client_notes(limit: int = 8) -> list[sqlite3.Row]:
    """Повертає останні безпечні нотатки для стенда."""

    return list(
        get_db().execute(
            """
            SELECT id, author, filename, description, blocked_vectors, created_at
            FROM client_notes
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    )


# ---------------------------------------------------------------------------
# Метадані зашифрованих документів (ЛР №5)
# ---------------------------------------------------------------------------

def create_document(
    *,
    doc_id: str,
    owner_id: int,
    original_filename: str,
    stored_filename: str,
    content_type: str,
    original_size: int,
    encrypted_size: int,
    sha256: str,
) -> None:
    """Зберігає метадані документа; вміст уже лежить у .enc-контейнері."""

    db = get_db()
    db.execute(
        """
        INSERT INTO documents (
            id, owner_id, original_filename, stored_filename,
            content_type, original_size, encrypted_size, sha256
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            doc_id,
            owner_id,
            original_filename,
            stored_filename,
            content_type,
            original_size,
            encrypted_size,
            sha256,
        ),
    )
    db.commit()


def get_document(doc_id: str) -> sqlite3.Row | None:
    """Повертає метадані одного документа за UUID."""

    return get_db().execute(
        """
        SELECT d.*, u.username AS owner_username,
               s.status AS signature_status,
               s.algorithm AS signature_algorithm,
               s.signed_at AS signature_signed_at,
               s.verified_at AS signature_verified_at,
               s.key_id AS signature_key_id,
               s.signer_id AS signature_signer_id,
               s.signature_b64 AS signature_b64,
               s.document_sha256 AS signature_document_sha256
        FROM documents AS d
        LEFT JOIN users AS u ON u.id = d.owner_id
        LEFT JOIN document_signatures AS s ON s.document_id = d.id
        WHERE d.id = ?
        """,
        (doc_id,),
    ).fetchone()


def list_documents_for_user(
    owner_id: int,
    *,
    is_admin: bool = False,
    limit: int = 50,
) -> list[sqlite3.Row]:
    """Повертає документи власника (або всі для адміністратора)."""

    db = get_db()
    if is_admin:
        rows = db.execute(
            """
            SELECT d.*, u.username AS owner_username,
                   s.status AS signature_status,
                   s.algorithm AS signature_algorithm,
                   s.signed_at AS signature_signed_at,
                   s.verified_at AS signature_verified_at,
                   s.key_id AS signature_key_id,
                   s.signer_id AS signature_signer_id,
                   s.signature_b64 AS signature_b64,
                   s.document_sha256 AS signature_document_sha256
            FROM documents AS d
            LEFT JOIN users AS u ON u.id = d.owner_id
            LEFT JOIN document_signatures AS s ON s.document_id = d.id
            ORDER BY d.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT d.*, u.username AS owner_username,
                   s.status AS signature_status,
                   s.algorithm AS signature_algorithm,
                   s.signed_at AS signature_signed_at,
                   s.verified_at AS signature_verified_at,
                   s.key_id AS signature_key_id,
                   s.signer_id AS signature_signer_id,
                   s.signature_b64 AS signature_b64,
                   s.document_sha256 AS signature_document_sha256
            FROM documents AS d
            LEFT JOIN users AS u ON u.id = d.owner_id
            LEFT JOIN document_signatures AS s ON s.document_id = d.id
            WHERE d.owner_id = ?
            ORDER BY d.created_at DESC
            LIMIT ?
            """,
            (owner_id, limit),
        ).fetchall()
    return list(rows)


def delete_document(doc_id: str) -> bool:
    """Видаляє метадані; файл видаляє сервісний шар."""

    db = get_db()
    cursor = db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    db.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Ключі підпису та ЕЦП документів (ЛР №6)
# ---------------------------------------------------------------------------

def deactivate_user_signing_keys(user_id: int) -> None:
    db = get_db()
    db.execute(
        "UPDATE user_signing_keys SET is_active = 0 "
        "WHERE user_id = ? AND is_active = 1",
        (user_id,),
    )
    db.commit()


def create_signing_key(
    *,
    key_id: str,
    user_id: int,
    algorithm: str,
    public_key_pem: str,
    private_key_pem_encrypted: str,
    fingerprint: str,
) -> None:
    db = get_db()
    db.execute(
        "UPDATE user_signing_keys SET is_active = 0 WHERE user_id = ?",
        (user_id,),
    )
    db.execute(
        """
        INSERT INTO user_signing_keys (
            key_id, user_id, algorithm, public_key_pem,
            private_key_pem_encrypted, fingerprint, is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, 1)
        """,
        (
            key_id,
            user_id,
            algorithm,
            public_key_pem,
            private_key_pem_encrypted,
            fingerprint,
        ),
    )
    db.commit()


def get_active_signing_key(user_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        """
        SELECT * FROM user_signing_keys
        WHERE user_id = ? AND is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def get_signing_key(key_id: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT * FROM user_signing_keys WHERE key_id = ?",
        (key_id,),
    ).fetchone()


def list_signing_keys(user_id: int) -> list[sqlite3.Row]:
    return list(
        get_db().execute(
            """
            SELECT key_id, user_id, algorithm, public_key_pem,
                   fingerprint, created_at, is_active
            FROM user_signing_keys
            WHERE user_id = ?
            ORDER BY is_active DESC, created_at DESC
            """,
            (user_id,),
        ).fetchall()
    )


def create_document_signature(
    *,
    document_id: str,
    signer_id: int,
    key_id: str,
    algorithm: str,
    document_sha256: str,
    signature_b64: str,
) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO document_signatures (
            document_id, signer_id, key_id, algorithm,
            document_sha256, signature_b64, status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'signed')
        ON CONFLICT(document_id) DO UPDATE SET
            signer_id = excluded.signer_id,
            key_id = excluded.key_id,
            algorithm = excluded.algorithm,
            document_sha256 = excluded.document_sha256,
            signature_b64 = excluded.signature_b64,
            signed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            verified_at = NULL,
            status = 'signed'
        """,
        (
            document_id,
            signer_id,
            key_id,
            algorithm,
            document_sha256,
            signature_b64,
        ),
    )
    db.commit()


def get_document_signature(document_id: str) -> sqlite3.Row | None:
    return get_db().execute(
        """
        SELECT s.*, u.username AS signer_username,
               k.public_key_pem, k.fingerprint AS key_fingerprint
        FROM document_signatures AS s
        LEFT JOIN users AS u ON u.id = s.signer_id
        LEFT JOIN user_signing_keys AS k ON k.key_id = s.key_id
        WHERE s.document_id = ?
        """,
        (document_id,),
    ).fetchone()


def mark_document_signature_verified(document_id: str, status: str) -> None:
    if status not in {"signed", "verified", "invalid"}:
        raise ValueError("Некоректний статус підпису.")
    db = get_db()
    db.execute(
        """
        UPDATE document_signatures
        SET status = ?,
            verified_at = CASE
                WHEN ? = 'verified' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHEN ? = 'invalid' THEN NULL
                ELSE verified_at
            END
        WHERE document_id = ?
        """,
        (status, status, status, document_id),
    )
    db.commit()


def list_document_signatures(user_id: int, limit: int = 20) -> list[sqlite3.Row]:
    return list(
        get_db().execute(
            """
            SELECT s.document_id, s.signer_id, s.algorithm, s.document_sha256,
                   s.signature_b64, s.signed_at, s.verified_at, s.status,
                   s.key_id, d.original_filename,
                   k.fingerprint AS key_fingerprint
            FROM document_signatures AS s
            JOIN documents AS d ON d.id = s.document_id
            LEFT JOIN user_signing_keys AS k ON k.key_id = s.key_id
            WHERE s.signer_id = ?
            ORDER BY s.signed_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    )


