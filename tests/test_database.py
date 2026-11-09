"""Інтеграційні тести схеми та параметризованих запитів SQLite.

Запуск:
    python -m unittest tests.test_database -v
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.auth_security import hash_password
from app.config import Config
from app.database import (
    count_users,
    create_user,
    find_user_by_id,
    find_user_by_username,
    get_db,
)


class DatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-db-"))
        cls.db_path = cls.temp_dir / "test.db"

        test_config = type(
            "TestConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "test-secret-key",
                "JWT_SECRET_KEY": "test-jwt-secret-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.db_path),
                "BCRYPT_ROUNDS": 4,
                "SESSION_COOKIE_SECURE": False,
            },
        )

        cls.app = create_app(test_config)
        cls.context = cls.app.app_context()
        cls.context.push()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        db = get_db()
        db.execute("DELETE FROM users")
        db.commit()

    def _create_demo_user(self, username="o.kravets", email="o.kravets@example.com"):
        password_hash, salt = hash_password("Vault#2026", rounds=4)
        return create_user(username, email, password_hash, salt)

    def test_schema_contains_all_required_fields(self):
        columns = {
            row["name"]
            for row in get_db().execute("PRAGMA table_info(users)").fetchall()
        }
        self.assertEqual(
            columns,
            {
                "id",
                "username",
                "email",
                "password_hash",
                "salt",
                "role",
                "created_at",
                "is_active",
            },
        )

    def test_create_and_find_user(self):
        user_id = self._create_demo_user()
        user = find_user_by_username("o.kravets")

        self.assertIsNotNone(user)
        self.assertEqual(user["id"], user_id)
        self.assertEqual(user["username"], "o.kravets")
        self.assertEqual(user["email"], "o.kravets@example.com")
        self.assertEqual(user["role"], "user")
        self.assertEqual(user["is_active"], 1)
        self.assertTrue(user["password_hash"].startswith("$2b$04$"))
        self.assertTrue(user["salt"].startswith("$2b$04$"))
        self.assertEqual(count_users(), 1)

    def test_find_user_by_id(self):
        user_id = self._create_demo_user()
        user = find_user_by_id(user_id)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "o.kravets")

    def test_username_lookup_is_case_insensitive(self):
        self._create_demo_user()
        user = find_user_by_username("O.KRAVETS")
        self.assertIsNotNone(user)

    def test_duplicate_username_is_rejected(self):
        self._create_demo_user()
        password_hash, salt = hash_password("Other#2026", rounds=4)

        with self.assertRaises(sqlite3.IntegrityError):
            create_user("O.KRAVETS", "other@example.com", password_hash, salt)

    def test_duplicate_email_is_rejected(self):
        self._create_demo_user()
        password_hash, salt = hash_password("Other#2026", rounds=4)

        with self.assertRaises(sqlite3.IntegrityError):
            create_user("other.user", "O.KRAVETS@EXAMPLE.COM", password_hash, salt)

    def test_sql_injection_payload_returns_no_user(self):
        self._create_demo_user()
        self.assertIsNone(find_user_by_username("' OR '1'='1"))
        self.assertIsNone(find_user_by_username("admin'--"))
        self.assertIsNone(find_user_by_username("' UNION SELECT 1,2,3--"))

    def test_sql_injection_does_not_change_user_count(self):
        self._create_demo_user()
        before = count_users()
        find_user_by_username("' OR '1'='1")
        self.assertEqual(count_users(), before)


if __name__ == "__main__":
    unittest.main()
