"""Юніт-тести криптографічного та валідаційного шару.

Запуск:
    python -m unittest tests.test_security -v
"""

from __future__ import annotations

import unittest

from app.auth_security import (
    hash_password,
    validate_email,
    validate_password,
    validate_username,
    verify_password,
)


class PasswordPolicyTests(unittest.TestCase):
    def test_strong_password_is_accepted(self):
        self.assertEqual(validate_password("Vault#2026"), [])

    def test_short_password_is_rejected(self):
        errors = validate_password("Aa1#")
        self.assertTrue(any("8 символів" in error for error in errors))

    def test_password_without_uppercase_is_rejected(self):
        errors = validate_password("vault#2026")
        self.assertTrue(any("велику літеру" in error for error in errors))

    def test_password_without_lowercase_is_rejected(self):
        errors = validate_password("VAULT#2026")
        self.assertTrue(any("малу літеру" in error for error in errors))

    def test_password_without_digit_is_rejected(self):
        errors = validate_password("Vault#Secret")
        self.assertTrue(any("цифру" in error for error in errors))

    def test_password_without_special_character_is_rejected(self):
        errors = validate_password("Vault2026")
        self.assertTrue(any("спеціальний символ" in error for error in errors))

    def test_password_over_72_bytes_is_rejected(self):
        errors = validate_password("Aa1#" + "x" * 80)
        self.assertTrue(any("72 байти" in error for error in errors))


class UsernameAndEmailTests(unittest.TestCase):
    def test_valid_username(self):
        self.assertEqual(validate_username("o.kravets"), [])

    def test_username_with_spaces_is_rejected(self):
        self.assertTrue(validate_username("o kravets"))

    def test_username_too_short_is_rejected(self):
        self.assertTrue(validate_username("ab"))

    def test_valid_email(self):
        self.assertEqual(validate_email("student@example.com"), [])

    def test_invalid_email_is_rejected(self):
        self.assertTrue(validate_email("not-an-email"))


class HashingTests(unittest.TestCase):
    def test_hash_uses_bcrypt_cost_12(self):
        digest, salt = hash_password("Vault#2026")
        self.assertTrue(digest.startswith("$2b$12$"))
        self.assertTrue(salt.startswith("$2b$12$"))
        self.assertNotIn("Vault#2026", digest)

    def test_same_password_gets_unique_salt_and_hash(self):
        first_hash, first_salt = hash_password("Vault#2026")
        second_hash, second_salt = hash_password("Vault#2026")

        self.assertNotEqual(first_hash, second_hash)
        self.assertNotEqual(first_salt, second_salt)

    def test_verify_accepts_correct_password(self):
        digest, _ = hash_password("Vault#2026")
        self.assertTrue(verify_password("Vault#2026", digest))

    def test_verify_rejects_wrong_password(self):
        digest, _ = hash_password("Vault#2026")
        self.assertFalse(verify_password("Vault#2027", digest))

    def test_verify_rejects_malformed_hash(self):
        self.assertFalse(verify_password("Vault#2026", "not-a-bcrypt-hash"))


if __name__ == "__main__":
    unittest.main()
