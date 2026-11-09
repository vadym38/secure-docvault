"""Юніт-тести AES-256-GCM контейнера (ЛР №5).

Запуск:
    python -m unittest tests.test_file_crypto -v
"""

from __future__ import annotations

import unittest

from cryptography.exceptions import InvalidTag

from app.file_crypto import (
    KEY_SIZE,
    MIN_CONTAINER_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    FileCipher,
    make_aad,
    parse_key_material,
)

KEY_A = bytes.fromhex("11" * 32)
KEY_B = bytes.fromhex("22" * 32)
AAD = b"docvault|file|v1|doc-1|1"


class KeyMaterialTests(unittest.TestCase):
    def test_valid_hex_key(self):
        self.assertEqual(parse_key_material("11" * 32), KEY_A)

    def test_invalid_hex_key(self):
        self.assertIsNone(parse_key_material("zz" * 32))
        self.assertIsNone(parse_key_material("11" * 31))
        self.assertIsNone(parse_key_material(""))

    def test_raw_key(self):
        self.assertEqual(parse_key_material(KEY_A), KEY_A)

    def test_make_aad_binds_document_and_owner(self):
        self.assertIn(b"doc-1", make_aad("doc-1", 1))
        self.assertNotEqual(make_aad("doc-1", 1), make_aad("doc-2", 1))
        self.assertNotEqual(make_aad("doc-1", 1), make_aad("doc-1", 2))


class ContainerFormatTests(unittest.TestCase):
    def setUp(self):
        self.cipher = FileCipher([KEY_A])

    def test_container_layout(self):
        plaintext = b"CONFIDENTIAL FINANCIAL REPORT"
        container = self.cipher.encrypt(plaintext, AAD)

        self.assertEqual(len(container), MIN_CONTAINER_SIZE + len(plaintext))
        self.assertEqual(len(container[:NONCE_SIZE]), 12)
        self.assertEqual(len(container[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]), 16)

        parts = self.cipher.parse_container(container)
        self.assertEqual(len(parts.nonce), 12)
        self.assertEqual(len(parts.tag), 16)
        self.assertEqual(parts.ciphertext, container[28:])

    def test_ciphertext_does_not_contain_plaintext(self):
        plaintext = b"CONFIDENTIAL FINANCIAL REPORT - SECURE DOCVAULT 2026"
        container = self.cipher.encrypt(plaintext, AAD)
        self.assertNotIn(b"CONFIDENTIAL", container)
        self.assertNotIn(plaintext, container)

    def test_nonce_is_unique_for_each_encryption(self):
        nonces = {
            self.cipher.encrypt(b"same data", AAD)[:NONCE_SIZE]
            for _ in range(100)
        }
        self.assertEqual(len(nonces), 100)

    def test_empty_plaintext_is_supported(self):
        container = self.cipher.encrypt(b"", AAD)
        self.assertEqual(len(container), MIN_CONTAINER_SIZE)
        self.assertEqual(self.cipher.decrypt(container, AAD), b"")

    def test_short_container_is_rejected(self):
        with self.assertRaises(ValueError):
            self.cipher.decrypt(b"too-short", AAD)


class DecryptionTests(unittest.TestCase):
    def setUp(self):
        self.cipher = FileCipher([KEY_A])
        self.plaintext = b"CONFIDENTIAL FINANCIAL REPORT 2026"
        self.container = self.cipher.encrypt(self.plaintext, AAD)

    def test_roundtrip(self):
        self.assertEqual(self.cipher.decrypt(self.container, AAD), self.plaintext)

    def test_wrong_key_raises_invalid_tag(self):
        with self.assertRaises(InvalidTag):
            FileCipher([KEY_B]).decrypt(self.container, AAD)

    def test_wrong_aad_raises_invalid_tag(self):
        with self.assertRaises(InvalidTag):
            self.cipher.decrypt(self.container, b"another-aad")

    def test_tampered_nonce_raises_invalid_tag(self):
        blob = bytearray(self.container)
        blob[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            self.cipher.decrypt(bytes(blob), AAD)

    def test_tampered_tag_raises_invalid_tag(self):
        blob = bytearray(self.container)
        blob[NONCE_SIZE] ^= 0xFF
        with self.assertRaises(InvalidTag):
            self.cipher.decrypt(bytes(blob), AAD)

    def test_tampered_ciphertext_raises_invalid_tag(self):
        blob = bytearray(self.container)
        blob[-1] ^= 0xFF
        with self.assertRaises(InvalidTag):
            self.cipher.decrypt(bytes(blob), AAD)

    def test_key_rotation_uses_old_key(self):
        old_container = FileCipher([KEY_A]).encrypt(b"old document", AAD)
        rotated = FileCipher([KEY_B, KEY_A])
        self.assertEqual(rotated.decrypt(old_container, AAD), b"old document")
        self.assertNotEqual(rotated.fingerprint, FileCipher([KEY_A]).fingerprint)

    def test_describe_returns_metadata(self):
        description = self.cipher.describe(self.container)
        self.assertEqual(description["nonce_size"], 12)
        self.assertEqual(description["tag_size"], 16)
        self.assertEqual(description["ciphertext_size"], len(self.plaintext))
        self.assertIn("nonce_hex", description)


class CipherConstructionTests(unittest.TestCase):
    def test_requires_a_key(self):
        with self.assertRaises(ValueError):
            FileCipher([])

    def test_rejects_wrong_key_size(self):
        with self.assertRaises(ValueError):
            FileCipher([b"x" * (KEY_SIZE - 1)])

    def test_key_count_and_fingerprint(self):
        cipher = FileCipher([KEY_A, KEY_B])
        self.assertEqual(cipher.key_count, 2)
        self.assertEqual(len(cipher.fingerprint), 16)


if __name__ == "__main__":
    unittest.main()
