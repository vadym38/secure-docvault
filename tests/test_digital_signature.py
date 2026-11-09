"""Юніт-тести RSA-PSS ЕЦП та ключів (ЛР №6).

Запуск:
    python -m unittest tests.test_digital_signature -v
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import hashes, serialization

from app import digital_signature as ds


class KeyGenerationTests(unittest.TestCase):
    def setUp(self):
        self.passphrase = "Sigil#2026!"
        self.private_key, self.public_key = ds.generate_keypair()

    def test_rsa_key_size_and_exponent(self):
        numbers = self.private_key.private_numbers()
        self.assertEqual(numbers.public_numbers.n.bit_length(), 2048)
        self.assertEqual(numbers.public_numbers.e, 65537)

    def test_public_pem_is_x509_spki(self):
        pem = ds.serialize_public_pem(self.public_key)
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        loaded = ds.load_public_pem(pem)
        self.assertEqual(
            loaded.public_numbers().n,
            self.public_key.public_numbers().n,
        )

    def test_private_pem_is_encrypted_pkcs8(self):
        pem = ds.serialize_private_pem(self.private_key, self.passphrase)
        self.assertTrue(
            pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        )
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", pem)

    def test_private_pem_loads_with_correct_passphrase(self):
        pem = ds.serialize_private_pem(self.private_key, self.passphrase)
        loaded = ds.load_private_pem(pem, self.passphrase)
        self.assertEqual(
            loaded.private_numbers().d,
            self.private_key.private_numbers().d,
        )

    def test_private_pem_rejects_wrong_passphrase(self):
        pem = ds.serialize_private_pem(self.private_key, self.passphrase)
        with self.assertRaises((ValueError, TypeError)):
            ds.load_private_pem(pem, "Wrong#2026!")

    def test_short_passphrase_is_rejected(self):
        with self.assertRaises(ValueError):
            ds.validate_passphrase("short")
        with self.assertRaises(ValueError):
            ds.serialize_private_pem(self.private_key, "")

    def test_fingerprint_is_sha256_of_spki(self):
        fingerprint = ds.public_key_fingerprint(self.public_key)
        self.assertEqual(len(fingerprint), 64)
        self.assertEqual(
            fingerprint,
            ds.fingerprint_from_pem(ds.serialize_public_pem(self.public_key)),
        )

    def test_generate_keypair_pem_helper(self):
        pair = ds.generate_keypair_pem(self.passphrase)
        self.assertTrue(pair.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(
            pair.private_key_pem_encrypted.startswith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            )
        )
        self.assertEqual(len(pair.fingerprint), 64)


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.passphrase = "Sigil#2026!"
        self.private_key, self.public_key = ds.generate_keypair()
        self.document = (
            b"OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n"
        )

    def test_sign_and_verify_document(self):
        signature = ds.sign_document(self.document, self.private_key)
        self.assertTrue(
            ds.verify_document(self.document, signature, self.public_key)
        )

    def test_signature_has_rsa_2048_size(self):
        signature = ds.sign_document(self.document, self.private_key)
        self.assertEqual(len(signature), 256)

    def test_tampered_document_is_rejected(self):
        signature = ds.sign_document(self.document, self.private_key)
        tampered = self.document.replace(b"APPROVED", b"REJECTED")
        self.assertFalse(
            ds.verify_document(tampered, signature, self.public_key)
        )

    def test_single_byte_change_is_rejected(self):
        signature = ds.sign_document(self.document, self.private_key)
        tampered = bytearray(self.document)
        tampered[0] ^= 0x01
        self.assertFalse(
            ds.verify_document(bytes(tampered), signature, self.public_key)
        )

    def test_tampered_signature_is_rejected(self):
        signature = bytearray(
            ds.sign_document(self.document, self.private_key)
        )
        signature[10] ^= 0xFF
        self.assertFalse(
            ds.verify_document(self.document, bytes(signature), self.public_key)
        )

    def test_wrong_public_key_is_rejected(self):
        signature = ds.sign_document(self.document, self.private_key)
        _other_private, other_public = ds.generate_keypair()
        self.assertFalse(
            ds.verify_document(self.document, signature, other_public)
        )

    def test_pss_is_probabilistic(self):
        first = ds.sign_document(self.document, self.private_key)
        second = ds.sign_document(self.document, self.private_key)
        self.assertNotEqual(first, second)
        self.assertTrue(
            ds.verify_document(self.document, first, self.public_key)
        )
        self.assertTrue(
            ds.verify_document(self.document, second, self.public_key)
        )

    def test_digest_is_sha256(self):
        digest = ds.sha256_digest(self.document)
        self.assertEqual(len(digest), 32)
        direct = hashes.Hash(hashes.SHA256())
        direct.update(self.document)
        self.assertEqual(digest, direct.finalize())

    def test_prehashed_signature_matches_document_signature(self):
        digest = ds.sha256_digest(self.document)
        signature = ds.sign_digest(digest, self.private_key)
        self.assertTrue(ds.verify_digest(digest, signature, self.public_key))
        self.assertTrue(
            ds.verify_document(self.document, signature, self.public_key)
        )

    def test_signature_base64_roundtrip(self):
        signature = ds.sign_document(self.document, self.private_key)
        encoded = ds.signature_to_b64(signature)
        self.assertEqual(ds.signature_from_b64(encoded), signature)


if __name__ == "__main__":
    unittest.main()
