"""Інтеграційні тести ЕЦП документів (ЛР №6).

Перевіряють генерацію ключів, PKCS#8/X.509 PEM, підписання, збереження
підпису в БД, статус Signed & Verified у download API, виявлення
фальсифікації та IDOR.

Запуск:
    python -m unittest tests.test_signatures -v
"""

from __future__ import annotations

import base64
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app import digital_signature as ds
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user, get_db

PASSWORD = "Vault#2026!"
PASSPHRASE = "Sigil#2026!"
PLAINTEXT = b"OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n"


class DigitalSignatureFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab6-"))
        cls.storage_dir = cls.temp_dir / "vault"
        test_config = type(
            "Lab6Config",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab6-secret-key",
                "JWT_SECRET_KEY": "lab6-jwt-secret-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab6.db"),
                "DOCUMENT_STORAGE_DIR": str(cls.storage_dir),
                "FILE_ENCRYPTION_KEY": "88" * 32,
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "MAX_DOCUMENT_BYTES": 1024 * 1024,
            },
        )
        cls.app = create_app(test_config)
        with cls.app.app_context():
            for username, email, role in (
                ("owner", "owner@example.com", "user"),
                ("other", "other@example.com", "user"),
                ("admin", "admin@example.com", "admin"),
            ):
                digest, salt = hash_password(PASSWORD, rounds=4)
                create_user(username, email, digest, salt, role=role)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM document_signatures")
            db.execute("DELETE FROM user_signing_keys")
            db.execute("DELETE FROM documents")
            db.commit()
        for path in self.storage_dir.glob("*.enc"):
            path.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Допоміжні
    # ------------------------------------------------------------------

    def _headers(self, username: str = "owner") -> dict:
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        return {
            "Authorization": f"Bearer {response.get_json()['access_token']}"
        }

    def _generate_key(self, username: str = "owner") -> dict:
        response = self.client.post(
            "/api/v1/keys/generate",
            headers=self._headers(username),
            json={"passphrase": PASSPHRASE},
        )
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()["key"]

    def _upload(self, username: str = "owner", content: bytes = PLAINTEXT):
        response = self.client.post(
            "/api/v1/documents/upload",
            headers=self._headers(username),
            data={"file": (io.BytesIO(content), "statement.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        return response.get_json()["document"]

    def _sign(self, doc_id: str, username: str = "owner", passphrase: str = PASSPHRASE):
        return self.client.post(
            f"/api/v1/documents/{doc_id}/sign",
            headers=self._headers(username),
            json={"passphrase": passphrase},
        )

    def _csrf_from(self, path: str) -> str:
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def _session_login(self, username: str = "owner") -> None:
        token = self._csrf_from("/login")
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": username,
                "password": PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 302)

    # ------------------------------------------------------------------
    # Ключі
    # ------------------------------------------------------------------

    def test_generate_key_returns_pem_and_stores_encrypted_private_key(self):
        key = self._generate_key()

        self.assertEqual(key["algorithm"], ds.ALGORITHM)
        self.assertTrue(key["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(
            key["private_key_pem_encrypted"].startswith(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            )
        )
        self.assertEqual(len(key["fingerprint"]), 64)

        with self.app.app_context():
            row = get_db().execute(
                "SELECT * FROM user_signing_keys WHERE key_id = ?",
                (key["key_id"],),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn(
            "BEGIN PRIVATE KEY",
            row["private_key_pem_encrypted"].replace(
                "BEGIN ENCRYPTED PRIVATE KEY", ""
            ),
        )

    def test_list_keys_never_exposes_private_key(self):
        key = self._generate_key()
        response = self.client.get("/api/v1/keys", headers=self._headers())
        data = response.get_json()["keys"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data[0]["key_id"], key["key_id"])
        self.assertNotIn("private_key_pem_encrypted", data[0])
        self.assertIn("public_key_pem", data[0])

    def test_export_private_key_requires_passphrase(self):
        key = self._generate_key()
        ok = self.client.post(
            f"/api/v1/keys/{key['key_id']}/export",
            headers=self._headers(),
            json={"passphrase": PASSPHRASE},
        )
        self.assertEqual(ok.status_code, 200)
        exported = ok.get_json()["private_key_pem_encrypted"]
        loaded = ds.load_private_pem(exported, PASSPHRASE)
        self.assertEqual(loaded.key_size, 2048)

        bad = self.client.post(
            f"/api/v1/keys/{key['key_id']}/export",
            headers=self._headers(),
            json={"passphrase": "Wrong#2026!"},
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()["error"]["code"], "invalid_passphrase")

    def test_keys_require_authentication(self):
        response = self.client.get("/api/v1/keys")
        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------------------
    # Підпис
    # ------------------------------------------------------------------

    def test_sign_without_key_is_rejected(self):
        document = self._upload()
        response = self._sign(document["document_id"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"]["code"], "signing_key_missing"
        )

    def test_sign_with_wrong_passphrase_is_rejected(self):
        self._generate_key()
        document = self._upload()
        response = self._sign(
            document["document_id"], passphrase="Wrong#2026!"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"]["code"], "invalid_passphrase"
        )

    def test_sign_stores_signature_in_db(self):
        self._generate_key()
        document = self._upload()
        response = self._sign(document["document_id"])

        self.assertEqual(response.status_code, 200)
        signature = response.get_json()["signature"]
        self.assertEqual(signature["status"], "verified")
        self.assertEqual(signature["algorithm"], ds.ALGORITHM)
        self.assertEqual(signature["signer"], "owner")
        self.assertEqual(len(base64.b64decode(signature["signature_b64"])), 256)

        with self.app.app_context():
            row = get_db().execute(
                "SELECT * FROM document_signatures WHERE document_id = ?",
                (document["document_id"],),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["signer_id"], 1)
        self.assertEqual(row["document_sha256"], document["sha256"])
        self.assertEqual(row["status"], "verified")

    def test_unsigned_download_reports_unsigned(self):
        document = self._upload()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Signature-Status"], "Unsigned")

    def test_signed_download_has_signed_and_verified_status(self):
        self._generate_key()
        document = self._upload()
        self._sign(document["document_id"])

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PLAINTEXT)
        self.assertEqual(
            response.headers["X-Signature-Status"], "Signed & Verified"
        )
        self.assertEqual(response.headers["X-Signer"], "owner")
        self.assertEqual(
            response.headers["X-Signature-Algorithm"], ds.ALGORITHM
        )
        self.assertEqual(len(response.headers["X-Signature-Fingerprint"]), 64)

    def test_metadata_includes_verified_signature(self):
        self._generate_key()
        document = self._upload()
        self._sign(document["document_id"])

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}",
            headers=self._headers(),
        )
        signature = response.get_json()["document"]["signature"]
        self.assertEqual(signature["status"], "verified")
        self.assertTrue(signature["verified"])
        self.assertEqual(signature["signer"], "owner")
        self.assertIsNotNone(signature["key_id"])

    def test_tampered_signature_blocks_download(self):
        self._generate_key()
        document = self._upload()
        self._sign(document["document_id"])

        with self.app.app_context():
            db = get_db()
            row = db.execute(
                "SELECT signature_b64 FROM document_signatures "
                "WHERE document_id = ?",
                (document["document_id"],),
            ).fetchone()
            raw = bytearray(base64.b64decode(row["signature_b64"]))
            raw[10] ^= 0xFF
            db.execute(
                "UPDATE document_signatures SET signature_b64 = ?, "
                "status = 'signed' WHERE document_id = ?",
                (
                    base64.b64encode(bytes(raw)).decode("ascii"),
                    document["document_id"],
                ),
            )
            db.commit()

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.get_json()["error"]["code"], "signature_invalid"
        )
        self.assertNotEqual(response.data, PLAINTEXT)

    def test_other_user_cannot_sign_document(self):
        self._generate_key("owner")
        document = self._upload("owner")
        response = self._sign(document["document_id"], username="other")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json()["error"]["code"], "document_forbidden"
        )

    def test_key_rotation_keeps_old_signature_verifiable(self):
        first_key = self._generate_key()
        document = self._upload()
        self._sign(document["document_id"])

        second_key = self._generate_key()
        self.assertNotEqual(first_key["key_id"], second_key["key_id"])

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["X-Signature-Status"], "Signed & Verified"
        )
        self.assertEqual(
            response.headers["X-Signature-Fingerprint"], first_key["fingerprint"]
        )

    # ------------------------------------------------------------------
    # Веб-інтерфейс
    # ------------------------------------------------------------------

    def test_signature_lab_ui_generates_key_and_shows_pem(self):
        self._session_login()
        csrf = self._csrf_from("/signature-lab")
        response = self.client.post(
            "/signature-lab/generate",
            data={
                "csrf_token": csrf,
                "passphrase": PASSPHRASE,
                "confirm": PASSPHRASE,
            },
        )
        self.assertEqual(response.status_code, 302)

        page = self.client.get("/signature-lab")
        body = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("BEGIN PUBLIC KEY", body)
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", body)
        self.assertIn("RSA-PSS 2048", body)

    def test_ui_sign_document(self):
        self._generate_key()
        self._session_login()
        csrf = self._csrf_from("/vault")
        upload = self.client.post(
            "/vault/upload",
            data={
                "csrf_token": csrf,
                "file": (io.BytesIO(PLAINTEXT), "ui-statement.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 302)
        doc_id = upload.headers["Location"].rstrip("/").split("/")[-1]

        csrf = self._csrf_from(f"/vault/{doc_id}")
        sign = self.client.post(
            f"/vault/{doc_id}/sign",
            data={"csrf_token": csrf, "passphrase": PASSPHRASE},
            follow_redirects=True,
        )
        body = sign.get_data(as_text=True)
        self.assertEqual(sign.status_code, 200)
        self.assertIn("Signed &amp; Verified", body)


if __name__ == "__main__":
    unittest.main()
