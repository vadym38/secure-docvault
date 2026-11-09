"""Інтеграційні тести сховища документів (ЛР №5).

Перевіряють AES-256-GCM контейнер на диску, API upload/download, IDOR,
цілісність (InvalidTag → 409) і веб-інтерфейс Cipher Vault.

Запуск:
    python -m unittest tests.test_documents -v
"""

from __future__ import annotations

import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user, get_db

PASSWORD = "Vault#2026!"
PLAINTEXT = b"CONFIDENTIAL FINANCIAL REPORT - SECURE DOCVAULT 2026\n"


class DocumentServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-lab5-"))
        cls.storage_dir = cls.temp_dir / "vault"
        test_config = type(
            "Lab5Config",
            (Config,),
            {
                "TESTING": True,
                "SECRET_KEY": "lab5-secret-key",
                "JWT_SECRET_KEY": "lab5-jwt-secret-key-0123456789abcdef0123456789abcdef",
                "DATABASE": str(cls.temp_dir / "lab5.db"),
                "DOCUMENT_STORAGE_DIR": str(cls.storage_dir),
                "FILE_ENCRYPTION_KEY": "33" * 32,
                "BCRYPT_ROUNDS": 4,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "MAX_DOCUMENT_BYTES": 1024,
                "ALLOWED_DOCUMENT_EXTENSIONS": frozenset(
                    {".txt", ".pdf", ".docx", ".csv"}
                ),
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
            db.execute("DELETE FROM documents")
            db.commit()
        for path in self.storage_dir.glob("*.enc"):
            path.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Допоміжні
    # ------------------------------------------------------------------

    def _token(self, username: str = "owner") -> str:
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["access_token"]

    def _headers(self, username: str = "owner") -> dict:
        return {"Authorization": f"Bearer {self._token(username)}"}

    def _upload(
        self,
        *,
        username: str = "owner",
        filename: str = "report.txt",
        content: bytes = PLAINTEXT,
    ):
        return self.client.post(
            "/api/v1/documents/upload",
            headers=self._headers(username),
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    def _uploaded_document(self, **kwargs) -> dict:
        response = self._upload(**kwargs)
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        return response.get_json()["document"]

    def _stored_path(self, document: dict) -> Path:
        return self.storage_dir / f"{document['document_id']}.enc"

    def _tamper(self, document: dict) -> None:
        path = self._stored_path(document)
        blob = bytearray(path.read_bytes())
        blob[30] ^= 0xFF
        path.write_bytes(blob)

    def _csrf_from(self, path: str) -> str:
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            page.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def _session_login(self) -> None:
        token = self._csrf_from("/login")
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "owner",
                "password": PASSWORD,
            },
        )
        self.assertEqual(response.status_code, 302)

    # ------------------------------------------------------------------
    # API: upload / list / download
    # ------------------------------------------------------------------

    def test_upload_creates_encrypted_container(self):
        document = self._uploaded_document()

        self.assertEqual(document["original_filename"], "report.txt")
        self.assertEqual(document["size_bytes"], len(PLAINTEXT))
        self.assertEqual(document["encrypted_size_bytes"], len(PLAINTEXT) + 28)
        self.assertEqual(document["content_type"], "text/plain")

        path = self._stored_path(document)
        self.assertTrue(path.exists())
        container = path.read_bytes()
        self.assertEqual(len(container), len(PLAINTEXT) + 28)
        self.assertNotIn(b"CONFIDENTIAL", container)
        self.assertNotIn(b"FINANCIAL", container)

    def test_list_documents_returns_owner_metadata(self):
        document = self._uploaded_document()
        response = self.client.get(
            "/api/v1/documents", headers=self._headers("owner")
        )
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data["documents"]), 1)
        self.assertEqual(
            data["documents"][0]["document_id"], document["document_id"]
        )
        self.assertEqual(data["documents"][0]["owner"], "owner")

    def test_download_roundtrip(self):
        document = self._uploaded_document()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("owner"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PLAINTEXT)
        self.assertEqual(response.headers["X-Document-Encryption"], "AES-256-GCM")
        self.assertEqual(
            response.headers["X-Content-SHA256"], document["sha256"]
        )
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_metadata_endpoint_returns_container_parts(self):
        document = self._uploaded_document()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}",
            headers=self._headers("owner"),
        )
        data = response.get_json()["document"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data["nonce_hex"]), 24)
        self.assertEqual(len(data["tag_hex"]), 32)
        self.assertEqual(data["ciphertext_size"], len(PLAINTEXT))
        self.assertEqual(data["total_size"], len(PLAINTEXT) + 28)
        self.assertTrue(data["hexdump"])
        self.assertIn("offset", data["hexdump"][0])

    def test_missing_token_is_rejected(self):
        response = self.client.get("/api/v1/documents")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "missing_token")

    def test_other_user_cannot_download(self):
        document = self._uploaded_document()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("other"),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json()["error"]["code"], "document_forbidden"
        )
        self.assertNotEqual(response.data, PLAINTEXT)

    def test_admin_can_download(self):
        document = self._uploaded_document()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("admin"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, PLAINTEXT)

    def test_missing_document_returns_404(self):
        response = self.client.get(
            "/api/v1/documents/00000000-0000-0000-0000-000000000000/download",
            headers=self._headers("owner"),
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.get_json()["error"]["code"], "document_not_found"
        )

    def test_missing_container_returns_404(self):
        document = self._uploaded_document()
        self._stored_path(document).unlink()
        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("owner"),
        )
        self.assertEqual(response.status_code, 404)

    # ------------------------------------------------------------------
    # Валідація
    # ------------------------------------------------------------------

    def test_empty_file_is_rejected(self):
        response = self._upload(content=b"")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_document")

    def test_disallowed_extension_is_rejected(self):
        response = self._upload(filename="malware.exe", content=b"MZ...")
        self.assertEqual(response.status_code, 400)
        self.assertIn("не дозволено", response.get_json()["error"]["message"])

    def test_too_large_file_is_rejected(self):
        response = self._upload(content=b"x" * 2048)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"]["code"], "document_too_large"
        )

    # ------------------------------------------------------------------
    # Цілісність
    # ------------------------------------------------------------------

    def test_tampered_container_returns_409_invalid_tag(self):
        document = self._uploaded_document()
        self._tamper(document)

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("owner"),
        )
        self.assertEqual(response.status_code, 409)
        payload = response.get_json()["error"]
        self.assertEqual(payload["code"], "integrity_error")
        self.assertIn("InvalidTag", payload["message"])

    def test_tampered_tag_is_detected(self):
        document = self._uploaded_document()
        path = self._stored_path(document)
        blob = bytearray(path.read_bytes())
        blob[12] ^= 0x01  # перший байт Auth Tag
        path.write_bytes(blob)

        response = self.client.get(
            f"/api/v1/documents/{document['document_id']}/download",
            headers=self._headers("owner"),
        )
        self.assertEqual(response.status_code, 409)

    def test_delete_removes_metadata_and_container(self):
        document = self._uploaded_document()
        path = self._stored_path(document)
        response = self.client.delete(
            f"/api/v1/documents/{document['document_id']}",
            headers=self._headers("owner"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(path.exists())
        self.assertEqual(
            self.client.get(
                "/api/v1/documents", headers=self._headers("owner")
            ).get_json()["documents"],
            [],
        )

    # ------------------------------------------------------------------
    # Веб-інтерфейс
    # ------------------------------------------------------------------

    def test_ui_upload_and_download(self):
        self._session_login()
        csrf = self._csrf_from("/vault")

        upload = self.client.post(
            "/vault/upload",
            data={
                "csrf_token": csrf,
                "file": (io.BytesIO(PLAINTEXT), "ui-report.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 302)
        location = upload.headers["Location"]
        self.assertIn("/vault/", location)

        detail = self.client.get(location)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("ui-report.txt", detail.get_data(as_text=True))

        doc_id = location.rstrip("/").split("/")[-1]
        download = self.client.get(f"/vault/{doc_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, PLAINTEXT)

    def test_ui_tampered_download_shows_error(self):
        self._session_login()
        document = self._uploaded_document()
        self._tamper(document)

        response = self.client.get(
            f"/vault/{document['document_id']}/download",
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("InvalidTag", body)
        self.assertNotIn(PLAINTEXT.decode(), body)


if __name__ == "__main__":
    unittest.main()
