"""Сервіс зашифрованого файлового сховища Secure DocVault (ЛР №5).

Шар між HTTP-маршрутами та AES-GCM:

* перевіряє права власника/адміністратора (захист від IDOR);
* шифрує файл на льоту та пише атомарний `.enc`-контейнер;
* зберігає метадані в SQLite;
* перед видачею перевіряє AES-GCM tag і SHA-256 відкритого тексту;
* не повертає жодного байта, якщо контейнер модифіковано.
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .database import (
    create_document,
    delete_document,
    get_document,
    list_documents_for_user,
)
from .file_crypto import FileCipher, make_aad
from .sanitizer import sanitize_filename

logger = logging.getLogger("docvault.documents")


class DocumentError(Exception):
    """Базова помилка доменного шару документів."""

    status = 400
    code = "document_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class DocumentValidationError(DocumentError):
    status = 400
    code = "invalid_document"


class DocumentTooLargeError(DocumentError):
    status = 413
    code = "document_too_large"


class DocumentNotFoundError(DocumentError):
    status = 404
    code = "document_not_found"


class DocumentForbiddenError(DocumentError):
    status = 403
    code = "document_forbidden"


class DocumentIntegrityError(DocumentError):
    status = 409
    code = "integrity_error"


class DocumentStorageError(DocumentError):
    status = 500
    code = "document_storage_error"


@dataclass(frozen=True)
class DownloadPayload:
    content: bytes
    filename: str
    content_type: str
    sha256: str


class DocumentService:
    """Керує .enc-контейнерами та метаданими документів."""

    def __init__(
        self,
        *,
        cipher: FileCipher,
        storage_dir: str | Path,
        max_bytes: int,
        allowed_extensions: set[str] | frozenset[str],
    ) -> None:
        self.cipher = cipher
        self.storage_dir = Path(storage_dir)
        self.max_bytes = int(max_bytes)
        self.allowed_extensions = {
            "." + item.lower().lstrip(".") for item in allowed_extensions
        }
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Допоміжні
    # ------------------------------------------------------------------

    @staticmethod
    def _user_id(user) -> int:
        return int(user["id"])

    @staticmethod
    def _is_admin(user) -> bool:
        return str(user["role"]) == "admin"

    def _authorize(self, document, user) -> None:
        if document is None:
            raise DocumentNotFoundError("Документ не знайдено.")
        if (
            int(document["owner_id"]) != self._user_id(user)
            and not self._is_admin(user)
        ):
            logger.warning(
                "IDOR attempt: user=%s tried document=%s owner=%s",
                user["username"],
                document["id"],
                document["owner_id"],
            )
            raise DocumentForbiddenError(
                "У вас немає прав на цей документ."
            )

    def _container_path(self, document) -> Path:
        # stored_filename формується сервісом, але все одно беремо лише
        # базове ім'я, щоб унеможливити path traversal із БД.
        safe_name = Path(str(document["stored_filename"])).name
        return self.storage_dir / safe_name

    def _validate_filename(self, filename: str) -> str:
        cleaned = sanitize_filename(filename)
        suffix = Path(cleaned).suffix.lower()
        if not suffix:
            raise DocumentValidationError(
                "Файл повинен мати розширення (наприклад, .pdf або .txt)."
            )
        if suffix not in self.allowed_extensions:
            raise DocumentValidationError(
                f"Розширення {suffix} не дозволено для сховища."
            )
        return cleaned

    @staticmethod
    def _safe_content_type(filename: str, declared: str | None = None) -> str:
        guessed, _encoding = mimetypes.guess_type(filename)
        if guessed:
            return guessed
        if declared and "/" in declared and len(declared) <= 100:
            return declared.split(";", 1)[0].strip().lower()
        return "application/octet-stream"

    def _write_atomic(self, destination: Path, payload: bytes) -> None:
        temp_path = destination.with_name(f".{destination.name}.tmp")
        try:
            with open(temp_path, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, destination)
        finally:
            temp_path.unlink(missing_ok=True)

    def _read_verified_plaintext(self, document) -> tuple[bytes, bytes]:
        """Читає контейнер, перевіряє GCM tag і SHA-256, повертає plaintext."""

        path = self._container_path(document)
        if not path.exists():
            raise DocumentNotFoundError(
                "Зашифрований контейнер відсутній на диску."
            )

        try:
            container = path.read_bytes()
        except OSError as exc:
            logger.exception("Не вдалося прочитати контейнер %s", path)
            raise DocumentStorageError("Не вдалося прочитати файл сховища.") from exc

        aad = make_aad(document["id"], document["owner_id"])
        try:
            plaintext = self.cipher.decrypt(container, aad)
        except InvalidTag as exc:
            logger.error(
                "AES-GCM InvalidTag: document=%s owner=%s",
                document["id"],
                document["owner_id"],
            )
            raise DocumentIntegrityError(
                "Цілісність порушено: AES-GCM tag не збігається (InvalidTag). "
                "Файл модифіковано або підмінено."
            ) from exc
        except ValueError as exc:
            logger.error("Пошкоджений контейнер %s: %s", document["id"], exc)
            raise DocumentIntegrityError(
                f"Пошкоджений шифроконтейнер: {exc}"
            ) from exc

        expected = str(document["sha256"])
        actual = hashlib.sha256(plaintext).hexdigest()
        if actual != expected:
            logger.error(
                "SHA-256 mismatch: document=%s expected=%s actual=%s",
                document["id"],
                expected,
                actual,
            )
            raise DocumentIntegrityError(
                "SHA-256 відкритого тексту не збігається з метаданими."
            )

        return plaintext, container

    def _serialize(self, document) -> dict:
        return {
            "document_id": document["id"],
            "original_filename": document["original_filename"],
            "content_type": document["content_type"],
            "size_bytes": int(document["original_size"]),
            "encrypted_size_bytes": int(document["encrypted_size"]),
            "sha256": document["sha256"],
            "owner_id": int(document["owner_id"]),
            "owner": document["owner_username"]
            if "owner_username" in document.keys()
            else None,
            "created_at": document["created_at"],
        }

    # ------------------------------------------------------------------
    # Публічні операції
    # ------------------------------------------------------------------

    def upload(
        self,
        user,
        *,
        filename: str,
        content_type: str | None,
        data: bytes,
    ) -> dict:
        if not filename:
            raise DocumentValidationError("Не вказано ім'я файлу.")
        if not data:
            raise DocumentValidationError("Порожній файл не можна зберегти.")
        if len(data) > self.max_bytes:
            raise DocumentTooLargeError(
                f"Файл перевищує ліміт {self.max_bytes} байт."
            )

        clean_name = self._validate_filename(filename)
        doc_id = str(uuid.uuid4())
        stored_filename = f"{doc_id}.enc"
        destination = self.storage_dir / stored_filename
        aad = make_aad(doc_id, self._user_id(user))

        try:
            container = self.cipher.encrypt(data, aad)
        except Exception as exc:  # pragma: no cover - апаратні/бібліотечні збої
            logger.exception("Помилка шифрування документа")
            raise DocumentStorageError("Не вдалося зашифрувати файл.") from exc

        try:
            self._write_atomic(destination, container)
        except OSError as exc:
            logger.exception("Помилка запису контейнера %s", destination)
            raise DocumentStorageError("Не вдалося зберегти контейнер.") from exc

        try:
            create_document(
                doc_id=doc_id,
                owner_id=self._user_id(user),
                original_filename=clean_name,
                stored_filename=stored_filename,
                content_type=self._safe_content_type(clean_name, content_type),
                original_size=len(data),
                encrypted_size=len(container),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        except Exception as exc:
            destination.unlink(missing_ok=True)
            logger.exception("Помилка запису метаданих документа %s", doc_id)
            raise DocumentStorageError(
                "Не вдалося зберегти метадані документа."
            ) from exc

        document = get_document(doc_id)
        logger.info(
            "Документ зашифровано: id=%s owner=%s size=%s encrypted=%s",
            doc_id,
            self._user_id(user),
            len(data),
            len(container),
        )
        return self._serialize(document)

    def list_for_user(self, user) -> list[dict]:
        rows = list_documents_for_user(
            self._user_id(user),
            is_admin=self._is_admin(user),
        )
        return [self._serialize(row) for row in rows]

    def download(self, user, doc_id: str) -> DownloadPayload:
        document = get_document(doc_id)
        self._authorize(document, user)
        plaintext, _container = self._read_verified_plaintext(document)
        return DownloadPayload(
            content=plaintext,
            filename=document["original_filename"],
            content_type=document["content_type"],
            sha256=document["sha256"],
        )

    def container_preview(
        self,
        user,
        doc_id: str,
        *,
        hex_limit: int = 256,
    ) -> dict:
        document = get_document(doc_id)
        self._authorize(document, user)
        _plaintext, container = self._read_verified_plaintext(document)
        parts = self.cipher.parse_container(container)
        preview = container[:hex_limit]

        return {
            **self._serialize(document),
            "total_size": parts.total_size,
            "nonce_hex": parts.nonce.hex(),
            "tag_hex": parts.tag.hex(),
            "ciphertext_size": len(parts.ciphertext),
            "ciphertext_hex": parts.ciphertext[:64].hex(),
            "hexdump": self.hexdump(preview),
            "hexdump_truncated": len(container) > hex_limit,
            "hexdump_size": len(preview),
        }

    def delete(self, user, doc_id: str) -> None:
        document = get_document(doc_id)
        self._authorize(document, user)
        path = self._container_path(document)
        path.unlink(missing_ok=True)
        if not delete_document(doc_id):
            raise DocumentNotFoundError("Документ не знайдено.")
        logger.info("Документ видалено: id=%s user=%s", doc_id, user["username"])

    def stats(self, user) -> dict:
        documents = self.list_for_user(user)
        return {
            "count": len(documents),
            "plaintext_bytes": sum(item["size_bytes"] for item in documents),
            "encrypted_bytes": sum(
                item["encrypted_size_bytes"] for item in documents
            ),
            "key_fingerprint": self.cipher.fingerprint,
        }

    @staticmethod
    def hexdump(data: bytes, width: int = 16) -> list[dict]:
        """Готує hexdump для шаблону/термінала без сторонніх утиліт."""

        lines: list[dict] = []
        for offset in range(0, len(data), width):
            chunk = data[offset : offset + width]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in chunk
            )
            lines.append(
                {
                    "offset": f"{offset:08x}",
                    "hex": hex_part.ljust(width * 3 - 1),
                    "ascii": ascii_part,
                }
            )
        return lines
