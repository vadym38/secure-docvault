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

from . import digital_signature as ds
from .database import (
    create_document,
    create_document_signature,
    create_signing_key,
    delete_document,
    get_active_signing_key,
    get_document,
    get_document_signature,
    get_signing_key,
    list_document_signatures,
    list_documents_for_user,
    list_signing_keys,
    mark_document_signature_verified,
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


class SigningKeyMissingError(DocumentError):
    status = 400
    code = "signing_key_missing"


class SigningKeyForbiddenError(DocumentError):
    status = 403
    code = "signing_key_forbidden"


class InvalidPassphraseError(DocumentError):
    status = 400
    code = "invalid_passphrase"


class SigningKeyError(DocumentError):
    status = 500
    code = "signing_key_error"


class DocumentSignatureError(DocumentError):
    status = 409
    code = "signature_invalid"


@dataclass(frozen=True)
class DownloadPayload:
    content: bytes
    filename: str
    content_type: str
    sha256: str
    signature_status: str = "Unsigned"
    signature_algorithm: str = ""
    signer: str = ""
    signature_fingerprint: str = ""
    signature_signed_at: str = ""


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
        keys = document.keys()
        signature_status = (
            document["signature_status"] if "signature_status" in keys else None
        )
        return {
            "document_id": document["id"],
            "original_filename": document["original_filename"],
            "content_type": document["content_type"],
            "size_bytes": int(document["original_size"]),
            "encrypted_size_bytes": int(document["encrypted_size"]),
            "sha256": document["sha256"],
            "owner_id": int(document["owner_id"]),
            "owner": document["owner_username"]
            if "owner_username" in keys
            else None,
            "created_at": document["created_at"],
            "signature_status": signature_status or "unsigned",
            "signature_algorithm": document["signature_algorithm"]
            if "signature_algorithm" in keys
            else None,
            "signature_signed_at": document["signature_signed_at"]
            if "signature_signed_at" in keys
            else None,
            "signature_verified_at": document["signature_verified_at"]
            if "signature_verified_at" in keys
            else None,
        }

    # ------------------------------------------------------------------
    # Ключі підпису та ЕЦП (ЛР №6)
    # ------------------------------------------------------------------

    def generate_signing_key(self, user, passphrase: str) -> dict:
        try:
            ds.validate_passphrase(passphrase)
            pair = ds.generate_keypair_pem(passphrase)
        except ValueError as exc:
            raise InvalidPassphraseError(str(exc)) from exc

        key_id = str(uuid.uuid4())
        try:
            create_signing_key(
                key_id=key_id,
                user_id=self._user_id(user),
                algorithm=ds.ALGORITHM,
                public_key_pem=pair.public_key_pem,
                private_key_pem_encrypted=pair.private_key_pem_encrypted,
                fingerprint=pair.fingerprint,
            )
        except Exception as exc:
            logger.exception("Не вдалося зберегти ключ підпису")
            raise SigningKeyError("Не вдалося зберегти ключ підпису.") from exc

        logger.info(
            "Ключ підпису створено: user=%s fingerprint=%s",
            user["username"],
            pair.fingerprint,
        )
        return {
            "key_id": key_id,
            "algorithm": ds.ALGORITHM,
            "public_key_pem": pair.public_key_pem,
            "private_key_pem_encrypted": pair.private_key_pem_encrypted,
            "fingerprint": pair.fingerprint,
            "is_active": True,
        }

    def list_signing_keys(self, user) -> list[dict]:
        return [
            {
                "key_id": row["key_id"],
                "algorithm": row["algorithm"],
                "public_key_pem": row["public_key_pem"],
                "fingerprint": row["fingerprint"],
                "created_at": row["created_at"],
                "is_active": bool(row["is_active"]),
            }
            for row in list_signing_keys(self._user_id(user))
        ]

    def active_signing_key(self, user) -> dict | None:
        row = get_active_signing_key(self._user_id(user))
        if row is None:
            return None
        return {
            "key_id": row["key_id"],
            "algorithm": row["algorithm"],
            "public_key_pem": row["public_key_pem"],
            "fingerprint": row["fingerprint"],
            "created_at": row["created_at"],
            "is_active": True,
        }

    def export_signing_key(
        self,
        user,
        key_id: str,
        passphrase: str,
    ) -> dict:
        row = get_signing_key(key_id)
        if row is None or int(row["user_id"]) != self._user_id(user):
            raise SigningKeyForbiddenError("Ключ підпису не знайдено.")
        try:
            private_key = ds.load_private_pem(
                row["private_key_pem_encrypted"],
                passphrase,
            )
            exported = ds.serialize_private_pem(private_key, passphrase)
        except (ValueError, TypeError) as exc:
            raise InvalidPassphraseError(
                "Невірна парольна фраза або пошкоджений ключ."
            ) from exc
        return {
            "key_id": key_id,
            "algorithm": row["algorithm"],
            "public_key_pem": row["public_key_pem"],
            "private_key_pem_encrypted": exported,
            "fingerprint": row["fingerprint"],
        }

    def get_encrypted_private_key(self, user, key_id: str) -> str:
        row = get_signing_key(key_id)
        if row is None or int(row["user_id"]) != self._user_id(user):
            raise SigningKeyForbiddenError("Ключ підпису не знайдено.")
        return row["private_key_pem_encrypted"]

    def _signature_info(self, document_id: str, status: str | None = None) -> dict:
        row = get_document_signature(document_id)
        if row is None:
            return {
                "status": "unsigned",
                "verified": False,
                "algorithm": None,
                "signer": None,
                "signed_at": None,
                "verified_at": None,
                "fingerprint": None,
                "key_id": None,
                "signature_b64": None,
                "document_sha256": None,
            }
        final_status = status or row["status"]
        return {
            "status": final_status,
            "verified": final_status == "verified",
            "algorithm": row["algorithm"],
            "signer": row["signer_username"],
            "signer_id": int(row["signer_id"]),
            "signed_at": row["signed_at"],
            "verified_at": row["verified_at"],
            "fingerprint": row["key_fingerprint"],
            "key_id": row["key_id"],
            "signature_b64": row["signature_b64"],
            "document_sha256": row["document_sha256"],
        }

    def _verify_signature(
        self,
        document,
        plaintext: bytes,
        *,
        update_status: bool = True,
    ) -> dict:
        row = get_document_signature(document["id"])
        if row is None:
            return self._signature_info(document["id"])

        valid = False
        try:
            public_key = ds.load_public_pem(row["public_key_pem"])
            signature = ds.signature_from_b64(row["signature_b64"])
            digest = ds.sha256_digest(plaintext)
            valid = ds.verify_digest(digest, signature, public_key)
        except (ValueError, TypeError):
            valid = False

        status = "verified" if valid else "invalid"
        if update_status:
            mark_document_signature_verified(document["id"], status)
        if not valid:
            logger.warning(
                "ЕЦП недійсний: document=%s signer=%s key=%s",
                document["id"],
                row["signer_id"],
                row["key_id"],
            )
        return self._signature_info(document["id"], status=status)

    def sign_document(self, user, doc_id: str, passphrase: str) -> dict:
        document = get_document(doc_id)
        self._authorize(document, user)

        key = get_active_signing_key(self._user_id(user))
        if key is None:
            raise SigningKeyMissingError(
                "Спочатку згенеруйте ключ підпису в Signature Lab."
            )

        try:
            private_key = ds.load_private_pem(
                key["private_key_pem_encrypted"],
                passphrase,
            )
        except (ValueError, TypeError) as exc:
            raise InvalidPassphraseError(
                "Невірна парольна фраза для приватного ключа."
            ) from exc

        plaintext, _container = self._read_verified_plaintext(document)
        digest = ds.sha256_digest(plaintext)
        signature = ds.sign_digest(digest, private_key)

        public_key = ds.load_public_pem(key["public_key_pem"])
        if not ds.verify_digest(digest, signature, public_key):
            raise SigningKeyError(
                "Підпис не пройшов самоперевірку відкритим ключем."
            )

        create_document_signature(
            document_id=doc_id,
            signer_id=self._user_id(user),
            key_id=key["key_id"],
            algorithm=key["algorithm"],
            document_sha256=digest.hex(),
            signature_b64=ds.signature_to_b64(signature),
        )
        mark_document_signature_verified(doc_id, "verified")
        logger.info(
            "Документ підписано: doc=%s signer=%s key=%s",
            doc_id,
            user["username"],
            key["key_id"],
        )
        return self._signature_info(doc_id, status="verified")

    def get_signature_info(self, user, doc_id: str) -> dict:
        document = get_document(doc_id)
        self._authorize(document, user)
        if get_document_signature(doc_id) is None:
            return self._signature_info(doc_id)
        plaintext, _container = self._read_verified_plaintext(document)
        return self._verify_signature(document, plaintext)

    def list_signatures(self, user, limit: int = 20) -> list[dict]:
        return [
            {
                "document_id": row["document_id"],
                "original_filename": row["original_filename"],
                "algorithm": row["algorithm"],
                "document_sha256": row["document_sha256"],
                "signature_b64": row["signature_b64"],
                "signed_at": row["signed_at"],
                "verified_at": row["verified_at"],
                "status": row["status"],
                "key_id": row["key_id"],
                "fingerprint": row["key_fingerprint"],
            }
            for row in list_document_signatures(self._user_id(user), limit=limit)
        ]

    def signing_stats(self, user) -> dict:
        keys = list_signing_keys(self._user_id(user))
        signatures = list_document_signatures(self._user_id(user), limit=200)
        active = next((key for key in keys if key["is_active"]), None)
        return {
            "keys": len(keys),
            "active_key_id": active["key_id"] if active else None,
            "fingerprint": active["fingerprint"] if active else None,
            "signatures": len(signatures),
            "verified": sum(1 for item in signatures if item["status"] == "verified"),
            "invalid": sum(1 for item in signatures if item["status"] == "invalid"),
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
        signature = self._verify_signature(document, plaintext)

        if signature["status"] == "invalid":
            raise DocumentSignatureError(
                "Цифровий підпис документа недійсний. Файл не видано."
            )

        status_label = (
            "Signed & Verified"
            if signature["status"] == "verified"
            else "Unsigned"
        )
        return DownloadPayload(
            content=plaintext,
            filename=document["original_filename"],
            content_type=document["content_type"],
            sha256=document["sha256"],
            signature_status=status_label,
            signature_algorithm=signature.get("algorithm") or "",
            signer=signature.get("signer") or "",
            signature_fingerprint=signature.get("fingerprint") or "",
            signature_signed_at=signature.get("signed_at") or "",
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
        signature = self._verify_signature(document, _plaintext)
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
            "signature": signature,
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
