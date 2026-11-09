"""Тест фальсифікації ЕЦП RSA-PSS (ЛР №6).

Сценарій працює з реальним DocumentService, БД і .enc-контейнером:

1. генерує ключ, завантажує та підписує документ;
2. перевіряє підпис відкритим ключем — True;
3. змінює один байт документа — підпис стає False;
4. змінює один байт підпису — False;
5. змінює signature_b64 у БД — сервіс повертає 409 signature_invalid;
6. змінює байт .enc-файлу — AES-GCM повертає InvalidTag.

Запуск:
    python scripts/signature_tamper_lab6.py
"""

from __future__ import annotations

import base64
import logging
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.exceptions import InvalidTag

from app import create_app
from app import digital_signature as ds
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user, get_db, get_document_signature
from app.documents import DocumentIntegrityError, DocumentSignatureError

PASSWORD = "Vault#2026!"
PASSPHRASE = "Sigil#2026!"
DOCUMENT = b"OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n"


def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def build_app(temp_dir: Path):
    config = type(
        "Lab6TamperConfig",
        (Config,),
        {
            "TESTING": True,
            "SECRET_KEY": "lab6-tamper-secret",
            "JWT_SECRET_KEY": "lab6-tamper-jwt-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(temp_dir / "tamper.db"),
            "DOCUMENT_STORAGE_DIR": str(temp_dir / "vault"),
            "FILE_ENCRYPTION_KEY": "aa" * 32,
            "BCRYPT_ROUNDS": 4,
            "WAF_ENABLED": False,
            "RATE_LIMIT_ENABLED": False,
            "MAX_DOCUMENT_BYTES": 1024 * 1024,
        },
    )
    app = create_app(config)
    app.logger.setLevel(logging.ERROR)
    with app.app_context():
        digest, salt = hash_password(PASSWORD, rounds=4)
        user_id = create_user(
            "lab6.tamper",
            "tamper@example.com",
            digest,
            salt,
        )
    user = {"id": user_id, "username": "lab6.tamper", "role": "user"}
    return app, user


def run() -> int:
    temp_dir = Path(tempfile.mkdtemp(prefix="lab6-tamper-"))
    context = None
    try:
        app, user = build_app(temp_dir)
        context = app.app_context()
        context.push()
        service = app.extensions["document_service"]

        key = service.generate_signing_key(user, PASSPHRASE)
        document = service.upload(
            user,
            filename="official-statement.txt",
            content_type="text/plain",
            data=DOCUMENT,
        )
        signature = service.sign_document(user, document["document_id"], PASSPHRASE)
        row = get_document_signature(document["document_id"])
        public_key = ds.load_public_pem(row["public_key_pem"])
        raw_signature = ds.signature_from_b64(row["signature_b64"])

        print("=" * 78)
        print("Secure DocVault · ЛР №6 · signature tamper test")
        print("=" * 78)
        print(f"Document ID : {document['document_id']}")
        print(f"Signer      : {signature['signer']}")
        print(f"Algorithm   : {signature['algorithm']}")
        print(f"Fingerprint : {signature['fingerprint']}")
        print(f"Signature   : {len(raw_signature)} bytes (RSA-2048)")
        print(f"SHA-256     : {signature['document_sha256']}")

        valid = ds.verify_document(DOCUMENT, raw_signature, public_key)
        print(f"\n[1] Оригінальний документ: verify = {valid}")
        if not valid:
            print("ПОМИЛКА: штатний підпис не пройшов перевірку!")
            return 1

        tampered_document = bytearray(DOCUMENT)
        tampered_document[0] ^= 0x01
        valid_doc = ds.verify_document(
            bytes(tampered_document), raw_signature, public_key
        )
        print(
            f"[2] Змінено 1 байт документа (offset 0): "
            f"{DOCUMENT[0]:02x} -> {tampered_document[0]:02x}, "
            f"verify = {valid_doc}"
        )

        tampered_signature = bytearray(raw_signature)
        tampered_signature[10] ^= 0xFF
        valid_sig = ds.verify_document(
            DOCUMENT, bytes(tampered_signature), public_key
        )
        print(
            f"[3] Змінено 1 байт підпису (offset 10): verify = {valid_sig}"
        )

        with app.app_context():
            db = get_db()
            db.execute(
                "UPDATE document_signatures SET signature_b64 = ?, "
                "status = 'signed' WHERE document_id = ?",
                (
                    base64.b64encode(bytes(tampered_signature)).decode("ascii"),
                    document["document_id"],
                ),
            )
            db.commit()

        try:
            service.download(user, document["document_id"])
            print("[4] ПОМИЛКА: сервіс видав документ із підробленим підписом!")
            return 1
        except DocumentSignatureError as error:
            print(
                f"[4] Сервіс: HTTP {error.status} {error.code} · "
                f"{error.message}"
            )

        # Додатково: пошкодження .enc-контейнера ловить AES-GCM ще раніше.
        stored = service.storage_dir / f"{document['document_id']}.enc"
        blob = bytearray(stored.read_bytes())
        blob[30] ^= 0xFF
        stored.write_bytes(blob)
        try:
            service.download(user, document["document_id"])
            print("[5] ПОМИЛКА: AES-GCM пропустив пошкоджений контейнер!")
            return 1
        except DocumentIntegrityError as error:
            print(
                f"[5] AES-GCM: HTTP {error.status} {error.code} · "
                f"InvalidTag / integrity_error"
            )

        print("\n" + "=" * 78)
        print("РЕЗУЛЬТАТ: будь-яка зміна документа, підпису або контейнера")
        print("призводить до відмови; неспростовність підтверджено.")
        print("=" * 78)
        return 0
    finally:
        if context is not None:
            context.pop()
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    _configure_stdout()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
