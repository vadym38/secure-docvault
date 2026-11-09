"""Демонстрація цілісності AES-256-GCM контейнера (ЛР №5).

Скрипт працює з реальним `DocumentService` і реальним файлом на диску:

1. створює тимчасовий Flask-застосунок, БД і каталог `vault/`;
2. завантажує документ через сервіс (AES-256-GCM, IV+Tag+Ciphertext);
3. друкує hexdump контейнера та доводить відсутність plaintext;
4. змінює один байт у `.enc`-файлі;
5. показує `InvalidTag` від AES-GCM і `409 integrity_error` від сервісу.

Запуск:
    python scripts/integrity_test_lab5.py --mode all
    python scripts/integrity_test_lab5.py --mode hexdump
    python scripts/integrity_test_lab5.py --mode integrity
"""

from __future__ import annotations

import argparse
import hashlib
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
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user
from app.documents import DocumentIntegrityError
from app.file_crypto import make_aad

CONFIDENTIAL = (
    b"CONFIDENTIAL FINANCIAL REPORT - SECURE DOCVAULT 2026\n"
    b"Amount: 1 250 000 UAH\nRecipient: vault@example.com\n"
)


def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _hexdump_lines(data: bytes, width: int = 16) -> list[str]:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
    return lines


def build_app(temp_dir: Path):
    config = type(
        "Lab5IntegrityConfig",
        (Config,),
        {
            "TESTING": True,
            "SECRET_KEY": "lab5-integrity-secret",
            "JWT_SECRET_KEY": "lab5-integrity-jwt-key-0123456789abcdef0123456789abcdef",
            "DATABASE": str(temp_dir / "integrity.db"),
            "DOCUMENT_STORAGE_DIR": str(temp_dir / "vault"),
            "FILE_ENCRYPTION_KEY": "55" * 32,
            "BCRYPT_ROUNDS": 4,
            "WAF_ENABLED": False,
            "RATE_LIMIT_ENABLED": False,
            "MAX_DOCUMENT_BYTES": 1024 * 1024,
            "ALLOWED_DOCUMENT_EXTENSIONS": frozenset({".txt", ".pdf"}),
        },
    )
    app = create_app(config)
    app.logger.setLevel(logging.ERROR)
    with app.app_context():
        digest, salt = hash_password("Vault#2026!", rounds=4)
        user_id = create_user(
            "lab5.integrity",
            "integrity@example.com",
            digest,
            salt,
        )
    user = {"id": user_id, "username": "lab5.integrity", "role": "user"}
    return app, user


def run(mode: str) -> int:
    temp_dir = Path(tempfile.mkdtemp(prefix="lab5-integrity-"))
    context = None
    try:
        app, user = build_app(temp_dir)
        context = app.app_context()
        context.push()
        service = app.extensions["document_service"]
        cipher = app.extensions["file_cipher"]

        document = service.upload(
            user,
            filename="financial-report.txt",
            content_type="text/plain",
            data=CONFIDENTIAL,
        )
        doc_id = document["document_id"]
        path = service.storage_dir / f"{doc_id}.enc"
        container = path.read_bytes()
        parts = cipher.parse_container(container)

        print("=" * 78)
        print("Secure DocVault · ЛР №5 · AES-256-GCM integrity test")
        print("=" * 78)
        print(f"Document ID       : {doc_id}")
        print(f"Original filename : {document['original_filename']}")
        print(f"Plaintext size    : {len(CONFIDENTIAL)} B")
        print(f"Container size    : {len(container)} B")
        print(f"Container file    : {path}")
        print(f"Plaintext SHA-256 : {hashlib.sha256(CONFIDENTIAL).hexdigest()}")
        print(f"IV / Nonce (12 B) : {parts.nonce.hex()}")
        print(f"Auth Tag  (16 B)  : {parts.tag.hex()}")
        print(f"Ciphertext size   : {len(parts.ciphertext)} B")
        print(
            "Plaintext marker  : "
            f"{'PRESENT (!)' if b'CONFIDENTIAL' in container else 'ABSENT — OK'}"
        )

        if mode in {"all", "hexdump"}:
            print("\n" + "-" * 78)
            print("HEXDUMP: [12 B IV][16 B Tag][Ciphertext]")
            print("-" * 78)
            for line in _hexdump_lines(container, width=16):
                print(line)
            print(
                "\nЛегенда: перші 12 байт — IV, наступні 16 — Auth Tag, "
                "далі — ciphertext."
            )

        if mode in {"all", "integrity"}:
            print("\n" + "-" * 78)
            print("INTEGRITY TEST: змінюємо 1 байт у ciphertext на диску")
            print("-" * 78)
            corrupted = bytearray(container)
            offset = 28 + 5
            original_byte = corrupted[offset]
            corrupted[offset] ^= 0xFF
            print(
                f"Byte offset {offset}: 0x{original_byte:02x} -> "
                f"0x{corrupted[offset]:02x}"
            )
            path.write_bytes(corrupted)

            try:
                cipher.decrypt(bytes(corrupted), make_aad(doc_id, user["id"]))
                print("ПОМИЛКА БЕЗПЕКИ: фальсифіковані дані пройшли перевірку!")
                return 1
            except InvalidTag:
                print(
                    "--> УСПІХ: AES-GCM викликав InvalidTag. "
                    "Tag не збігається, plaintext не видано."
                )

            try:
                service.download(user, doc_id)
                print("ПОМИЛКА БЕЗПЕКИ: сервіс видав фальсифікований файл!")
                return 1
            except DocumentIntegrityError as error:
                print(
                    "--> Сервіс: HTTP 409 integrity_error · "
                    f"{error.message}"
                )

        print("\n" + "=" * 78)
        print("РЕЗУЛЬТАТ: контейнер не містить plaintext, будь-яка зміна байта")
        print("виявляється AES-GCM; сервіс блокує видачу файлу.")
        print("=" * 78)
        return 0
    finally:
        if context is not None:
            context.pop()
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    _configure_stdout()
    parser = argparse.ArgumentParser(description="Lab 5 AES-GCM integrity test")
    parser.add_argument(
        "--mode",
        choices=("all", "hexdump", "integrity"),
        default="all",
    )
    args = parser.parse_args()
    return run(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
