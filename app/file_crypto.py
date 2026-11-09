"""Автентифіковане шифрування файлів AES-256-GCM (ЛР №5).

Формат контейнера (рівно як у завданні):

    [ 12 байт IV / Nonce ][ 16 байт Auth Tag ][ N байт Ciphertext ]

`cryptography.hazmat.primitives.ciphers.aead.AESGCM` повертає
`ciphertext || tag`, тому модуль явно розділяє tag і ciphertext, щоб
зберегти контейнер у потрібному порядку. Для кожного файлу генерується
новий 96-бітний nonce через `os.urandom(12)`.

AAD (Associated Data) прив'язує контейнер до метаданих документа:
`docvault|file|v1|<document_id>|<owner_id>`. Якщо контейнер перейменувати,
підмінити власника або переставити між записами БД, tag не зійдеться.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MIN_CONTAINER_SIZE = NONCE_SIZE + TAG_SIZE
AAD_PREFIX = b"docvault|file|v1"


@dataclass(frozen=True)
class ContainerParts:
    """Розібраний шифроконтейнер."""

    nonce: bytes
    tag: bytes
    ciphertext: bytes

    @property
    def total_size(self) -> int:
        return len(self.nonce) + len(self.tag) + len(self.ciphertext)


def parse_key_material(value: str | bytes | None) -> bytes | None:
    """Приймає 32-байтний ключ у hex (64 символи) або сирі 32 байти."""

    if value is None:
        return None
    if isinstance(value, bytes):
        return value if len(value) == KEY_SIZE else None

    candidate = value.strip()
    if len(candidate) == 2 * KEY_SIZE:
        try:
            key = bytes.fromhex(candidate)
        except ValueError:
            return None
        return key if len(key) == KEY_SIZE else None
    return None


def make_aad(document_id: str, owner_id: int | str) -> bytes:
    """Associated Data, що зв'язує контейнер із документом і власником."""

    return f"{AAD_PREFIX.decode()}|{document_id}|{owner_id}".encode("utf-8")


class FileCipher:
    """AES-256-GCM із підтримкою поточного та старих ключів (ротація)."""

    def __init__(self, keys: Sequence[bytes]) -> None:
        if not keys:
            raise ValueError("Потрібен хоча б один ключ AES-256.")
        if any(len(key) != KEY_SIZE for key in keys):
            raise ValueError("Кожен ключ AES-256 має бути 32 байти.")
        self._keys = tuple(keys)

    @property
    def current_key(self) -> bytes:
        return self._keys[0]

    @property
    def key_count(self) -> int:
        return len(self._keys)

    @property
    def fingerprint(self) -> str:
        """Безпечний для показу відбиток поточного ключа."""

        return hashlib.sha256(self.current_key).hexdigest()[:16]

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """Шифрує дані та повертає [IV][Tag][Ciphertext]."""

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext має бути bytes")
        nonce = os.urandom(NONCE_SIZE)
        ciphertext_with_tag = AESGCM(self.current_key).encrypt(
            nonce,
            bytes(plaintext),
            associated_data,
        )
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]
        return nonce + tag + ciphertext

    def decrypt(self, container: bytes, associated_data: bytes) -> bytes:
        """Перевіряє tag і повертає plaintext; інакше raise InvalidTag."""

        parts = self.parse_container(container)
        payload = parts.ciphertext + parts.tag
        last_error: InvalidTag | None = None

        for key in self._keys:
            try:
                return AESGCM(key).decrypt(
                    parts.nonce,
                    payload,
                    associated_data,
                )
            except InvalidTag as exc:
                last_error = exc

        raise last_error or InvalidTag("AES-GCM authentication failed")

    def parse_container(self, container: bytes) -> ContainerParts:
        if not isinstance(container, (bytes, bytearray)):
            raise TypeError("container має бути bytes")
        if len(container) < MIN_CONTAINER_SIZE:
            raise ValueError(
                f"Пошкоджений контейнер: {len(container)} байт, "
                f"мінімум {MIN_CONTAINER_SIZE}."
            )
        raw = bytes(container)
        return ContainerParts(
            nonce=raw[:NONCE_SIZE],
            tag=raw[NONCE_SIZE : NONCE_SIZE + TAG_SIZE],
            ciphertext=raw[NONCE_SIZE + TAG_SIZE :],
        )

    def describe(self, container: bytes) -> dict:
        parts = self.parse_container(container)
        return {
            "total_size": parts.total_size,
            "nonce_size": len(parts.nonce),
            "tag_size": len(parts.tag),
            "ciphertext_size": len(parts.ciphertext),
            "nonce_hex": parts.nonce.hex(),
            "tag_hex": parts.tag.hex(),
            "ciphertext_hex": parts.ciphertext[:64].hex(),
        }


def initialize_file_cipher(app) -> FileCipher:
    """Створює FileCipher та кладе його в app.extensions.

    Якщо `FILE_ENCRYPTION_KEY` не задано, для локального стенда генерується
    ефемерний ключ. Це зручно для тестів, але файли не переживуть рестарт.
    У production задайте `FILE_ENCRYPTION_KEY_REQUIRED=1`, щоб старт без
    ключа завершувався помилкою.
    """

    raw = app.config.get("FILE_ENCRYPTION_KEY", "")
    if raw:
        current = parse_key_material(raw)
        if current is None:
            raise RuntimeError(
                "FILE_ENCRYPTION_KEY має бути 32-байтним ключем у hex "
                "(64 символи)."
            )
    else:
        if app.config.get("FILE_ENCRYPTION_KEY_REQUIRED", False):
            raise RuntimeError(
                "FILE_ENCRYPTION_KEY не задано. У production ключ "
                "обов'язковий; згенеруйте: python -c \"import secrets; "
                "print(secrets.token_hex(32))\"."
            )
        current = AESGCM.generate_key(bit_length=256)
        app.config["FILE_ENCRYPTION_KEY"] = current.hex()
        app.logger.warning(
            "FILE_ENCRYPTION_KEY не задано: згенеровано ефемерний ключ. "
            "Файли не вдасться розшифрувати після перезапуску."
        )

    old_keys: list[bytes] = []
    for candidate in str(app.config.get("FILE_ENCRYPTION_KEY_OLD", "")).split(","):
        candidate = candidate.strip()
        if not candidate:
            continue
        parsed = parse_key_material(candidate)
        if parsed is None:
            app.logger.warning(
                "FILE_ENCRYPTION_KEY_OLD містить некоректний ключ — пропущено."
            )
            continue
        old_keys.append(parsed)

    cipher = FileCipher((current, *old_keys))
    app.extensions["file_cipher"] = cipher
    app.config["FILE_ENCRYPTION_KEY_FINGERPRINT"] = cipher.fingerprint
    app.logger.info(
        "FileCipher: AES-256-GCM, key fingerprint=%s, keys=%d",
        cipher.fingerprint,
        cipher.key_count,
    )
    return cipher
