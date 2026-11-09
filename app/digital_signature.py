"""Електронний цифровий підпис RSA-PSS + SHA-256 (ЛР №6).

Приватний ключ серіалізується у PKCS#8 PEM **із парольною фразою**
(`BestAvailableEncryption`). Відкритий ключ — X.509 SubjectPublicKeyInfo
PEM. Підпис обчислюється над SHA-256-дайджестом документа через
`Prehashed(hashes.SHA256())`, а не над сирим файлом, щоб явно показати
етап хешування.

Схема: RSA-2048, public exponent 65537, RSA-PSS з MGF1(SHA-256) і
`salt_length=MAX_LENGTH`.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

ALGORITHM = "RSA-PSS-2048-SHA256"
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
MIN_PASSPHRASE_LENGTH = 8
MAX_PASSPHRASE_LENGTH = 128


@dataclass(frozen=True)
class KeyPairPem:
    public_key_pem: str
    private_key_pem_encrypted: str
    fingerprint: str


def validate_passphrase(passphrase: str) -> None:
    if not passphrase or len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Парольна фраза має містити щонайменше "
            f"{MIN_PASSPHRASE_LENGTH} символів."
        )
    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Парольна фраза не може перевищувати "
            f"{MAX_PASSPHRASE_LENGTH} символів."
        )


def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    return private_key, private_key.public_key()


def serialize_public_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def serialize_private_pem(
    private_key: rsa.RSAPrivateKey,
    passphrase: str,
) -> str:
    validate_passphrase(passphrase)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        ),
    ).decode("ascii")


def load_private_pem(
    encrypted_pem: str,
    passphrase: str,
) -> rsa.RSAPrivateKey:
    validate_passphrase(passphrase)
    key = serialization.load_pem_private_key(
        encrypted_pem.encode("ascii"),
        password=passphrase.encode("utf-8"),
    )
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("PEM містить не RSA-ключ.")
    return key


def load_public_pem(public_pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("PEM містить не RSA-відкритий ключ.")
    return key


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def fingerprint_from_pem(public_pem: str) -> str:
    return public_key_fingerprint(load_public_pem(public_pem))


def sha256_digest(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def sign_digest(
    digest: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    if len(digest) != 32:
        raise ValueError("Очікується SHA-256 дайджест (32 байти).")
    return private_key.sign(
        digest,
        _pss_padding(),
        utils.Prehashed(hashes.SHA256()),
    )


def verify_digest(
    digest: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
) -> bool:
    if len(digest) != 32:
        return False
    try:
        public_key.verify(
            signature,
            digest,
            _pss_padding(),
            utils.Prehashed(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_document(
    document: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    return sign_digest(sha256_digest(document), private_key)


def verify_document(
    document: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
) -> bool:
    return verify_digest(sha256_digest(document), signature, public_key)


def signature_to_b64(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def signature_from_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def generate_keypair_pem(passphrase: str) -> KeyPairPem:
    private_key, public_key = generate_keypair()
    return KeyPairPem(
        public_key_pem=serialize_public_pem(public_key),
        private_key_pem_encrypted=serialize_private_pem(private_key, passphrase),
        fingerprint=public_key_fingerprint(public_key),
    )
