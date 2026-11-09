"""Криптографічний та валідаційний шар Secure DocVault.

Головні принципи:
* пароль ніколи не зберігається у відкритому вигляді;
* для кожного пароля генерується унікальна криптографічна сіль;
* використовується повільний алгоритм bcrypt із work factor 12;
* перевірка пароля виконується через bcrypt.checkpw (constant-time compare);
* валідація складності пароля відбувається і на сервері, і в інтерфейсі.
"""

from __future__ import annotations

import re
from functools import lru_cache

import bcrypt

# Ім'я користувача: 3–32 символи, латиниця, цифри та . _ -
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Достатньо сувора, але практична перевірка email без зовнішніх залежностей.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

# bcrypt приймає не більше 72 байтів вхідних даних.
BCRYPT_MAX_BYTES = 72


def validate_username(username: str) -> list[str]:
    """Повертає список помилок для імені користувача (порожній — все гаразд)."""

    errors: list[str] = []
    username = (username or "").strip()

    if not username:
        errors.append("Ім'я користувача не може бути порожнім.")
        return errors

    if not USERNAME_RE.fullmatch(username):
        errors.append(
            "Ім'я користувача має містити 3–32 символи: латиницю, цифри, крапку, дефіс або підкреслення."
        )

    return errors


def validate_email(email: str) -> list[str]:
    """Перевіряє формат email та його довжину."""

    errors: list[str] = []
    email = (email or "").strip()

    if not email:
        errors.append("Email не може бути порожнім.")
        return errors

    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors.append("Введіть коректну адресу електронної пошти.")

    return errors


def validate_password(password: str) -> list[str]:
    """Перевіряє складність пароля за вимогами лабораторної роботи.

    Вимоги: мінімум 8 символів, великі та малі літери, цифра, спеціальний
    символ. Додатково обмежуємо довжину 72 байтами через особливість bcrypt
    та забороняємо пробіли на початку/в кінці.
    """

    errors: list[str] = []
    password = password or ""

    if not password:
        errors.append("Пароль не може бути порожнім.")
        return errors

    if len(password) < 8:
        errors.append("Пароль має містити щонайменше 8 символів.")

    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        errors.append("Пароль не може перевищувати 72 байти (обмеження bcrypt).")

    if password != password.strip():
        errors.append("Пароль не повинен починатися або закінчуватися пробілом.")

    if not any(ch.isupper() for ch in password):
        errors.append("Додайте хоча б одну велику літеру.")

    if not any(ch.islower() for ch in password):
        errors.append("Додайте хоча б одну малу літеру.")

    if not any(ch.isdigit() for ch in password):
        errors.append("Додайте хоча б одну цифру.")

    if not any((not ch.isalnum()) and (not ch.isspace()) for ch in password):
        errors.append("Додайте хоча б один спеціальний символ (!@#$%^&* тощо).")

    return errors


def hash_password(password: str, rounds: int = 12) -> tuple[str, str]:
    """Хешує пароль і повертає пару (bcrypt-хеш, сіль).

    Сіль генерується bcrypt.gensalt() для кожного пароля окремо. Вона також
    вбудована у сам bcrypt-хеш, але повертається окремо, щоб явно заповнити
    поле salt у схемі users і продемонструвати унікальність солей у звіті.
    """

    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_BYTES:
        raise ValueError("Пароль перевищує 72 байти — bcrypt не може його обробити.")

    salt = bcrypt.gensalt(rounds=rounds)
    digest = bcrypt.hashpw(encoded, salt)
    return digest.decode("ascii"), salt.decode("ascii")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Перевіряє пароль через bcrypt.checkpw.

    checkpw виконує порівняння у постійному часі (constant-time), тому за
    часом відповіді не можна визначити, скільки перших символів збіглося.
    """

    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("ascii"),
        )
    except (ValueError, TypeError):
        # Пошкоджений або некоректний хеш не повинен ламати запит.
        return False


@lru_cache(maxsize=4)
def _dummy_hash(rounds: int) -> bytes:
    """Створює службовий хеш для вирівнювання часу входу.

    Якщо користувача не знайдено, сервер усе одно виконує bcrypt-перевірку
    над dummy-хешем. Це ускладнює user enumeration за часом відповіді.
    """

    return bcrypt.hashpw(b"docvault-dummy-password", bcrypt.gensalt(rounds=rounds))


def verify_dummy(plain_password: str, rounds: int = 12) -> None:
    """Виконує «холостий» bcrypt-розрахунок для неіснуючого користувача."""

    try:
        bcrypt.checkpw(plain_password.encode("utf-8"), _dummy_hash(rounds))
    except (ValueError, TypeError):
        pass
