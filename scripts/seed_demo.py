"""Створює демонстраційного користувача для ручної перевірки.

Приклад:
    python scripts/seed_demo.py
    python scripts/seed_demo.py --username o.kravets --password "Vault#2026!"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from app import create_app  # noqa: E402
from app.auth_security import (  # noqa: E402
    hash_password,
    validate_email,
    validate_password,
    validate_username,
)
from app.database import create_user, find_user_by_username  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Створити демо-користувача Secure DocVault")
    parser.add_argument("--username", default="o.kravets")
    parser.add_argument("--email", default="o.kravets@docvault.local")
    parser.add_argument("--password", default="Vault#2026!")
    parser.add_argument("--role", default="user", choices=("user", "admin"))
    args = parser.parse_args()

    errors = (
        validate_username(args.username)
        + validate_email(args.email)
        + validate_password(args.password)
    )
    if errors:
        for error in errors:
            print(f"[!] {error}")
        return 2

    app = create_app()

    with app.app_context():
        if find_user_by_username(args.username) is not None:
            print(f"[i] Користувач {args.username!r} уже існує — нічого не змінено.")
            return 0

        password_hash, salt = hash_password(args.password)
        user_id = create_user(
            args.username,
            args.email,
            password_hash,
            salt,
            role=args.role,
        )

    print(f"[+] Створено користувача {args.username!r} (id={user_id}, role={args.role}).")
    print(f"    Пароль: {args.password}")
    print("    Хеш і сіль збережено у таблиці users.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
