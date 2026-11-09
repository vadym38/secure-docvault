"""Точка входу Secure DocVault.

Запуск:
    python run.py

Перед запуском створіть .env на основі .env.example і задайте SECRET_KEY.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402  (імпорт після load_dotenv)

app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
