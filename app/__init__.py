"""Application factory для Secure DocVault (етап 5)."""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from .api import api_bp
from .auth import auth_bp
from .client_security import client_bp
from .config import Config
from .database import init_app as init_database
from .documents import DocumentService
from .documents_api import documents_api_bp
from .file_crypto import initialize_file_cipher
from .jwt_service import MIN_SECRET_BYTES
from .keys_api import keys_api_bp
from .network_guard import install_network_middleware
from .network_lab import network_bp
from .security import install_security_middleware
from .signature_lab import signature_bp
from .vault import vault_bp


def _validate_jwt_config(app: Flask) -> None:
    """Fail-closed перевірка JWT-конфігурації на старті застосунку."""

    secret = app.config.get("JWT_SECRET_KEY", "")
    if not secret or len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
        raise RuntimeError(
            "JWT_SECRET_KEY не задано або він коротший за 32 байти (256 біт). "
            'Згенеруйте ключ: python -c "import secrets; print(secrets.token_hex(32))" '
            "і додайте його у .env."
        )

    if app.config.get("JWT_ALGORITHM") != "HS256":
        raise RuntimeError("Для цієї роботи дозволено лише алгоритм HS256.")

    if app.config.get("JWT_ACCESS_TTL_SECONDS", 0) <= 0:
        raise RuntimeError("JWT_ACCESS_TTL_SECONDS має бути додатним.")

    if app.config.get("JWT_REFRESH_TTL_SECONDS", 0) <= 0:
        raise RuntimeError("JWT_REFRESH_TTL_SECONDS має бути додатним.")


def create_app(config_object: type = Config) -> Flask:
    """Створює та налаштовує Flask-застосунок."""

    app = Flask(__name__)
    app.config.from_object(config_object)
    _validate_jwt_config(app)

    init_database(app)
    file_cipher = initialize_file_cipher(app)
    app.extensions["document_service"] = DocumentService(
        cipher=file_cipher,
        storage_dir=app.config["DOCUMENT_STORAGE_DIR"],
        max_bytes=app.config["MAX_DOCUMENT_BYTES"],
        allowed_extensions=app.config["ALLOWED_DOCUMENT_EXTENSIONS"],
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(documents_api_bp)
    app.register_blueprint(keys_api_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(signature_bp)

    install_network_middleware(app)
    install_security_middleware(app)

    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith("/api/"):
            return jsonify(
                error={
                    "code": "bad_request",
                    "message": "Некоректний API-запит.",
                }
            ), 400
        return (
            render_template(
                "error.html",
                code=400,
                title="Некоректний запит",
                message=getattr(error, "description", "Сервер відхилив запит."),
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(
                error={
                    "code": "not_found",
                    "message": "API-маршрут не знайдено.",
                }
            ), 404
        return (
            render_template(
                "error.html",
                code=404,
                title="Сторінку не знайдено",
                message="Перевірте адресу або поверніться до безпечної зони.",
            ),
            404,
        )

    @app.errorhandler(405)
    def method_not_allowed(_error):
        if request.path.startswith("/api/"):
            return jsonify(
                error={
                    "code": "method_not_allowed",
                    "message": "Цей API-маршрут не приймає такий HTTP-метод.",
                }
            ), 405
        return (
            render_template(
                "error.html",
                code=405,
                title="Метод не дозволено",
                message="Цей маршрут не приймає такий HTTP-метод.",
            ),
            405,
        )

    @app.errorhandler(413)
    def payload_too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify(
                error={
                    "code": "payload_too_large",
                    "message": "Запит перевищує дозволений розмір.",
                }
            ), 413
        return (
            render_template(
                "error.html",
                code=413,
                title="Файл завеликий",
                message="Розмір запиту перевищує ліміт сховища.",
            ),
            413,
        )

    @app.errorhandler(500)
    def internal_error(_error):
        if request.path.startswith("/api/"):
            return jsonify(
                error={
                    "code": "internal_error",
                    "message": "Внутрішня помилка API.",
                }
            ), 500
        return (
            render_template(
                "error.html",
                code=500,
                title="Внутрішня помилка",
                message="Сервер не зміг обробити запит. Спробуйте пізніше.",
            ),
            500,
        )

    return app
