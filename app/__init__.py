"""Application factory для Secure DocVault (етап 2)."""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from .api import api_bp
from .auth import auth_bp
from .config import Config
from .database import init_app as init_database
from .jwt_service import MIN_SECRET_BYTES


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
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    @app.after_request
    def add_security_headers(response):
        """Додає базові захисні заголовки до кожної відповіді."""

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        return response

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
