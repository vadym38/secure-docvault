"""Application factory для Secure DocVault (етап 1)."""

from __future__ import annotations

from flask import Flask, render_template

from .auth import auth_bp
from .config import Config
from .database import init_app as init_database


def create_app(config_object: type = Config) -> Flask:
    """Створює та налаштовує Flask-застосунок."""

    app = Flask(__name__)
    app.config.from_object(config_object)

    init_database(app)
    app.register_blueprint(auth_bp)

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
