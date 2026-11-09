"""Захисні HTTP-заголовки та політика CORS (ЛР №3).

Модуль свідомо не використовує wildcard `*` для CORS: дозволені Origin
задаються явним списком у конфігурації. CSP забороняє inline-скрипти та
inline-стилі, тому весь клієнтський код винесено у файли `static/`.
"""

from __future__ import annotations

from flask import Flask, Response, request

# Директиви CSP. `script-src 'self'` без 'unsafe-inline' — ключова вимога
# ЛР №3. `report-uri` дозволяє збирати звіти про порушення на стенді.
CSP_POLICY = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "report-uri /client-lab/csp-report"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP_POLICY,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "X-Permitted-Cross-Domain-Policies": "none",
}

SECURITY_HEADER_MATRIX: tuple[dict[str, str], ...] = (
    {
        "name": "Content-Security-Policy",
        "value": "script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "threat": "XSS, injected inline scripts, data: payloads, clickjacking",
    },
    {
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000; includeSubDomains",
        "threat": "SSL-stripping, downgrade to HTTP, cookie interception",
    },
    {
        "name": "X-Content-Type-Options",
        "value": "nosniff",
        "threat": "MIME-sniffing перетворення тексту на виконуваний скрипт",
    },
    {
        "name": "X-Frame-Options",
        "value": "DENY",
        "threat": "Clickjacking / UI redressing через iframe",
    },
    {
        "name": "Referrer-Policy",
        "value": "strict-origin-when-cross-origin",
        "threat": "Витік URL із токенами на сторонні сайти",
    },
    {
        "name": "Permissions-Policy",
        "value": "geolocation=(), microphone=(), camera=()",
        "threat": "Несанкціонований доступ до пристроїв через вбудований код",
    },
)


def _allowed_origins(app: Flask) -> set[str]:
    """Повертає нормалізований список дозволених Origin."""

    raw = app.config.get("CORS_ALLOWED_ORIGINS", [])
    if isinstance(raw, str):
        raw = raw.split(",")
    return {str(origin).strip().rstrip("/") for origin in raw if str(origin).strip()}


def _add_vary_origin(response: Response) -> None:
    """Додає Origin до Vary, не дублюючи значення."""

    current = response.headers.get("Vary", "")
    values = [item.strip() for item in current.split(",") if item.strip()]
    if "Origin" not in values:
        values.append("Origin")
    response.headers["Vary"] = ", ".join(values)


def install_security_middleware(app: Flask) -> None:
    """Реєструє after_request-обробник із заголовками та CORS."""

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)

        # CORS застосовується лише до запитів із заголовком Origin.
        origin = request.headers.get("Origin")
        if origin:
            _add_vary_origin(response)
            if origin.rstrip("/") in _allowed_origins(app):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = (
                    "Authorization, Content-Type, X-CSRF-Token, X-Requested-With"
                )
                response.headers["Access-Control-Expose-Headers"] = "WWW-Authenticate"
                response.headers["Access-Control-Max-Age"] = "600"
            # Для стороннього Origin ACAO не встановлюється взагалі:
            # браузер самостійно заблокує читання відповіді.

        return response
