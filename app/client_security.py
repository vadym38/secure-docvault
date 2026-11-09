"""Лабораторія клієнтського захисту (ЛР №3).

Маршрути стенда:
* ``/client-lab``          — огляд, санітизатор і збережені нотатки;
* ``/client-lab/csp``      — демонстрація блокування inline-скриптів CSP;
* ``/client-lab/cookies``  — атрибути HttpOnly / Secure / SameSite;
* ``/client-lab/headers``  — матриця реальних захисних заголовків;
* ``/client-lab/cors``     — дозволений і сторонній Origin.

Сторінки навмисно не використовують inline-скриптів: CSP із
``script-src 'self'`` дозволяє лише файли з ``static/js``.
"""

from __future__ import annotations

import hmac
import secrets

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    make_response,
    render_template,
    request,
    session,
)

from .database import create_client_note, list_client_notes
from .sanitizer import (
    inspect_sanitization,
    sanitize_comment,
    sanitize_description,
    sanitize_filename,
)
from .security import CSP_POLICY, SECURITY_HEADER_MATRIX

client_bp = Blueprint("client", __name__, url_prefix="/client-lab")


def _verify_csrf() -> None:
    """Перевіряє CSRF-токен для POST-форм лабораторії."""

    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "")

    if not expected or not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="Недійсний CSRF-токен. Оновіть сторінку та спробуйте ще раз.",
        )


def _author() -> str:
    user = g.get("user")
    return user["username"] if user is not None else "guest"


def _render_lab(*, result: dict | None = None):
    return render_template(
        "client_lab.html",
        result=result,
        notes=list_client_notes(limit=8),
        header_matrix=SECURITY_HEADER_MATRIX,
        csp_policy=CSP_POLICY,
        allowed_origins=current_app.config.get("CORS_ALLOWED_ORIGINS", []),
        max_text=current_app.config.get("CLIENT_LAB_MAX_TEXT", 2000),
    )


def _probe(path: str, origin: str, *, method: str = "GET", extra_headers=None):
    """Виконує внутрішній запит, щоб показати реальні заголовки відповіді."""

    headers = {"Origin": origin}
    if extra_headers:
        headers.update(extra_headers)
    return current_app.test_client().open(path, method=method, headers=headers)


def _cors_snapshot(
    origin: str,
    *,
    path: str = "/api/v1/health",
    method: str = "GET",
    extra_headers=None,
) -> dict:
    response = _probe(path, origin, method=method, extra_headers=extra_headers)
    return {
        "origin": origin,
        "method": method,
        "path": path,
        "status": response.status_code,
        "acao": response.headers.get("Access-Control-Allow-Origin"),
        "credentials": response.headers.get("Access-Control-Allow-Credentials"),
        "methods": response.headers.get("Access-Control-Allow-Methods"),
        "headers": response.headers.get("Access-Control-Allow-Headers"),
        "vary": response.headers.get("Vary"),
        "allowed": response.headers.get("Access-Control-Allow-Origin") == origin,
    }


# ---------------------------------------------------------------------------
# Головна сторінка та санітизація
# ---------------------------------------------------------------------------

@client_bp.get("")
@client_bp.get("/")
def lab_index():
    return _render_lab()


@client_bp.post("/sanitize")
def sanitize_submit():
    """Приймає XSS-payload, санітизує його та зберігає безпечну версію."""

    _verify_csrf()

    raw_filename = request.form.get("filename", "")
    raw_description = request.form.get("description", "")
    raw_comment = request.form.get("comment", "")
    max_text = current_app.config.get("CLIENT_LAB_MAX_TEXT", 2000)

    filename = sanitize_filename(raw_filename)
    description = sanitize_description(raw_description, max_length=max_text)
    comment = sanitize_comment(raw_comment, max_length=max_text)

    combined = "\n".join(
        part for part in (raw_filename, raw_description, raw_comment) if part
    )
    report = inspect_sanitization(combined)
    blocked = ", ".join(report.blocked_vectors) or "—"

    stored = False
    if filename or description or comment:
        create_client_note(
            author=_author(),
            filename=filename or "document",
            description=description or comment or "(порожній опис)",
            blocked_vectors=blocked,
        )
        stored = True

    result = {
        "original": combined,
        "filename": filename,
        "description": description,
        "comment": comment,
        "blocked": blocked,
        "stored": stored,
        "report": report,
    }
    return _render_lab(result=result)


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------

@client_bp.get("/csp")
def csp_lab():
    return render_template(
        "client_lab_csp.html",
        csp_policy=CSP_POLICY,
        payloads=(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
        ),
    )


@client_bp.post("/csp-report")
def csp_report():
    """Приймає звіти браузера про порушення CSP (report-uri)."""

    payload = request.get_data(cache=False, as_text=True) or ""
    current_app.logger.warning("CSP violation report: %s", payload[:2000])
    return "", 204


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

@client_bp.get("/cookies")
def cookies_lab():
    """Встановлює демонстраційні cookie з повним набором атрибутів."""

    # Цей запис змушує Flask оновити підписану сесійну cookie.
    session["client_lab_cookie_probe"] = "1"

    response = make_response(
        render_template(
            "client_lab_cookies.html",
            cookie_specs=(
                {
                    "name": "docvault_session",
                    "http_only": True,
                    "secure": bool(current_app.config.get("SESSION_COOKIE_SECURE")),
                    "same_site": current_app.config.get("SESSION_COOKIE_SAMESITE"),
                    "purpose": "Підписана сесія Flask (CSRF-токен, user_id)",
                },
                {
                    "name": "docvault_demo_session",
                    "http_only": True,
                    "secure": True,
                    "same_site": "Strict",
                    "purpose": "Демонстраційний ідентифікатор сесії",
                },
                {
                    "name": "docvault_demo_csrf",
                    "http_only": False,
                    "secure": True,
                    "same_site": "Strict",
                    "purpose": "Публічний CSRF-токен для double-submit перевірки",
                },
            ),
        )
    )

    response.set_cookie(
        "docvault_demo_session",
        secrets.token_urlsafe(24),
        max_age=3600,
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/",
    )
    response.set_cookie(
        "docvault_demo_csrf",
        secrets.token_urlsafe(24),
        max_age=3600,
        httponly=False,
        secure=True,
        samesite="Strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Заголовки та CORS
# ---------------------------------------------------------------------------

@client_bp.get("/headers")
def headers_lab():
    probe = _probe("/api/v1/health", "https://probe.invalid")
    return render_template(
        "client_lab_headers.html",
        header_matrix=SECURITY_HEADER_MATRIX,
        csp_policy=CSP_POLICY,
        response_headers=list(probe.headers.items()),
        status_code=probe.status_code,
    )


@client_bp.get("/cors")
def cors_lab():
    origins = current_app.config.get("CORS_ALLOWED_ORIGINS", [])
    allowed_origin = origins[0] if origins else "http://localhost:5000"

    return render_template(
        "client_lab_cors.html",
        allowed_origin=allowed_origin,
        allowed_origins=origins,
        allowed=_cors_snapshot(allowed_origin),
        denied=_cors_snapshot("https://evil.example"),
        preflight=_cors_snapshot(
            allowed_origin,
            path="/api/v1/auth/login",
            method="OPTIONS",
            extra_headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, authorization",
            },
        ),
    )
