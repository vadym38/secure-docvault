"""Лабораторний стенд WAF / Rate Limiting (ЛР №4).

Маршрути:
* ``/waf-lab``          — панель стану, демонстраційні атаки, журнал;
* ``/waf-lab/events``   — JSON для живого оновлення журналу;
* ``/waf-lab/reset``    — лабораторний скид стану (CSRF + config-прапорець).
"""

from __future__ import annotations

import hmac

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .waf_filter import signature_table

network_bp = Blueprint("network", __name__, url_prefix="/waf-lab")


def _guard():
    return current_app.extensions["network_guard"]


def _verify_csrf() -> None:
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get(
        "X-CSRF-Token", ""
    )
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="Недійсний CSRF-токен. Оновіть сторінку та спробуйте ще раз.",
        )


@network_bp.get("")
@network_bp.get("/")
def lab_index():
    guard = _guard()
    return render_template(
        "waf_lab.html",
        rules=guard.rule_table(),
        signatures=signature_table(),
        incidents=guard.incidents.recent(40),
        stats=guard.stats(),
        greylist=guard.greylist.active(),
        greylist_seconds=guard.greylist_seconds,
        allow_reset=bool(current_app.config.get("WAF_LAB_ALLOW_RESET", True)),
        waf_enabled=guard.waf_enabled,
        rate_limit_enabled=guard.rate_limit_enabled,
    )


@network_bp.get("/events")
def events():
    guard = _guard()
    return jsonify(
        {
            "stats": guard.stats(),
            "incidents": guard.incidents.recent(40),
            "greylist": guard.greylist.active(),
            "rules": guard.rule_table(),
        }
    )


@network_bp.post("/reset")
def reset():
    _verify_csrf()

    if not current_app.config.get("WAF_LAB_ALLOW_RESET", True):
        abort(403, description="Лабораторний Reset вимкнено конфігурацією.")

    guard = _guard()
    guard.reset()
    wants_json = (
        request.headers.get("X-Requested-With") == "fetch"
        or request.accept_mimetypes.best == "application/json"
    )
    if wants_json:
        return jsonify({"ok": True, "stats": guard.stats()})

    return redirect(url_for("network.lab_index"))
