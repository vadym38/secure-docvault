"""Signature Lab — керування ключами та ЕЦП (ЛР №6)."""

from __future__ import annotations

import hmac
from io import BytesIO

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from .auth import login_required
from .digital_signature import MIN_PASSPHRASE_LENGTH
from .documents import DocumentError

signature_bp = Blueprint(
    "signature",
    __name__,
    url_prefix="/signature-lab",
)


def _service():
    return current_app.extensions["document_service"]


def _verify_csrf() -> None:
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="Недійсний CSRF-токен. Оновіть сторінку та спробуйте ще раз.",
        )


@signature_bp.get("")
@login_required
def index():
    service = _service()
    keys = service.list_signing_keys(g.user)
    active_key = service.active_signing_key(g.user)
    private_pem = None
    if active_key:
        private_pem = service.get_encrypted_private_key(
            g.user, active_key["key_id"]
        )

    return render_template(
        "signature_lab.html",
        keys=keys,
        active_key=active_key,
        private_pem=private_pem,
        signatures=service.list_signatures(g.user),
        stats=service.signing_stats(g.user),
        min_passphrase=MIN_PASSPHRASE_LENGTH,
    )


@signature_bp.post("/generate")
@login_required
def generate():
    _verify_csrf()
    passphrase = request.form.get("passphrase", "")
    confirm = request.form.get("confirm", "")

    if passphrase != confirm:
        flash("Парольні фрази не збігаються.", "error")
        return redirect(url_for("signature.index"))

    try:
        key = _service().generate_signing_key(g.user, passphrase)
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("signature.index"))

    flash(
        f"Ключ RSA-PSS 2048 створено. Fingerprint: {key['fingerprint']}.",
        "success",
    )
    return redirect(url_for("signature.index"))


@signature_bp.get("/keys/<key_id>/private")
@login_required
def export_private(key_id: str):
    pem = _service().get_encrypted_private_key(g.user, key_id)
    return send_file(
        BytesIO(pem.encode("utf-8")),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{key_id}-private-encrypted.pem",
    )


@signature_bp.get("/keys/<key_id>/public")
@login_required
def export_public(key_id: str):
    keys = _service().list_signing_keys(g.user)
    key = next((item for item in keys if item["key_id"] == key_id), None)
    if key is None:
        abort(404)
    return send_file(
        BytesIO(key["public_key_pem"].encode("ascii")),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{key_id}-public.pem",
    )
