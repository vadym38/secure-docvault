"""Веб-інтерфейс зашифрованого сховища Secure DocVault (ЛР №5)."""

from __future__ import annotations

import hmac

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
from io import BytesIO

from .auth import login_required
from .digital_signature import MIN_PASSPHRASE_LENGTH
from .documents import DocumentError, DocumentTooLargeError

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")


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


@vault_bp.get("")
@login_required
def index():
    service = _service()
    documents = service.list_for_user(g.user)
    return render_template(
        "vault.html",
        documents=documents,
        stats=service.stats(g.user),
        signing_stats=service.signing_stats(g.user),
        has_signing_key=service.active_signing_key(g.user) is not None,
        key_fingerprint=service.cipher.fingerprint,
        key_count=service.cipher.key_count,
        max_bytes=service.max_bytes,
        allowed_extensions=sorted(service.allowed_extensions),
        storage_name=service.storage_dir.name,
    )


@vault_bp.post("/upload")
@login_required
def upload():
    _verify_csrf()
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        flash("Оберіть файл для завантаження.", "error")
        return redirect(url_for("vault.index"))

    service = _service()
    try:
        data = upload_file.stream.read(service.max_bytes + 1)
        if len(data) > service.max_bytes:
            raise DocumentTooLargeError(
                f"Файл перевищує ліміт {service.max_bytes} байт."
            )
        document = service.upload(
            g.user,
            filename=upload_file.filename,
            content_type=upload_file.mimetype,
            data=data,
        )
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("vault.index"))

    flash(
        f"Файл «{document['original_filename']}» зашифровано AES-256-GCM "
        f"і збережено як {document['document_id']}.enc.",
        "success",
    )
    return redirect(url_for("vault.document_detail", doc_id=document["document_id"]))


@vault_bp.get("/<doc_id>")
@login_required
def document_detail(doc_id: str):
    service = _service()
    try:
        document = service.container_preview(g.user, doc_id)
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("vault.index"))
    return render_template(
        "vault_document.html",
        document=document,
        active_key=service.active_signing_key(g.user),
        min_passphrase=MIN_PASSPHRASE_LENGTH,
        key_fingerprint=service.cipher.fingerprint,
    )


@vault_bp.post("/<doc_id>/sign")
@login_required
def sign(doc_id: str):
    _verify_csrf()
    passphrase = request.form.get("passphrase", "")
    service = _service()
    try:
        signature = service.sign_document(g.user, doc_id, passphrase)
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("vault.document_detail", doc_id=doc_id))

    flash(
        f"Документ підписано RSA-PSS. Статус: Signed & Verified "
        f"({signature['algorithm']}).",
        "success",
    )
    return redirect(url_for("vault.document_detail", doc_id=doc_id))


@vault_bp.get("/<doc_id>/download")
@login_required
def download(doc_id: str):
    service = _service()
    try:
        payload = service.download(g.user, doc_id)
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("vault.index"))

    response = send_file(
        BytesIO(payload.content),
        mimetype=payload.content_type,
        as_attachment=True,
        download_name=payload.filename,
    )
    response.headers["X-Content-SHA256"] = payload.sha256
    response.headers["X-Document-Encryption"] = "AES-256-GCM"
    response.headers["X-Signature-Status"] = payload.signature_status
    if payload.signature_algorithm:
        response.headers["X-Signature-Algorithm"] = payload.signature_algorithm
    if payload.signer:
        response.headers["X-Signer"] = payload.signer
    if payload.signature_fingerprint:
        response.headers["X-Signature-Fingerprint"] = payload.signature_fingerprint
    return response


@vault_bp.post("/<doc_id>/delete")
@login_required
def delete(doc_id: str):
    _verify_csrf()
    service = _service()
    try:
        service.delete(g.user, doc_id)
    except DocumentError as error:
        flash(str(error), "error")
        return redirect(url_for("vault.index"))
    flash("Документ і його зашифрований контейнер видалено.", "success")
    return redirect(url_for("vault.index"))
