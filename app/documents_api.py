"""REST API зашифрованих документів (ЛР №5).

Маршрути (усі потребують `Authorization: Bearer <access_token>`):

* POST   /api/v1/documents/upload              — завантаження + шифрування;
* GET    /api/v1/documents                     — список своїх документів;
* GET    /api/v1/documents/<id>                — метадані + hex-прев'ю;
* GET    /api/v1/documents/<id>/download       — дешифрування + видача;
* DELETE /api/v1/documents/<id>                — видалення документа.
"""

from __future__ import annotations

from io import BytesIO

from flask import Blueprint, current_app, g, jsonify, request, send_file

from .api import ApiError, handle_api_error, require_access_token
from .documents import (
    DocumentError,
    DocumentTooLargeError,
)

documents_api_bp = Blueprint(
    "documents_api",
    __name__,
    url_prefix="/api/v1/documents",
)

documents_api_bp.register_error_handler(ApiError, handle_api_error)


@documents_api_bp.errorhandler(DocumentError)
def handle_document_error(error: DocumentError):
    response = jsonify(
        error={
            "code": error.code,
            "message": error.message,
        }
    )
    response.status_code = error.status
    return response


@documents_api_bp.after_request
def add_document_api_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _service():
    return current_app.extensions["document_service"]


@documents_api_bp.post("/upload")
@require_access_token
def upload_document():
    upload = request.files.get("file")
    if upload is None:
        raise ApiError(
            400,
            "missing_file",
            "Передайте файл у полі `file` (multipart/form-data).",
        )

    service = _service()
    data = upload.stream.read(service.max_bytes + 1)
    if len(data) > service.max_bytes:
        raise DocumentTooLargeError(
            f"Файл перевищує ліміт {service.max_bytes} байт."
        )

    document = service.upload(
        g.api_user,
        filename=upload.filename or "",
        content_type=upload.mimetype,
        data=data,
    )
    return jsonify({"status": "success", "document": document}), 201


@documents_api_bp.get("")
@require_access_token
def list_documents():
    return jsonify({"documents": _service().list_for_user(g.api_user)})


@documents_api_bp.get("/<doc_id>")
@require_access_token
def get_document(doc_id: str):
    return jsonify({"document": _service().container_preview(g.api_user, doc_id)})


@documents_api_bp.get("/<doc_id>/download")
@require_access_token
def download_document(doc_id: str):
    payload = _service().download(g.api_user, doc_id)
    response = send_file(
        BytesIO(payload.content),
        mimetype=payload.content_type,
        as_attachment=True,
        download_name=payload.filename,
    )
    response.headers["X-Content-SHA256"] = payload.sha256
    response.headers["X-Document-Encryption"] = "AES-256-GCM"
    return response


@documents_api_bp.delete("/<doc_id>")
@require_access_token
def delete_document(doc_id: str):
    _service().delete(g.api_user, doc_id)
    return jsonify({"status": "deleted", "document_id": doc_id})
