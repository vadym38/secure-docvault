"""REST API ключів підпису (ЛР №6).

Усі маршрути потребують JWT Bearer. Приватний ключ ніколи не
повертається у відкритому вигляді: лише PKCS#8 PEM, зашифрований
парольною фразою користувача.
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from .api import ApiError, handle_api_error, require_access_token
from .documents import DocumentError

keys_api_bp = Blueprint(
    "keys_api",
    __name__,
    url_prefix="/api/v1/keys",
)

keys_api_bp.register_error_handler(ApiError, handle_api_error)


@keys_api_bp.errorhandler(DocumentError)
def handle_key_error(error: DocumentError):
    response = jsonify(
        error={
            "code": error.code,
            "message": error.message,
        }
    )
    response.status_code = error.status
    return response


@keys_api_bp.after_request
def add_key_api_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _service():
    return current_app.extensions["document_service"]


@keys_api_bp.post("/generate")
@require_access_token
def generate_key():
    data = request.get_json(silent=True) or {}
    passphrase = str(data.get("passphrase", ""))
    if not passphrase:
        raise ApiError(
            400,
            "missing_passphrase",
            "Передайте парольну фразу для захисту приватного ключа.",
        )
    key = _service().generate_signing_key(g.api_user, passphrase)
    return jsonify(
        {
            "status": "success",
            "algorithm": key["algorithm"],
            "key": key,
            "message": (
                "Ключ RSA-PSS 2048 створено. Приватний ключ зашифровано "
                "PKCS#8; парольна фраза не зберігається."
            ),
        }
    ), 201


@keys_api_bp.get("")
@require_access_token
def list_keys():
    return jsonify({"keys": _service().list_signing_keys(g.api_user)})


@keys_api_bp.get("/active")
@require_access_token
def active_key():
    key = _service().active_signing_key(g.api_user)
    return jsonify({"key": key}), 200 if key else 404


@keys_api_bp.get("/<key_id>")
@require_access_token
def get_key(key_id: str):
    keys = _service().list_signing_keys(g.api_user)
    key = next((item for item in keys if item["key_id"] == key_id), None)
    if key is None:
        raise ApiError(404, "key_not_found", "Ключ підпису не знайдено.")
    return jsonify({"key": key})


@keys_api_bp.post("/<key_id>/export")
@require_access_token
def export_key(key_id: str):
    data = request.get_json(silent=True) or {}
    passphrase = str(data.get("passphrase", ""))
    if not passphrase:
        raise ApiError(
            400,
            "missing_passphrase",
            "Підтвердіть експорт парольною фразою.",
        )
    key = _service().export_signing_key(g.api_user, key_id, passphrase)
    return jsonify(
        {
            "key_id": key_id,
            "algorithm": key["algorithm"],
            "public_key_pem": key["public_key_pem"],
            "private_key_pem_encrypted": key["private_key_pem_encrypted"],
            "fingerprint": key["fingerprint"],
            "format": "PKCS#8 PEM (encrypted), X.509 SubjectPublicKeyInfo",
        }
    )
