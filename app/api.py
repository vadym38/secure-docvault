"""REST API v1 Secure DocVault: stateless JWT-автентифікація (ЛР №2).

Маршрути:
* POST /api/v1/auth/login   — перевірка пароля та випуск пари токенів;
* POST /api/v1/auth/refresh — ротація Refresh-токена з виявленням reuse;
* POST /api/v1/auth/logout  — відкликання Access-токена та Refresh-родини;
* GET  /api/v1/user/profile — захищений ресурс (Bearer Access Token);
* GET  /api/v1/health       — службовий статус API.

Усі помилки повертаються у єдиному JSON-форматі. Жоден SQL-запит не
будується конкатенацією: робота з БД делегована app.database.
"""

from __future__ import annotations

import datetime as dt
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

from .auth_security import verify_dummy, verify_password
from .database import (
    find_refresh_token,
    find_user_by_id,
    find_user_by_username,
    is_access_token_revoked,
    parse_utc,
    revoke_access_token,
    revoke_all_user_refresh_tokens,
    revoke_refresh_family,
    revoke_refresh_token,
    rotate_refresh_token,
    store_refresh_token,
    utc_iso,
)
from .jwt_service import (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    TokenError,
    TokenPair,
    decode_token,
    issue_token_pair,
)

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


class ApiError(Exception):
    """Помилка API з HTTP-статусом і машинозчитуваним кодом."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@api_bp.errorhandler(ApiError)
def handle_api_error(error: ApiError):
    response = jsonify(
        error={
            "code": error.code,
            "message": error.message,
        }
    )
    response.status_code = error.status
    if error.status == 401:
        response.headers["WWW-Authenticate"] = 'Bearer realm="secure-docvault"'
    return response


@api_bp.after_request
def add_api_headers(response):
    """Забороняє кешувати відповіді з токенами та персональними даними."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


# ---------------------------------------------------------------------------
# Допоміжні функції
# ---------------------------------------------------------------------------

def _json_body(*, optional: bool = False) -> dict:
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict() if request.form else None

    if data is None:
        if optional:
            return {}
        raise ApiError(400, "invalid_json", "Очікується JSON-об'єкт у тілі запиту.")

    if not isinstance(data, dict):
        raise ApiError(400, "invalid_json", "Тіло запиту має бути JSON-об'єктом.")

    return data


def _bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    if not header:
        raise ApiError(
            401,
            "missing_token",
            "Потрібен заголовок Authorization: Bearer <access_token>.",
        )

    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise ApiError(
            401,
            "invalid_authorization_header",
            "Заголовок Authorization має формат: Bearer <access_token>.",
        )

    return parts[1]


def _public_user(user) -> dict:
    return {
        "id": int(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"],
        "is_active": bool(user["is_active"]),
    }


def _claim_time_iso(value: int | float) -> str:
    return utc_iso(dt.datetime.fromtimestamp(int(value), tz=dt.timezone.utc))


def _pair_payload(
    pair: TokenPair,
    *,
    user=None,
    rotated: bool = False,
) -> dict:
    payload = {
        "token_type": "Bearer",
        "access_token": pair.access.token,
        "refresh_token": pair.refresh.token,
        "expires_in": current_app.config["JWT_ACCESS_TTL_SECONDS"],
        "refresh_expires_in": current_app.config["JWT_REFRESH_TTL_SECONDS"],
        "access_expires_at": utc_iso(pair.access.expires_at),
        "refresh_expires_at": utc_iso(pair.refresh.expires_at),
    }
    if rotated:
        payload["rotated"] = True
        payload["previous_refresh_revoked"] = True
    if user is not None:
        payload["user"] = _public_user(user)
    return payload


def _issue_pair(user, *, family_id: str | None = None) -> TokenPair:
    pair = issue_token_pair(
        int(user["id"]),
        user["username"],
        user["role"],
        family_id=family_id,
    )
    store_refresh_token(
        jti=pair.refresh.jti,
        family_id=pair.family_id,
        user_id=int(user["id"]),
        issued_at=utc_iso(pair.refresh.issued_at),
        expires_at=utc_iso(pair.refresh.expires_at),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
    )
    return pair


def require_access_token(view):
    """Декоратор захисту ендпоінтів: Bearer + підпис + тип + revoke-список."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _bearer_token()

        try:
            payload = decode_token(token, expected_type=ACCESS_TOKEN)
        except TokenError as exc:
            raise ApiError(401, exc.code, exc.message) from exc

        if is_access_token_revoked(payload["jti"]):
            raise ApiError(401, "token_revoked", "Access-токен відкликано.")

        user = find_user_by_id(int(payload["sub"]))
        if user is None or not user["is_active"]:
            raise ApiError(
                401,
                "user_inactive",
                "Користувача не знайдено або його обліковий запис вимкнено.",
            )

        g.api_user = user
        g.jwt_payload = payload
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Автентифікація
# ---------------------------------------------------------------------------

@api_bp.post("/auth/login")
def login():
    """Перевіряє пароль і видає Access + Refresh токени."""

    data = _json_body()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        raise ApiError(
            400,
            "validation_error",
            "Поля username та password є обов'язковими.",
        )

    user = find_user_by_username(username)
    rounds = current_app.config["BCRYPT_ROUNDS"]

    if user is None:
        verify_dummy(password, rounds=rounds)
        raise ApiError(
            401,
            "invalid_credentials",
            "Невірне ім'я користувача або пароль.",
        )

    if not user["is_active"]:
        verify_dummy(password, rounds=rounds)
        raise ApiError(
            401,
            "invalid_credentials",
            "Невірне ім'я користувача або пароль.",
        )

    if not verify_password(password, user["password_hash"]):
        raise ApiError(
            401,
            "invalid_credentials",
            "Невірне ім'я користувача або пароль.",
        )

    pair = _issue_pair(user)
    return jsonify(_pair_payload(pair, user=user)), 200


@api_bp.post("/auth/refresh")
def refresh():
    """Ротує Refresh-токен. Повторне використання відкликає всю родину."""

    data = _json_body()
    token = data.get("refresh_token")
    if not token or not isinstance(token, str):
        raise ApiError(
            400,
            "missing_refresh_token",
            "Передайте refresh_token у тілі запиту.",
        )

    try:
        payload = decode_token(token, expected_type=REFRESH_TOKEN)
    except TokenError as exc:
        raise ApiError(401, exc.code, exc.message) from exc

    jti = payload["jti"]
    family_id = payload["family"]
    row = find_refresh_token(jti)

    if row is None:
        raise ApiError(
            401,
            "refresh_token_unknown",
            "Refresh-токен не знайдено в базі. Увійдіть повторно.",
        )

    if row["revoked_at"]:
        if row["revoked_reason"] == "rotated":
            revoked = revoke_refresh_family(row["family_id"], reason="reuse_detected")
            raise ApiError(
                401,
                "refresh_token_reuse",
                "Виявлено повторне використання Refresh-токена. "
                f"Відкликано активних токенів родини: {revoked}.",
            )
        raise ApiError(
            401,
            "refresh_token_revoked",
            "Refresh-токен уже відкликано. Увійдіть повторно.",
        )

    if row["family_id"] != family_id:
        raise ApiError(
            401,
            "invalid_token",
            "Refresh-токен не належить заявленій родині токенів.",
        )

    if parse_utc(row["expires_at"]) <= dt.datetime.now(dt.timezone.utc):
        revoke_refresh_token(jti, reason="expired")
        raise ApiError(
            401,
            "refresh_token_expired",
            "Термін дії Refresh-токена минув. Увійдіть повторно.",
        )

    user = find_user_by_id(int(row["user_id"]))
    if user is None or not user["is_active"]:
        raise ApiError(
            401,
            "user_inactive",
            "Користувача не знайдено або його обліковий запис вимкнено.",
        )

    new_pair = issue_token_pair(
        int(user["id"]),
        user["username"],
        user["role"],
        family_id=family_id,
    )

    rotated = rotate_refresh_token(
        old_jti=jti,
        new_jti=new_pair.refresh.jti,
        family_id=family_id,
        user_id=int(user["id"]),
        issued_at=utc_iso(new_pair.refresh.issued_at),
        expires_at=utc_iso(new_pair.refresh.expires_at),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
    )

    if not rotated:
        revoked = revoke_refresh_family(family_id, reason="reuse_detected")
        raise ApiError(
            401,
            "refresh_token_reuse",
            "Refresh-токен уже використано. "
            f"Відкликано активних токенів родини: {revoked}.",
        )

    return jsonify(_pair_payload(new_pair, user=user, rotated=True)), 200


@api_bp.post("/auth/logout")
@require_access_token
def logout():
    """Відкликає Access-токен і Refresh-токени користувача."""

    payload = g.jwt_payload
    user = g.api_user

    revoke_access_token(
        payload["jti"],
        int(user["id"]),
        _claim_time_iso(payload["exp"]),
        reason="logout",
    )

    data = _json_body(optional=True)
    refresh_token = data.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token:
        try:
            refresh_payload = decode_token(refresh_token, expected_type=REFRESH_TOKEN)
        except TokenError:
            refresh_payload = None

        if refresh_payload and str(refresh_payload["sub"]) == str(user["id"]):
            revoke_refresh_family(refresh_payload["family"], reason="logout")
        else:
            revoke_all_user_refresh_tokens(int(user["id"]), reason="logout")
    else:
        revoke_all_user_refresh_tokens(int(user["id"]), reason="logout")

    return jsonify(
        status="logged_out",
        message="Access-токен додано до blacklist, Refresh-токени відкликано.",
    ), 200


# ---------------------------------------------------------------------------
# Захищений ресурс
# ---------------------------------------------------------------------------

@api_bp.get("/user/profile")
@require_access_token
def profile():
    """Доступний лише з валідним Access Token."""

    user = g.api_user
    payload = g.jwt_payload

    return jsonify(
        user=_public_user(user),
        token={
            "type": payload["type"],
            "jti": payload["jti"],
            "issued_at": _claim_time_iso(payload["iat"]),
            "expires_at": _claim_time_iso(payload["exp"]),
            "algorithm": current_app.config["JWT_ALGORITHM"],
        },
    ), 200


@api_bp.get("/health")
def health():
    """Публічний службовий маршрут без автентифікації."""

    return jsonify(
        status="ok",
        service="secure-docvault-api",
        stage="v0.2-jwt-api",
        algorithm=current_app.config["JWT_ALGORITHM"],
    ), 200
