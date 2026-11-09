"""Сервіс випуску та криптографічної валідації JWT (ЛР №2).

Реалізовано:
* підпис HMAC-SHA256 (HS256) ключем довжиною не менше 256 біт;
* короткоживучий Access Token (15 хвилин) і Refresh Token (7 діб);
* обов'язкову перевірку підпису, `exp`, `iat`, `nbf`, `iss`, `aud`, `type`;
* явну заборону підміни алгоритму (`alg: none` та будь-який інший alg);
* унікальний `jti` для кожного токена (потрібен для ротації/revoke).
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass
from typing import Any

import jwt
from flask import current_app

ACCESS_TOKEN = "access"
REFRESH_TOKEN = "refresh"
MIN_SECRET_BYTES = 32


class TokenError(Exception):
    """Помилка валідації JWT із машинозчитуваним кодом."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IssuedToken:
    """Випущений токен разом із його службовими клеймами."""

    token: str
    jti: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    claims: dict[str, Any]


@dataclass(frozen=True)
class TokenPair:
    """Пара Access + Refresh, яка видається клієнту."""

    access: IssuedToken
    refresh: IssuedToken
    family_id: str


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _secret_key() -> str:
    key = current_app.config.get("JWT_SECRET_KEY", "")
    if not key or len(key.encode("utf-8")) < MIN_SECRET_BYTES:
        raise RuntimeError(
            "JWT_SECRET_KEY має містити щонайменше 32 байти (256 біт). "
            "Задайте ключ у .env, згенерований через secrets.token_hex(32)."
        )
    return key


def _algorithm() -> str:
    return current_app.config.get("JWT_ALGORITHM", "HS256")


def _base_claims(
    user_id: int,
    token_type: str,
    jti: str,
    issued_at: dt.datetime,
    expires_at: dt.datetime,
) -> dict[str, Any]:
    return {
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "sub": str(user_id),
        "type": token_type,
        "jti": jti,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
    }


def _encode(claims: dict[str, Any]) -> str:
    return jwt.encode(claims, _secret_key(), algorithm=_algorithm())


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    *,
    now: dt.datetime | None = None,
    ttl_seconds: int | None = None,
) -> IssuedToken:
    """Створює короткоживучий Access Token із роллю користувача."""

    issued_at = now or _now()
    ttl = ttl_seconds or current_app.config["JWT_ACCESS_TTL_SECONDS"]
    expires_at = issued_at + dt.timedelta(seconds=ttl)
    jti = secrets.token_urlsafe(24)

    claims = _base_claims(user_id, ACCESS_TOKEN, jti, issued_at, expires_at)
    claims.update({"username": username, "role": role})

    return IssuedToken(
        token=_encode(claims),
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
        claims=claims,
    )


def create_refresh_token(
    user_id: int,
    family_id: str,
    *,
    now: dt.datetime | None = None,
    ttl_seconds: int | None = None,
) -> IssuedToken:
    """Створює довгоживучий Refresh Token у межах родини токенів."""

    issued_at = now or _now()
    ttl = ttl_seconds or current_app.config["JWT_REFRESH_TTL_SECONDS"]
    expires_at = issued_at + dt.timedelta(seconds=ttl)
    jti = secrets.token_urlsafe(24)

    claims = _base_claims(user_id, REFRESH_TOKEN, jti, issued_at, expires_at)
    claims["family"] = family_id

    return IssuedToken(
        token=_encode(claims),
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
        claims=claims,
    )


def issue_token_pair(
    user_id: int,
    username: str,
    role: str,
    *,
    family_id: str | None = None,
) -> TokenPair:
    """Випускає пару Access + Refresh. Нова сім'я — якщо family_id не задано."""

    family = family_id or secrets.token_urlsafe(24)
    return TokenPair(
        access=create_access_token(user_id, username, role),
        refresh=create_refresh_token(user_id, family),
        family_id=family,
    )


def decode_token(token: str, *, expected_type: str | None = None) -> dict[str, Any]:
    """Декодує та перевіряє JWT. Кидає TokenError із конкретним кодом."""

    if not token or not isinstance(token, str):
        raise TokenError("invalid_token", "Токен відсутній або має некоректний формат.")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid_token", "Токен пошкоджений або має некоректний формат.") from exc

    # Явна перевірка алгоритму до декодування. Це закриває клас атак
    # algorithm confusion та 'alg': 'none', навіть якщо бібліотека зміниться.
    if header.get("alg") != _algorithm():
        raise TokenError(
            "invalid_algorithm",
            f"Алгоритм підпису заборонено. Очікується {_algorithm()}.",
        )

    try:
        payload = jwt.decode(
            token,
            _secret_key(),
            algorithms=[_algorithm()],
            audience=current_app.config["JWT_AUDIENCE"],
            issuer=current_app.config["JWT_ISSUER"],
            leeway=current_app.config["JWT_LEEWAY_SECONDS"],
            options={
                "require": ["exp", "iat", "nbf", "sub", "jti", "type", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token_expired", "Термін дії токена минув.") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenError(
            "invalid_signature",
            "Підпис JWT недійсний. Токен змінено або підписано іншим ключем.",
        ) from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("invalid_audience", "Токен призначено для іншої аудиторії.") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError("invalid_issuer", "Невідомий видавець токена.") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenError("missing_claim", "У токені відсутнє обов'язкове клеймо.") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise TokenError("invalid_algorithm", "Алгоритм підпису не дозволено.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid_token", "Токен недійсний або пошкоджений.") from exc

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.isdigit() or int(subject) <= 0:
        raise TokenError("invalid_subject", "Некоректний ідентифікатор користувача в токені.")

    token_type = payload.get("type")
    if token_type not in (ACCESS_TOKEN, REFRESH_TOKEN):
        raise TokenError("invalid_token_type", "Невідомий тип токена.")

    if expected_type is not None and token_type != expected_type:
        raise TokenError(
            "invalid_token_type",
            f"Очікувався {expected_type}-токен, отримано {token_type}.",
        )

    if token_type == REFRESH_TOKEN and not payload.get("family"):
        raise TokenError("missing_claim", "Refresh-токен не містить ідентифікатора родини.")

    return payload
