"""Юніт-тести сервісу JWT: підпис, TTL, типи та заборона alg:none."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

from app import create_app
from app.config import Config
from app.jwt_service import (
    TokenError,
    create_access_token,
    decode_token,
    issue_token_pair,
)

TEST_SECRET = "unit-jwt-secret-key-0123456789abcdef0123456789abcdef"


def _b64url(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> dict:
    padded = value + "=" * ((4 - (len(value) % 4)) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class JwtServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-jwt-"))
        test_config = type(
            "JwtConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "unit-session-secret",
                "JWT_SECRET_KEY": TEST_SECRET,
                "DATABASE": str(cls.temp_dir / "jwt.db"),
                "BCRYPT_ROUNDS": 4,
            },
        )
        cls.app = create_app(test_config)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_issue_pair_contains_expected_claims(self):
        with self.app.app_context():
            pair = issue_token_pair(7, "alice", "user")
            access = decode_token(pair.access.token, expected_type="access")
            refresh = decode_token(pair.refresh.token, expected_type="refresh")

        self.assertEqual(access["sub"], "7")
        self.assertEqual(access["username"], "alice")
        self.assertEqual(access["role"], "user")
        self.assertEqual(access["type"], "access")
        self.assertEqual(access["iss"], "secure-docvault")
        self.assertEqual(access["aud"], "secure-docvault-api")
        self.assertTrue(access["jti"])
        self.assertEqual(refresh["type"], "refresh")
        self.assertEqual(refresh["family"], pair.family_id)
        self.assertNotEqual(pair.access.jti, pair.refresh.jti)

    def test_expired_access_token_is_rejected(self):
        with self.app.app_context():
            issued = create_access_token(
                1,
                "alice",
                "user",
                now=datetime.now(timezone.utc) - timedelta(minutes=20),
                ttl_seconds=60,
            )
            with self.assertRaises(TokenError) as context:
                decode_token(issued.token, expected_type="access")

        self.assertEqual(context.exception.code, "token_expired")

    def test_modified_payload_breaks_signature(self):
        with self.app.app_context():
            pair = issue_token_pair(1, "alice", "user")
            header, payload, signature = pair.access.token.split(".")
            claims = _decode_b64url(payload)
            claims["role"] = "admin"
            tampered = f"{header}.{_b64url(claims)}.{signature}"

            with self.assertRaises(TokenError) as context:
                decode_token(tampered, expected_type="access")

        self.assertEqual(context.exception.code, "invalid_signature")

    def test_alg_none_is_rejected(self):
        header = _b64url({"alg": "none", "typ": "JWT"})
        payload = _b64url(
            {
                "sub": "1",
                "type": "access",
                "jti": "none-token",
                "iss": "secure-docvault",
                "aud": "secure-docvault-api",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "nbf": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            }
        )
        token = f"{header}.{payload}."

        with self.app.app_context():
            with self.assertRaises(TokenError) as context:
                decode_token(token, expected_type="access")

        self.assertEqual(context.exception.code, "invalid_algorithm")

    def test_refresh_token_cannot_be_used_as_access(self):
        with self.app.app_context():
            pair = issue_token_pair(1, "alice", "user")
            with self.assertRaises(TokenError) as context:
                decode_token(pair.refresh.token, expected_type="access")

        self.assertEqual(context.exception.code, "invalid_token_type")

    def test_token_signed_with_another_key_is_rejected(self):
        claims = {
            "iss": "secure-docvault",
            "aud": "secure-docvault-api",
            "sub": "1",
            "type": "access",
            "jti": "foreign",
            "username": "alice",
            "role": "admin",
            "iat": datetime.now(timezone.utc),
            "nbf": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        foreign = jwt.encode(claims, "another-secret-key-0123456789abcdef0123456789", algorithm="HS256")

        with self.app.app_context():
            with self.assertRaises(TokenError) as context:
                decode_token(foreign, expected_type="access")

        self.assertEqual(context.exception.code, "invalid_signature")

    def test_missing_required_claim_is_rejected(self):
        now = datetime.now(timezone.utc)
        incomplete = jwt.encode(
            {
                "iss": "secure-docvault",
                "aud": "secure-docvault-api",
                "sub": "1",
                "type": "access",
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(minutes=5),
            },
            TEST_SECRET,
            algorithm="HS256",
        )

        with self.app.app_context():
            with self.assertRaises(TokenError) as context:
                decode_token(incomplete, expected_type="access")

        self.assertEqual(context.exception.code, "missing_claim")

    def test_short_secret_fails_closed(self):
        test_config = type(
            "ShortSecretConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "short",
                "JWT_SECRET_KEY": "too-short",
                "DATABASE": str(self.temp_dir / "short.db"),
            },
        )
        with self.assertRaises(RuntimeError):
            create_app(test_config)


if __name__ == "__main__":
    unittest.main()
