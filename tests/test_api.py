"""Інтеграційні тести REST API v1: JWT, ротація та захист маршрутів."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import create_app
from app.auth_security import hash_password
from app.config import Config
from app.database import create_user, get_db
from app.jwt_service import create_access_token

JWT_SECRET = "api-jwt-secret-key-0123456789abcdef0123456789abcdef"
PASSWORD = "Vault#2026!"


def _decode_payload(token: str) -> dict:
    part = token.split(".")[1]
    padded = part + "=" * ((4 - (len(part) % 4)) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _encode_payload(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="docvault-api-"))
        test_config = type(
            "ApiConfig",
            (Config,),
            {
                "TESTING": True,
                "WAF_ENABLED": False,
                "RATE_LIMIT_ENABLED": False,
                "SECRET_KEY": "api-session-secret",
                "JWT_SECRET_KEY": JWT_SECRET,
                "DATABASE": str(cls.temp_dir / "api.db"),
                "BCRYPT_ROUNDS": 4,
            },
        )
        cls.app = create_app(test_config)

        with cls.app.app_context():
            digest, salt = hash_password(PASSWORD, rounds=4)
            cls.user_id = create_user("alice", "alice@example.local", digest, salt)
            digest, salt = hash_password(PASSWORD, rounds=4)
            cls.inactive_id = create_user("bob", "bob@example.local", digest, salt)
            get_db().execute("UPDATE users SET is_active = 0 WHERE id = ?", (cls.inactive_id,))
            get_db().commit()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self.client = self.app.test_client()

    def _login(self, username: str = "alice", password: str = PASSWORD):
        return self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )

    def _tokens(self):
        response = self._login()
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def _auth(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def test_health_is_public(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["stage"], "v0.2-jwt-api")

    def test_login_returns_token_pair(self):
        data = self._tokens()
        self.assertEqual(data["token_type"], "Bearer")
        self.assertEqual(data["expires_in"], 900)
        self.assertEqual(data["refresh_expires_in"], 604800)
        self.assertTrue(data["access_token"].count(".") == 2)
        self.assertTrue(data["refresh_token"].count(".") == 2)
        self.assertEqual(data["user"]["username"], "alice")
        self.assertNotIn("password_hash", data["user"])
        self.assertNotIn("salt", data["user"])

    def test_login_rejects_wrong_password(self):
        response = self._login(password="Wrong#2026!")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_credentials")

    def test_login_rejects_unknown_user_with_same_error(self):
        response = self._login(username="nobody")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_credentials")

    def test_login_blocks_sql_injection(self):
        response = self._login(username="' OR '1'='1", password="anything")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_credentials")

    def test_profile_without_token_returns_401(self):
        response = self.client.get("/api/v1/user/profile")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "missing_token")
        self.assertIn("Bearer", response.headers["WWW-Authenticate"])

    def test_profile_with_malformed_header_returns_401(self):
        response = self.client.get(
            "/api/v1/user/profile",
            headers={"Authorization": "Token abc"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_authorization_header")

    def test_profile_with_valid_token_returns_user(self):
        data = self._tokens()
        response = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(data["access_token"]),
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["user"]["username"], "alice")
        self.assertEqual(payload["token"]["type"], "access")
        self.assertEqual(payload["token"]["algorithm"], "HS256")
        self.assertNotIn("password_hash", payload["user"])

    def test_profile_rejects_tampered_role(self):
        data = self._tokens()
        header, payload, signature = data["access_token"].split(".")
        claims = _decode_payload(data["access_token"])
        claims["role"] = "admin"
        tampered = f"{header}.{_encode_payload(claims)}.{signature}"

        response = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(tampered),
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_signature")

    def test_profile_rejects_alg_none(self):
        header = _encode_payload({"alg": "none", "typ": "JWT"})
        payload = _encode_payload(
            {
                "iss": "secure-docvault",
                "aud": "secure-docvault-api",
                "sub": "1",
                "type": "access",
                "jti": "none",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "nbf": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            }
        )
        response = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(f"{header}.{payload}."),
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_algorithm")

    def test_expired_access_token_is_rejected(self):
        with self.app.app_context():
            issued = create_access_token(
                self.user_id,
                "alice",
                "user",
                now=datetime.now(timezone.utc) - timedelta(minutes=20),
                ttl_seconds=60,
            )
        response = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(issued.token),
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "token_expired")

    def test_refresh_rotates_token(self):
        data = self._tokens()
        old_refresh = data["refresh_token"]

        response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        self.assertEqual(response.status_code, 200)
        rotated = response.get_json()
        self.assertTrue(rotated["rotated"])
        self.assertTrue(rotated["previous_refresh_revoked"])
        self.assertNotEqual(rotated["refresh_token"], old_refresh)

        profile = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(rotated["access_token"]),
        )
        self.assertEqual(profile.status_code, 200)

    def test_refresh_reuse_revokes_family(self):
        data = self._tokens()
        old_refresh = data["refresh_token"]

        first = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        self.assertEqual(first.status_code, 200)
        new_refresh = first.get_json()["refresh_token"]

        reuse = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        self.assertEqual(reuse.status_code, 401)
        self.assertEqual(reuse.get_json()["error"]["code"], "refresh_token_reuse")

        after = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": new_refresh},
        )
        self.assertEqual(after.status_code, 401)
        self.assertEqual(after.get_json()["error"]["code"], "refresh_token_revoked")

    def test_refresh_rejects_access_token(self):
        data = self._tokens()
        response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": data["access_token"]},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_token_type")

    def test_refresh_rejects_unknown_token(self):
        response = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "unknown.token.value"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_token")

    def test_logout_revokes_access_and_refresh(self):
        data = self._tokens()
        response = self.client.post(
            "/api/v1/auth/logout",
            headers=self._auth(data["access_token"]),
            json={"refresh_token": data["refresh_token"]},
        )
        self.assertEqual(response.status_code, 200)

        profile = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(data["access_token"]),
        )
        self.assertEqual(profile.status_code, 401)
        self.assertEqual(profile.get_json()["error"]["code"], "token_revoked")

        refresh = self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": data["refresh_token"]},
        )
        self.assertEqual(refresh.status_code, 401)
        self.assertEqual(refresh.get_json()["error"]["code"], "refresh_token_revoked")

    def test_inactive_user_cannot_login_or_use_token(self):
        response = self._login(username="bob")
        self.assertEqual(response.status_code, 401)

        with self.app.app_context():
            issued = create_access_token(self.inactive_id, "bob", "user")
        profile = self.client.get(
            "/api/v1/user/profile",
            headers=self._auth(issued.token),
        )
        self.assertEqual(profile.status_code, 401)
        self.assertEqual(profile.get_json()["error"]["code"], "user_inactive")

    def test_api_responses_are_not_cached(self):
        response = self._login()
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Pragma"], "no-cache")

    def test_unknown_api_route_returns_json(self):
        response = self.client.get("/api/v1/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
