"""Application/device-bound short-lived access tokens."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable

from app.applicationapi.security import b64url_decode, b64url_encode


class ApplicationTokenError(ValueError):
    pass


class ApplicationAccessTokenService:
    """Single-algorithm HMAC token with mandatory app/user/device claims."""

    def __init__(self, key: bytes, *, ttl_seconds: int = 300,
                 now: Callable[[], float] = time.time) -> None:
        if len(key) != 32:
            raise ValueError("Application access-token key must be 32 bytes")
        self._key = key
        self.ttl_seconds = int(ttl_seconds)
        self._now = now

    def _signature(self, value: bytes) -> str:
        return b64url_encode(hmac.new(self._key, value, hashlib.sha256).digest())

    def issue(self, *, user_id: int, application_id: int,
              application_public_id: str, device_id: int,
              device_key_id: str, application_key_id: int,
              token_family_id: str) -> tuple[str, int]:
        now = int(self._now())
        expires = now + self.ttl_seconds
        payload = {
            "sub": str(user_id),
            "app": str(application_id),
            "aid": application_public_id,
            "dev": str(device_id),
            "dkid": device_key_id,
            "akid": str(application_key_id),
            "fam": token_family_id,
            "iat": now,
            "exp": expires,
            "jti": secrets.token_hex(16),
            "typ": "application_access",
        }
        body = b64url_encode(json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signed = f"zgaa.{body}".encode("ascii")
        return f"zgaa.{body}.{self._signature(signed)}", expires

    def verify(self, token: str) -> dict[str, str | int]:
        try:
            prefix, body, signature = token.split(".")
        except ValueError as exc:
            raise ApplicationTokenError("invalid access token") from exc
        signed = f"{prefix}.{body}".encode("ascii", errors="strict")
        expected = self._signature(signed)
        if prefix != "zgaa" or not hmac.compare_digest(expected, signature):
            raise ApplicationTokenError("invalid access token")
        try:
            payload = json.loads(b64url_decode(body).decode("utf-8"))
        except Exception as exc:
            raise ApplicationTokenError("invalid access token") from exc
        required = {"sub", "app", "aid", "dev", "dkid", "akid", "fam", "jti"}
        if payload.get("typ") != "application_access" or not required <= payload.keys():
            raise ApplicationTokenError("invalid access token")
        now = int(self._now())
        if int(payload.get("exp", 0)) <= now or int(payload.get("iat", 0)) > now + 30:
            raise ApplicationTokenError("access token expired or not yet valid")
        return payload
