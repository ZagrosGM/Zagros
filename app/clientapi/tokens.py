"""HMAC-signed access tokens (dependency-free, JSON-based).

Format: ``zga.<b64url(payload)>.<b64url(signature)>`` where the payload is
``{"sub", "iat", "exp", "jti", "typ"}`` and the signature is
HMAC-SHA256(server_secret, "zga.<payload>").

This intentionally mirrors JWT semantics while staying transparent: the
only accepted algorithm is HS256 — there is no ``alg`` field to confuse
(class of JWT alg-confusion attacks is impossible by construction).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenError(ValueError):
    pass


class SignedTokenService:
    """Issues/verifies access tokens against a server secret."""

    def __init__(self, secret: bytes | str, *, ttl_seconds: int = 900) -> None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if len(secret) < 16:
            raise ValueError("token secret must be at least 16 bytes")
        self._secret = secret
        self.ttl_seconds = ttl_seconds

    def _sign(self, signing_input: str) -> str:
        return _b64e(hmac.new(self._secret, signing_input.encode("ascii"),
                              hashlib.sha256).digest())

    def issue(self, subject: int | str, *, ttl_seconds: int | None = None,
              token_type: str = "access") -> tuple[str, int]:
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        now = int(time.time())
        payload = {
            "sub": str(subject), "iat": now, "exp": now + ttl,
            "jti": uuid.uuid4().hex, "typ": token_type,
        }
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"zga.{body}"
        return f"{signing_input}.{self._sign(signing_input)}", now + ttl

    def verify(self, token: str, *, expected_type: str = "access") -> dict:
        try:
            prefix, body, sig = token.split(".")
        except ValueError as exc:
            raise TokenError("malformed token") from exc
        if prefix != "zga":
            raise TokenError("unknown token prefix")
        signing_input = f"{prefix}.{body}"
        if not hmac.compare_digest(self._sign(signing_input), sig):
            raise TokenError("bad signature")
        try:
            payload = json.loads(_b64d(body))
        except Exception as exc:  # noqa: BLE001
            raise TokenError("bad payload") from exc
        if payload.get("typ") != expected_type:
            raise TokenError("wrong token type")
        if int(payload.get("exp", 0)) < int(time.time()):
            raise TokenError("token expired")
        if not payload.get("sub") or not payload.get("jti"):
            raise TokenError("missing claims")
        return payload
