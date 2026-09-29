"""Cryptographic request authentication for ``/api/application/v1``.

The body hash covers the exact received bytes. Canonical request MAC keys are
purpose-bound HKDF outputs of an X25519 exchange between one installation's
private key and the Application server's config-encryption key. Public keys
are not treated as secrets and no static client secret exists.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto.x25519 import x25519

_CANONICAL_PREFIX = "ZAGROS-APPLICATION-REQUEST-V1"
_MAC_INFO = b"zagros/application/request-mac/v1"
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class RequestSecurityError(ValueError):
    pass


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str, *, expected_length: int | None = None) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise RequestSecurityError("invalid base64url value")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise RequestSecurityError("invalid base64url value") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise RequestSecurityError("invalid encoded length")
    return decoded


def normalize_target(path: str, raw_query: str = "") -> str:
    """RFC-3986-ish stable target with sorted, duplicate-preserving query."""

    path = path or "/"
    if (_BAD_PERCENT_RE.search(path) or _BAD_PERCENT_RE.search(raw_query)
            or len(path) > 2048 or len(raw_query) > 4096):
        raise RequestSecurityError("invalid request target")
    try:
        normalized_path = quote(
            unquote(path, errors="strict"), safe="/-._~")
        pairs = [
            (quote(key, safe="-._~"), quote(value, safe="-._~"))
            for key, value in parse_qsl(
                raw_query, keep_blank_values=True, strict_parsing=False,
                encoding="utf-8", errors="strict", max_num_fields=100)
        ]
    except (UnicodeError, ValueError) as exc:
        raise RequestSecurityError("invalid request target") from exc
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    pairs.sort()
    query = "&".join(f"{key}={value}" for key, value in pairs)
    return normalized_path + ("?" + query if query else "")


def canonical_request(*, method: str, path: str, raw_query: str,
                      timestamp: int, nonce: str, application_id: str,
                      application_key_id: str, device_id: str | None,
                      body: bytes) -> bytes:
    if not _NONCE_RE.fullmatch(nonce or ""):
        raise RequestSecurityError("invalid nonce")
    if (not _IDENTIFIER_RE.fullmatch(application_id or "")
            or not _IDENTIFIER_RE.fullmatch(application_key_id or "")
            or (device_id not in {None, ""}
                and not _IDENTIFIER_RE.fullmatch(device_id))):
        raise RequestSecurityError("invalid signed identifier")
    body_hash = hashlib.sha256(body).hexdigest()
    fields = (
        _CANONICAL_PREFIX,
        method.upper(),
        normalize_target(path, raw_query),
        str(int(timestamp)),
        nonce,
        application_id,
        application_key_id,
        device_id or "-",
        body_hash,
    )
    if any("\n" in field or "\r" in field for field in fields):
        raise RequestSecurityError("canonical field contains a newline")
    return ("\n".join(fields) + "\n").encode("utf-8")


def derive_request_mac_key(*, private_key: bytes, peer_public_key: bytes,
                           application_id: str, application_key_id: str,
                           device_key_id: str | None) -> bytes:
    shared = x25519(private_key, peer_public_key)
    scope = "\0".join((
        application_id, application_key_id, device_key_id or "-",
    )).encode("utf-8")
    salt = hashlib.sha256(b"zagros/application/request-salt/v1\0" + scope).digest()
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=_MAC_INFO + b"\0" + scope,
    ).derive(shared)


def request_signature(mac_key: bytes, canonical: bytes) -> str:
    return b64url_encode(hmac.new(mac_key, canonical, hashlib.sha256).digest())


def verify_request_signature(mac_key: bytes, canonical: bytes,
                             signature: str) -> bool:
    try:
        provided = b64url_decode(signature, expected_length=32)
    except RequestSecurityError:
        # Keep one HMAC calculation on malformed signatures.
        provided = b"\0" * 32
    expected = hmac.new(mac_key, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


@dataclass(frozen=True, slots=True)
class SignedRequest:
    method: str
    path: str
    raw_query: str
    body: bytes
    application_id: str
    application_key_id: str
    device_id: str | None
    timestamp: int
    nonce: str
    signature: str

    def canonical(self) -> bytes:
        # Reject malformed encodings before any SQL key lookup. A SHA-256 HMAC
        # is always 32 bytes and therefore exactly 43 unpadded base64url chars.
        b64url_decode(self.signature, expected_length=32)
        return canonical_request(
            method=self.method, path=self.path, raw_query=self.raw_query,
            timestamp=self.timestamp, nonce=self.nonce,
            application_id=self.application_id,
            application_key_id=self.application_key_id,
            device_id=self.device_id, body=self.body,
        )
