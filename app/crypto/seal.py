"""Sealed delivery envelopes.

Construction (version 1)::

    shared  = X25519(ephemeral_private, recipient_public)
    key     = HKDF-SHA256(shared, salt=None, info=SEAL_INFO, length=32)
    (ct|tag)= AES-256-GCM(key, nonce=random(12), payload, aad=ephemeral_public)
    envelope= {"v":1, "alg", "eph": b64, "nonce": b64, "ct": b64}

The envelope is safe to transmit over any authenticated channel; only the
holder of ``recipient_private`` can open it. The AAD binds the ciphertext to
the ephemeral public key so envelopes cannot be mixed and matched.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from pydantic import BaseModel

from app.crypto.aesgcm import AesGcmError, aes_gcm_decrypt, aes_gcm_encrypt
from app.crypto.x25519 import public_from_private, x25519

SEAL_INFO = b"zagros-seal-v1"
SEAL_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM"


class SealError(ValueError):
    """Raised when an envelope is malformed or fails authentication."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001 - normalize to SealError
        raise SealError(f"invalid base64 in envelope: {exc}") from exc


def _hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class SealedEnvelope(BaseModel):
    """Wire representation of a sealed payload (JSON-safe)."""

    v: int = 1
    alg: str = SEAL_ALGORITHM
    eph: str          # base64url ephemeral X25519 public key (32 bytes)
    nonce: str        # base64url 12-byte GCM nonce
    ct: str           # base64url ciphertext||tag

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, text: str) -> "SealedEnvelope":
        try:
            return cls.model_validate(json.loads(text))
        except SealError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SealError(f"malformed envelope: {exc}") from exc


def seal(payload: bytes, recipient_public: bytes) -> SealedEnvelope:
    """Seal ``payload`` to the recipient's X25519 public key.

    A fresh ephemeral keypair and nonce are generated for every call, so two
    seals of identical payloads produce unrelated envelopes (forward secrecy
    per delivery).
    """
    eph_private = os.urandom(32)
    eph_public = public_from_private(eph_private)
    shared = x25519(eph_private, recipient_public)
    key = _hkdf_sha256(shared, SEAL_INFO, 32)
    nonce = os.urandom(12)
    ct = aes_gcm_encrypt(key, nonce, payload, aad=eph_public)
    return SealedEnvelope(eph=_b64e(eph_public), nonce=_b64e(nonce), ct=_b64e(ct))


def open_envelope(envelope: SealedEnvelope, recipient_private: bytes) -> bytes:
    """Open an envelope with the recipient's private key."""
    if envelope.v != 1 or envelope.alg != SEAL_ALGORITHM:
        raise SealError(f"unsupported envelope version/algorithm: v={envelope.v}")
    eph_public = _b64d(envelope.eph)
    nonce = _b64d(envelope.nonce)
    ct = _b64d(envelope.ct)
    if len(eph_public) != 32 or len(nonce) != 12:
        raise SealError("bad envelope field sizes")
    try:
        shared = x25519(recipient_private, eph_public)
    except ValueError as exc:
        raise SealError(str(exc)) from exc
    key = _hkdf_sha256(shared, SEAL_INFO, 32)
    try:
        return aes_gcm_decrypt(key, nonce, ct, aad=eph_public)
    except AesGcmError as exc:
        raise SealError("envelope authentication failed") from exc


def check_seal_roundtrip() -> bool:  # pragma: no cover - dev helper
    priv, pub = __import__("app.crypto.x25519", fromlist=["generate_keypair"]).generate_keypair()
    return open_envelope(seal(b"ping", pub), priv) == b"ping"
