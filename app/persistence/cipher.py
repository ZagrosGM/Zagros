"""Encryption-at-rest for account credentials (``credentials_enc``).

AES-256-GCM with an AAD binding each ciphertext to its row identity
(``user_id:core_id:account_id``) — ciphertexts cannot be swapped between
rows without failing authentication. The 32-byte data key is derived from
the deployment's master secret (``ZAGROS_SECRET_KEY``) with HKDF-SHA256.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from app.crypto.aesgcm import AesGcmError, aes_gcm_decrypt, aes_gcm_encrypt

_KEY_INFO = b"zagros/db-credentials/v1"
_PREFIX = "v1:"


class CipherError(ValueError):
    pass


def _hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_key(master_secret: str | bytes, *, info: bytes = _KEY_INFO) -> bytes:
    """Derive the 32-byte data key from any-length master secret."""
    if isinstance(master_secret, str):
        master_secret = master_secret.encode("utf-8")
    if len(master_secret) < 16:
        raise CipherError("master secret must be at least 16 bytes (set ZAGROS_SECRET_KEY)")
    return _hkdf_sha256(master_secret, info, 32)


class SecretsCipher:
    """Encrypts/decrypts JSON payloads for user_core_accounts credentials."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise CipherError("data key must be 32 bytes (see derive_key)")
        self._key = key

    @classmethod
    def from_master_secret(cls, master_secret: str | bytes) -> "SecretsCipher":
        return cls(derive_key(master_secret))

    def encrypt_json(self, value: dict[str, Any], *, aad: str) -> str:
        plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        ct = aes_gcm_encrypt(self._key, nonce, plaintext, aad=aad.encode("utf-8"))
        return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")

    def decrypt_json(self, blob: str, *, aad: str) -> dict[str, Any]:
        if not blob.startswith(_PREFIX):
            raise CipherError("unknown credentials format (missing v1 prefix)")
        raw = base64.b64decode(blob[len(_PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        try:
            plaintext = aes_gcm_decrypt(self._key, nonce, ct, aad=aad.encode("utf-8"))
        except AesGcmError as exc:
            raise CipherError("credentials failed authentication "
                              "(wrong key or tampered/swapped row)") from exc
        try:
            value = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise CipherError("credentials payload is not JSON") from exc
        if not isinstance(value, dict):
            raise CipherError("credentials payload must be a JSON object")
        return value
