"""Registered-device Application config envelope (version 1).

The legacy sealed channel accepted an arbitrary recipient key. This contract
always encrypts to the already-enrolled device key and combines two independent
cross-identity X25519 exchanges:

* Application static config private key × registered device public key;
* per-response server ephemeral private key × registered device public key.

All public metadata is AES-GCM AAD. The complete unsigned envelope, including
ciphertext, is signed by the Application Ed25519 identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel

from app.applicationapi.security import b64url_decode, b64url_encode
from app.crypto.aesgcm import AesGcmError, aes_gcm_decrypt, aes_gcm_encrypt
from app.crypto.x25519 import generate_keypair, x25519

CONFIG_ENVELOPE_ALGORITHM = "X25519X2-HKDF-SHA256-AES-256-GCM+Ed25519"
_CONFIG_INFO = b"zagros/application/config-envelope/v1"
_SIGNATURE_PREFIX = b"ZAGROS-APPLICATION-CONFIG-ENVELOPE-V1\n"


class ConfigEnvelopeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ConfigEnvelopeClaims:
    application_id: str
    application_key_id: str
    signing_key_id: str
    device_id: str
    config_id: str
    connection_id: str | None
    core_id: str
    protocol: str
    engine: str
    issued_at: int
    not_before: int
    expires_at: int


class ApplicationConfigEnvelope(BaseModel):
    v: int = 1
    alg: str = CONFIG_ENVELOPE_ALGORITHM
    application_id: str
    application_key_id: str
    signing_key_id: str
    device_id: str
    config_id: str
    connection_id: str | None = None
    core_id: str
    protocol: str
    engine: str
    issued_at: int
    not_before: int
    expires_at: int
    salt: str
    eph: str
    nonce: str
    ct: str
    signature: str


def _json(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def _metadata(envelope: ApplicationConfigEnvelope) -> dict:
    return envelope.model_dump(exclude={"ct", "signature"})


def _unsigned(envelope: ApplicationConfigEnvelope) -> dict:
    return envelope.model_dump(exclude={"signature"})


def _derive_key(*, static_shared: bytes, ephemeral_shared: bytes,
                salt: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=_CONFIG_INFO + b"\0" + hashlib.sha256(aad).digest(),
    ).derive(static_shared + ephemeral_shared)


def seal_application_config(
    payload: bytes,
    *,
    claims: ConfigEnvelopeClaims,
    application_config_private_key: bytes,
    device_public_key: bytes,
    application_signing_private_key: bytes,
    ephemeral_private_key: bytes | None = None,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> ApplicationConfigEnvelope:
    if not payload:
        raise ConfigEnvelopeError("config payload must not be empty")
    if not (claims.issued_at <= claims.not_before < claims.expires_at):
        raise ConfigEnvelopeError("invalid config validity interval")
    if ephemeral_private_key is None:
        ephemeral_private_key, ephemeral_public_key = generate_keypair()
    else:
        from app.crypto.x25519 import public_from_private

        ephemeral_public_key = public_from_private(ephemeral_private_key)
    salt = salt if salt is not None else os.urandom(32)
    nonce = nonce if nonce is not None else os.urandom(12)
    if len(salt) != 32 or len(nonce) != 12:
        raise ConfigEnvelopeError("invalid salt or nonce size")

    try:
        static_shared = x25519(
            application_config_private_key, device_public_key)
        ephemeral_shared = x25519(ephemeral_private_key, device_public_key)
    except ValueError as exc:
        raise ConfigEnvelopeError("invalid X25519 key material") from exc

    envelope = ApplicationConfigEnvelope(
        application_id=claims.application_id,
        application_key_id=claims.application_key_id,
        signing_key_id=claims.signing_key_id,
        device_id=claims.device_id,
        config_id=claims.config_id,
        connection_id=claims.connection_id,
        core_id=claims.core_id,
        protocol=claims.protocol,
        engine=claims.engine,
        issued_at=claims.issued_at,
        not_before=claims.not_before,
        expires_at=claims.expires_at,
        salt=b64url_encode(salt),
        eph=b64url_encode(ephemeral_public_key),
        nonce=b64url_encode(nonce),
        ct="pending",
        signature="pending",
    )
    aad = _json(_metadata(envelope))
    key = _derive_key(
        static_shared=static_shared, ephemeral_shared=ephemeral_shared,
        salt=salt, aad=aad)
    envelope.ct = b64url_encode(aes_gcm_encrypt(key, nonce, payload, aad=aad))
    signing_input = _SIGNATURE_PREFIX + _json(_unsigned(envelope))
    try:
        signature = Ed25519PrivateKey.from_private_bytes(
            application_signing_private_key).sign(signing_input)
    except ValueError as exc:
        raise ConfigEnvelopeError("invalid signing key material") from exc
    envelope.signature = b64url_encode(signature)
    return envelope


def open_application_config(
    envelope: ApplicationConfigEnvelope,
    *,
    device_private_key: bytes,
    application_config_public_key: bytes,
    application_signing_public_key: bytes,
    now: int,
    expected_application_id: str | None = None,
    expected_device_id: str | None = None,
) -> bytes:
    if envelope.v != 1 or envelope.alg != CONFIG_ENVELOPE_ALGORITHM:
        raise ConfigEnvelopeError("unsupported config envelope")
    if (expected_application_id is not None
            and envelope.application_id != expected_application_id):
        raise ConfigEnvelopeError("config envelope binding mismatch")
    if (expected_device_id is not None
            and envelope.device_id != expected_device_id):
        raise ConfigEnvelopeError("config envelope binding mismatch")

    try:
        signature = b64url_decode(envelope.signature, expected_length=64)
        Ed25519PublicKey.from_public_bytes(
            application_signing_public_key).verify(
                signature, _SIGNATURE_PREFIX + _json(_unsigned(envelope)))
    except (InvalidSignature, ValueError) as exc:
        raise ConfigEnvelopeError("config envelope signature invalid") from exc
    if now < envelope.not_before or now >= envelope.expires_at:
        raise ConfigEnvelopeError("config envelope is outside its validity window")

    try:
        salt = b64url_decode(envelope.salt, expected_length=32)
        ephemeral_public = b64url_decode(envelope.eph, expected_length=32)
        nonce = b64url_decode(envelope.nonce, expected_length=12)
        ciphertext = b64url_decode(envelope.ct)
        static_shared = x25519(
            device_private_key, application_config_public_key)
        ephemeral_shared = x25519(device_private_key, ephemeral_public)
    except ValueError as exc:
        raise ConfigEnvelopeError("config envelope key material invalid") from exc
    aad = _json(_metadata(envelope))
    key = _derive_key(
        static_shared=static_shared, ephemeral_shared=ephemeral_shared,
        salt=salt, aad=aad)
    try:
        return aes_gcm_decrypt(key, nonce, ciphertext, aad=aad)
    except AesGcmError as exc:
        raise ConfigEnvelopeError("config envelope authentication failed") from exc
