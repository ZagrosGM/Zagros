"""Zagros cryptographic primitives — self-contained, dependency-free.

This package provides everything the platform needs at runtime without
requiring binary dependencies:

* :mod:`app.crypto.aesgcm`   — AES-GCM AEAD (FIPS-197 + SP800-38D)
* :mod:`app.crypto.x25519`   — X25519 ECDH key agreement (RFC 7748)
* :mod:`app.crypto.seal`     — sealed delivery envelopes (X25519 + HKDF-SHA256
                               + AES-256-GCM) used by the client API so that
                               connection secrets only ever exist in memory
                               on the server and inside the official app.
* :mod:`app.crypto.passwords`— scrypt password hashing (RFC 7914 via hashlib)

All primitives are verified against standard test vectors (NIST, RFC) and
cross-checked at development time against the reference `cryptography`
library; the golden digests are embedded in ``tests/crypto/``.
"""
from app.crypto.aesgcm import aes_gcm_decrypt, aes_gcm_encrypt
from app.crypto.x25519 import (
    X25519_KEY_SIZE,
    generate_keypair,
    public_from_private,
)
from app.crypto.seal import (
    SEAL_INFO,
    SealedEnvelope,
    SealError,
    open_envelope,
    seal,
)
from app.crypto.passwords import PasswordHasher, PasswordHashError

__all__ = [
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "public_from_private",
    "generate_keypair",
    "X25519_KEY_SIZE",
    "seal",
    "open_envelope",
    "SealedEnvelope",
    "SealError",
    "SEAL_INFO",
    "PasswordHasher",
    "PasswordHashError",
]
