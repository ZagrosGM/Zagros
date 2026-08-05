"""X25519 ECDH key agreement — RFC 7748 (Curve25519 Montgomery ladder).

Used by sealed delivery: the app generates an ephemeral keypair, sends its
public key with the connect-token, and the platform seals the connection
payload to that key. Only the holder of the ephemeral private key (the app,
in memory) can open the envelope.

Verified against the RFC 7748 test vectors and cross-checked at development
time against ``cryptography``; golden digests live in
``tests/crypto/test_x25519.py``.
"""
from __future__ import annotations

import os

_P = 2**255 - 19
_A24 = 121665
_BASE_POINT = 9

X25519_KEY_SIZE = 32


def _clamp(scalar: bytes) -> int:
    if len(scalar) != X25519_KEY_SIZE:
        raise ValueError("X25519 scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _ladder(k: int, u: int) -> int:
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) ** 2) % _P
        z3 = (x1 * ((da - cb) ** 2)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P)) % _P


def _x25519_pure(private_key: bytes, public_key: bytes) -> bytes:
    """Compute the 32-byte shared secret.

    Per RFC 7748, the most significant bit of the received u-coordinate is
    masked before use (non-canonical inputs with u >= 2^255 are normalized;
    see the RFC test vectors — one of them exercises exactly this case).

    The all-zero output (low-order / non-contributory peer key) is rejected
    explicitly instead of being returned, because silently accepting it would
    make sealed delivery encrypt to a key an attacker can predict.
    """
    if len(public_key) != X25519_KEY_SIZE:
        raise ValueError("X25519 public key must be 32 bytes")
    received = bytearray(public_key)
    received[31] &= 0x7F  # RFC 7748: implementations MUST mask the MSB
    result = _ladder(_clamp(private_key), int.from_bytes(received, "little"))
    out = result.to_bytes(X25519_KEY_SIZE, "little")
    if not any(out):
        raise ValueError("non-contributory X25519 public key rejected")
    return out


def public_from_private(private_key: bytes) -> bytes:
    """Derive the public key for a 32-byte private key (base point mult)."""
    result = _ladder(_clamp(private_key), _BASE_POINT)
    return result.to_bytes(X25519_KEY_SIZE, "little")


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_key, public_key)`` from the OS CSPRNG."""
    private = os.urandom(X25519_KEY_SIZE)
    return private, public_from_private(private)


# ---------------------------------------------------------------------- #
# backend dispatch: prefer `cryptography`'s X25519 (constant-time, fast);
# the pure-Python Montgomery ladder stays as the bootstrap fallback. Both
# are pinned to the RFC 7748 vectors in tests.
# ---------------------------------------------------------------------- #
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey as _LibX25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PublicKey as _LibX25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization as _lib_ser

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - minimal bootstrap only
    _HAS_CRYPTOGRAPHY = False

if _HAS_CRYPTOGRAPHY:

    def x25519(private_key: bytes, public_key: bytes) -> bytes:
        if len(private_key) != 32:
            raise ValueError("X25519 scalar must be 32 bytes")
        if len(public_key) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        # uniforms the pure-path contract: null shared secret → ValueError
        if public_key == b"\x00" * 32:
            raise ValueError("non-contributory X25519 public key rejected")
        priv = _LibX25519PrivateKey.from_private_bytes(private_key)
        pub = _LibX25519PublicKey.from_public_bytes(public_key)
        try:
            return priv.exchange(pub)
        except ValueError as exc:  # any other non-contributory point
            raise ValueError(
                "non-contributory X25519 public key rejected") from exc

    def public_from_private(private_key: bytes) -> bytes:
        priv = _LibX25519PrivateKey.from_private_bytes(private_key)
        return priv.public_key().public_bytes(
            _lib_ser.Encoding.Raw, _lib_ser.PublicFormat.Raw)

else:  # pragma: no cover - exercised when cryptography is absent

    x25519 = _x25519_pure
