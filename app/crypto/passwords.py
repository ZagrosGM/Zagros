"""Password hashing for Zagros app credentials and admin accounts.

Algorithm: scrypt (RFC 7914) via :func:`hashlib.scrypt` — memory-hard,
available in the Python standard library, no binary dependency.

Serial format::

    $zg-scrypt$v1$<n>$<r>$<p>$<salt-b64url>$<hash-b64url>

A parsed hash also reports :meth:`PasswordHasher.needs_rehash`, so the
service layer can transparently upgrade hashes when the cost parameters are
raised in the future.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_FORMAT_PREFIX = "$zg-scrypt$v1"
_MIN_N = 2**14
_MAX_N = 2**20  # 1 GiB memory at r=8 — hard ceiling to avoid DoS via crafted hashes


class PasswordHashError(ValueError):
    pass


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001
        raise PasswordHashError(f"invalid base64 in password hash: {exc}") from exc


class PasswordHasher:
    """scrypt hasher with fixed platform cost parameters."""

    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1,
                 salt_bytes: int = 16, dklen: int = 32) -> None:
        if not (_MIN_N <= n <= _MAX_N) or (n & (n - 1)) != 0:
            raise PasswordHashError("scrypt n must be a power of two in [2^14, 2^20]")
        if r < 1 or p < 1:
            raise PasswordHashError("scrypt r and p must be positive")
        self.n, self.r, self.p, self.salt_bytes, self.dklen = n, r, p, salt_bytes, dklen

    def hash(self, password: str) -> str:
        if not password:
            raise PasswordHashError("password must not be empty")
        salt = os.urandom(self.salt_bytes)
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=self.n, r=self.r, p=self.p, dklen=self.dklen,
        )
        return f"{_FORMAT_PREFIX}${self.n}${self.r}${self.p}${_b64e(salt)}${_b64e(digest)}"

    @staticmethod
    def parse(serial: str) -> tuple[int, int, int, bytes, bytes]:
        parts = serial.split("$")
        # "$zg-scrypt$v1$n$r$p$salt$hash" -> ['', 'zg-scrypt', 'v1', n, r, p, salt, hash]
        if len(parts) != 8 or parts[1] != "zg-scrypt" or parts[2] != "v1":
            raise PasswordHashError("unrecognized password hash format")
        try:
            n, r, p = int(parts[3]), int(parts[4]), int(parts[5])
        except ValueError as exc:
            raise PasswordHashError("non-numeric scrypt parameters") from exc
        if not (2**10 <= n <= _MAX_N) or (n & (n - 1)) != 0:
            raise PasswordHashError("scrypt n out of accepted range")
        salt, digest = _b64d(parts[6]), _b64d(parts[7])
        if len(salt) < 8 or len(digest) < 16:
            raise PasswordHashError("salt or digest too short")
        return n, r, p, salt, digest

    def verify(self, password: str, serial: str) -> bool:
        """Constant-time verification; False on any malformed input."""
        try:
            n, r, p, salt, expected = self.parse(serial)
        except PasswordHashError:
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)

    def needs_rehash(self, serial: str) -> bool:
        """True when the stored hash uses weaker-than-current parameters."""
        try:
            n, r, p, _, _ = self.parse(serial)
        except PasswordHashError:
            return True
        return (n, r, p) != (self.n, self.r, self.p)
