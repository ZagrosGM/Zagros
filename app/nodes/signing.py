"""Shared request-signing contract between the panel and zagros-node.

This module is the single source of truth for the wire format, and it is
byte-identical to ``node_agent/security.py`` in the zagros-node repository.
Signing lives in a tiny dependency-free module (rather than inside the
client) so both sides, plus the tests, derive the digest from one place:
a change here is a breaking protocol change and must be released on both
sides together.

Canonical request string::

    "\\n".join(METHOD, path, timestamp, nonce, sha256(body))

signed with HMAC-SHA256 using the 32-byte key handed over once, inside the
certificate-pinned TLS registration exchange.
"""
from __future__ import annotations

import hashlib
import hmac

SIGNATURE_HEADER = "X-Zagros-Signature"
NODE_HEADER = "X-Zagros-Node"
TIMESTAMP_HEADER = "X-Zagros-Timestamp"
NONCE_HEADER = "X-Zagros-Nonce"

# Requests older (or newer) than this are refused by the node.
REPLAY_WINDOW_SECONDS = 300


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(method: str, path: str, timestamp: str,
                      nonce: str, body: bytes) -> bytes:
    return "\n".join((method.upper(), path, timestamp, nonce,
                      body_hash(body))).encode("utf-8")


def signature(key: bytes, method: str, path: str, timestamp: str,
              nonce: str, body: bytes) -> str:
    return hmac.new(
        key, canonical_request(method, path, timestamp, nonce, body),
        hashlib.sha256).hexdigest()


def verify_signature(key: bytes, provided: str, method: str, path: str,
                     timestamp: str, nonce: str, body: bytes) -> None:
    """Raise :class:`ValueError` when the digest does not match."""
    expected = signature(key, method, path, timestamp, nonce, body)
    if not hmac.compare_digest(expected, provided):
        raise ValueError("invalid request signature")
