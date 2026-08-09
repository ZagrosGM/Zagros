"""Shared wizard certificate validation (alpha.7.5 items 6/8).

ONE validator for every certificate a wizard can reference — stored
(certificate_ref), pasted content (certificate + certificate_key) or
server-side paths (certificate_path + certificate_key_path). Same rules the
sing-box driver pioneered in alpha.7.4: real PEM parse, key/cert public-key
match, expiry surfaced loudly. xray previously trusted uploads blindly;
both drivers now share this module instead of diverging.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CertificateError(ValueError):
    """A wizard certificate failed validation — message is operator-ready."""


def validate_pem_pair(cert_pem, key_pem, *, context: str) -> x509.Certificate:
    """Parse + cross-check a PEM certificate/private-key pair.

    Returns the parsed certificate on success; raises CertificateError with
    a precise reason otherwise (never a bare cryptography traceback at the
    operator).
    """
    cert_raw = cert_pem.encode() if isinstance(cert_pem, str) else bytes(cert_pem)
    key_raw = key_pem.encode() if isinstance(key_pem, str) else bytes(key_pem)
    try:
        cert = x509.load_pem_x509_certificate(cert_raw)
    except ValueError as exc:
        raise CertificateError(f"{context}: certificate is not a valid PEM ({exc})") from exc
    try:
        key = serialization.load_pem_private_key(key_raw, password=None)
    except ValueError as exc:
        raise CertificateError(
            f"{context}: private key is not a valid unencrypted PEM ({exc})") from exc
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise CertificateError(f"{context}: certificate and private key do NOT match")
    days = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
    if days <= 0:
        raise CertificateError(f"{context}: certificate is EXPIRED")
    return cert


def validate_pem_pair_paths(cert_path: str, key_path: str, *,
                            context: str) -> x509.Certificate:
    """Mode B (path) of the wizard certificate contract (alpha.7.5 item 6):
    the operator points at PEM files on the PANEL HOST (inside the panel
    container that is the same filesystem the cores see); the pair must
    exist, be readable, and pass :func:`validate_pem_pair`."""
    if not cert_path or not key_path:
        raise CertificateError(
            f"{context}: certificate path AND private-key path are required together")
    cert_file, key_file = Path(cert_path), Path(key_path)
    for p, what in ((cert_file, "certificate"), (key_file, "private key")):
        if not p.is_file():
            raise CertificateError(f"{context}: {what} file not found: {p}")
    try:
        cert_raw = cert_file.read_bytes()
        key_raw = key_file.read_bytes()
    except OSError as exc:
        raise CertificateError(f"{context}: cannot read the certificate files: {exc}") from exc
    return validate_pem_pair(cert_raw, key_raw, context=context)


def expiry_days(cert: x509.Certificate) -> int:
    return (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
