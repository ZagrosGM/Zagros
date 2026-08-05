"""Shared PKI helpers for core backends.

Single home for the self-signed-certificate generation that several QUIC
cores (hysteria2, tuic) need when the operator does not supply their own
TLS material. OpenVPN keeps its own mini-CA flow (CA + server signing)
inside its backend — that is genuinely different logic, not duplication.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from app.cores.exceptions import CoreError


def ensure_self_signed_cert(
    cert_path: str,
    key_path: str,
    common_name: str,
    *,
    days: int = 3650,
) -> tuple[str, str]:
    """Materialize an ECDSA (P-256) self-signed certificate if absent.

    Idempotent: existing material is reused untouched. The private key is
    chmod 0600. Raises :class:`CoreError` when openssl is unavailable or
    generation fails — callers surface an honest CORE_ERROR status rather
    than running half-configured.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    if shutil.which("openssl") is None:
        raise CoreError("openssl not found — provide cert/key paths in settings.")
    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:P-256",
         "-keyout", key_path, "-out", cert_path,
         "-days", str(days), "-nodes", "-subj", f"/CN={common_name}"],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise CoreError(f"openssl self-signed cert failed: {proc.stderr.strip()}")
    os.chmod(key_path, 0o600)
    return cert_path, key_path
