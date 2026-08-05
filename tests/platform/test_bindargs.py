"""Tests for app.platform.bindargs — the uvicorn bind/TLS policy.

The headline regression test: UVICORN_HOST must be honored VERBATIM even
when no TLS files are configured (upstream Marzban silently rewrote the
host to 127.0.0.1 — the real-world bug this module fixes).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.platform.bindargs import BindArgsError, compute_bind_args  # noqa: E402


# --------------------------------------------------------------------- #
# plain HTTP (auto, no TLS files)
# --------------------------------------------------------------------- #

def test_uvicorn_host_honored_verbatim_without_tls():
    """THE regression: no TLS must NOT silently rewrite the bind host."""
    args, tls = compute_bind_args(host="0.0.0.0", port=8000)
    assert args == {"host": "0.0.0.0", "port": 8000}
    assert tls is False


def test_loopback_host_also_honored():
    args, tls = compute_bind_args(host="127.0.0.1", port=8080)
    assert args == {"host": "127.0.0.1", "port": 8080}
    assert tls is False


def test_empty_strings_are_treated_as_unset():
    args, tls = compute_bind_args(host="0.0.0.0", port=8000, uds="",
                                  ssl_certfile="", ssl_keyfile="")
    assert args == {"host": "0.0.0.0", "port": 8000}
    assert tls is False


# --------------------------------------------------------------------- #
# TLS modes
# --------------------------------------------------------------------- #

def test_auto_mode_enables_tls_with_cert_and_key():
    args, tls = compute_bind_args(host="0.0.0.0", port=443,
                                  ssl_certfile="/c/fullchain.pem",
                                  ssl_keyfile="/c/key.pem")
    assert args["ssl_certfile"] == "/c/fullchain.pem"
    assert args["ssl_keyfile"] == "/c/key.pem"
    assert args["host"] == "0.0.0.0"  # TLS also honors the host verbatim
    assert tls is True


def test_tls_mode_on_requires_cert_and_key():
    with pytest.raises(BindArgsError, match="TLS_MODE=on"):
        compute_bind_args(host="0.0.0.0", port=8000, tls_mode="on")


def test_tls_mode_on_accepts_complete_pair():
    args, tls = compute_bind_args(host="0.0.0.0", port=443, tls_mode="on",
                                  ssl_certfile="/c/cert.pem",
                                  ssl_keyfile="/c/key.pem")
    assert tls is True
    assert "ssl_certfile" in args


def test_tls_mode_off_forces_plain_http_even_with_files():
    args, tls = compute_bind_args(host="0.0.0.0", port=8000, tls_mode="off",
                                  ssl_certfile="/c/cert.pem",
                                  ssl_keyfile="/c/key.pem")
    assert tls is False
    assert "ssl_certfile" not in args
    assert args == {"host": "0.0.0.0", "port": 8000}


def test_invalid_tls_mode_fails_fast():
    with pytest.raises(BindArgsError, match="invalid TLS_MODE"):
        compute_bind_args(host="0.0.0.0", port=8000, tls_mode="maybe")


def test_half_configured_tls_fails_fast():
    """One-file TLS configs are always a mistake — surface them loudly."""
    with pytest.raises(BindArgsError, match="TOGETHER"):
        compute_bind_args(host="0.0.0.0", port=8000,
                          ssl_certfile="/c/cert.pem")
    with pytest.raises(BindArgsError, match="TOGETHER"):
        compute_bind_args(host="0.0.0.0", port=8000,
                          ssl_keyfile="/c/key.pem")


def test_half_configured_tls_ignored_when_mode_off():
    args, tls = compute_bind_args(host="0.0.0.0", port=8000, tls_mode="off",
                                  ssl_certfile="/c/cert.pem")
    assert tls is False
    assert args == {"host": "0.0.0.0", "port": 8000}


# --------------------------------------------------------------------- #
# CA certfile + UDS precedence
# --------------------------------------------------------------------- #

def test_ca_certfile_forwarded_as_ssl_ca_certs_when_tls_active():
    args, tls = compute_bind_args(host="0.0.0.0", port=443,
                                  ssl_certfile="/c/cert.pem",
                                  ssl_keyfile="/c/key.pem",
                                  ssl_ca_certfile="/c/ca.pem")
    assert args["ssl_ca_certs"] == "/c/ca.pem"
    assert tls is True


def test_ca_certfile_ignored_without_tls():
    args, tls = compute_bind_args(host="0.0.0.0", port=8000,
                                  ssl_ca_certfile="/c/ca.pem")
    assert "ssl_ca_certs" not in args
    assert tls is False


def test_uds_wins_over_host_port():
    args, tls = compute_bind_args(host="0.0.0.0", port=8000,
                                  uds="/run/zagros.sock")
    assert args == {"uds": "/run/zagros.sock"}
    assert tls is False


def test_uds_wins_with_tls_too():
    args, tls = compute_bind_args(host="0.0.0.0", port=443,
                                  uds="/run/zagros.sock",
                                  ssl_certfile="/c/cert.pem",
                                  ssl_keyfile="/c/key.pem")
    assert args == {"ssl_certfile": "/c/cert.pem",
                    "ssl_keyfile": "/c/key.pem",
                    "uds": "/run/zagros.sock"}
    assert tls is True
