import click
import logging
import os
import ssl

import uvicorn
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app import app as app, logger  # noqa: F401  (re-exported uvicorn target: `uvicorn main:app`)
from app.platform.bindargs import BindArgsError, compute_bind_args
from config import (DEBUG, TLS_MODE, UVICORN_HOST, UVICORN_PORT, UVICORN_SSL_CA_CERTFILE,
                    UVICORN_SSL_CA_TYPE, UVICORN_SSL_CERTFILE, UVICORN_SSL_KEYFILE, UVICORN_UDS)


def validate_cert_and_key(cert_file_path, key_file_path, ca_type):
    if ca_type == "private":
        logger.warning(f"""
{click.style('IMPORTANT!', blink=True, bold=True, fg="yellow")} 
You're running Zagros with: {click.style('UVICORN_SSL_CA_TYPE', italic=True, fg="magenta")}: {click.style(f'{ca_type}', bold=True, fg="yellow")}. 
Self-signed CAs are useful in testing or internal use cases, they’re not suitable for secure public internet communications.
        """)
        return

    if not os.path.isfile(cert_file_path):
        raise ValueError(f"SSL certificate file '{cert_file_path}' does not exist.")
    if not os.path.isfile(key_file_path):
        raise ValueError(f"SSL key file '{key_file_path}' does not exist.")

    try:
        context = ssl.create_default_context()
        context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)
    except ssl.SSLError as e:
        raise ValueError(f"SSL Error: {e}")

    try:
        with open(cert_file_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        if cert.issuer == cert.subject:
            raise ValueError("The certificate is self-signed and not issued by a trusted CA.")

    except Exception as e:
        raise ValueError(f"Certificate verification failed: {e}")


def _warn_plain_http(host: str, port: int):
    """Loud advisory for plain-HTTP binds (replaces the old 127.0.0.1 trap).

    The host is NEVER rewritten — the operator's UVICORN_HOST is honored
    verbatim; this warning exists so an accidental plain-HTTP exposure is
    impossible to miss in the logs.
    """
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if loopback:
        hint = f"""
The server is binding to {host} (loopback only). To reach the panel from your machine, use SSH port forwarding:

{click.style(f'ssh -L {port}:localhost:{port} user@server', italic=True, fg="cyan")}

Then, navigate to {click.style(f'http://127.0.0.1:{port}', bold=True)} on your computer. In this setup, subscription functionality will not work for your devices."""
    else:
        hint = f"""
The server is binding to {click.style(host, bold=True, fg="yellow")} over PLAIN HTTP — the panel and subscription URLs will be reachable WITHOUT TLS encryption, which exposes admin credentials to anyone on the path. Only do this in trusted networks or behind a VPN.

Recommended options:
1. Set {click.style('UVICORN_SSL_CERTFILE', italic=True, fg="magenta")} and {click.style('UVICORN_SSL_KEYFILE', italic=True, fg="magenta")} in .env to enable TLS directly, or
2. keep this host reachable only from a reverse proxy (Nginx/Caddy) that terminates SSL, or use VPN/SSH access.
"""
    logger.warning(f"""
{click.style('IMPORTANT!', blink=True, bold=True, fg="yellow")}
You're running Zagros without TLS (no {click.style('UVICORN_SSL_CERTFILE', italic=True, fg="magenta")} / {click.style('UVICORN_SSL_KEYFILE', italic=True, fg="magenta")} configured, or TLS_MODE=off).
{hint}
        """)


if __name__ == "__main__":
    # Do NOT change workers count for now
    # multi-workers support isn't implemented yet for APScheduler and XRay module

    if UVICORN_SSL_CA_TYPE not in ["public", "private"]:
        UVICORN_SSL_CA_TYPE = "public"

    try:
        bind_args, tls_active = compute_bind_args(
            host=UVICORN_HOST,
            port=UVICORN_PORT,
            uds=UVICORN_UDS,
            tls_mode=TLS_MODE,
            ssl_certfile=UVICORN_SSL_CERTFILE,
            ssl_keyfile=UVICORN_SSL_KEYFILE,
            ssl_ca_certfile=UVICORN_SSL_CA_CERTFILE,
        )
    except BindArgsError as exc:
        logger.critical("invalid bind/TLS configuration: %s", exc)
        raise SystemExit(2)

    if tls_active:
        validate_cert_and_key(UVICORN_SSL_CERTFILE, UVICORN_SSL_KEYFILE, UVICORN_SSL_CA_TYPE)
        if UVICORN_SSL_CA_CERTFILE and not os.path.isfile(UVICORN_SSL_CA_CERTFILE):
            raise ValueError(
                f"SSL CA certificate file '{UVICORN_SSL_CA_CERTFILE}' does not exist."
            )
    else:
        if (UVICORN_SSL_CA_CERTFILE and TLS_MODE != "off"):
            logger.warning(
                "UVICORN_SSL_CA_CERTFILE is set but TLS is not active — the CA file is ignored "
                "(set UVICORN_SSL_CERTFILE/KEYFILE or check TLS_MODE)."
            )
        if "host" in bind_args:
            _warn_plain_http(bind_args["host"], bind_args["port"])

    try:
        uvicorn.run(
            "main:app",
            **bind_args,
            workers=1,
            reload=DEBUG,
            log_level=logging.DEBUG if DEBUG else logging.INFO
        )
    except FileNotFoundError:  # to prevent error on removing unix sock
        pass
