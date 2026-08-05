"""Pure uvicorn bind-argument computation for the Zagros panel.

Extracted from ``main.py`` so the HTTP-bind / TLS policy is unit-testable
without importing the application stack (``main`` pulls in the whole app).

Design contract (Marzban parity — minus the localhost trap):

* ``UVICORN_HOST`` is honored VERBATIM in every mode. Nothing ever rewrites
  it. The historical upstream behavior of silently forcing ``127.0.0.1``
  when no TLS files were configured was the root cause of the real-world
  bug "``UVICORN_HOST=0.0.0.0`` in ``.env`` but the service listens on
  ``127.0.0.1:8000``"; Zagros replaces that silent override with a loud
  warning emitted by ``main.py`` (see ``_warn_plain_http``).
* ``TLS_MODE``:
    - ``auto`` (default): TLS is active iff BOTH ``UVICORN_SSL_CERTFILE``
      and ``UVICORN_SSL_KEYFILE`` are configured; otherwise plain HTTP.
    - ``on``: TLS is REQUIRED — boot fails fast with a clear message when
      cert/key are missing (never silently degrades to plain HTTP).
    - ``off``: forces plain HTTP even when cert/key variables are set
      (reverse proxy / LAN setups that terminate TLS upstream).
* A configured ``UVICORN_UDS`` takes precedence over host/port in every
  mode — choosing a Unix socket behind a reverse proxy is deliberate.
* ``UVICORN_SSL_CA_CERTFILE`` (optional) is forwarded as uvicorn's
  ``ssl_ca_certs`` for client-certificate verification chains.
"""
from __future__ import annotations


class BindArgsError(ValueError):
    """Misconfigured bind/TLS settings — fail fast with a clear message."""


VALID_TLS_MODES = ("auto", "on", "off")


def compute_bind_args(
    *,
    host: str,
    port: int,
    uds: str | None = None,
    tls_mode: str = "auto",
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
    ssl_ca_certfile: str | None = None,
) -> tuple[dict, bool]:
    """Return ``(uvicorn_kwargs, tls_active)`` for the given settings.

    Raises :class:`BindArgsError` on inconsistent configuration — half
    configured TLS is always an operator mistake and must surface loudly
    instead of silently binding plain HTTP.
    """
    mode = (tls_mode or "auto").strip().lower()
    if mode not in VALID_TLS_MODES:
        raise BindArgsError(
            f"invalid TLS_MODE={tls_mode!r} — expected one of "
            f"{', '.join(VALID_TLS_MODES)} (auto=TLS when cert+key set, "
            f"on=require TLS, off=force plain HTTP)"
        )

    # Normalize empty strings to None so "unset" has exactly one shape.
    cert = ssl_certfile or None
    key = ssl_keyfile or None
    ca = ssl_ca_certfile or None
    sock = uds or None

    if (cert is None) != (key is None):
        if mode == "off":
            pass  # TLS explicitly disabled — stray TLS vars are ignored
        else:
            raise BindArgsError(
                "UVICORN_SSL_CERTFILE and UVICORN_SSL_KEYFILE must be set "
                "TOGETHER (only one is configured). Fix your .env, or set "
                "TLS_MODE=off if a reverse proxy terminates TLS for you."
            )

    tls_active = mode != "off" and cert is not None and key is not None

    if mode == "on" and not tls_active:
        raise BindArgsError(
            "TLS_MODE=on requires both UVICORN_SSL_CERTFILE and "
            "UVICORN_SSL_KEYFILE in your .env — refusing to start insecure."
        )

    bind_args: dict = {}
    if tls_active:
        bind_args["ssl_certfile"] = cert
        bind_args["ssl_keyfile"] = key
        if ca is not None:
            bind_args["ssl_ca_certs"] = ca

    if sock is not None:
        # Unix domain socket wins over host/port in every mode.
        bind_args["uds"] = sock
    else:
        # THE fix: the operator's host is used verbatim — no 127.0.0.1
        # override, no DEBUG special-casing. Plain-HTTP deployments get a
        # loud warning from main.py instead of a silent security decision.
        bind_args["host"] = host
        bind_args["port"] = port

    return bind_args, tls_active
