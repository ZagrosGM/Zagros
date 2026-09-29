"""Redact subscription tokens from the uvicorn access log.

Subscription bearer tokens travel in the URL path (``/sub/<token>``,
``/sub/file/<token>/<core>/<tag>``, ``/zagros/sub/<token>`` and the
operator-configurable ``/{sub_path}/{token}`` catch-all), so uvicorn's
default access log persisted them in plaintext. A leaked log line is a
leaked subscription.

This module installs a :class:`logging.Filter` on the ``uvicorn.access``
logger that rewrites the token segments to ``<redacted>``. Routing,
responses and status codes are untouched — only the emitted log text.

Rules (in order):
1. JWT-shaped tokens (``eyJ…payload.sig``) anywhere in the line.
2. ``/sub/file/<token>/`` — the per-file download endpoint.
3. ``/sub/<token>`` and ``/zagros/sub/<token>`` — portal/raw endpoints.
4. Any other path segment (or query value) of 30+ base64url characters —
   the legacy ``b64(username,timestamp)+sig`` tokens always qualify, which
   covers the configurable ``/{sub_path}/{token}`` catch-all whose prefix
   is operator-chosen and cannot be matched literally. UUID-shaped values
   are explicitly exempt so build/worker ids stay readable.

Only stdlib: the pure :func:`redact_subscription_tokens` is unit-testable
without the FastAPI stack.
"""

from __future__ import annotations

import logging
import re

_REPLACEMENT = "<redacted>"

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SUB_FILE = re.compile(r"(/sub/file/)[^/?\s\"']+")
# The canonical token is the LAST segment: a further `/...` means this is the
# operator-configured `/{sub_path}/...` prefix, whose token is caught by the
# shape rule below (keeps the readable prefix intact in the log line).
_SUB_CANON = re.compile(
    r"((?:/zagros)?/sub/)(?!file/)[^/?\s\"']+(?=[?\s\"']|$)"
)

_UUID = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_LONG_SEGMENT = re.compile(
    r"(/)(?!" + _UUID + r"(?=[/?\s\"']|$))([A-Za-z0-9_-]{30,})(?=[/?\s\"']|$)"
)
_LONG_QUERY_VALUE = re.compile(
    r"(=)(?!" + _UUID + r"(?=[&\s\"']|$))([A-Za-z0-9_-]{30,})(?=[&\s\"']|$)"
)


def redact_subscription_tokens(text: str) -> str:
    """Return [text] with subscription bearer tokens replaced."""
    redacted = _JWT.sub(_REPLACEMENT, text)
    redacted = _SUB_FILE.sub(r"\1" + _REPLACEMENT, redacted)
    redacted = _SUB_CANON.sub(r"\1" + _REPLACEMENT, redacted)
    redacted = _LONG_SEGMENT.sub(r"\1" + _REPLACEMENT, redacted)
    redacted = _LONG_QUERY_VALUE.sub(r"\1" + _REPLACEMENT, redacted)
    return redacted


class SubscriptionTokenRedactionFilter(logging.Filter):
    """Redact the request-path arg of uvicorn access records.

    Uvicorn emits exactly one record shape on this logger — the 5-tuple
    ``(client_addr, method, full_path, http_version, status)`` — and its
    ``AccessFormatter.formatMessage`` unpacks all five. Rewriting the whole
    message (or clearing ``args``) breaks formatting with ``ValueError``,
    so only element [2] (path + query string) is rewritten, in place.
    Anything else passes through untouched.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if (
            isinstance(args, tuple)
            and len(args) == 5
            and isinstance(args[2], str)
        ):
            record.args = (
                args[0],
                args[1],
                redact_subscription_tokens(args[2]),
                args[3],
                args[4],
            )
        return True


def install_access_log_redaction() -> None:
    """Attach the redaction filter to ``uvicorn.access`` (idempotent)."""
    access_logger = logging.getLogger("uvicorn.access")
    for existing in access_logger.filters:
        if isinstance(existing, SubscriptionTokenRedactionFilter):
            return
    access_logger.addFilter(SubscriptionTokenRedactionFilter())
