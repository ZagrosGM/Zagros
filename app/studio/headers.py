"""HTTP header parsing for the wizard's Headers section (alpha.7.5 item 4).

The wizard UI offers headers as one-per-line text (``Name: value``) or a
JSON-ish dict from structured callers; translators (xray ws/tcp-camouflage,
sing-box ws/http) consume a validated ``dict[str, str]``. Anything else is
a precise CoreError — headers end up on the wire, so CRLF injection or a
malformed name must fail BEFORE a core restart, never inside it.
"""
from __future__ import annotations

import re
from typing import Any

from app.cores.exceptions import CoreError

# RFC 7230 token (header field-name)
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class HeaderError(CoreError):
    """A wizard header block failed validation — surfaces as a CoreError so
    driver translators stay uniform (422 at the API boundary, not a 500)."""


def _check(name: str, value: str, *, context: str) -> None:
    if not name or not _TOKEN.match(name):
        raise HeaderError(f"{context}: invalid HTTP header name {name!r}")
    if any(ord(c) < 0x20 and c != "\t" for c in value) or "\x7f" in value:
        raise HeaderError(
            f"{context}: header {name!r} contains control characters (CRLF "
            f"injection is refused)")


def parse_http_headers(value: Any, *, context: str) -> dict[str, str]:
    """Accept ``None``/empty, a ``dict``, or newline-separated ``Name: value``
    lines; return a validated header map (empty when nothing was given)."""
    if value is None or value == "" :
        return {}
    if isinstance(value, dict):
        out: dict[str, str] = {}
        for k, v in value.items():
            name, text = str(k).strip(), str(v)
            _check(name, text, context=context)
            out[name] = text
        return out
    if not isinstance(value, str):
        raise HeaderError(
            f"{context}: headers must be a mapping or 'Name: value' lines, "
            f"got {type(value).__name__}")
    out = {}
    for lineno, raw_line in enumerate(value.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue  # blank lines and comments are ignored
        if ":" not in line:
            raise HeaderError(
                f"{context}: header line {lineno} has no 'Name: value' shape: "
                f"{line!r}")
        name, val = line.split(":", 1)
        name, val = name.strip(), val.strip()
        _check(name, val, context=context)
        out[name] = val
    return out
