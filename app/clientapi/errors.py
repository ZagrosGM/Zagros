"""Client API errors — deliberately low-information towards attackers.

`AuthFailedError` is raised for unknown usernames AND wrong passwords alike
(the service spends a scrypt verification on both paths) so the endpoint
does not enumerate valid usernames.
"""
from __future__ import annotations


class ClientApiError(Exception):
    """Base class; carries an HTTP-ish status code for the router layer."""

    status_code = 400
    error_code = "client_api_error"


class AuthFailedError(ClientApiError):
    status_code = 401
    error_code = "auth_failed"


class UserSuspendedError(ClientApiError):
    status_code = 403
    error_code = "user_suspended"


class ConnectTokenError(ClientApiError):
    """Expired, unknown, or replayed connect-token (uniform by design)."""

    status_code = 401
    error_code = "connect_token_invalid"


class RateLimitedError(ClientApiError):
    status_code = 429
    error_code = "rate_limited"
