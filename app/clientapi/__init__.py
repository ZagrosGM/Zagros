"""Zagros Client API — the backend for the official app.

Design contract (doc §15):
* The user enters ONLY an app username/password. No subscription link, no
  raw config is ever exposed through this API.
* Every response is stripped of secrets. Connection material leaves the
  server exclusively through the sealed channel:
  ``POST /connect`` issues a one-time 30-second connect-token, then
  ``POST /config`` consumes it together with the app's ephemeral X25519
  public key and returns an envelope only that app instance can open.
* All state flows through ports (Protocol classes) — SQL implementations
  live in ``app.persistence``.
"""
from app.clientapi.errors import (
    AuthFailedError,
    ClientApiError,
    ConnectTokenError,
    RateLimitedError,
    UserSuspendedError,
)
from app.clientapi.models import (
    AppCredentials,
    AuthTokens,
    ClientProfile,
    ConnectOffer,
    CorePublicView,
)
from app.clientapi.service import ClientApiService
from app.clientapi.stores import (
    ClientDataProvider,
    ConnectTokenRecord,
    ConnectTokenStore,
    RefreshTokenRecord,
    InMemoryConnectTokenStore,
    InMemoryRefreshTokenStore,
    RefreshTokenStore,
)
from app.clientapi.tokens import SignedTokenService

__all__ = [
    "AuthFailedError",
    "ClientApiError",
    "ConnectTokenError",
    "RateLimitedError",
    "UserSuspendedError",
    "AppCredentials",
    "AuthTokens",
    "ClientProfile",
    "ConnectOffer",
    "CorePublicView",
    "ClientApiService",
    "ClientDataProvider",
    "ConnectTokenRecord",
    "ConnectTokenStore",
    "RefreshTokenRecord",
    "InMemoryConnectTokenStore",
    "InMemoryRefreshTokenStore",
    "RefreshTokenStore",
    "SignedTokenService",
]
