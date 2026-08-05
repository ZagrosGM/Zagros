"""Client API models — everything here is safe to show to the app UI.

Secret material NEVER appears in these dataclasses; connection payloads
travel only inside :class:`app.crypto.seal.SealedEnvelope`.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AppCredentials(BaseModel):
    """Newly issued app credentials — shown ONCE at issuance, then only the
    scrypt hash persists server-side."""

    username: str
    password: str


class AuthTokens(BaseModel):
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    token_type: str = "Bearer"


class CorePublicView(BaseModel):
    """What the app may display about one core account — no secrets."""

    core_id: str
    protocol: str
    engine: str
    display_name: str
    status: str = "active"           # active / suspended


class ClientProfile(BaseModel):
    """The app's home-screen model: identity, quota, expiry, core list."""

    user_id: int
    username: str
    status: str
    online: bool = False
    used_bytes: int = 0
    data_limit_bytes: int | None = None
    expire_at: datetime | None = None
    cores: list[CorePublicView] = Field(default_factory=list)

    @property
    def remaining_bytes(self) -> int | None:
        if self.data_limit_bytes is None:
            return None
        return max(0, self.data_limit_bytes - self.used_bytes)


class ConnectOffer(BaseModel):
    """Response of POST /connect/{core_id}."""

    connect_token: str
    expires_at: datetime
    ttl_seconds: int
