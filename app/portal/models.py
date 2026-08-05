"""Portal data models (framework-agnostic)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from app.cores.delivery import DeliverySection


class ClientAuthMode(str, Enum):
    """How end users receive their connection material (panel setting)."""

    SUBSCRIPTION_LINK = "subscription_link"    # Mode 1: classic portal page
    APPLICATION_LOGIN = "application_login"    # Mode 2: official Zagros app only


class PageKind(str, Enum):
    PORTAL = "portal"
    APP_DOWNLOAD = "app_download"


class AppDownload(BaseModel):
    """A configured download target for the official app (admin-managed)."""

    platform: str                    # android / ios / windows / macos / linux
    name: str                        # display label, e.g. "Zagros for Android"
    url: str                         # direct download or store link
    primary: bool = False


class PortalSettings(BaseModel):
    """Panel-level portal settings; ``users.client_auth_mode`` overrides
    :attr:`client_auth_mode` per user when set."""

    brand: str = "Zagros"
    portal_title: str = "اشتراک من"
    client_auth_mode: ClientAuthMode = ClientAuthMode.SUBSCRIPTION_LINK
    app_downloads: list[AppDownload] = Field(default_factory=list)
    support_url: str | None = None
    home_url: str | None = None
    default_lang: str = "fa"


class PortalUserView(BaseModel):
    """Everything the portal may show about the subscription owner."""

    user_id: int
    username: str
    status: str = "active"           # active / limited / expired / disabled / on_hold
    used_bytes: int = 0
    data_limit_bytes: int | None = None
    expire_at: datetime | None = None
    online: bool = False
    client_auth_mode: ClientAuthMode | None = None   # per-user override (None = inherit)

    @property
    def remaining_bytes(self) -> int | None:
        if self.data_limit_bytes is None:
            return None
        return max(0, self.data_limit_bytes - self.used_bytes)

    @property
    def usage_ratio(self) -> float | None:
        if not self.data_limit_bytes:
            return None
        return min(1.0, self.used_bytes / self.data_limit_bytes)


class PortalPage(BaseModel):
    """A fully-assembled page ready for the renderer (or JSON export)."""

    kind: PageKind
    brand: str = "Zagros"
    title: str = ""
    lang: str = "fa"
    direction: str = "rtl"
    user: PortalUserView
    sections: list[DeliverySection] = Field(default_factory=list)
    apps: list[AppDownload] = Field(default_factory=list)
    support_url: str | None = None
    notes: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
