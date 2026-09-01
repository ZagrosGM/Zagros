"""Portal data models (framework-agnostic)."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, Field

from app.cores.delivery import DeliverySection


class ClientAuthMode(str, Enum):
    """How end users receive their connection material (panel setting)."""

    SUBSCRIPTION_LINK = "subscription_link"    # Mode 1: classic portal page
    APPLICATION_LOGIN = "application_login"    # Mode 2: official Zagros app only


_AUTH_MODE_ALIASES = {
    # the dashboard posted this shorthand id and got a raw 422 —
    # normalize at the schema edge so the spellings stay one concept
    "app_login": "application_login",
    "sub_link": "subscription_link",
}


def _coerce_auth_mode(value: object) -> object:
    if isinstance(value, str):
        return _AUTH_MODE_ALIASES.get(value, value)
    return value


CoercedClientAuthMode = Annotated[ClientAuthMode,
                                  BeforeValidator(_coerce_auth_mode)]


_SUBSCRIPTION_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
# uploaded subscription page templates: flat file names only (never a path)
_SUBSCRIPTION_TEMPLATE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(?:html|htm)$", re.IGNORECASE)


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
    client_auth_mode: CoercedClientAuthMode = ClientAuthMode.SUBSCRIPTION_LINK
    app_downloads: list[AppDownload] = Field(default_factory=list)
    support_url: str | None = None
    home_url: str | None = None
    default_lang: str = "fa"
    # identity + link shape surfaced by the dashboard Subscription page
    # (saved them and they silently vanished — the schema now owns
    # them, with validation instead of free-form strings):
    app_name: str = Field(default="Zagros", max_length=64)
    subscription_path: str = "sub"
    # Legacy complete prefix remains the migration/backward-compat field.
    subscription_url_prefix: str | None = None
    public_domain: str | None = None
    custom_subdomain: str | None = None
    public_port: int | None = Field(default=None, ge=1, le=65535)
    public_scheme: Literal["http", "https"] = "https"
    tls_certificate_id: str | None = None
    force_https: bool = False
    # shared: routes remain on the panel listener; dedicated: Zagros binds a
    # second listener; external_proxy: URL ownership belongs to Nginx/Caddy/etc.
    listener_mode: Literal["shared", "dedicated", "external_proxy"] = "shared"
    listen_address: str = "0.0.0.0"
    qr_base_url: str | None = None
    # filename of an operator-uploaded subscription page
    # template (see app/portal/templates_store.py). None = the built-in page.
    # Selection is by name only — the renderer resolves it inside the managed
    # directory, so a settings value can never reach outside it.
    subscription_template: str | None = None

    def public_base_url(self) -> str | None:
        if self.public_domain:
            domain = self.public_domain.strip().strip(".")
            sub = (self.custom_subdomain or "").strip().strip(".")
            host = f"{sub}.{domain}" if sub else domain
            scheme = "https" if self.force_https else self.public_scheme
            default_port = 443 if scheme == "https" else 80
            suffix = (f":{self.public_port}"
                      if self.public_port and self.public_port != default_port else "")
            return f"{scheme}://{host}{suffix}"
        return (self.subscription_url_prefix or "").strip().rstrip("/") or None

    def canonical_path(self, token: str = "<token>") -> str:
        """Canonical configured route; legacy /zagros/sub remains an alias."""
        path = (self.subscription_path or "sub").strip().strip("/") or "sub"
        return f"/{path}/{token}"

    def canonical_url(self, token: str = "<token>") -> str | None:
        base = self.public_base_url()
        return f"{base}{self.canonical_path(token)}" if base else None

    def normalize(self) -> "PortalSettings":
        path = (self.subscription_path or "sub").strip().strip("/") or "sub"
        if not _SUBSCRIPTION_PATH_RE.match(path):
            raise ValueError(
                "subscription_path must be 1-32 chars of a-z 0-9 . _ - "
                "and start with a letter or digit"
            )
        if path.lower() in {
            "api", "dashboard", "statics", "client", "docs", "redoc",
            "openapi", "favicon", "health",
        }:
            raise ValueError(f"subscription_path '{path}' is reserved by the panel")
        domain = (self.public_domain or "").strip().strip(".") or None
        subdomain = (self.custom_subdomain or "").strip().strip(".") or None
        if domain and ("/" in domain or "://" in domain or " " in domain):
            raise ValueError("public_domain must be a hostname without scheme/path")
        if subdomain and not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?", subdomain):
            raise ValueError("custom_subdomain is not a valid DNS label")
        try:
            ipaddress.ip_address(self.listen_address)
        except ValueError as exc:
            raise ValueError("listen_address must be an IPv4/IPv6 address") from exc
        scheme = "https" if self.force_https else self.public_scheme
        public_port = self.public_port
        if self.listener_mode == "dedicated":
            public_port = public_port or (443 if scheme == "https" else 80)
            if not domain:
                raise ValueError("dedicated subscription listener requires public_domain")
            if scheme == "https" and not self.tls_certificate_id:
                raise ValueError(
                    "dedicated HTTPS subscription listener requires a managed TLS certificate")
        prefix = self.model_copy(update={
            "public_domain": domain, "custom_subdomain": subdomain,
            "public_port": public_port,
        }).public_base_url()
        qr_base = (self.qr_base_url or "").strip().rstrip("/") or None
        if qr_base and not re.match(r"^https?://", qr_base, re.I):
            raise ValueError("qr_base_url must start with http:// or https://")
        certificate = (self.tls_certificate_id or "").strip() or None
        if (self.force_https or self.public_scheme == "https") and domain and not certificate:
            # A reverse proxy may own the cert; selection is optional here but
            # the test/apply surface reports that distinction explicitly.
            certificate = None
        template = (self.subscription_template or "").strip() or None
        if template and not _SUBSCRIPTION_TEMPLATE_RE.match(template):
            raise ValueError(
                "subscription_template must be an uploaded .html/.htm file name")
        return self.model_copy(update={
            "app_name": (self.app_name or "Zagros").strip() or "Zagros",
            "subscription_path": path,
            "subscription_url_prefix": prefix,
            "subscription_template": template,
            "public_domain": domain,
            "custom_subdomain": subdomain,
            "public_port": public_port,
            "tls_certificate_id": certificate,
            "listen_address": self.listen_address.strip(),
            "qr_base_url": qr_base,
            "public_scheme": scheme,
        })


class PortalUserView(BaseModel):
    """Everything the portal may show about the subscription owner."""

    user_id: int
    username: str
    status: str = "active"           # active / limited / expired / disabled / on_hold
    used_bytes: int = 0
    data_limit_bytes: int | None = None
    expire_at: datetime | None = None
    online: bool = False
    # per-user override (None = inherit); same alias tolerance as the panel
    # setting so a legacy-stored shorthand cannot 422 the whole portal page
    client_auth_mode: CoercedClientAuthMode | None = None

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
    app_name: str = "Zagros"
    title: str = ""
    lang: str = "fa"
    direction: str = "rtl"
    user: PortalUserView
    sections: list[DeliverySection] = Field(default_factory=list)
    apps: list[AppDownload] = Field(default_factory=list)
    support_url: str | None = None
    notes: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
