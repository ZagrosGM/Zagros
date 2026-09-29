"""Canonical public/domain models for Zagros Application identities.

This module intentionally contains no bearer tokens, passwords, activation
secrets, private keys, or raw connection configurations.  Secret-bearing
request/response schemas are added with the endpoints that use them and must
remain separate from the public read models below.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


class AccessMode(str, Enum):
    """Canonical per-user delivery mode persisted in ``users.access_mode``."""

    SUBSCRIPTION = "subscription"
    APPLICATION = "application"


_ACCESS_MODE_ALIASES: dict[str, AccessMode] = {
    "subscription": AccessMode.SUBSCRIPTION,
    "subscription_link": AccessMode.SUBSCRIPTION,
    "sub_link": AccessMode.SUBSCRIPTION,
    "application": AccessMode.APPLICATION,
    "application_login": AccessMode.APPLICATION,
    "app_login": AccessMode.APPLICATION,
}


_LEGACY_ACCESS_MODES: dict[AccessMode, str] = {
    AccessMode.SUBSCRIPTION: "subscription_link",
    AccessMode.APPLICATION: "application_login",
}


def canonical_access_mode(value: AccessMode | str | None) -> AccessMode | None:
    """Return the canonical mode while accepting all deployed legacy aliases.

    ``None`` remains ``None`` so callers can preserve inheritance from the
    panel-wide setting. Unknown values fail closed instead of silently becoming
    subscription access.
    """

    if value is None:
        return None
    if isinstance(value, AccessMode):
        return value
    normalized = str(value).strip().lower()
    try:
        return _ACCESS_MODE_ALIASES[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported access mode: {value!r}") from exc


def legacy_client_auth_mode(value: AccessMode | str | None) -> str | None:
    """Map a canonical/legacy spelling to the still-supported portal value."""

    mode = canonical_access_mode(value)
    return _LEGACY_ACCESS_MODES[mode] if mode is not None else None


class ApplicationStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class ApplicationKeyPurpose(str, Enum):
    SIGNING = "signing"
    CONFIG_ENCRYPTION = "config_encryption"


class ApplicationKeyAlgorithm(str, Enum):
    ED25519 = "ed25519"
    X25519 = "x25519"


class ApplicationKeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class ApplicationGrantStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ApplicationDeviceStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ApplicationBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    api_base_url: str = Field(min_length=1, max_length=2048)
    default_lang: str = Field(default="fa", min_length=2, max_length=16)
    branding: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "api_base_url", "default_lang")
    @classmethod
    def _strip_nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class ApplicationCreate(ApplicationBase):
    """Non-secret fields accepted when an administrator creates an app."""

    owner_admin_id: int = Field(gt=0)


class ApplicationPublic(ApplicationBase):
    """Safe administrative/public projection of an Application."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    public_id: UUID
    owner_admin_id: int
    status: ApplicationStatus
    active_signing_kid: str | None = None
    active_config_kid: str | None = None
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class ApplicationKeyPublic(BaseModel):
    """Key metadata/public material; encrypted private material is excluded."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    application_id: int
    kid: str
    purpose: ApplicationKeyPurpose
    algorithm: ApplicationKeyAlgorithm
    public_key: str
    status: ApplicationKeyStatus
    not_before: datetime
    not_after: datetime | None = None
    created_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class ApplicationGrantPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    application_id: int
    user_id: int
    status: ApplicationGrantStatus
    granted_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class ApplicationDevicePublic(BaseModel):
    """Safe app-device view. It exposes a fingerprint, never a private key."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    application_id: int
    device_hint: str
    device_key_fingerprint: str
    device_key_id: str
    status: ApplicationDeviceStatus = Field(
        validation_alias=AliasChoices("status", "device_status"))
    name: str | None = None
    platform: str | None = None
    app_version: str | None = None
    first_seen: datetime
    last_seen: datetime
    last_authenticated_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
