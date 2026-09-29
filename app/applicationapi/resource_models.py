"""Secret-free profile/device/config metadata for the Application API.

Raw driver payloads are deliberately absent. They exist only inside the
signed encrypted envelope returned by the one-time config delivery endpoint.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, SecretStr


class ApplicationView(BaseModel):
    application_id: str
    name: str
    default_lang: str
    branding: dict[str, Any] = Field(default_factory=dict)


class ApplicationProfile(BaseModel):
    username: str
    status: str
    online: bool = False
    used_bytes: int = 0
    data_limit_bytes: int | None = None
    remaining_bytes: int | None = None
    expire_at: datetime | None = None
    application: ApplicationView


class ApplicationDeviceView(BaseModel):
    device_id: str
    key_fingerprint: str
    name: str | None = None
    platform: str | None = None
    app_version: str | None = None
    status: str
    is_current: bool = False
    first_seen: datetime
    last_seen: datetime
    last_authenticated_at: datetime | None = None
    revoked_at: datetime | None = None


class ApplicationDeviceList(BaseModel):
    devices: list[ApplicationDeviceView] = Field(default_factory=list)


class DeviceRevokeBody(BaseModel):
    password: SecretStr = Field(min_length=1, max_length=256)


class DeviceRevokeResult(BaseModel):
    device_id: str
    status: str = "revoked"


class AuthorityRevokeResult(BaseModel):
    resource: str
    resource_id: str
    status: str = "revoked"


class ApplicationConfigView(BaseModel):
    # Random public grant reference. It has no authority without a matching
    # access token and a fresh request signed by the registered device.
    config_id: str | None = None
    core_id: str
    protocol: str
    engine: str
    display_name: str
    status: str
    expires_at: datetime | None = None


class ApplicationConfigList(BaseModel):
    configs: list[ApplicationConfigView] = Field(default_factory=list)
