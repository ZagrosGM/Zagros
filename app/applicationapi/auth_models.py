"""Secret-bearing Application authentication request/response schemas.

Input secrets use ``SecretStr`` so accidental validation/log representations
are redacted. Plaintext activation/refresh values are returned only by their
one-time issuance endpoints and are never stored in plaintext.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr


class ApplicationCreateBody(BaseModel):
    # None resolves to the calling (sudo) admin; explicit ids stay supported
    # so service/CLI callers keep working unchanged.
    owner_admin_id: int | None = Field(default=None, gt=0)
    name: str = Field(min_length=1, max_length=128)
    api_base_url: str = Field(min_length=1, max_length=2048)
    default_lang: str = Field(default="fa", min_length=2, max_length=16)
    branding: dict = Field(default_factory=dict)
    # f-panel-7: 'all_users' (default) or 'bound_only'
    user_access_mode: str = Field(default="all_users",
                                  pattern="^(all_users|bound_only)$")


class ApplicationBootstrap(BaseModel):
    application_id: str
    name: str
    status: str
    user_access_mode: str = "all_users"
    signing_key_id: str
    signing_public_key: str
    config_key_id: str
    config_public_key: str


class ApplicationListItem(BaseModel):
    """Safe admin list projection (no key material)."""

    id: int
    public_id: str
    owner_admin_id: int
    name: str
    status: str
    api_base_url: str
    default_lang: str
    user_access_mode: str = "all_users"
    active_signing_kid: str | None = None
    active_config_kid: str | None = None


class OverviewGrant(BaseModel):
    application_id: str
    name: str
    status: str


class OverviewBuildTarget(BaseModel):
    platform: str
    arch: str
    artifact: str
    status: str


class OverviewBuildArtifact(BaseModel):
    platform: str
    arch: str
    artifact: str
    filename: str
    rel_path: str
    sha256: str
    size_bytes: int


class OverviewLatestBuild(BaseModel):
    build_id: str
    version: str | None = None
    build_number: int | None = None
    status: str
    progress: int | None = None
    created_at: datetime | None = None
    targets: list[OverviewBuildTarget] = Field(default_factory=list)
    artifacts: list[OverviewBuildArtifact] = Field(default_factory=list)


class UserApplicationOverview(BaseModel):
    """Everything the Users dialog needs for the Application-login section."""

    user_id: int
    username: str
    access_mode: str | None = None
    effective_access_mode: str | None = None
    app_username: str | None = None
    has_app_credentials: bool = False
    grants: list[OverviewGrant] = Field(default_factory=list)
    latest_builds: dict[str, OverviewLatestBuild | None] = Field(
        default_factory=dict)


class ApplicationGrantBody(BaseModel):
    user_id: int = Field(gt=0)


class ApplicationGrantResult(BaseModel):
    grant_id: int
    application_id: str
    user_id: int
    status: str


class ActivationTicketIssueBody(BaseModel):
    user_id: int = Field(gt=0)
    ttl_seconds: int = Field(default=600, ge=60, le=3600)
    intended_device_public_key: str | None = Field(default=None, max_length=64)


class ActivationTicketResult(BaseModel):
    activation_ticket: str
    expires_at: datetime
    application_id: str
    user_id: int
    # QR enrollment page for external apps (item 4): absolute URL the
    # reseller encodes as QR. None only when the route cannot see the
    # public base (never in normal panel operation).
    enrollment_url: str | None = None


class EnrollBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=256)
    # Authorization is EITHER a panel-issued activation ticket (QR/reseller
    # flow, kept for compatibility) OR an app-build attestation signature
    # produced by the signing key embedded at build time. The app never asks
    # users for a code.
    activation_ticket: SecretStr | None = Field(default=None, max_length=2048)
    app_kid: str | None = Field(default=None, max_length=64)
    app_signature: str | None = Field(default=None, min_length=86, max_length=128)
    device_public_key: str = Field(min_length=43, max_length=44)
    device_name: str | None = Field(default=None, max_length=128)
    platform: str | None = Field(default=None, max_length=32)
    app_version: str | None = Field(default=None, max_length=64)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=256)


class RefreshBody(BaseModel):
    refresh_token: SecretStr = Field(min_length=32, max_length=256)


class LogoutBody(BaseModel):
    refresh_token: SecretStr = Field(min_length=32, max_length=256)


class ApplicationAuthTokens(BaseModel):
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    token_type: str = "Bearer"


class EnrollResult(BaseModel):
    device_id: str
    device_key_fingerprint: str
    tokens: ApplicationAuthTokens


class LegacyClientGone(BaseModel):
    error: str = "legacy_client_api_gone"
    message: str
    replacement: str = "/api/application/v1/"


class AccessModeBody(BaseModel):
    mode: str = Field(min_length=1, max_length=32)


class AccessModeResult(BaseModel):
    user_id: int
    username: str
    access_mode: str | None = None
    effective_access_mode: str | None = None


class ApplicationDetail(ApplicationListItem):
    """Full admin projection: list fields plus the branding document."""

    branding: dict = Field(default_factory=dict)


class ApplicationGrantListItem(BaseModel):
    user_id: int
    username: str
    status: str
    granted_at: datetime | None = None


class ApplicationKeyPublic(BaseModel):
    kid: str
    public_key: str


class ApplicationPublicKeys(BaseModel):
    """Active PUBLIC keys only — feeds the build-config prefill.

    Private key material never leaves the encrypted envelope column.
    """

    signing: ApplicationKeyPublic | None = None
    config: ApplicationKeyPublic | None = None


class ApplicationIconMeta(BaseModel):
    sha256: str
    size_bytes: int
    width: int
    height: int
    mime: str = "image/png"
    # Rendered Android density pack (None for icons uploaded before packs).
    android_pack_sha256: str | None = None
    android_pack_bytes: int | None = None
    updated_at: str | None = None
