"""Zagros relational schema (SQLAlchemy 2.0, declarative).

Design notes (doc §15.6):
* Panel identity lives in ``users``; per-core identity in
  ``user_core_accounts`` (with AES-256-GCM-encrypted credentials).
* The unified quota ledger is ``user_usage`` + the raw ``usage_records``
  journal; drivers' delta baselines persist in ``usage_baselines``.
* ``settings`` is a typed KV store powering portal/policy/platform settings;
  hot runtime state of cores lives in ``cores`` via the CoreStateStore port.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.persistence.base import Base, UtcDateTime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------- #
# admins & users
# --------------------------------------------------------------------- #

class AdminModel(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    is_sudo: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


class ApplicationModel(Base):
    """Operator-owned Official/White-label Application identity."""

    __tablename__ = "applications"
    __table_args__ = (
        Index("ix_applications_owner_status", "owner_admin_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    owner_admin_id: Mapped[int] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active")
    api_base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    default_lang: Mapped[str] = mapped_column(
        String(16), nullable=False, default="fa", server_default="fa")
    # f-panel-7: who may sign in to this application.
    #   all_users  — every user with app credentials may enroll/sign in
    #                (default; the Bound-users list becomes an allowlist
    #                that is not required for access)
    #   bound_only — only users with an ACTIVE grant (Bound users) may
    #                enroll/sign in; un-granted sessions fail closed
    user_access_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="all_users",
        server_default="all_users")
    branding: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # KIDs, not secret/private-key data. Purpose/algorithm are checked by the
    # key-rotation service before these pointers are changed.
    active_signing_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active_config_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class ApplicationKeyModel(Base):
    """Purpose-separated, rotatable Application signing/ECDH key."""

    __tablename__ = "application_keys"
    __table_args__ = (
        UniqueConstraint("application_id", "kid", name="uq_application_key_kid"),
        CheckConstraint(
            "(purpose = 'signing' AND algorithm = 'ed25519') OR "
            "(purpose = 'config_encryption' AND algorithm = 'x25519')",
            name="ck_application_key_purpose_algorithm",
        ),
        Index("ix_application_keys_app_purpose_status",
              "application_id", "purpose", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    kid: Mapped[str] = mapped_column(String(64), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    # The panel-side private key is stored only as an authenticated encrypted
    # envelope. No plaintext/private-key compatibility column exists.
    private_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active")
    not_before: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    not_after: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class UserModel(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "access_mode IS NULL OR access_mode IN ('subscription', 'application')",
            name="ck_users_access_mode",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    data_limit_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    data_limit_reset_strategy: Mapped[str] = mapped_column(String(20), default="no_reset")
    expire_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    ip_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Decimal Mbps; 0 means unlimited. Non-null defaults keep every upgraded
    # user unthrottled until an operator explicitly opts in.
    download_limit_mbps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0")
    upload_limit_mbps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0")
    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    online_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    # ``client_auth_mode`` remains the deployed portal compatibility value.
    # New Application APIs persist the canonical subscription/application
    # spelling in ``access_mode``; repositories dual-write the two columns.
    access_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    client_auth_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Zagros app credentials (Mode 2); password stored as scrypt hash only
    app_username: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    app_password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)

    accounts: Mapped[list["UserCoreAccountModel"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class ApplicationUserGrantModel(Base):
    """Explicit authorization for a user to authenticate through an app."""

    __tablename__ = "application_user_grants"
    __table_args__ = (
        UniqueConstraint("application_id", "user_id", name="uq_application_user_grant"),
        Index("ix_application_grants_user_status", "user_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active")
    granted_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class ApplicationActivationTicketModel(Base):
    """Hashed, single-use ticket binding activation to an app and key."""

    __tablename__ = "application_activation_tickets"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NULL AND application_user_grant_id IS NULL) OR "
            "(user_id IS NOT NULL AND application_user_grant_id IS NOT NULL)",
            name="ck_application_activation_user_binding",
        ),
        Index("ix_application_activation_expiry", "application_id", "expires_at"),
        Index("ix_application_activation_user", "application_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    application_key_id: Mapped[int] = mapped_column(
        ForeignKey("application_keys.id", ondelete="CASCADE"), nullable=False)
    # Nullable only for forward compatibility with any foundation rows created
    # before Phase 3. Authentication rejects unbound tickets; all new issuance
    # binds both the user and the exact active app-user grant.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    application_user_grant_id: Mapped[int | None] = mapped_column(
        ForeignKey("application_user_grants.id", ondelete="CASCADE"), nullable=True)
    ticket_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    intended_device_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class ApplicationConfigGrantModel(Base):
    """Short-lived, one-time authority for one registered device/core config."""

    __tablename__ = "application_config_grants"
    __table_args__ = (
        Index(
            "ix_application_config_grant_scope",
            "application_id", "user_id", "device_id", "expires_at",
        ),
        Index("ix_application_config_grant_expiry", "expires_at"),
        Index("ix_application_config_grant_family", "token_family_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Public random reference only. It is not sufficient without a valid
    # bound access token and a fresh signed request from the enrolled device.
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("subscription_devices.id", ondelete="CASCADE"), nullable=False)
    application_key_id: Mapped[int] = mapped_column(
        ForeignKey("application_keys.id", ondelete="CASCADE"), nullable=False)
    token_family_id: Mapped[str] = mapped_column(String(64), nullable=False)
    core_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # The exact source account selected by GET /configs. These columns are
    # nullable only for rows created by the backward-compatible Phase 4
    # migration; Phase 6 never issues an unscoped selector.
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_account_id: Mapped[str | None] = mapped_column(String(190), nullable=True)
    # Bound atomically by connections/start. Config delivery rejects an
    # unbound selector, so a permanent user/core identity is never delivered.
    connection_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)


class ApplicationConnectionModel(Base):
    """Canonical desired/observed state for one Application device tunnel."""

    __tablename__ = "application_connections"
    __table_args__ = (
        Index(
            "ix_application_connection_scope",
            "application_id", "user_id", "device_id", "updated_at",
        ),
        Index("ix_application_connection_expiry", "not_after", "status"),
        UniqueConstraint("active_key", name="uq_application_connection_active_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("subscription_devices.id", ondelete="CASCADE"), nullable=False)
    application_key_id: Mapped[int] = mapped_column(
        ForeignKey("application_keys.id", ondelete="CASCADE"), nullable=False)
    token_family_id: Mapped[str] = mapped_column(String(64), nullable=False)
    core_id: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    target_kind: Mapped[str] = mapped_column(
        String(12), nullable=False, default="local", server_default="local")
    # Portable partial-unique invariant: populated only while this connection
    # is current, then nulled on every terminal transition.
    active_key: Mapped[str | None] = mapped_column(String(190), nullable=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending", server_default="pending")
    observed_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="unknown", server_default="unknown")
    teardown_capability: Mapped[str] = mapped_column(
        String(32), nullable=False, default="authorization_only",
        server_default="authorization_only")
    requested_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    renewed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    not_after: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow)
    observed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    stop_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class ApplicationConnectionLeaseModel(Base):
    """Encrypted, renewable device account mapped to the canonical user."""

    __tablename__ = "application_connection_leases"
    __table_args__ = (
        UniqueConstraint("connection_id", name="uq_application_connection_lease_connection"),
        UniqueConstraint("account_id", name="uq_application_connection_lease_account"),
        Index("ix_application_connection_lease_expiry", "not_after", "status"),
        Index("ix_application_connection_lease_owner", "user_id", "core_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    connection_id: Mapped[int] = mapped_column(
        ForeignKey("application_connections.id", ondelete="CASCADE"), nullable=False)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("subscription_devices.id", ondelete="CASCADE"), nullable=False)
    core_id: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    target_kind: Mapped[str] = mapped_column(
        String(12), nullable=False, default="local", server_default="local")
    account_id: Mapped[str] = mapped_column(String(190), nullable=False)
    # AES-256-GCM sealed account.settings with row-specific AAD. Temporary
    # UUIDs/passwords/private keys are never stored as plaintext.
    credentials_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending", server_default="pending")
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    renewed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    not_after: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoke_requested_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    removed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class ApplicationRequestNonceModel(Base):
    """Durable replay ledger for signed Application API requests."""

    __tablename__ = "application_request_nonces"
    __table_args__ = (
        UniqueConstraint(
            "application_id", "nonce_hash",
            name="uq_application_request_nonce",
        ),
        Index("ix_application_request_nonce_expiry", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("subscription_devices.id", ondelete="CASCADE"), nullable=True)
    application_key_id: Mapped[int | None] = mapped_column(
        ForeignKey("application_keys.id", ondelete="CASCADE"), nullable=True)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_timestamp: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


class ApplicationAuthThrottleModel(Base):
    """Persistent IP/username/device throttle bucket; keys are one-way hashes."""

    __tablename__ = "application_auth_throttles"
    __table_args__ = (
        UniqueConstraint(
            "application_id", "bucket_type", "bucket_hash",
            name="uq_application_auth_throttle_bucket",
        ),
        Index("ix_application_auth_throttle_blocked", "blocked_until"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    bucket_type: Mapped[str] = mapped_column(String(32), nullable=False)
    bucket_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0,
                                                server_default="0")
    window_started_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    blocked_until: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow)


class SubscriptionDeviceModel(Base):
    """One stable identifier enrolled for subscription/config delivery.

    Only a SHA-256 digest and a short non-secret hint are retained. ``last_ip``
    is request metadata, never identity: the stable header remains the sole
    enrollment key.
    """
    __tablename__ = "subscription_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_hash", name="uq_subscription_device"),
        UniqueConstraint(
            "user_id", "application_id", "device_public_key",
            name="uq_subscription_device_app_key",
        ),
        CheckConstraint(
            "(application_id IS NULL AND device_public_key IS NULL AND "
            "device_key_fingerprint IS NULL AND device_key_id IS NULL AND "
            "device_status IS NULL) OR "
            "(application_id IS NOT NULL AND device_public_key IS NOT NULL AND "
            "device_key_fingerprint IS NOT NULL AND device_key_id IS NOT NULL AND "
            "device_status IN ('active', 'revoked'))",
            name="ck_subscription_device_application_binding",
        ),
        Index("ix_subscription_devices_user", "user_id"),
        Index("ix_subscription_devices_application", "application_id"),
        Index("ix_subscription_devices_app_status", "application_id", "device_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    # Null application/key bindings preserve every legacy subscription device;
    # those rows never become cryptographic Application devices implicitly.
    application_id: Mapped[int | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=True)
    device_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    device_hint: Mapped[str] = mapped_column(String(24), nullable=False)
    device_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_key_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    app_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class IPBanModel(Base):
    """Auditable timed source-IP ban; nftables is a projection of active rows."""
    __tablename__ = "ip_bans"
    __table_args__ = (
        Index("ix_ip_bans_active_expiry", "active", "expires_at"),
        Index("ix_ip_bans_user", "user_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    banned_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")


class IPActivityModel(Base):
    """Observed authenticated source IP, independent from stable HWID rows."""

    __tablename__ = "ip_activity"
    __table_args__ = (
        Index("ix_ip_activity_last_seen", "last_seen"),
        Index("ix_ip_activity_user_last", "user_id", "last_seen"),
        Index("ix_ip_activity_core_last", "core_id", "last_seen"),
        Index("ix_ip_activity_node_last", "node_id", "last_seen"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_key: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    core_id: Mapped[str] = mapped_column(String(32), nullable=False)
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    active_since: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


# --------------------------------------------------------------------- #
# cores & their configuration
# --------------------------------------------------------------------- #

class CoreModel(Base):
    __tablename__ = "cores"

    id: Mapped[int] = mapped_column(primary_key=True)
    core_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    state: Mapped[str] = mapped_column(String(16), default="loaded")
    health: Mapped[str] = mapped_column(String(16), default="unknown")
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    core_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow, onupdate=_utcnow)


class CoreInboundModel(Base):
    __tablename__ = "core_inbounds"
    __table_args__ = (UniqueConstraint("core_id", "tag", name="uq_inbound_per_core"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    core_id: Mapped[str] = mapped_column(String(32), index=True)
    tag: Mapped[str] = mapped_column(String(128))
    protocol: Mapped[str] = mapped_column(String(32))
    listen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CoreHostModel(Base):
    __tablename__ = "core_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    core_id: Mapped[str] = mapped_column(String(32), index=True)
    # (item 13): which inbound of the core this host variant
    # belongs to — marzban-era rows backfilled from extras by migration
    # 0008; "" never matches a live tag (inert by design).
    inbound_tag: Mapped[str] = mapped_column(String(256), default="", server_default="")
    remark: Mapped[str] = mapped_column(String(256))
    address: Mapped[str] = mapped_column(String(256))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # comma multi-value lists (MultipleSNI/MultipleHost) need room — 1000,
    # mirroring the legacy hosts table (e7b869e999b4)
    sni: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    host_header: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    security: Mapped[str | None] = mapped_column(String(32), nullable=True)
    alpn: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # marzban-era per-host flags preserved on migration (inbound_tag,
    # allowinsecure, is_disabled, mux_enable, random_user_agent); JSON so
    # future host attributes never need another schema change.
    extras: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sort: Mapped[int] = mapped_column(Integer, default=0)


class NodeModel(Base):
    """A remote Zagros node (multi-core agent), or a legacy Xray-only row.

    Pairing state machine: ``pending`` (token issued, not yet paired) →
    ``connected`` (certificate pinned, signing key sealed) → ``error``.
    """

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    address: Mapped[str] = mapped_column(String(256))
    port: Mapped[int] = mapped_column(Integer, default=62050)
    # Read-only bootstrap/info port the panel uses to discover the node and
    # fetch the certificate it then pins (see app/nodes/client.py).
    api_port: Mapped[int] = mapped_column(Integer, default=62051)
    status: Mapped[str] = mapped_column(String(20), default="unhealthy")
    usage_coefficient: Mapped[float] = mapped_column(Float, default=1.0)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    agent_type: Mapped[str] = mapped_column(String(32), default="legacy_xray")
    agent_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # AES-GCM sealed signing key returned once during native registration.
    agent_credentials_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Sealed one-time registration token (destroyed the moment pairing
    # succeeds) and its hash — the panel must be able to complete pairing
    # without asking the operator to retype the token.
    registration_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    registration_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    panel_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    add_as_new_host: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


# --------------------------------------------------------------------- #
# user <-> core accounts & usage ledger
# --------------------------------------------------------------------- #

class UserCoreAccountModel(Base):
    __tablename__ = "user_core_accounts"
    __table_args__ = (
        UniqueConstraint("user_id", "core_id", "account_id", name="uq_core_account"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    core_id: Mapped[str] = mapped_column(String(32), index=True)
    account_id: Mapped[str] = mapped_column(String(190))
    protocol: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: AES-256-GCM sealed JSON of account.settings (uuid/password/keys)
    credentials_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    user: Mapped[UserModel] = relationship(back_populates="accounts")


class UserUsageModel(Base):
    """The unified quota ledger — one row per user, all cores folded in."""

    __tablename__ = "user_usage"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"),
                                         primary_key=True)
    uplink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow, onupdate=_utcnow)


class UsageBaselineModel(Base):
    """Per-(core, account[, node]) counter baselines for delta computation.

    Persisted so an engine restart never re-reports the same traffic twice
    (exactly-once accounting across restarts, doc §15.6).
    """

    __tablename__ = "usage_baselines"

    key: Mapped[str] = mapped_column(String(190), primary_key=True)  # "core:account[:node]"
    uplink_base: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink_base: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow, onupdate=_utcnow)


class UsageRecordModel(Base):
    """Append-only usage journal (per polling batch, per account)."""

    __tablename__ = "usage_records"
    __table_args__ = (
        Index("ix_usage_owner_time", "user_id", "recorded_at"),
        Index("ix_usage_recorded_at", "recorded_at"),
        Index("ix_usage_core_time", "core_id", "recorded_at"),
        Index("ix_usage_node_time", "node_id", "recorded_at"),
    )

    # SQLite only auto-increments INTEGER PRIMARY KEY (rowid alias);
    # BigInteger would silently break autoincrement there.
    seq: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"),
                                                nullable=True, index=True)
    core_id: Mapped[str] = mapped_column(String(32), index=True)
    account_id: Mapped[str] = mapped_column(String(190))
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id", ondelete="SET NULL"),
                                                nullable=True)
    uplink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


class UsageAggregateModel(Base):
    """Small cumulative rollups for system/core/node Statistics cards."""

    __tablename__ = "usage_aggregates"

    dimension: Mapped[str] = mapped_column(String(190), primary_key=True)
    uplink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow,
                                                  onupdate=_utcnow)


class SystemUsageBucketModel(Base):
    """Five-minute real-accounting rollup; one row regardless of user count."""

    __tablename__ = "system_usage_buckets"

    bucket_start: Mapped[datetime] = mapped_column(UtcDateTime, primary_key=True)
    uplink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    downlink_bytes: Mapped[int] = mapped_column(BigInteger, default=0)


# --------------------------------------------------------------------- #
# devices & sessions
# --------------------------------------------------------------------- #

class DeviceModel(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    platform: Mapped[str | None] = mapped_column(String(32), nullable=True)
    app_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    current_core: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cores_json: Mapped[list[str]] = mapped_column(JSON, default=list)


class DeviceSessionModel(Base):
    """Closed/archived sessions (history); live sessions are in-memory."""

    __tablename__ = "device_sessions"
    __table_args__ = (Index("ix_sessions_user_started", "user_id", "started_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(190), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"),
                                                nullable=True)
    core_id: Mapped[str] = mapped_column(String(32), index=True)
    account_id: Mapped[str] = mapped_column(String(190))
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id", ondelete="SET NULL"),
                                                nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime)
    ended_at: Mapped[datetime] = mapped_column(UtcDateTime)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)


# --------------------------------------------------------------------- #
# policies / routing / outbounds (visual editors' storage)
# --------------------------------------------------------------------- #

class PolicyModel(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


class RoutingRuleModel(Base):
    __tablename__ = "routing_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class OutboundProfileModel(Base):
    __tablename__ = "outbound_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RoutingDomainModel(Base):
    """Stable Linux table/mark identity for one named outbound.

    Runtime process/interface details are deliberately not persisted; they
    are reconstructed and verified on every boot. Keeping the identity row
    makes upgrades and rollback preserve table ids even when outbound order
    changes.
    """

    __tablename__ = "routing_domains"

    outbound_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    table_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    fwmark: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    definition_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow,
                                                 onupdate=_utcnow)


# --------------------------------------------------------------------- #
# platform settings / tokens / audit / plugins
# --------------------------------------------------------------------- #

class SettingModel(Base):
    """Typed key-value settings (portal, client auth mode, studio docs...)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow, onupdate=_utcnow)


class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        CheckConstraint(
            "(application_id IS NULL AND device_id IS NULL AND "
            "application_key_id IS NULL AND token_family_id IS NULL) OR "
            "(application_id IS NOT NULL AND device_id IS NOT NULL AND "
            "application_key_id IS NOT NULL AND token_family_id IS NOT NULL)",
            name="ck_refresh_token_application_binding",
        ),
        Index("ix_refresh_tokens_application", "application_id"),
        Index("ix_refresh_tokens_device", "device_id"),
        Index("ix_refresh_tokens_family", "token_family_id"),
    )

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # Null bindings preserve legacy Client API refresh tokens. Application API
    # issuance binds all three and uses the family fields for rotation/reuse
    # detection; service enforcement arrives with the authentication phase.
    application_id: Mapped[int | None] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("subscription_devices.id", ondelete="CASCADE"), nullable=True)
    application_key_id: Mapped[int | None] = mapped_column(
        ForeignKey("application_keys.id", ondelete="CASCADE"), nullable=True)
    token_family_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    rotated_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_time", "at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(190), nullable=True)
    detail_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class PluginModel(Base):
    __tablename__ = "plugins"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    installed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


# --------------------------------------------------------------------- #
# white-label build system (Phase 12)
# --------------------------------------------------------------------- #
# SQL is the durable source of truth for builds: requested revisions,
# per-platform job state, artifact checksums, worker identities and
# encrypted build credentials. Redis/RQ is transport (job dispatch) and
# ephemeral state (live logs, heartbeats) only — a lost Redis never loses
# build history or artifacts, and every worker callback re-validates
# against these rows.


class AppBuildModel(Base):
    """One white-label build request for an Application (panel-side truth)."""

    __tablename__ = "app_builds"
    __table_args__ = (
        Index("ix_app_builds_application_status", "application_id", "status"),
        Index("ix_app_builds_owner_status", "owner_admin_id", "status"),
        UniqueConstraint("application_id", "build_number",
                         name="uq_app_builds_app_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="RESTRICT"), nullable=False)
    owner_admin_id: Mapped[int] = mapped_column(
        ForeignKey("admins.id", ondelete="RESTRICT"), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    build_number: Mapped[int] = mapped_column(nullable=False)
    source_repo: Mapped[str] = mapped_column(String(512), nullable=False)
    source_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    # Phase 14: pinned SDK source. Nullable only so pre-Phase-14 rows stay
    # readable — the service requires both pins for every new build, and
    # the v2 worker refuses a job document without them.
    sdk_source_repo: Mapped[str | None] = mapped_column(
        String(512), nullable=True)
    sdk_source_revision: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    build_config: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict)
    config_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_platforms: Mapped[list] = mapped_column(JSON, nullable=False)
    # Public IDs of build credentials attached at request time (ids only —
    # material is decrypted just-in-time for the authenticated worker).
    credential_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", server_default="queued")
    progress: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0")
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(
        String(500), nullable=True)
    log_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow)


class BuildPlatformJobModel(Base):
    """Per-platform unit of work inside a build (one RQ job each)."""

    __tablename__ = "build_platform_jobs"
    __table_args__ = (
        Index("ix_build_jobs_build_status", "build_id", "status"),
        Index("ix_build_jobs_queue", "queue_job_id"),
        UniqueConstraint("build_id", "platform", "arch", "artifact",
                         name="uq_build_jobs_build_target"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    build_id: Mapped[int] = mapped_column(
        ForeignKey("app_builds.id", ondelete="CASCADE"), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    arch: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact: Mapped[str] = mapped_column(
        String(16), nullable=False, default="apk", server_default="apk")
    queue_name: Mapped[str] = mapped_column(String(64), nullable=False)
    queue_job_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True)
    # SHA-256 hex of the one-time job token (high-entropy random; the token
    # itself is shown to the worker once, inside the RQ payload only).
    job_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    job_token_valid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", server_default="queued")
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(
        String(500), nullable=True)
    log_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class AppBuildArtifactModel(Base):
    """Immutable, checksummed release file produced by a platform job."""

    __tablename__ = "app_build_artifacts"
    __table_args__ = (
        Index("ix_build_artifacts_build", "build_id"),
        UniqueConstraint("build_id", "platform", "arch", "filename",
                         name="uq_build_artifacts_target_file"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    build_id: Mapped[int] = mapped_column(
        ForeignKey("app_builds.id", ondelete="CASCADE"), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    arch: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact: Mapped[str] = mapped_column(
        String(16), nullable=False, default="apk", server_default="apk")
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    rel_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    signature_ref: Mapped[str | None] = mapped_column(
        String(1024), nullable=True)
    sbom_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    provenance: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)


class BuildWorkerModel(Base):
    """Registered build worker (native pool member or VPS pool member)."""

    __tablename__ = "build_workers"
    __table_args__ = (
        Index("ix_build_workers_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    worker_id: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    platform_labels: Mapped[list] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending",
        server_default="pending")
    api_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    register_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    register_token_expires_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=_utcnow, onupdate=_utcnow)


class BuildCredentialModel(Base):
    """Encrypted build-time secret (VPS SSH, signing keys).

    Only metadata leaves this table through the API — plaintext is
    decrypted just-in-time when dispatching a job to an authenticated
    worker, never listed or echoed back.
    """

    __tablename__ = "build_credentials"
    __table_args__ = (
        Index("ix_build_credentials_scope_owner",
              "scope", "owner_ref", "revoked"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    owner_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    encrypted_material: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the *envelope* (not the secret): distinguishes rotations
    # without creating a brute-forceable hash of a low-entropy secret.
    envelope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0")
    revoked_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True)
