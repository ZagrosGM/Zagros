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


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    data_limit_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    data_limit_reset_strategy: Mapped[str] = mapped_column(String(20), default="no_reset")
    expire_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    device_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admins.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
    online_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    # Client Authentication Mode override (None -> inherit panel setting)
    client_auth_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Zagros app credentials (Mode 2); password stored as scrypt hash only
    app_username: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    app_password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)

    accounts: Mapped[list["UserCoreAccountModel"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


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
    # alpha.7.2 (item 13): which inbound of the core this host variant
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
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    address: Mapped[str] = mapped_column(String(256))
    port: Mapped[int] = mapped_column(Integer, default=62050)
    status: Mapped[str] = mapped_column(String(20), default="unhealthy")
    usage_coefficient: Mapped[float] = mapped_column(Float, default=1.0)
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    agent_type: Mapped[str] = mapped_column(String(32), default="legacy_xray")
    agent_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # AES-GCM sealed signing key returned once during native registration.
    agent_credentials_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    __table_args__ = (Index("ix_usage_owner_time", "user_id", "recorded_at"),)

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

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    rotated_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=_utcnow)
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
