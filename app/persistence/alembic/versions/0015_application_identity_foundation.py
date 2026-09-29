"""Application identity, device binding and durable auth state foundation.

Revision ID: 0015_application_identity
Revises: 0014_monitoring_statistics
Create Date: 2026-09-06

The revision is deliberately additive. Existing users, subscription devices
and Client API refresh tokens remain valid with nullable Application bindings.
Legacy ``client_auth_mode`` values are copied to canonical ``access_mode``
values without modifying app usernames or password hashes.
"""
from __future__ import annotations

from collections.abc import Callable

import sqlalchemy as sa
from alembic import op

revision = "0015_application_identity"
down_revision = "0014_monitoring_statistics"
branch_labels = None
depends_on = None


ColumnFactory = Callable[[], sa.Column]


def _inspector():
    return sa.inspect(op.get_bind())


def _tables() -> set[str]:
    return set(_inspector().get_table_names())


def _columns(table: str) -> set[str]:
    return {column["name"] for column in _inspector().get_columns(table)}


def _index_names(table: str) -> set[str]:
    return {index["name"] for index in _inspector().get_indexes(table) if index.get("name")}


def _unique_names(table: str) -> set[str]:
    return {
        constraint["name"]
        for constraint in _inspector().get_unique_constraints(table)
        if constraint.get("name")
    }


def _check_names(table: str) -> set[str]:
    getter = getattr(_inspector(), "get_check_constraints", None)
    if getter is None:
        return set()
    return {
        constraint["name"]
        for constraint in getter(table)
        if constraint.get("name")
    }


def _has_foreign_key(table: str, local_columns: list[str],
                     remote_table: str) -> bool:
    expected = tuple(local_columns)
    return any(
        tuple(constraint.get("constrained_columns") or ()) == expected
        and constraint.get("referred_table") == remote_table
        for constraint in _inspector().get_foreign_keys(table)
    )


def _add_missing_columns(table: str,
                         factories: dict[str, ColumnFactory]) -> None:
    existing = _columns(table)
    missing = [name for name in factories if name not in existing]
    if not missing:
        return
    with op.batch_alter_table(table) as batch:
        for name in missing:
            batch.add_column(factories[name]())


def _ensure_index(table: str, name: str, columns: list[str]) -> None:
    if name not in _index_names(table):
        op.create_index(name, table, columns)


def _create_foundation_tables() -> None:
    tables = _tables()
    if "applications" not in tables:
        op.create_table(
            "applications",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("public_id", sa.String(36), nullable=False),
            sa.Column("owner_admin_id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("status", sa.String(20), nullable=False,
                      server_default="active"),
            sa.Column("api_base_url", sa.String(2048), nullable=False),
            sa.Column("default_lang", sa.String(16), nullable=False,
                      server_default="fa"),
            sa.Column("branding", sa.JSON(), nullable=False),
            sa.Column("active_signing_kid", sa.String(64), nullable=True),
            sa.Column("active_config_kid", sa.String(64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_reason", sa.String(500), nullable=True),
            sa.ForeignKeyConstraint(
                ["owner_admin_id"], ["admins.id"],
                name="fk_applications_owner_admin", ondelete="RESTRICT"),
            sa.UniqueConstraint("public_id", name="uq_applications_public_id"),
        )
        op.create_index(
            "ix_applications_owner_status", "applications",
            ["owner_admin_id", "status"])

    tables = _tables()
    if "application_keys" not in tables:
        op.create_table(
            "application_keys",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("kid", sa.String(64), nullable=False),
            sa.Column("purpose", sa.String(32), nullable=False),
            sa.Column("algorithm", sa.String(32), nullable=False),
            sa.Column("public_key", sa.Text(), nullable=False),
            sa.Column("private_key_encrypted", sa.Text(), nullable=False),
            sa.Column("encryption_key_id", sa.String(128), nullable=False),
            sa.Column("status", sa.String(20), nullable=False,
                      server_default="active"),
            sa.Column("not_before", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_reason", sa.String(500), nullable=True),
            sa.ForeignKeyConstraint(
                ["application_id"], ["applications.id"],
                name="fk_application_keys_application", ondelete="CASCADE"),
            sa.UniqueConstraint(
                "application_id", "kid", name="uq_application_key_kid"),
            sa.CheckConstraint(
                "(purpose = 'signing' AND algorithm = 'ed25519') OR "
                "(purpose = 'config_encryption' AND algorithm = 'x25519')",
                name="ck_application_key_purpose_algorithm"),
        )
        op.create_index(
            "ix_application_keys_app_purpose_status", "application_keys",
            ["application_id", "purpose", "status"])

    tables = _tables()
    if "application_user_grants" not in tables:
        op.create_table(
            "application_user_grants",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False,
                      server_default="active"),
            sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_reason", sa.String(500), nullable=True),
            sa.ForeignKeyConstraint(
                ["application_id"], ["applications.id"],
                name="fk_application_user_grants_application", ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"],
                name="fk_application_user_grants_user", ondelete="CASCADE"),
            sa.UniqueConstraint(
                "application_id", "user_id", name="uq_application_user_grant"),
        )
        op.create_index(
            "ix_application_grants_user_status", "application_user_grants",
            ["user_id", "status"])

    tables = _tables()
    if "application_activation_tickets" not in tables:
        op.create_table(
            "application_activation_tickets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("application_key_id", sa.Integer(), nullable=False),
            sa.Column("ticket_hash", sa.String(64), nullable=False),
            sa.Column("jti", sa.String(64), nullable=False),
            sa.Column("intended_device_key_hash", sa.String(64), nullable=True),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_reason", sa.String(500), nullable=True),
            sa.ForeignKeyConstraint(
                ["application_id"], ["applications.id"],
                name="fk_application_activation_application", ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["application_key_id"], ["application_keys.id"],
                name="fk_application_activation_key", ondelete="CASCADE"),
            sa.UniqueConstraint("ticket_hash", name="uq_application_activation_hash"),
            sa.UniqueConstraint("jti", name="uq_application_activation_jti"),
        )
        op.create_index(
            "ix_application_activation_expiry",
            "application_activation_tickets", ["application_id", "expires_at"])

    tables = _tables()
    if "application_auth_throttles" not in tables:
        op.create_table(
            "application_auth_throttles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("bucket_type", sa.String(32), nullable=False),
            sa.Column("bucket_hash", sa.String(64), nullable=False),
            sa.Column("failure_count", sa.Integer(), nullable=False,
                      server_default="0"),
            sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.ForeignKeyConstraint(
                ["application_id"], ["applications.id"],
                name="fk_application_auth_throttles_application", ondelete="CASCADE"),
            sa.UniqueConstraint(
                "application_id", "bucket_type", "bucket_hash",
                name="uq_application_auth_throttle_bucket"),
        )
        op.create_index(
            "ix_application_auth_throttle_blocked",
            "application_auth_throttles", ["blocked_until"])


def _upgrade_users() -> None:
    if "users" not in _tables():
        return
    _add_missing_columns("users", {
        "access_mode": lambda: sa.Column("access_mode", sa.String(32), nullable=True),
    })
    # Backfill only recognized legacy values. Unknown data remains NULL and
    # therefore cannot be mistaken for Application authorization.
    op.get_bind().execute(sa.text(
        "UPDATE users SET access_mode = CASE "
        "WHEN LOWER(TRIM(client_auth_mode)) IN "
        "('subscription', 'subscription_link', 'sub_link') THEN 'subscription' "
        "WHEN LOWER(TRIM(client_auth_mode)) IN "
        "('application', 'application_login', 'app_login') THEN 'application' "
        "ELSE access_mode END "
        "WHERE access_mode IS NULL AND client_auth_mode IS NOT NULL"
    ))
    if "ck_users_access_mode" not in _check_names("users"):
        with op.batch_alter_table("users") as batch:
            batch.create_check_constraint(
                "ck_users_access_mode",
                "access_mode IS NULL OR access_mode IN ('subscription', 'application')")


def _upgrade_subscription_devices() -> None:
    if "subscription_devices" not in _tables():
        return
    _add_missing_columns("subscription_devices", {
        "application_id": lambda: sa.Column("application_id", sa.Integer(), nullable=True),
        "device_public_key": lambda: sa.Column(
            "device_public_key", sa.String(64), nullable=True),
        "device_key_fingerprint": lambda: sa.Column(
            "device_key_fingerprint", sa.String(64), nullable=True),
        "device_key_id": lambda: sa.Column("device_key_id", sa.String(64), nullable=True),
        "device_status": lambda: sa.Column("device_status", sa.String(20), nullable=True),
        "name": lambda: sa.Column("name", sa.String(128), nullable=True),
        "platform": lambda: sa.Column("platform", sa.String(32), nullable=True),
        "app_version": lambda: sa.Column("app_version", sa.String(64), nullable=True),
        "last_authenticated_at": lambda: sa.Column(
            "last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        "revoked_at": lambda: sa.Column(
            "revoked_at", sa.DateTime(timezone=True), nullable=True),
        "revoked_reason": lambda: sa.Column(
            "revoked_reason", sa.String(500), nullable=True),
    })

    unique_names = _unique_names("subscription_devices")
    check_names = _check_names("subscription_devices")
    need_fk = not _has_foreign_key(
        "subscription_devices", ["application_id"], "applications")
    need_unique = "uq_subscription_device_app_key" not in unique_names
    need_check = "ck_subscription_device_application_binding" not in check_names
    if need_fk or need_unique or need_check:
        with op.batch_alter_table("subscription_devices") as batch:
            if need_fk:
                batch.create_foreign_key(
                    "fk_subscription_devices_application", "applications",
                    ["application_id"], ["id"], ondelete="CASCADE")
            if need_unique:
                batch.create_unique_constraint(
                    "uq_subscription_device_app_key",
                    ["user_id", "application_id", "device_public_key"])
            if need_check:
                batch.create_check_constraint(
                    "ck_subscription_device_application_binding",
                    "(application_id IS NULL AND device_public_key IS NULL AND "
                    "device_key_fingerprint IS NULL AND device_key_id IS NULL AND "
                    "device_status IS NULL) OR "
                    "(application_id IS NOT NULL AND device_public_key IS NOT NULL AND "
                    "device_key_fingerprint IS NOT NULL AND device_key_id IS NOT NULL AND "
                    "device_status IN ('active', 'revoked'))")

    _ensure_index(
        "subscription_devices", "ix_subscription_devices_application",
        ["application_id"])
    _ensure_index(
        "subscription_devices", "ix_subscription_devices_app_status",
        ["application_id", "device_status"])


def _upgrade_refresh_tokens() -> None:
    if "refresh_tokens" not in _tables():
        return
    _add_missing_columns("refresh_tokens", {
        "application_id": lambda: sa.Column("application_id", sa.Integer(), nullable=True),
        "device_id": lambda: sa.Column("device_id", sa.Integer(), nullable=True),
        "application_key_id": lambda: sa.Column(
            "application_key_id", sa.Integer(), nullable=True),
        "token_family_id": lambda: sa.Column(
            "token_family_id", sa.String(64), nullable=True),
        "parent_token_hash": lambda: sa.Column(
            "parent_token_hash", sa.String(64), nullable=True),
        "last_used_at": lambda: sa.Column(
            "last_used_at", sa.DateTime(timezone=True), nullable=True),
        "revoked_at": lambda: sa.Column(
            "revoked_at", sa.DateTime(timezone=True), nullable=True),
        "revoked_reason": lambda: sa.Column(
            "revoked_reason", sa.String(500), nullable=True),
    })

    check_names = _check_names("refresh_tokens")
    wanted_fks = {
        "fk_refresh_tokens_application": (
            "applications", ["application_id"], ["id"]),
        "fk_refresh_tokens_device": (
            "subscription_devices", ["device_id"], ["id"]),
        "fk_refresh_tokens_application_key": (
            "application_keys", ["application_key_id"], ["id"]),
    }
    missing_fks = [
        name for name, (remote_table, local_columns, _remote_columns)
        in wanted_fks.items()
        if not _has_foreign_key("refresh_tokens", local_columns, remote_table)
    ]
    need_check = "ck_refresh_token_application_binding" not in check_names
    if missing_fks or need_check:
        with op.batch_alter_table("refresh_tokens") as batch:
            for name in missing_fks:
                remote_table, local_columns, remote_columns = wanted_fks[name]
                batch.create_foreign_key(
                    name, remote_table, local_columns, remote_columns,
                    ondelete="CASCADE")
            if need_check:
                batch.create_check_constraint(
                    "ck_refresh_token_application_binding",
                    "(application_id IS NULL AND device_id IS NULL AND "
                    "application_key_id IS NULL AND token_family_id IS NULL) OR "
                    "(application_id IS NOT NULL AND device_id IS NOT NULL AND "
                    "application_key_id IS NOT NULL AND token_family_id IS NOT NULL)")

    _ensure_index("refresh_tokens", "ix_refresh_tokens_application", ["application_id"])
    _ensure_index("refresh_tokens", "ix_refresh_tokens_device", ["device_id"])
    _ensure_index("refresh_tokens", "ix_refresh_tokens_family", ["token_family_id"])


def _create_request_nonce_table() -> None:
    if "application_request_nonces" in _tables():
        return
    op.create_table(
        "application_request_nonces",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("application_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("application_key_id", sa.Integer(), nullable=True),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("request_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"],
            name="fk_application_request_nonce_application", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_id"], ["subscription_devices.id"],
            name="fk_application_request_nonce_device", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["application_key_id"], ["application_keys.id"],
            name="fk_application_request_nonce_key", ondelete="CASCADE"),
        sa.UniqueConstraint(
            "application_id", "nonce_hash",
            name="uq_application_request_nonce"),
    )
    op.create_index(
        "ix_application_request_nonce_expiry",
        "application_request_nonces", ["expires_at"])


def upgrade() -> None:
    _create_foundation_tables()
    _upgrade_users()
    _upgrade_subscription_devices()
    _upgrade_refresh_tokens()
    _create_request_nonce_table()


def downgrade() -> None:
    # Deliberately non-destructive. Dropping app/device key history, one-time
    # ticket hashes, replay nonces or revocation metadata would silently weaken
    # authorization. Alembic may stamp 0014; replaying this idempotent upgrade
    # restores the forward revision without altering retained rows.
    pass
