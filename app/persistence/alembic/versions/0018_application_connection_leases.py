"""Add canonical Application connections and renewable device leases.

Revision ID: 0018_application_connection_leases
Revises: 0017_application_config_grants
Create Date: 2026-09-07

The migration is additive. Existing Phase 4 config-grant rows remain readable,
while every newly issued selector is scoped to a protocol/source account and
must be bound to a device connection before delivery.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_application_connection_leases"
down_revision = "0017_application_config_grants"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {str(row["name"]) for row in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {str(row["name"]) for row in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    tables = _tables()
    if "application_config_grants" in tables:
        existing = _columns("application_config_grants")
        if "protocol" not in existing:
            op.add_column(
                "application_config_grants",
                sa.Column("protocol", sa.String(length=32), nullable=True),
            )
        if "source_account_id" not in existing:
            op.add_column(
                "application_config_grants",
                sa.Column("source_account_id", sa.String(length=190), nullable=True),
            )

    if "application_connections" not in tables:
        op.create_table(
            "application_connections",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("public_id", sa.String(length=36), nullable=False),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("device_id", sa.Integer(), nullable=False),
            sa.Column("application_key_id", sa.Integer(), nullable=False),
            sa.Column("token_family_id", sa.String(length=64), nullable=False),
            sa.Column("core_id", sa.String(length=32), nullable=False),
            sa.Column("protocol", sa.String(length=32), nullable=False),
            sa.Column("node_id", sa.Integer(), nullable=True),
            sa.Column("target_kind", sa.String(length=12), nullable=False,
                      server_default="local"),
            sa.Column("active_key", sa.String(length=190), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False,
                      server_default="pending"),
            sa.Column("observed_status", sa.String(length=24), nullable=False,
                      server_default="unknown"),
            sa.Column("teardown_capability", sa.String(length=32), nullable=False,
                      server_default="authorization_only"),
            sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("renewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("stop_reason", sa.String(length=500), nullable=True),
            sa.Column("last_error", sa.String(length=1000), nullable=True),
            sa.ForeignKeyConstraint(["application_id"], ["applications.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["device_id"], ["subscription_devices.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["application_key_id"], ["application_keys.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("public_id", name="uq_application_connection_public_id"),
            sa.UniqueConstraint("active_key", name="uq_application_connection_active_key"),
        )
        op.create_index(
            "ix_application_connection_scope", "application_connections",
            ["application_id", "user_id", "device_id", "updated_at"],
        )
        op.create_index(
            "ix_application_connection_expiry", "application_connections",
            ["not_after", "status"],
        )

    tables = _tables()
    if "application_connection_leases" not in tables:
        op.create_table(
            "application_connection_leases",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("public_id", sa.String(length=36), nullable=False),
            sa.Column("connection_id", sa.Integer(), nullable=False),
            sa.Column("application_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("device_id", sa.Integer(), nullable=False),
            sa.Column("core_id", sa.String(length=32), nullable=False),
            sa.Column("protocol", sa.String(length=32), nullable=False),
            sa.Column("node_id", sa.Integer(), nullable=True),
            sa.Column("target_kind", sa.String(length=12), nullable=False,
                      server_default="local"),
            sa.Column("account_id", sa.String(length=190), nullable=False),
            sa.Column("credentials_enc", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False,
                      server_default="pending"),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("renewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoke_requested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoke_reason", sa.String(length=500), nullable=True),
            sa.Column("last_error", sa.String(length=1000), nullable=True),
            sa.ForeignKeyConstraint(["connection_id"], ["application_connections.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["application_id"], ["applications.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["device_id"], ["subscription_devices.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("public_id", name="uq_application_connection_lease_public_id"),
            sa.UniqueConstraint("connection_id",
                                name="uq_application_connection_lease_connection"),
            sa.UniqueConstraint("account_id", name="uq_application_connection_lease_account"),
        )
        op.create_index(
            "ix_application_connection_lease_expiry", "application_connection_leases",
            ["not_after", "status"],
        )
        op.create_index(
            "ix_application_connection_lease_owner", "application_connection_leases",
            ["user_id", "core_id"],
        )


def downgrade() -> None:
    # Connection and lease rows are security/audit history. Keep them on a
    # downgrade so a subsequent forward migration cannot resurrect authority.
    pass
