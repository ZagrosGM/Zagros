"""Add short-lived, one-time Application config grants.

Revision ID: 0017_application_config_grants
Revises: 0016_activation_ticket_binding
Create Date: 2026-09-06

The grant reference is a random public identifier, not a standalone bearer
secret: config retrieval still requires a valid bound access token and a new
signed request from the enrolled device. No raw config is persisted here.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_application_config_grants"
down_revision = "0016_activation_ticket_binding"
branch_labels = None
depends_on = None

_TABLE = "application_config_grants"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if _TABLE in set(inspector.get_table_names()):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("public_id", sa.String(length=36), nullable=False),
        sa.Column("application_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("application_key_id", sa.Integer(), nullable=False),
        sa.Column("token_family_id", sa.String(length=64), nullable=False),
        sa.Column("core_id", sa.String(length=32), nullable=False),
        sa.Column("connection_id", sa.String(length=64), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(
            ["application_id"], ["applications.id"],
            name="fk_application_config_grant_application", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_application_config_grant_user", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_id"], ["subscription_devices.id"],
            name="fk_application_config_grant_device", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["application_key_id"], ["application_keys.id"],
            name="fk_application_config_grant_key", ondelete="CASCADE"),
        sa.UniqueConstraint(
            "public_id", name="uq_application_config_grant_public_id"),
    )
    op.create_index(
        "ix_application_config_grant_scope", _TABLE,
        ["application_id", "user_id", "device_id", "expires_at"])
    op.create_index(
        "ix_application_config_grant_expiry", _TABLE, ["expires_at"])
    op.create_index(
        "ix_application_config_grant_family", _TABLE, ["token_family_id"])


def downgrade() -> None:
    # Keep consumed/revoked delivery history and its security audit linkage.
    # Forward replay is safe because upgrade() is schema-inspection guarded.
    pass
