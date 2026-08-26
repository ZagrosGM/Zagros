"""Pending native Node enrollment and persistent execution targets.

Revision ID: 0012_native_node_routing
Revises: 0011_user_bandwidth_limits
Create Date: 2026-08-27

NULL node targets mean the local Master, preserving Alpha 8.9 behavior. Pending
registration rows retain only a digest of a high-entropy, one-use credential.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0012_native_node_routing"
down_revision = "0011_user_bandwidth_limits"
branch_labels = None
depends_on = None


def _tables(bind) -> set[str]:
    return set(sa.inspect(bind).get_table_names())


def _columns(bind, table: str) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if "node_id" not in _columns(bind, "users"):
        with op.batch_alter_table("users") as batch:
            batch.add_column(sa.Column("node_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_users_node_id_nodes", "nodes", ["node_id"], ["id"], ondelete="SET NULL")
            batch.create_index("ix_users_node_id", ["node_id"])

    if "node_id" not in _columns(bind, "user_core_accounts"):
        with op.batch_alter_table("user_core_accounts") as batch:
            batch.add_column(sa.Column("node_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_user_core_accounts_node_id_nodes", "nodes", ["node_id"], ["id"], ondelete="SET NULL")
            batch.create_index("ix_user_core_accounts_node_id", ["node_id"])

    if "pending_node_registrations" not in _tables(bind):
        op.create_table(
            "pending_node_registrations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("node_id", sa.Integer(), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("node_id", name="uq_pending_node_registration_node"),
            sa.UniqueConstraint("token_hash", name="uq_pending_node_registration_token"),
        )
        op.create_index("ix_pending_node_registrations_node_id", "pending_node_registrations", ["node_id"], unique=True)
        op.create_index("ix_pending_node_registrations_token_hash", "pending_node_registrations", ["token_hash"], unique=True)
        op.create_index("ix_pending_node_registrations_status", "pending_node_registrations", ["status"])
        op.create_index("ix_pending_node_registrations_expires_at", "pending_node_registrations", ["expires_at"])


def downgrade() -> None:
    bind = op.get_bind()
    if "pending_node_registrations" in _tables(bind):
        op.drop_table("pending_node_registrations")

    if "node_id" in _columns(bind, "user_core_accounts"):
        with op.batch_alter_table("user_core_accounts") as batch:
            batch.drop_index("ix_user_core_accounts_node_id")
            batch.drop_constraint("fk_user_core_accounts_node_id_nodes", type_="foreignkey")
            batch.drop_column("node_id")

    if "node_id" in _columns(bind, "users"):
        with op.batch_alter_table("users") as batch:
            batch.drop_index("ix_users_node_id")
            batch.drop_constraint("fk_users_node_id_nodes", type_="foreignkey")
            batch.drop_column("node_id")
