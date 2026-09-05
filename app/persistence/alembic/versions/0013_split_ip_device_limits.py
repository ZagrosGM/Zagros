"""split online IP limits from subscription device enrollment.

Revision ID: 0013_split_ip_device_limits
Revises: 0012_zagros_node_management
Create Date: 2026-09-05

The former ``device_limit`` was an online source-IP cap.  v1.0.4 gives that
policy its accurate name (``ip_limit``), then reuses ``device_limit`` only for
stable subscription identifiers.  Existing values therefore move to
``ip_limit`` and ``device_limit`` is cleared exactly as promised to operators.

Both the platform bind and a separate legacy bind are upgraded because Zagros
supports deployments where ZAGROS_DATABASE_URL and SQLALCHEMY_DATABASE_URL do
not point at the same database.
"""
from __future__ import annotations

import os
import time

from alembic import op

revision = "0013_split_ip_device_limits"
down_revision = "0012_zagros_node_management"
branch_labels = None
depends_on = None


def _upgrade_users(conn) -> None:
    import sqlalchemy as sa

    inspector = sa.inspect(conn)
    if "users" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("users")}
    if "ip_limit" not in columns:
        conn.execute(sa.text("ALTER TABLE users ADD COLUMN ip_limit INTEGER"))
    # Preserve a pre-existing ip_limit if an interrupted/replayed migration
    # already populated it. Only positive old values represented a real cap.
    conn.execute(sa.text(
        "UPDATE users SET ip_limit = device_limit "
        "WHERE (ip_limit IS NULL OR ip_limit = 0) AND device_limit > 0"
    ))
    conn.execute(sa.text("UPDATE users SET device_limit = NULL"))
    if "device_limit_disabled" in columns:
        # Undo only statuses provably created by the retired limiter. Manual,
        # quota and expiry disables have different flags/statuses and remain.
        conditions = ["device_limit_disabled = 1", "status = 'limited'"]
        if {"data_limit", "used_traffic"}.issubset(columns):
            conditions.append("(data_limit IS NULL OR used_traffic < data_limit)")
        if "expire" in columns:
            conditions.append("(expire IS NULL OR expire > :now_epoch)")
        conn.execute(sa.text(
            "UPDATE users SET status = 'active' WHERE " + " AND ".join(conditions)
        ), {"now_epoch": int(time.time())})
        conn.execute(sa.text("UPDATE users SET device_limit_disabled = 0"))


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or "sqlite:///db.sqlite3"


def upgrade() -> None:
    import sqlalchemy as sa

    current = op.get_bind()
    _upgrade_users(current)

    # A distinct legacy store is legal. Running this against the same sqlite
    # file is harmless: the schema/value guards make the second pass a no-op.
    legacy_url = sa.engine.make_url(_legacy_url())
    current_url = current.engine.url
    if legacy_url != current_url:
        legacy = sa.create_engine(legacy_url)
        try:
            with legacy.begin() as conn:
                _upgrade_users(conn)
        finally:
            legacy.dispose()

    inspector = sa.inspect(current)
    tables = set(inspector.get_table_names())
    if "subscription_devices" not in tables:
        op.create_table(
            "subscription_devices",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("device_hash", sa.String(length=64), nullable=False),
            sa.Column("device_hint", sa.String(length=24), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("user_agent", sa.String(length=512), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("user_id", "device_hash", name="uq_subscription_device"),
        )
        op.create_index("ix_subscription_devices_user", "subscription_devices", ["user_id"])

    if "ip_bans" not in tables:
        op.create_table(
            "ip_bans",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("ip", sa.String(length=45), nullable=False),
            sa.Column("banned_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reason", sa.String(length=128), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )
        op.create_index("ix_ip_bans_active_expiry", "ip_bans", ["active", "expires_at"])
        op.create_index("ix_ip_bans_user", "ip_bans", ["user_id"])


def downgrade() -> None:
    # Deliberately no destructive downgrade: copying ip_limit back would
    # overwrite real HWID limits created after this migration, and dropping
    # enrollment/ban history would silently weaken access control.
    pass
