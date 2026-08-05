"""core_hosts.extras — preserve marzban-era per-host attributes on migration.

Revision ID: 0003_core_host_extras
Revises: 0002_legacy_schema
Create Date: 2026-08-05

0001 creates the column automatically for fresh databases (the table is
materialized from the current metadata). This revision upgrades databases
created BEFORE the column existed, and backfills existing rows to ``{}``.

The column is nullable at the schema level (portable across sqlite /
MySQL / PostgreSQL *without* a server-side JSON default — MySQL rejects
plain string defaults on JSON columns); application code always writes a
dict (model-level ``default=dict``), and the backfill makes the data
uniform.
"""
from __future__ import annotations

from alembic import op

revision = "0003_core_host_extras"
down_revision = "0002_legacy_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    import sqlalchemy as sa
    from sqlalchemy.engine.reflection import Inspector

    conn = op.get_bind()
    columns = {c["name"] for c in Inspector.from_engine(conn).get_columns("core_hosts")}
    if "extras" not in columns:
        op.add_column("core_hosts", sa.Column("extras", sa.JSON(), nullable=True))
    op.execute(sa.text("UPDATE core_hosts SET extras = '{}' WHERE extras IS NULL"))


def downgrade() -> None:
    # dropping migrated data (host attributes) on downgrade would be a
    # silent data-loss foot-gun; keep the column, matching 0002's policy.
    pass
