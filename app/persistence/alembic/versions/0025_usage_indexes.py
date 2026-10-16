"""Drop redundant single-column usage_records indexes (f-usageretain-1).

Revision ID: 0025_usage_indexes
Revises: 0024_config_grant_inbound_tag

The hottest insert table carried two indexes that are strict prefixes of
existing composite indexes:

* ``ix_usage_records_user_id``  ⊂ ``ix_usage_owner_time (user_id, recorded_at)``
* ``ix_usage_records_core_id``  ⊂ ``ix_usage_core_time (core_id, recorded_at)``

Every real query filters or groups along time as well, so the composites
serve them; the single-column indexes only added write cost and disk on
every 30-second sweep.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_usage_indexes"
down_revision = "0024_config_grant_inbound_tag"
branch_labels = None
depends_on = None

_REDUNDANT = ("ix_usage_records_user_id", "ix_usage_records_core_id")


def upgrade() -> None:
    existing = {ix["name"] for ix in sa.inspect(op.get_bind())
                .get_indexes("usage_records")}
    for index_name in _REDUNDANT:
        if index_name in existing:
            op.drop_index(index_name, table_name="usage_records")


def downgrade() -> None:
    op.create_index("ix_usage_records_user_id", "usage_records", ["user_id"])
    op.create_index("ix_usage_records_core_id", "usage_records", ["core_id"])
