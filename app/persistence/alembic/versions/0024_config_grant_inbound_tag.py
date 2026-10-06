"""Per-inbound Application config items (f-appinbounds-2).

Revision ID: 0024_config_grant_inbound_tag
Revises: 0023_application_user_access_mode

``application_config_grants.inbound_tag`` (VARCHAR(64) NULL): when a core
exposes several inbounds for the same protocol, GET /configs now returns
one item per inbound (display name suffixed with the listener tag) and
each item carries its own grant. The tag travels into the lease account
settings at delivery time, so the sealed envelope is built for exactly
that listener instead of always the first usable one. NULL preserves the
historical behavior for rows created before this column and for cores
that do not expose per-inbound items.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024_config_grant_inbound_tag"
down_revision = "0023_application_user_access_mode"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {str(col["name"])
            for col in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if "application_config_grants" in _tables():
        if "inbound_tag" not in _columns("application_config_grants"):
            op.add_column("application_config_grants", sa.Column(
                "inbound_tag", sa.String(length=64), nullable=True))


def downgrade() -> None:
    if ("application_config_grants" in _tables()
            and "inbound_tag" in _columns("application_config_grants")):
        op.drop_column("application_config_grants", "inbound_tag")
