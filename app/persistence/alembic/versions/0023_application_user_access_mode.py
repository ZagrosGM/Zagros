"""Per-application user access mode (f-panel-7).

Revision ID: 0023_application_user_access_mode
Revises: 0022_admin_permissions

``applications.user_access_mode`` (VARCHAR(20) NOT NULL, default
``all_users``):

* ``all_users``  — every user with issued app credentials may enroll and
  sign in; the Bound-users list stays as bookkeeping/allowlist tooling
  but is NOT required for access. This is the DEFAULT, including for
  every application created before this column existed.
* ``bound_only`` — the historical behavior: only users with an ACTIVE
  grant may enroll/sign in; everyone else fails closed.

Server default backfills existing rows as ``all_users`` so upgrading
operators get the friendlier default without any manual step; switching
an application to ``bound_only`` is one explicit admin action.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_application_user_access_mode"
down_revision = "0022_admin_permissions"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {str(col["name"])
            for col in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if "applications" in _tables():
        if "user_access_mode" not in _columns("applications"):
            op.add_column("applications", sa.Column(
                "user_access_mode", sa.String(length=20), nullable=False,
                server_default="all_users"))


def downgrade() -> None:
    if "applications" in _tables() and "user_access_mode" in _columns("applications"):
        op.drop_column("applications", "user_access_mode")
