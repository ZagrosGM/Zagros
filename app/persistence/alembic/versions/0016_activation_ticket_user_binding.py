"""Bind activation tickets to the intended user and Application grant.

Revision ID: 0016_activation_ticket_binding
Revises: 0015_application_identity
Create Date: 2026-09-06

Foundation-era rows remain representable with both binding columns NULL but
are rejected by the Phase 3 authentication service. Every newly issued ticket
has both bindings. This is additive and preserves any existing hashed ticket
history.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_activation_ticket_binding"
down_revision = "0015_application_identity"
branch_labels = None
depends_on = None

_TABLE = "application_activation_tickets"


def _inspector():
    return sa.inspect(op.get_bind())


def _columns() -> set[str]:
    return {column["name"] for column in _inspector().get_columns(_TABLE)}


def _has_fk(local_column: str, remote_table: str) -> bool:
    return any(
        tuple(fk.get("constrained_columns") or ()) == (local_column,)
        and fk.get("referred_table") == remote_table
        for fk in _inspector().get_foreign_keys(_TABLE)
    )


def upgrade() -> None:
    if _TABLE not in set(_inspector().get_table_names()):
        return
    columns = _columns()
    missing = []
    if "user_id" not in columns:
        missing.append(sa.Column("user_id", sa.Integer(), nullable=True))
    if "application_user_grant_id" not in columns:
        missing.append(sa.Column(
            "application_user_grant_id", sa.Integer(), nullable=True))
    if missing:
        with op.batch_alter_table(_TABLE) as batch:
            for column in missing:
                batch.add_column(column)

    unique_checks = {
        check.get("name") for check in _inspector().get_check_constraints(_TABLE)
    }
    index_names = {
        index.get("name") for index in _inspector().get_indexes(_TABLE)
    }
    need_user_fk = not _has_fk("user_id", "users")
    need_grant_fk = not _has_fk(
        "application_user_grant_id", "application_user_grants")
    need_check = "ck_application_activation_user_binding" not in unique_checks
    if need_user_fk or need_grant_fk or need_check:
        with op.batch_alter_table(_TABLE) as batch:
            if need_user_fk:
                batch.create_foreign_key(
                    "fk_application_activation_user", "users",
                    ["user_id"], ["id"], ondelete="CASCADE")
            if need_grant_fk:
                batch.create_foreign_key(
                    "fk_application_activation_grant", "application_user_grants",
                    ["application_user_grant_id"], ["id"], ondelete="CASCADE")
            if need_check:
                batch.create_check_constraint(
                    "ck_application_activation_user_binding",
                    "(user_id IS NULL AND application_user_grant_id IS NULL) OR "
                    "(user_id IS NOT NULL AND application_user_grant_id IS NOT NULL)")
    if "ix_application_activation_user" not in index_names:
        op.create_index(
            "ix_application_activation_user", _TABLE,
            ["application_id", "user_id"])


def downgrade() -> None:
    # Non-destructive for the same reason as 0015: dropping user/grant binding
    # would turn scoped tickets into ambiguous Application-wide credentials.
    pass
