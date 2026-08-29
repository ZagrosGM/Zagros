"""Zagros node management: bootstrap port, pairing state and host binding.

Revision ID: 0012_zagros_node_management
Revises: 0011_user_bandwidth_limits

The legacy Marzban Xray-only node transport is gone; a node is now the
standalone multi-core agent. This revision adds the columns the new flow
needs and is column-idempotent, so databases created by a later
``create_all`` (which already materialises current metadata) upgrade cleanly.

* ``api_port``                — read-only bootstrap/info port (default 62051)
* ``panel_id``                — identifier this panel presents when pairing
* ``registration_token_enc``  — sealed one-time token (cleared after pairing)
* ``registration_token_hash`` — its SHA-256, kept for auditing/rotation
* ``add_as_new_host``         — bind the node address as a Host on sync
* ``agent_version``           — agent version reported at registration
* ``last_error``              — why the node is red, not just *that* it is red
* ``created_at``              — audit trail for issued installer commands
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0012_zagros_node_management"
down_revision = "0011_user_bandwidth_limits"
branch_labels = None
depends_on = None

_COLUMNS = {
    "api_port": sa.Column("api_port", sa.Integer(), nullable=False,
                          server_default="62051"),
    "panel_id": sa.Column("panel_id", sa.String(128), nullable=True),
    "registration_token_enc": sa.Column("registration_token_enc", sa.Text(),
                                        nullable=True),
    "registration_token_hash": sa.Column("registration_token_hash",
                                         sa.String(128), nullable=True),
    "add_as_new_host": sa.Column("add_as_new_host", sa.Boolean(), nullable=False,
                                 server_default=sa.false()),
    "agent_version": sa.Column("agent_version", sa.String(32), nullable=True),
    "last_error": sa.Column("last_error", sa.String(1024), nullable=True),
    "created_at": sa.Column("created_at", sa.DateTime(), nullable=True),
}


def _existing() -> set[str]:
    return {column["name"]
            for column in sa.inspect(op.get_bind()).get_columns("nodes")}


def upgrade() -> None:
    existing = _existing()
    missing = [name for name in _COLUMNS if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("nodes") as batch:
        for name in missing:
            batch.add_column(_COLUMNS[name])


def downgrade() -> None:
    existing = _existing()
    present = [name for name in _COLUMNS if name in existing]
    if not present:
        return
    with op.batch_alter_table("nodes") as batch:
        for name in present:
            batch.drop_column(name)
