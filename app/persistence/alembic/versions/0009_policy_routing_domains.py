"""stable policy-routing domains and legacy rule priority backfill.

Revision ID: 0009_policy_routing_domains
Revises: 0008_core_host_inbound_tag
Create Date: 2026-08-13

The authoritative// outbounds/rules remain in the
settings KV rows.  This migration adds only derived stable Linux identities;
it never moves or deletes the old documents.  Downgrade can therefore drop
the table without losing user configuration.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision = "0009_policy_routing_domains"
down_revision = "0008_core_host_inbound_tag"
branch_labels = None
depends_on = None

_TABLE_MIN = 11000
_TABLE_SPAN = 18000


def _table_for(name: str, used: set[int]) -> int:
    candidate = _TABLE_MIN + int(hashlib.sha256(name.encode()).hexdigest()[:8], 16) % _TABLE_SPAN
    while candidate in used or candidate in (253, 254, 255):
        candidate += 1
        if candidate >= _TABLE_MIN + _TABLE_SPAN:
            candidate = _TABLE_MIN
    return candidate


def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    if "routing_domains" not in inspector.get_table_names():
        op.create_table(
            "routing_domains",
            sa.Column("outbound_name", sa.String(length=128), primary_key=True),
            sa.Column("table_id", sa.Integer(), nullable=False, unique=True),
            sa.Column("fwmark", sa.Integer(), nullable=False, unique=True),
            sa.Column("definition_hash", sa.String(length=64), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False,
                      server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_routing_domains_table_id", "routing_domains", ["table_id"], unique=True)
        op.create_index("ix_routing_domains_fwmark", "routing_domains", ["fwmark"], unique=True)

    settings = sa.table(
        "settings",
        sa.column("key", sa.String()),
        sa.column("value_json", sa.JSON()),
    )
    rows = dict(conn.execute(
        sa.select(settings.c.key, settings.c.value_json).where(
            settings.c.key.in_(["admin.outbounds.v1", "admin.routing.rules.v1"]))
    ).all())

    outbounds = rows.get("admin.outbounds.v1") or []
    domains = sa.table(
        "routing_domains",
        sa.column("outbound_name", sa.String()),
        sa.column("table_id", sa.Integer()),
        sa.column("fwmark", sa.Integer()),
        sa.column("definition_hash", sa.String()),
        sa.column("updated_at", sa.DateTime()),
    )
    existing = conn.execute(sa.select(domains.c.outbound_name, domains.c.table_id)).all()
    known = {str(name): int(table) for name, table in existing}
    used = set(known.values())
    for outbound in sorted(outbounds, key=lambda item: str(item.get("name") or "")):
        name = str(outbound.get("name") or "").strip()
        if not name or name in known:
            continue
        table_id = _table_for(name, used)
        used.add(table_id)
        fingerprint = hashlib.sha256(
            __import__("json").dumps(outbound, sort_keys=True,
                                     separators=(",", ":")).encode()
        ).hexdigest()
        conn.execute(domains.insert().values(
            outbound_name=name, table_id=table_id, fwmark=table_id,
            definition_hash=fingerprint,
            updated_at=datetime.now(timezone.utc),
        ))

    rules = rows.get("admin.routing.rules.v1") or []
    changed = False
    for index, rule in enumerate(rules):
        if "priority" not in rule:
            rule["priority"] = (index + 1) * 10
            changed = True
        if "enabled" not in rule:
            rule["enabled"] = True
            changed = True
    if changed:
        conn.execute(
            settings.update()
            .where(settings.c.key == "admin.routing.rules.v1")
            .values(value_json=rules)
        )


def downgrade() -> None:
    conn = op.get_bind()
    if "routing_domains" not in Inspector.from_engine(conn).get_table_names():
        return
    indexes = {item["name"] for item in Inspector.from_engine(conn).get_indexes("routing_domains")}
    for name in ("ix_routing_domains_table_id", "ix_routing_domains_fwmark"):
        if name in indexes:
            op.drop_index(name, table_name="routing_domains")
    op.drop_table("routing_domains")
