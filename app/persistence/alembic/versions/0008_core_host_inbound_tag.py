"""core_hosts.inbound_tag — promote migrated hosts to live host-settings entries.

Revision ID: 0008_core_host_inbound_tag
Revises: 0007_core_consolidation
Create Date: 2026-08-08

The Host Settings engine keys admin host entries by
``(core_id, inbound_tag)``. ``core_hosts`` (0001) carried no inbound tag —
marzban-era rows stashed it inside the ``extras`` JSON blob (0003), which
is fine for archival but wrong for a live query key. This revision:

1. adds a real, indexed ``inbound_tag`` column and backfills it from
   ``extras`` so hosts preserved from an upgraded Marzban install become
   live entries once an admin assigns them to a core's inbound (an empty
   tag matches nothing — zero behavior change until then);
2. widens ``sni`` / ``host_header`` to 1000 chars — comma multi-value
   lists (MultipleHost/MultipleSNI) overflow the original 256 (the legacy
   ``hosts`` table grew the same way, e7b869e999b4). Idempotent: column
   guards make replay a no-op; the widen is dialect-conditional
   (sqlite accepts ALTER TYPE syntax but ignores widths, so it runs
   everywhere; engines rejecting it keep the old width and the engine
   keeps working — width is a safety rail, not a semantic).
"""
from __future__ import annotations

from alembic import op

revision = "0008_core_host_inbound_tag"
down_revision = "0007_core_consolidation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    import sqlalchemy as sa
    from sqlalchemy.engine.reflection import Inspector

    conn = op.get_bind()
    columns = {c["name"] for c in Inspector.from_engine(conn).get_columns("core_hosts")}
    if "inbound_tag" not in columns:
        op.add_column(
            "core_hosts",
            sa.Column("inbound_tag", sa.String(length=256), nullable=False,
                      server_default=""),
        )
    indexes = {ix["name"] for ix in Inspector.from_engine(conn).get_indexes("core_hosts")}
    if "ix_core_hosts_inbound_tag" not in indexes:
        op.create_index("ix_core_hosts_inbound_tag", "core_hosts",
                        ["core_id", "inbound_tag"])
    # widen multi-value columns (marzban hosts learned the same lesson at
    # e7b869e999b4); a dialect that refuses keeps the old width — inert.
    # f-panel-9: PostgreSQL aborts the WHOLE transaction when a statement
    # fails, so each best-effort statement is isolated in a SAVEPOINT —
    # a refusal now rolls back only that statement, not the migration.
    for col in ("sni", "host_header"):
        try:
            with conn.begin_nested():
                op.alter_column("core_hosts", col,
                                type_=sa.String(length=1000),
                                existing_type=sa.String(length=256))
        except Exception:  # noqa: BLE001
            pass
    # backfill from the marzban-era extras blob. json_extract exists on
    # SQLite/MySQL but NOT on PostgreSQL (there the native JSON ->> operator
    # applies); on engines with neither the tags stay '' (inert) instead of
    # guessing. The savepoint keeps any failure from aborting the migration.
    try:
        with conn.begin_nested():
            if conn.dialect.name == "postgresql":
                op.execute(sa.text(
                    "UPDATE core_hosts SET inbound_tag = "
                    "COALESCE(extras::json->>'inbound_tag', '') "
                    "WHERE (inbound_tag IS NULL OR inbound_tag = '') "
                    "AND extras IS NOT NULL"
                ))
            else:
                op.execute(sa.text(
                    "UPDATE core_hosts SET inbound_tag = "
                    "COALESCE(json_extract(extras, '$.inbound_tag'), '') "
                    "WHERE (inbound_tag IS NULL OR inbound_tag = '') AND extras IS NOT NULL"
                ))
    except Exception:  # noqa: BLE001 — non-JSON engine: tags stay '' (inert)
        pass


def downgrade() -> None:
    # dropping host entry keys on downgrade would orphan live host
    # settings; keep the column, matching 0002/0003's no-data-loss policy.
    pass
