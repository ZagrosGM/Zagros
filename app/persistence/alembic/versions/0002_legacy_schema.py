"""Legacy stack schema (admins, nodes, legacy users, ...) — separate engine.

Revision ID: 0002_legacy_schema
Revises: 0001_zagros_initial
Create Date: 2026-08-05

The Zagros platform keeps **two database schemas by design**:

* **P3** (``app.persistence``) — the multi-core platform schema, bound to
  ``ZAGROS_DATABASE_URL`` (what Alembic migrations act on).
* **legacy** (``app.db`` — admin accounts, legacy users/nodes for the
  retained upstream API surface, ``zagros-cli`` and ``hostctl`` management
  commands), bound to ``SQLALCHEMY_DATABASE_URL``.

Splitting is mandatory: the two stacks historically reuse table names
(``admins``, ``users``, ``nodes``) with **different column layouts**, so
co-locating them in one database corrupts both. ``.env.example`` therefore
points the two URLs at different files, and the installers do the same.

This revision materializes the legacy metadata **on the legacy engine**,
idempotently (``checkfirst=True``). It deliberately uses a separate,
short-lived connection rather than Alembic's P3 bind: the version stamp
stays on the P3 database while the legacy schema is provisioned on its own
database. Creating idempotent tables best-effort keeps replays safe.

Downgrade intentionally keeps the legacy tables: dropping admin/user data
on a downgrade would be an irreversible data-loss foot-gun.
"""
from __future__ import annotations

import os

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0002_legacy_schema"
down_revision = "0001_zagros_initial"
branch_labels = None
depends_on = None

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py


def _legacy_url() -> str:
    return os.environ.get("SQLALCHEMY_DATABASE_URL") or _LEGACY_URL_FALLBACK


def _legacy_metadata():
    # Import order matters for the legacy tree: the application object must
    # exist first (see app/__init__ lazy build), otherwise `app.db.models`
    # hits the upstream circular import surface.
    import app as _app_warm  # noqa: F401

    getattr(_app_warm, "app")

    import app.db.models  # noqa: F401 — register all legacy models
    from app.db.base import Base as LegacyBase

    return LegacyBase.metadata


def _seed_singletons(engine) -> None:
    """Replicate the upstream migrations' REQUIRED seed rows for a fresh
    legacy schema (verified against app/db/migrations/versions/):

    * ``system``  (id=1, uplink=0, downlink=0)      — 3cf36a5fde73
    * ``tls``     (id=1, self-signed key/cert)      — 7a0dbb8a2f65
    * ``jwt``     (id=1, random 64-hex secret_key)  — 9d5a518ae432

    Without these singleton rows the legacy API fails at runtime
    (``db.query(JWT).first().secret_key`` → ``AttributeError`` on None, and
    likewise for ``System``/``TLS``). The (older) ``proxies`` upstream
    migration only migrated *existing* user data, so a fresh schema needs
    no row there. Idempotent by design: existing rows are never touched
    (never rotate keys, never overwrite certificates).
    """
    import secrets

    from sqlalchemy import MetaData, Table, func, select

    from app.utils.crypto import generate_certificate

    metadata = MetaData()
    with engine.begin() as conn:
        if engine.dialect.has_table(conn, "system"):
            system = Table("system", metadata, autoload_with=conn)
            if conn.execute(select(func.count()).select_from(system)).scalar() == 0:
                conn.execute(system.insert().values(id=1, uplink=0, downlink=0))
        if engine.dialect.has_table(conn, "tls"):
            tls_table = Table("tls", metadata, autoload_with=conn)
            if conn.execute(select(func.count()).select_from(tls_table)).scalar() == 0:
                tls = generate_certificate()
                conn.execute(tls_table.insert().values(
                    id=1, key=tls["key"], certificate=tls["cert"]))
        if engine.dialect.has_table(conn, "jwt"):
            jwt_table = Table("jwt", metadata, autoload_with=conn)
            if conn.execute(select(func.count()).select_from(jwt_table)).scalar() == 0:
                conn.execute(jwt_table.insert().values(
                    id=1, secret_key=secrets.token_hex(32)))


def upgrade() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_legacy_url())
    try:
        _legacy_metadata().create_all(bind=engine, checkfirst=True)
        _seed_singletons(engine)
    finally:
        engine.dispose()


def downgrade() -> None:  # noqa: D103 — data-safety: never drop legacy data
    pass
