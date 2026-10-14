"""Alembic environment for the Zagros schema.

URL resolution order:
1. ``ZAGROS_DATABASE_URL`` env var (recommended),
2. legacy ``SQLALCHEMY_DATABASE_URL`` env var (upgrade path),
3. ``sqlalchemy.url`` from alembic.ini.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Load the panel's .env BEFORE any os.environ lookups below: alembic runs
# as its own process (e.g. `alembic upgrade head` at container boot) and
# compose only MOUNTS the file, it is not injected into the environment.
from app.env_loader import load_zagros_env  # noqa: E402

load_zagros_env()

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

url = (
    os.environ.get("ZAGROS_DATABASE_URL")
    or os.environ.get("SQLALCHEMY_DATABASE_URL")
    or config.get_main_option("sqlalchemy.url")
)
if url:
    config.set_main_option("sqlalchemy.url", url)

from app.persistence.base import Base  # noqa: E402
import app.persistence.models  # noqa: E402,F401 — register all models

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _ensure_wide_revision_column(connection) -> None:
    """f-panel-9: keep ``alembic_version.version_num`` at VARCHAR(255).

    Alembic creates the table with VARCHAR(32); several released revision
    IDs are longer, and MySQL/MariaDB/PostgreSQL enforce the length (SQLite
    ignores it), so upgrades died with "Data too long for column
    'version_num'". Widening here covers fresh installs (the table is
    pre-created wide) and upgraded installs (an existing narrow column is
    altered before any migration runs).

    f-release-fix: NEVER touch the connection on sqlite — the reflection
    opened by inspecting ``alembic_version`` left alembic's own version
    stamp and in-transaction backfills uncommitted on re-upgrades (the
    v1.1.1 release gate caught real databases migrating without a stamped
    version). sqlite ignores lengths, so there is nothing to do there.
    """
    if connection.dialect.name == "sqlite":
        return
    import sqlalchemy as sa

    def _commit():
        if not connection.in_transaction():
            return
        try:
            connection.commit()
        except Exception:  # noqa: BLE001 — sqlite driver differences
            pass

    inspector = sa.inspect(connection)
    if "alembic_version" not in inspector.get_table_names():
        connection.execute(sa.text(
            "CREATE TABLE alembic_version ("
            "version_num VARCHAR(255) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
        _commit()
        return
    column = next((c for c in inspector.get_columns("alembic_version")
                   if c["name"] == "version_num"), None)
    length = getattr((column or {}).get("type"), "length", None) or 0
    if not length or length >= 255:
        return
    dialect = connection.dialect.name
    if dialect == "postgresql":
        connection.execute(sa.text(
            "ALTER TABLE alembic_version ALTER COLUMN version_num "
            "TYPE VARCHAR(255)"))
        _commit()
    elif dialect in ("mysql", "mariadb"):
        connection.execute(sa.text(
            "ALTER TABLE alembic_version MODIFY version_num "
            "VARCHAR(255) NOT NULL"))
        _commit()
    # sqlite ignores lengths — nothing to do.


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        _ensure_wide_revision_column(connection)
        context.configure(connection=connection, target_metadata=target_metadata,
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
