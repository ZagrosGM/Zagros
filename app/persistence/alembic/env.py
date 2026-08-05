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


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
