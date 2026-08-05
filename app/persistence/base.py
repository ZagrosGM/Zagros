"""SQLAlchemy foundation for Zagros persistence.

* Declarative base shared by all models.
* :class:`UtcDateTime` — a DateTime that guarantees timezone-aware UTC
  datetimes in Python even on databases (SQLite) that discard tzinfo.
* :func:`create_session_factory` — one place that owns engine options.

The layer is intentionally **synchronous SQLAlchemy** executed via
``asyncio.to_thread`` in the repository adapters: it works with every
DB-API driver without extra async dependencies and the panel's write volume
(user CRUD + telemetry batches) never justifies an async engine.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import DateTime, TypeDecorator


class Base(DeclarativeBase):
    pass


class UtcDateTime(TypeDecorator):
    """DateTime stored naive-UTC, always returned tz-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("UtcDateTime refuses naive datetimes (use timezone.utc)")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc)
        return value.replace(tzinfo=timezone.utc)


def create_session_factory(
    url: str,
    *,
    pool_size: int = 10,
    max_overflow: int = 30,
    echo: bool = False,
) -> sessionmaker:
    """Build an engine + session factory for the given SQLAlchemy URL.

    SQLite gets WAL mode + foreign keys ON (they are OFF by default!) —
    both are required for the schema's referential integrity to mean
    anything.
    """
    connect_args: dict = {}
    engine_kwargs: dict = {"echo": echo, "future": True}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if ":memory:" not in url:
            engine_kwargs.update({"pool_size": pool_size, "max_overflow": max_overflow})
    else:
        engine_kwargs.update({"pool_size": pool_size, "max_overflow": max_overflow})
    engine = create_engine(url, connect_args=connect_args, **engine_kwargs)

    if engine.url.get_backend_name() == "sqlite":
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_schema(engine_or_factory) -> None:
    """Create all tables (used by tests & first boot; Alembic owns upgrades)."""
    engine: Engine = (
        engine_or_factory.kw["bind"] if isinstance(engine_or_factory, sessionmaker)
        else engine_or_factory
    )
    import app.persistence.models  # noqa: F401 — register all models

    Base.metadata.create_all(engine)
