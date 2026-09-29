import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import (
    SQLALCHEMY_DATABASE_URL,
    SQLALCHEMY_POOL_SIZE,
    SQLIALCHEMY_MAX_OVERFLOW,
)

# f-dbmerge: once the one-time legacy merge has run, the legacy engine
# serves the MAIN database (the durable decision lives in a marker row of
# the main database). Until that marker exists — fresh panels, or an
# operator who never merged — the configured URL is used unchanged.
def _marker_present(main_url: str) -> bool:
    engine = None
    try:
        engine = create_engine(main_url)
        with engine.connect() as conn:
            for expr in ("`key`", '"key"'):
                try:
                    row = conn.execute(text(
                        "SELECT value_json FROM settings "
                        f"WHERE {expr} = 'dbmerge'")).scalar()
                    return row is not None
                except Exception:  # noqa: BLE001 — next quoting style
                    continue
    except Exception:  # noqa: BLE001 — unreachable DB: stay configured
        return False
    finally:
        if engine is not None:
            engine.dispose()
    return False


_CONFIGURED_LEGACY_URL = SQLALCHEMY_DATABASE_URL


def _effective_legacy_url() -> str:
    configured = _CONFIGURED_LEGACY_URL
    main_url = os.environ.get("ZAGROS_DATABASE_URL") or ""
    if not main_url or not configured or main_url == configured:
        return configured
    return main_url if _marker_present(main_url) else configured


SQLALCHEMY_DATABASE_URL = _effective_legacy_url()


_RENAMES_DECIDED: bool | None = None


def legacy_table_name(base: str) -> str:
    """f-dbmerge: after the one-time merge the four tables that collide
    with the platform layer live under ``legacy_*`` names in the MAIN
    database; before the merge they keep their original names in the
    legacy database, so an un-merged panel behaves exactly like the
    previous version."""
    global _RENAMES_DECIDED
    if base not in ("users", "admins", "nodes", "next_plans"):
        return base
    if _RENAMES_DECIDED is None:
        if os.environ.get("ZAGROS_FORCE_LEGACY_RENAMES") == "1":
            _RENAMES_DECIDED = True
        else:
            main_url = os.environ.get("ZAGROS_DATABASE_URL") or ""
            _RENAMES_DECIDED = bool(
                main_url
                and main_url != _CONFIGURED_LEGACY_URL
                and _marker_present(main_url)
            )
    return f"legacy_{base}" if _RENAMES_DECIDED else base

IS_SQLITE = SQLALCHEMY_DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_size=SQLALCHEMY_POOL_SIZE,
        max_overflow=SQLIALCHEMY_MAX_OVERFLOW,
        pool_recycle=3600,
        pool_timeout=10
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass
