"""Marker-aware URL/table resolution for legacy-engine migrations.

f-dbmerge-5 (v1.1.1 fresh-install crash): the boot pipeline runs dbmerge
BEFORE Alembic. On a fresh install dbmerge provisions the consolidated
single-database layout — legacy tables under ``legacy_*`` names inside the
MAIN database plus the ``dbmerge`` marker — after which the runtime legacy
engine (``app.db.base``) serves the MAIN database. These migrations used to
resolve their engine from the RAW ``SQLALCHEMY_DATABASE_URL`` instead, so
``0002`` (whose ``import app`` flips the models into rename mode) created
``legacy_admins`` in a brand-new legacy file while ``0004`` looked for plain
``admins`` → ``NoSuchTableError`` → every fresh install rolled back.

Every legacy-engine revision MUST resolve both the URL and the table names
through the same machinery the runtime uses:

* :func:`legacy_url` — what ``app.db.base`` actually serves (marker-aware);
* :func:`table` — ``legacy_<name>`` after the merge, plain name before it.

Both are safe on every layout: un-merged panels keep the raw URL and plain
names (pre-merge behaviour, byte-for-byte), merged panels target the main
database and the renamed tables.
"""
from __future__ import annotations

import os

_LEGACY_URL_FALLBACK = "sqlite:///db.sqlite3"  # identical to config.py


def _warm() -> None:
    """Build the application object so the merge marker machinery loads.

    ``app.db.base`` decides the rename/redirect state lazily from the
    marker row; that decision needs the package import side effects that
    the runtime (and 0002's ``_legacy_metadata``) already perform.
    """
    import app as _app  # noqa: F401

    getattr(_app, "app", None)


def legacy_url() -> str:
    """The legacy engine URL as the runtime legacy layer resolves it."""
    _warm()
    from app.db.base import SQLALCHEMY_DATABASE_URL as _effective

    return (_effective
            or os.environ.get("SQLALCHEMY_DATABASE_URL")
            or _LEGACY_URL_FALLBACK)


def table(base: str) -> str:
    """Legacy table name, honoring the post-merge ``legacy_*`` renames."""
    _warm()
    from app.db.base import legacy_table_name

    return legacy_table_name(base)
