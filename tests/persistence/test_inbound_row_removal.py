"""Deleting a wizard-removed listener must never 500 on legacy association rows.

Bug: ``exclude_inbounds_association`` and ``template_inbounds_association``
declare plain FKs to ``inbounds(tag)`` without ON DELETE CASCADE. Deleting an
xray inbound that the 3x-ui restore had bound to a proxy (exclusion rows)
answered 500 on the live panel — pymysql 1451 on ``DELETE FROM inbounds``.
``crud.remove_inbound_row`` removes the association rows first, then the
inbound (Hosts go via delete-orphan). The suite engine here enables SQLite's
``PRAGMA foreign_keys`` so the ordering stays honestly pinned in CI instead
of being masked by SQLite's permissive default.

Run: pytest tests/persistence/test_inbound_row_removal.py -q
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def fk_db(tmp_path):
    """A private LEGACY store (app.db engine) with foreign keys enforced.

    Same isolation pattern as test_legacy_import.py: app.db builds ONE engine
    from SQLALCHEMY_DATABASE_URL at first import, so the modules are evicted
    again on the way out to leave other suites free to configure their own
    engine.
    """
    def _ours(name):
        return name == "config" or name == "app" or name.startswith("app.")

    saved = {name: mod for name, mod in sys.modules.items() if _ours(name)}
    os.environ.setdefault(
        "SQLALCHEMY_DATABASE_URL",
        f"sqlite:///{tempfile.mkdtemp(prefix='zagros-fk-')}/unused.db")
    try:
        from sqlalchemy import create_engine, event
        from sqlalchemy.orm import sessionmaker

        from app.db.base import Base
        import app.db.models  # noqa: F401  - registers the legacy tables

        engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}",
                               connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        Base.metadata.create_all(engine)
        factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        yield factory
        engine.dispose()
    finally:
        for name in [n for n in sys.modules if _ours(n)]:
            if name not in saved:
                del sys.modules[name]
        sys.modules.update(saved)


def _seed(factory):
    """User with an ss proxy excluded from ``in-1`` + a template on ``in-1``."""
    from app.db.models import Proxy, ProxyTypes, User, UserTemplate

    with factory() as db:
        from app.db import crud

        inb = crud.get_or_create_inbound(db, "in-1")
        proxy = Proxy(type=ProxyTypes.Shadowsocks,
                      settings={"password": "pw",
                                "method": "chacha20-ietf-poly1305"})
        proxy.excluded_inbounds.append(inb)
        user = User(username="alice")
        user.proxies.append(proxy)
        db.add(user)
        db.add(UserTemplate(name="tpl", inbounds=[inb]))
        db.commit()
    return inb


def test_remove_inbound_row_is_applied_and_associations_go_first(fk_db):
    """The deletion that used to 500 must succeed and leave NO dangling rows."""
    from sqlalchemy import select

    from app.db import crud
    from app.db.models import (
        ProxyInbound,
        excluded_inbounds_association,
        template_inbounds_association,
    )

    _seed(fk_db)
    with fk_db() as db:
        assert crud.remove_inbound_row(db, "in-1") is True

    with fk_db() as db:
        assert db.query(ProxyInbound).filter_by(tag="in-1").first() is None
        assert list(db.execute(select(excluded_inbounds_association)).all()) == []
        assert list(db.execute(select(template_inbounds_association)).all()) == []
        # the proxy and its owner survive — only the association was pruned
        from app.db.models import Proxy, UserTemplate

        proxy = db.query(Proxy).filter(Proxy.type == "shadowsocks").one()
        assert proxy.excluded_inbounds == []
        assert db.query(UserTemplate).filter_by(name="tpl").one().inbounds == []


def test_remove_inbound_row_ghost_tag_is_false_and_harmless(fk_db):
    from app.db import crud

    with fk_db() as db:
        assert crud.remove_inbound_row(db, "never-existed") is False
        assert crud.remove_inbound_row(db, "in-1") is False  # never seeded


def test_remove_inbound_row_twice_is_idempotent(fk_db):
    from app.db import crud

    _seed(fk_db)
    with fk_db() as db:
        assert crud.remove_inbound_row(db, "in-1") is True
        assert crud.remove_inbound_row(db, "in-1") is False
