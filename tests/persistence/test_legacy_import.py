"""An import has to land where the panel actually keeps users.

The bug this file exists for: a Marzban restore reported ``users_migrated:
338`` and the operator's user list did not change. Both were true — the rows
went into the platform database, while ``/api/users`` (and everything the UI
does with a user: edit it, hand out its subscription, build its config) reads
the **legacy** store. A migration that only writes half the pair produces a
user nobody can manage: a success that yields nothing.

Nothing here may import ``app.db`` at module scope. Its engine is a
process-wide singleton built from ``SQLALCHEMY_DATABASE_URL`` at import time,
and importing it here would freeze that engine on our path before suites that
configure their own database get a chance — which broke 37 of their tests.
These tests therefore build a private engine at fixture time.
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
def panel_db(tmp_path):
    """A private legacy store, leaving every other suite's database alone.

    ``app.db`` builds ONE engine, from ``SQLALCHEMY_DATABASE_URL``, the first
    time it is imported — and nothing can rebind it afterwards. Importing it
    here therefore has to leave no trace: the modules are evicted again on the
    way out so whichever suite configures the environment next still gets to
    build its own engine. (Without this, 37 tests in
    ``tests/platform/test_admin_api.py`` lost their schema.)
    """
    def _ours(name):
        return name == "config" or name == "app" or name.startswith("app.")

    # ``config`` reads SQLALCHEMY_DATABASE_URL once, at import time: evicting
    # only app.* would rebuild the engine from the *old* URL.
    saved = {name: mod for name, mod in sys.modules.items() if _ours(name)}
    os.environ.setdefault("SQLALCHEMY_DATABASE_URL",
                          f"sqlite:///{tempfile.mkdtemp(prefix='zagros-legacy-')}/panel.db")
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from app.db.base import Base
        import app.db.models  # noqa: F401  - registers the legacy tables
        from app.persistence.legacy_import import import_users, protocol_supported

        engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        yield factory, import_users, protocol_supported
        engine.dispose()
    finally:
        for name in [n for n in sys.modules if _ours(n)]:
            if name not in saved:
                del sys.modules[name]
        sys.modules.update(saved)


def _snapshot(users, proxies=()):
    from app.persistence.legacy_reader import LegacySnapshot

    snap = LegacySnapshot()
    snap.users = list(users)
    snap.proxies = list(proxies)
    return snap


def _user(**overrides):
    base = {"id": 1, "username": "someone", "status": "active", "data_limit": None,
            "used_traffic": 0, "expire": None, "note": "", "device_limit": None,
            "data_limit_reset_strategy": "no_reset"}
    base.update(overrides)
    return base


def test_users_become_panel_users_with_their_data(panel_db):
    panel_db, import_users, _ = panel_db
    """The report said 338 imported; the user list must actually show them."""
    snap = _snapshot(
        [_user(username="abbas", data_limit=53687091200, used_traffic=34294574339,
               device_limit=3, note="from marzban")],
        [{"id": 1, "user_id": 1, "type": "vless", "settings": {"id": "uuid-1"}},
         {"id": 2, "user_id": 1, "type": "vmess", "settings": {"id": "uuid-2"}}],
    )
    report = import_users(snap, panel_db)

    assert report["created"] == 1
    assert report["proxies_created"] == 2
    with panel_db() as session:
        from app.db.models import User

        user = session.query(User).filter(User.username == "abbas").one()
        assert user.data_limit == 53687091200          # 50 GiB survived
        assert user.used_traffic == 34294574339        # so did the usage
        assert user.device_limit == 3
        assert {p.type.value for p in user.proxies} == {"vless", "vmess"}


def test_importing_twice_does_not_duplicate(panel_db):
    panel_db, import_users, _ = panel_db
    snap = _snapshot([_user(username="behnam")])
    assert import_users(snap, panel_db)["created"] == 1
    second = import_users(snap, panel_db)
    assert second["created"] == 0
    assert second["skipped_existing"] == 1
    with panel_db() as session:
        from app.db.models import User

        assert session.query(User).count() == 1


def test_a_protocol_we_cannot_store_is_reported_not_swallowed(panel_db):
    panel_db, import_users, protocol_supported = panel_db
    """The panel stores vmess/vless/trojan/shadowsocks. Anything else must be
    named in the report, or the operator is left guessing."""
    assert protocol_supported("vless")
    assert not protocol_supported("hysteria2")

    snap = _snapshot(
        [_user(username="modern")],
        [{"id": 1, "user_id": 1, "type": "hysteria2", "settings": {"password": "x"}}],
    )
    report = import_users(snap, panel_db)
    # the user still arrives — just without a proxy we cannot represent
    assert report["created"] == 1
    assert report["proxies_created"] == 0
    assert report["proxies_unsupported"] == 1
    assert "hysteria2" in report["unsupported_protocols"]
    assert any("hysteria2" in w for w in report["warnings"])


def test_dry_run_writes_nothing(panel_db):
    panel_db, import_users, _ = panel_db
    snap = _snapshot([_user(username="preview")],
                     [{"id": 1, "user_id": 1, "type": "vless", "settings": {}}])
    report = import_users(snap, panel_db, dry_run=True)
    assert report["created"] == 1
    with panel_db() as session:
        from app.db.models import Proxy, User

        assert session.query(User).count() == 0
        assert session.query(Proxy).count() == 0
