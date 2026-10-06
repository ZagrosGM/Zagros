"""f-panel-9 — an expired user is reactivated by a future expire date alone.

The edit dialog echoes the user's current status back; 'expired'/'limited'
must be accepted (never a 422) and crud.update_user's expire/data-limit
re-evaluation must flip an expired user to active when the new expire is
in the future — over the real legacy schema.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


def _env_for(db_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
        "UVICORN_PORT": "8044",
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def db_session(tmp_path_factory):
    db = tmp_path_factory.mktemp("reactiv") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    # warm the real package so the legacy import chain resolves, then
    # create the legacy tables exactly like a real deployment has them.
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018

    from app.db.base import Base, SessionLocal, engine

    Base.metadata.create_all(engine)
    session = SessionLocal()
    yield session
    session.close()


def _expired_user(session, username: str):
    from app.db.models import User

    row = User(username=username, status="expired",
               expire=int(time.time()) - 3600)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


class TestExpiredReactivation:
    def test_future_expire_alone_reactivates(self, db_session):
        from app.db.crud import update_user
        from app.models.user import UserModify

        row = _expired_user(db_session, "reactiv-future")
        modify = UserModify(status="expired",
                            expire=int(time.time()) + 30 * 86400)
        updated = update_user(db_session, row, modify)
        assert updated.status.value == "active"

    def test_read_back_status_without_change_stays_expired(self, db_session):
        from app.db.crud import update_user
        from app.db.models import User
        from app.models.user import UserModify

        row = _expired_user(db_session, "reactiv-stay")
        past = int(time.time()) - 60
        modify = UserModify(status="expired", expire=past)
        updated = update_user(db_session, row, modify)
        assert updated.status.value == "expired"
        db_session.query(User).filter_by(username="reactiv-stay").delete()
        db_session.commit()

    def test_limited_read_back_accepted(self, db_session):
        from app.db.crud import update_user
        from app.db.models import User
        from app.models.user import UserModify, UserStatusModify

        assert UserStatusModify("limited").value == "limited"
        assert UserStatusModify("expired").value == "expired"
        row = _expired_user(db_session, "reactiv-lim")
        modify = UserModify(status="limited",
                            expire=int(time.time()) + 30 * 86400)
        updated = update_user(db_session, row, modify)
        # the expire path only re-evaluates active/expired; an explicit
        # 'limited' stays an explicit admin choice
        assert updated.status.value == "limited"
        db_session.query(User).filter_by(username="reactiv-lim").delete()
        db_session.commit()
