"""f-xrayclear-1 — removing every Xray protocol from a user must stick.

The edit dialog used to skip the `proxies` key when the admin unchecked the
last protocol, and the API could not even express the removal: `{}` meant
"no change" everywhere. Now omitted = no change, explicit {} = remove all,
over the real legacy schema.
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
        "UVICORN_PORT": "8046",
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
    db = tmp_path_factory.mktemp("xrayclear") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)
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


def _user_with_proxies(session, username: str):
    from app.db.models import Proxy, User

    row = User(username=username, status="active",
               expire=int(time.time()) + 30 * 86400)
    row.proxies.append(Proxy(type="vmess", settings={"id": "35e4e39c-7d5c-4f4b-8b71-558e4f37ff53"}))
    row.proxies.append(Proxy(type="vless", settings={}))
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def _proxy_types(user) -> set[str]:
    values = {getattr(p.type, "value", p.type) for p in user.proxies}
    return {str(v).lower() for v in values}


class TestProxyClear:
    def test_omitted_proxies_keep_current_protocols(self, db_session):
        from app.db.crud import update_user
        from app.models.user import UserModify

        row = _user_with_proxies(db_session, "xclear-omit")
        before = _proxy_types(row)
        updated = update_user(db_session, row, UserModify(note="touched"))
        assert _proxy_types(updated) == before == {"vmess", "vless"}
        db_session.query(type(row)).filter_by(username="xclear-omit").delete()
        db_session.commit()

    def test_explicit_empty_mapping_removes_every_protocol(self, db_session):
        from app.db.crud import update_user
        from app.models.user import UserModify

        row = _user_with_proxies(db_session, "xclear-all")
        updated = update_user(db_session, row, UserModify(proxies={}))
        db_session.expire(updated)
        assert _proxy_types(updated) == set(), \
            "explicit {} must remove every protocol (f-xrayclear-1)"
        db_session.query(type(row)).filter_by(username="xclear-all").delete()
        db_session.commit()

    def test_partial_mapping_replaces_protocols(self, db_session):
        from app.db.crud import update_user
        from app.models.user import UserModify

        row = _user_with_proxies(db_session, "xclear-partial")
        updated = update_user(db_session, row, UserModify(proxies={"vmess": {}}))
        db_session.expire(updated)
        assert _proxy_types(updated) == {"vmess"}
        db_session.query(type(row)).filter_by(username="xclear-partial").delete()
        db_session.commit()
