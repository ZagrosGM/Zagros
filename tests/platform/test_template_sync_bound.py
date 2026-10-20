"""f-tplsync-1 (v1.1.3 bugfix 2) — syncing users created from a template.

Editing a template must be able to push the new specs (quota/expiry/core
grants) onto every user bound to it: ``POST /zagros/users/apply-template``
with ``bound_to_template`` re-applies the template to all rows carrying its
id, capped at 500 like the explicit-username batch.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _migrate(env):
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr


@pytest.fixture()
def runtime(tmp_path, monkeypatch):
    db = tmp_path / "platform.db"
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "tplsync-test-key-0123456789",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    for var in env:
        if var.startswith(("ZAGROS_", "SQLALCHEMY_")):
            monkeypatch.setenv(var, env[var])
    _migrate(env)
    from app.platform.runtime import PlatformRuntime
    rt = PlatformRuntime.from_env()
    rt.verify_schema()
    yield rt


class _FakeKV:
    async def get_value(self, key):
        return None

    async def set_value(self, key, value):
        return None


@pytest.fixture()
def admin_ctx():
    """The router guard normally publishes the caller; tests set the real
    contextvar inside the running loop's context (ContextVar.set, never
    attribute patching)."""
    from app.platform.routers import _current_admin

    class _Ctx:
        username = "sync_sudo_caller"
        is_sudo = True

    _current_admin.set(_Ctx())
    yield _Ctx


_SEED_SEQ = iter(range(1000))  # the legacy engine is a per-process
                               # singleton: every seed gets a fresh namespace


def _seed(runtime, *, bound: int = 2, extra_unbound: bool = True):
    tag = f"{next(_SEED_SEQ):03d}"
    from app.db import GetDB, crud
    from app.db.crud import create_user_template
    from app.db.models import User as LegacyUser
    from app.models.admin import AdminCreate
    from app.models.user import UserCreate
    from app.models.user_template import UserTemplateCreate

    with GetDB() as db:
        admin = crud.create_admin(db, AdminCreate(
            username=f"syncadmin_{tag}", password="x " * 6, is_sudo=True))
        tpl = create_user_template(db, UserTemplateCreate(
            name=f"sync-tpl-{tag}", data_limit=7 * 1024 ** 3,
            expire_duration=14 * 86400, inbounds={}))
        usernames = []
        for i in range(bound):
            name = f"sync_user_{tag}_{i}"
            u = crud.create_user(db, UserCreate(
                username=name, status="active", data_limit=999,
                expire=None, proxies={"vless": {}}, inbounds={}),
                admin=admin)
            u.template_id = tpl.id
            usernames.append(name)
        if extra_unbound:
            crud.create_user(db, UserCreate(
                username=f"sync_free_{tag}", status="active", data_limit=1,
                expire=None, proxies={"vless": {}}, inbounds={}),
                admin=admin)
        db.commit()
        return tpl.id, usernames, tag


def test_bound_to_template_syncs_only_bound_users(runtime, admin_ctx):
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from app.platform import admin_api
    from app.platform.admin_api import ApplyTemplateBody

    tpl_id, usernames, tag = _seed(runtime, bound=2)

    out = asyncio.run(admin_api.users_apply_template(
        ApplyTemplateBody(template_id=tpl_id, bound_to_template=True),
        runtime=runtime))

    assert out["ok"] is True
    assert sorted(out["applied"]) == sorted(usernames), (
        "every BOUND user is synced, in one pass")
    assert out["errors"] == []
    with GetDB() as db:
        rows = {u.username: u for u in db.query(LegacyUser).all()}
        for name in usernames:
            assert rows[name].data_limit == 7 * 1024 ** 3, "quota from template"
            assert rows[name].template_id == tpl_id
            assert rows[name].expire is not None, "expiry re-dated from template"
        # an unbound user is NOT touched by the template sync
        assert rows[f"sync_free_{tag}"].data_limit == 1
        assert rows[f"sync_free_{tag}"].template_id is None


def test_explicit_batch_survives_a_missing_user(runtime, admin_ctx):
    """Per-user isolation: an unknown username is REPORTED, the real users
    in the same batch still apply."""
    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from app.platform import admin_api
    from app.platform.admin_api import ApplyTemplateBody

    tpl_id, usernames, tag = _seed(runtime, bound=1)
    ghost = f"sync_ghost_{tag}"
    out = asyncio.run(admin_api.users_apply_template(
        ApplyTemplateBody(template_id=tpl_id,
                          usernames=[usernames[0], ghost]),
        runtime=runtime))
    assert out["applied"] == usernames[:1]
    assert out["errors"] == [{"username": ghost, "error": "not found"}]

    with GetDB() as db:
        rows = {u.username: u for u in db.query(LegacyUser).all()}
        assert rows[usernames[0]].data_limit == 7 * 1024 ** 3
        assert rows[usernames[0]].template_id == tpl_id


def test_unknown_template_404(runtime, admin_ctx):
    from fastapi import HTTPException

    from app.platform import admin_api
    from app.platform.admin_api import ApplyTemplateBody

    with pytest.raises(HTTPException) as err:
        asyncio.run(admin_api.users_apply_template(
            ApplyTemplateBody(template_id=987654, bound_to_template=True),
            runtime=runtime))
    assert err.value.status_code == 404
