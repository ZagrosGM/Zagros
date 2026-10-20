"""f-transfer-1 (v1.1.3) — moving users from one admin to another.

Sudo-only; ownership only (credentials, limits, usage and subscription
links stay with the user); BOTH engines are re-pointed — the legacy
``users.admin_id`` and the platform projection's ``admin_id``.
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

_SEQ = iter(range(10_000))


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
        "ZAGROS_SECRET_KEY": "transfer-test-key-0123456789",
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


@pytest.fixture()
def sudo_ctx(runtime):
    from app.db import GetDB, crud
    from app.models.admin import AdminCreate
    from app.platform.routers import _current_admin

    with GetDB() as db:
        if crud.get_admin(db, "transfer_root") is None:
            crud.create_admin(db, AdminCreate(
                username="transfer_root", password="x " * 8, is_sudo=True))

    class _Ctx:
        username = "transfer_root"
        is_sudo = True

    _current_admin.set(_Ctx())
    return _Ctx


def _seed(runtime, *, users: int = 2):
    from app.db import GetDB, crud
    from app.models.admin import AdminCreate
    from app.models.user import UserCreate

    tag = f"{next(_SEQ)}"
    with GetDB() as db:
        source = crud.create_admin(db, AdminCreate(
            username=f"src_admin_{tag}", password="x " * 6, is_sudo=False))
        target = crud.create_admin(db, AdminCreate(
            username=f"dst_admin_{tag}", password="x " * 6, is_sudo=False))
        names = []
        for i in range(users):
            name = f"tr_user_{tag}_{i}"
            crud.create_user(db, UserCreate(
                username=name, status="active", data_limit=123,
                expire=None, proxies={"vless": {}}, inbounds={}),
                admin=source)
            names.append(name)
        db.commit()
    return tag, names, f"dst_admin_{tag}"


def test_transfer_moves_both_engines(runtime, sudo_ctx):
    from sqlalchemy import select

    from app.db import GetDB
    from app.db.models import User as LegacyUser
    from app.persistence.models import UserModel
    from app.platform import admin_api
    from app.platform.admin_api import TransferUsersBody

    tag, names, target = _seed(runtime)
    out = asyncio.run(admin_api.users_transfer(
        TransferUsersBody(usernames=names, target_admin=target),
        request=None, runtime=runtime))

    assert out["ok"] is True
    assert len(out["transferred"]) == 2
    assert all(item["from"].startswith("src_admin_")
               for item in out["transferred"])

    with GetDB() as db:
        for name in names:
            row = db.query(LegacyUser).filter(LegacyUser.username == name).one()
            assert row.admin is not None
            assert row.admin.username == target, "legacy owner re-pointed"
            # the user keeps everything that belongs to it
            assert row.data_limit == 123
            assert len(row.proxies) == 1

    with runtime.session_factory() as s:
        for name in names:
            pid = s.execute(select(UserModel.id).where(
                UserModel.username == name)).scalar_one()
            admin_id = s.execute(select(UserModel.admin_id).where(
                UserModel.id == pid)).scalar_one()
            assert admin_id is not None, "platform mirror re-pointed too"


def test_transfer_reports_unknown_users(runtime, sudo_ctx):
    from app.platform import admin_api
    from app.platform.admin_api import TransferUsersBody

    tag, names, target = _seed(runtime, users=1)
    ghost = f"tr_ghost_{tag}"
    out = asyncio.run(admin_api.users_transfer(
        TransferUsersBody(usernames=[names[0], ghost], target_admin=target),
        request=None, runtime=runtime))
    assert len(out["transferred"]) == 1
    assert out["errors"] == [{"username": ghost, "error": "not found"}]


def test_transfer_is_sudo_only(runtime):
    from fastapi import HTTPException

    from app.platform import admin_api
    from app.platform.admin_api import TransferUsersBody
    from app.platform.routers import _current_admin

    tag, names, target = _seed(runtime, users=1)

    class _NonSudo:
        username = f"never_seeded_{tag}"
        is_sudo = False

    _current_admin.set(_NonSudo())
    with pytest.raises(HTTPException) as err:
        asyncio.run(admin_api.users_transfer(
            TransferUsersBody(usernames=names, target_admin=target),
            request=None, runtime=runtime))
    assert err.value.status_code == 403


def test_transfer_rejects_unknown_target(runtime, sudo_ctx):
    from fastapi import HTTPException

    from app.platform import admin_api
    from app.platform.admin_api import TransferUsersBody

    tag, names, _target = _seed(runtime, users=1)
    with pytest.raises(HTTPException) as err:
        asyncio.run(admin_api.users_transfer(
            TransferUsersBody(usernames=names, target_admin="no_such_admin"),
            request=None, runtime=runtime))
    assert err.value.status_code == 404
