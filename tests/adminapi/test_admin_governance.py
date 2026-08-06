"""Admin governance (alpha.7 feature) — REAL crud/auth enforcement tests.

Runs against a throwaway SQLite pair (env is pinned BEFORE the legacy app
warms up, so the legacy engine binds the temp database, never the repo's).

Covered contracts (user-facing spec):
  * max_users — create_user fails once the admin owns cap users;
  * traffic_alloc_limit — create AND update fail past the budget;
  * expire_at — login (validate_admin) andJWT (Admin.get_admin) both die;
  * traffic_consume_limit — suspend-all on crossing, revive-exactly-those
    after raising, manual disables never touched;
  * race safety — N concurrent creators can never exceed the cap;
  * persistence — create/update/partial-update round-trip + clearing.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="zggov-"))
os.environ.setdefault("SQLALCHEMY_DATABASE_URL", f"sqlite:///{_TMP}/legacy.db")
os.environ.setdefault("ZAGROS_DATABASE_URL", f"sqlite:///{_TMP}/platform.db")
os.environ.setdefault("ZAGROS_SECRET_KEY", "governance-test-key-0123456789")

try:
    import sqlalchemy  # noqa: F401
    import pytest
    _HAS = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS = False
    import pytest

import app as _app_warm  # noqa: E402
_app_warm.app  # noqa: B018 - force warm-up of the legacy import chain

from fastapi import HTTPException  # noqa: E402

from app.db import GetDB, crud  # noqa: E402
from app.db.base import Base, engine  # noqa: E402
from app.db.models import JWT, Admin, User  # noqa: E402
from app.dependencies import validate_admin  # noqa: E402
from app.models.admin import Admin as PydanticAdmin  # noqa: E402
from app.models.admin import AdminCreate, AdminModify, AdminPartialModify  # noqa: E402
from app.models.user import UserCreate, UserModify, UserStatus  # noqa: E402
from app.utils.jwt import create_admin_token  # noqa: E402

Base.metadata.create_all(engine)

_counter = 0


def _mk_admin(db, **over) -> Admin:
    global _counter
    _counter += 1
    payload = dict(username=f"gov{_counter}", password="secret-pass-1",
                   is_sudo=False)
    payload.update(over)
    return crud.create_admin(db, AdminCreate(**payload))


def _mk_user(db, admin, *, limit=None, used=0, status=UserStatus.active) -> User:
    global _counter
    _counter += 1
    dbuser = crud.create_user(
        db,
        UserCreate(username=f"user{_counter}", proxies={"vless": {}},
                   data_limit=limit or 0),
        admin=admin)
    dbuser.used_traffic = used
    dbuser.status = status
    db.commit()
    db.refresh(dbuser)
    return dbuser


# --------------------------------------------------------------------- #
# max_users
# --------------------------------------------------------------------- #

def test_max_users_caps_creation() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, max_users=2)
        _mk_user(db, admin)
        _mk_user(db, admin)
        with pytest.raises(crud.AdminLimitError) as err:
            _mk_user(db, admin)
        assert err.value.code == "max_users"


def test_admin_without_cap_creates_freely() -> None:
    with GetDB() as db:
        admin = _mk_admin(db)
        for _ in range(4):
            _mk_user(db, admin)


# --------------------------------------------------------------------- #
# traffic_alloc_limit
# --------------------------------------------------------------------- #

def test_allocation_budget_blocks_create_and_update() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, traffic_alloc_limit=100)
        u1 = _mk_user(db, admin, limit=60)
        with pytest.raises(crud.AdminLimitError) as err:
            _mk_user(db, admin, limit=50)  # 60 + 50 > 100
        assert err.value.code == "traffic_alloc_limit"
        _mk_user(db, admin, limit=40)  # exactly the budget: allowed
        with pytest.raises(crud.AdminLimitError):
            crud.update_user(db, u1, UserModify(data_limit=70))  # 70+40 > 100
        crud.update_user(db, u1, UserModify(data_limit=60))  # back to legal


# --------------------------------------------------------------------- #
# expire_at
# --------------------------------------------------------------------- #

def test_expired_admin_cannot_login() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, expire_at=datetime.utcnow() - timedelta(days=1))
        assert crud.admin_is_expired(admin)
        with pytest.raises(HTTPException) as err:
            validate_admin(db, admin.username, "secret-pass-1")
        assert err.value.status_code == 401
        assert "expired" in str(err.value.detail).lower()


def test_unexpired_admin_logs_in() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, expire_at=datetime.utcnow() + timedelta(days=30))
        result = validate_admin(db, admin.username, "secret-pass-1")
        assert result is not None and result.username == admin.username


def test_expired_admin_token_is_rejected() -> None:
    with GetDB() as db:
        if db.query(JWT).first() is None:
            db.add(JWT(id=1, secret_key="ab" * 32))
            db.commit()
        admin = _mk_admin(db, expire_at=datetime.utcnow() - timedelta(hours=2))
        issued = create_admin_token(admin.username, False)
        token = issued.access_token if hasattr(issued, "access_token") else issued
        with pytest.raises(HTTPException) as err:
            PydanticAdmin.get_admin(token, db)
        assert err.value.status_code == 401
        assert "expired" in str(err.value.detail).lower()


# --------------------------------------------------------------------- #
# traffic_consume_limit (suspend-all / revive flagged only)
# --------------------------------------------------------------------- #

def test_consumption_cap_suspends_and_revives() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, traffic_consume_limit=1_000)
        u1 = _mk_user(db, admin, used=600)
        u2 = _mk_user(db, admin, used=300)
        manual_disabled = _mk_user(db, admin, used=0, status=UserStatus.disabled)

        changed = crud.enforce_admin_consumption(db, admin)
        assert (600 + 300) < 1_000
        assert not changed["suspended"]  # still below the cap

        u2.used_traffic = 450
        db.commit()  # total = 1050 >= 1000
        changed = crud.enforce_admin_consumption(db, admin)
        assert {u.username for u in changed["suspended"]} == {u1.username, u2.username}
        db.refresh(u1)
        db.refresh(u2)
        db.refresh(manual_disabled)
        assert u1.status == UserStatus.disabled and u1.admin_limit_disabled
        assert u2.status == UserStatus.disabled and u2.admin_limit_disabled
        # the user an operator disabled by hand is NOT flagged
        assert manual_disabled.status == UserStatus.disabled
        assert not manual_disabled.admin_limit_disabled

        # idempotent: second run suspends nobody again
        changed = crud.enforce_admin_consumption(db, admin)
        assert not changed["suspended"] and not changed["reactivated"]

        # raise the cap -> exactly the flagged users are revived
        crud.update_admin(db, admin, AdminModify(
            is_sudo=False, traffic_consume_limit=5_000))
        changed = crud.enforce_admin_consumption(db, admin)
        assert {u.username for u in changed["reactivated"]} == {u1.username, u2.username}
        db.refresh(u1)
        db.refresh(manual_disabled)
        assert u1.status == UserStatus.active and not u1.admin_limit_disabled
        assert manual_disabled.status == UserStatus.disabled  # never touched


# --------------------------------------------------------------------- #
# race safety — concurrent creators under a cap
# --------------------------------------------------------------------- #

def test_concurrent_creates_never_exceed_cap() -> None:
    with GetDB() as db:
        admin = _mk_admin(db, max_users=3)

    attempts = 9
    results = {"created": 0, "rejected": 0, "errors": []}
    lock = threading.Lock()

    def worker(i: int, admin_id: int) -> None:
        try:
            with GetDB() as db:
                admin = db.query(Admin).get(admin_id)
                crud.create_user(
                    db,
                    UserCreate(username=f"race{i}", proxies={"vless": {}}),
                    admin=admin)
            with lock:
                results["created"] += 1
        except crud.AdminLimitError:
            with lock:
                results["rejected"] += 1
        except Exception as exc:  # noqa: BLE001 — surfaced by the assert below
            with lock:
                results["errors"].append(f"{type(exc).__name__}: {exc}")

    with GetDB() as db:
        _admin_id = db.query(Admin).order_by(Admin.id.desc()).first().id

    threads = [threading.Thread(target=worker, args=(i, _admin_id)) for i in range(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not results["errors"], f"unexpected failures: {results['errors']}"
    with GetDB() as db:
        final = db.query(User).filter(User.admin_id == _admin_id).count()
    assert final == 3, f"cap violated: {final} users under a max_users=3 cap"
    assert results["created"] == 3 and results["rejected"] == attempts - 3


# --------------------------------------------------------------------- #
# persistence round-trip
# --------------------------------------------------------------------- #

def test_governance_fields_roundtrip() -> None:
    with GetDB() as db:
        expiry = datetime.utcnow().replace(microsecond=0) + timedelta(days=10)
        admin = _mk_admin(db, max_users=5, expire_at=expiry,
                          traffic_alloc_limit=2 * 1024 ** 3,
                          traffic_consume_limit=10 * 1024 ** 3)
        assert admin.max_users == 5
        assert admin.expire_at.replace(microsecond=0) == expiry.replace(microsecond=0)
        assert admin.traffic_alloc_limit == 2 * 1024 ** 3
        assert admin.traffic_consume_limit == 10 * 1024 ** 3

        # partial update: change one, leave the rest
        crud.partial_update_admin(db, admin, AdminPartialModify(max_users=9))
        assert admin.max_users == 9
        assert admin.traffic_alloc_limit == 2 * 1024 ** 3

        # explicit clearing via falsy value
        crud.update_admin(db, admin, AdminModify(
            is_sudo=False, max_users=0, traffic_alloc_limit=None,
            traffic_consume_limit=None, expire_at=None))
        assert admin.max_users is None
        assert admin.traffic_alloc_limit is None
        assert admin.expire_at is None


def test_get_admins_attaches_aggregates() -> None:
    with GetDB() as db:
        admin = _mk_admin(db)
        _mk_user(db, admin, limit=40, used=25)
        _mk_user(db, admin, limit=60, used=5)
        listed = [a for a in crud.get_admins(db) if a.username == admin.username][0]
        assert listed.users_count == 2
        assert listed.users_allocated_traffic == 100
        assert listed.users_lifetime_usage == 30


# --------------------------------------------------------------------- #
# router regression: core-sync failure must NOT 500 the admin modify
# --------------------------------------------------------------------- #

def test_modify_admin_core_sync_failure_stays_200(monkeypatch) -> None:
    """Live E2E caught this: when the xray binary is absent (dev box,
    mid-install, multi-core platforms), `xray.core.restart` raises
    AFTER the governance change committed — the PUT must still succeed;
    the scheduler review loop retries the core sync every tick.
    """
    from fastapi.testclient import TestClient

    import app.routers.admin as admin_router

    with GetDB() as db:
        _mk_admin(db, username="sudo-http", is_sudo=True)
        gov = _mk_admin(db, username="gov-http")
        u = _mk_user(db, gov, used=2048)
        uname = u.username
    token = create_admin_token("sudo-http", is_sudo=True)

    def _boom(*_a, **_k):
        raise FileNotFoundError("/usr/local/bin/xray missing")

    monkeypatch.setattr(admin_router.xray.core, "restart", _boom)

    client = TestClient(_app_warm.app)
    resp = client.put(
        "/api/admin/gov-http",
        json={"is_sudo": False, "traffic_consume_limit": 1024},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    with GetDB() as db:
        row = db.query(User).filter(User.username == uname).one()
        assert row.status == UserStatus.disabled
        assert row.admin_limit_disabled is True
