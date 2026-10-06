"""f-applogin-2 — attested enrollment must not hard-require the Bound grant.

``enroll_attested_device`` carried a bound_only-era hard check on the
user's application grant. On the default ``all_users`` mode (f-panel-7:
the grant is optional bookkeeping) EVERY enrollment failed with a
traceless 401 "enrollment request is invalid" AFTER the password had
been verified correct — the app shows that as "wrong username or
password". The grant is required again only when the application is
explicitly ``bound_only``.

Runs over the real schema (alembic head) and the real cipher.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic", "cryptography")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


def _migrate(db: Path) -> None:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "UVICORN_PORT": "8044",
    })
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


def _insert_admin(db: Path, admin_id: int = 1) -> None:
    import sqlite3

    con = sqlite3.connect(db)
    cols = [c[1] for c in con.execute("PRAGMA table_info(admins)")]
    row = {"id": admin_id, "username": f"admin{admin_id}", "is_admin": True,
           "is_sudo": False, "password_hash": "x" * 60,
           "created_at": "2026-01-01 00:00:00"}
    usable = [c for c in cols if c in row]
    con.execute(
        "INSERT INTO admins ({}) VALUES ({})".format(
            ",".join(usable), ",".join("?" * len(usable))),
        [row[c] for c in usable])
    con.commit()
    con.close()


def _repository(db: Path):
    import sqlalchemy as sa

    from app.applicationapi.repository import ApplicationAuthRepository
    from app.persistence.cipher import SecretsCipher

    engine = sa.create_engine(f"sqlite:///{db}", connect_args={
        "check_same_thread": False})
    factory = sa.orm.sessionmaker(bind=engine, autoflush=False,
                                  expire_on_commit=False)
    cipher = SecretsCipher.from_master_secret("test-secret-0123456789abcdef")
    identifier_key = cipher._key  # 32 bytes, only used as HMAC input here
    return ApplicationAuthRepository(factory, cipher, identifier_key)


def _context(repo, application: dict, user_id: int,
             grant_id: int | None = None):
    from app.applicationapi.repository import (
        RequestKeyContext, UserAuthContext)

    key = repo.enrollment_request_key(
        application["application_id"], application["config_key_id"])
    return UserAuthContext(
        application_db_id=key.application_db_id,
        application_public_id=key.application_public_id,
        application_status=key.application_status,
        application_key_db_id=key.key_db_id,
        application_key_id=key.key_id,
        application_key_status=key.key_status,
        user_id=user_id, app_username=f"u{user_id}.test",
        password_hash=None, user_status="active",
        access_mode="application",
        expire_at=None, data_limit_bytes=None, used_bytes=0,
        device_limit=None, grant_id=grant_id,
        grant_status=("active" if grant_id else None),
    )


def _insert_user(db: Path, user_id: int) -> None:
    import sqlite3

    con = sqlite3.connect(db)
    cols = [c[1] for c in con.execute("PRAGMA table_info(users)")]
    row = {"id": user_id, "username": f"u{user_id}", "status": "active",
           "data_limit_reset_strategy": "no_reset",
           "access_mode": "application",
           "client_auth_mode": "application_login",
           "app_username": f"u{user_id}.test",
           "created_at": "2026-01-01 00:00:00"}
    usable = [c for c in cols if c in row]
    con.execute(
        "INSERT INTO users ({}) VALUES ({})".format(
            ",".join(usable), ",".join("?" * len(usable))),
        [row[c] for c in usable])
    con.commit()
    con.close()


def test_all_users_enrolls_without_a_grant_and_bound_only_requires_it(tmp_path: Path) -> None:
    db = tmp_path / "main.db"
    _migrate(db)
    _insert_admin(db)

    repo = _repository(db)
    app_all = repo.create_application(
        owner_admin_id=1, name="all-mode", api_base_url="https://panel.test",
        default_lang="fa", branding={},
        user_access_mode="all_users")
    app_bound = repo.create_application(
        owner_admin_id=1, name="bound-mode", api_base_url="https://panel.test",
        default_lang="fa", branding={},
        user_access_mode="bound_only")
    _insert_user(db, 11)

    now = datetime.now(timezone.utc)
    device_key = os.urandom(32)

    # all_users: NO grant — enrollment must succeed (the regression)
    context = _context(repo, app_all, 11)
    device = repo.enroll_attested_device(
        context=context, device_public_key=device_key,
        device_name="probe", platform="android", app_version="1.0.1",
        source_ip="127.0.0.1", user_agent="pytest", now=now)
    assert device.device_key_id.startswith("dev-")

    # bound_only: still fails closed without an ACTIVE grant
    context_b = _context(repo, app_bound, 11)
    from app.applicationapi.errors import ApplicationAuthFailed

    with pytest.raises(ApplicationAuthFailed):
        repo.enroll_attested_device(
            context=context_b, device_public_key=os.urandom(32),
            device_name="probe", platform="android", app_version="1.0.1",
            source_ip="127.0.0.1", user_agent="pytest", now=now)

    # bound_only WITH an ACTIVE grant enrolls (grant_id resolves through
    # enrollment_user_context's outer join in the live flow)
    granted = repo.grant_user(
        application_public_id=app_bound["application_id"], user_id=11)
    context_b = _context(repo, app_bound, 11, grant_id=granted["grant_id"])
    device_b = repo.enroll_attested_device(
        context=context_b, device_public_key=os.urandom(32),
        device_name="probe", platform="android", app_version="1.0.1",
        source_ip="127.0.0.1", user_agent="pytest", now=now)
    assert device_b.device_key_id.startswith("dev-")


def test_access_user_context_without_grant_does_not_crash(tmp_path: Path) -> None:
    """f-applogin-2b: the access-token path validated the missing grant
    correctly but then dereferenced it unconditionally — a 500 on every
    authenticated profile/config/connections call for grant-less users
    (the app showed 'operation not completed' right after a successful
    login)."""
    db = tmp_path / "main.db"
    _migrate(db)
    _insert_admin(db)

    repo = _repository(db)
    app_all = repo.create_application(
        owner_admin_id=1, name="all-mode", api_base_url="https://panel.test",
        default_lang="fa", branding={},
        user_access_mode="all_users")
    _insert_user(db, 21)

    now = datetime.now(timezone.utc)
    context = _context(repo, app_all, 21)
    device = repo.enroll_attested_device(
        context=context, device_public_key=os.urandom(32),
        device_name="probe", platform="android", app_version="1.0.1",
        source_ip="127.0.0.1", user_agent="pytest", now=now)

    # an active refresh-token family, as issued by a real login
    import hashlib as _hashlib

    from app.applicationapi.repository import RefreshIssue

    family = "fam-" + os.urandom(8).hex()
    secret = "refresh-" + os.urandom(8).hex()
    repo.save_initial_refresh(
        context=context, device_id=device.id,
        issue=RefreshIssue(
            secret=secret,
            token_hash=_hashlib.sha256(secret.encode()).hexdigest(),
            family_id=family,
            expires_at=now + timedelta(hours=1)),
        now=now, user_agent="pytest")

    loaded = repo.access_user_context(
        application_id=context.application_db_id,
        application_public_id=context.application_public_id,
        user_id=21, device_id=device.id,
        device_key_id=device.device_key_id,
        application_key_id=context.application_key_db_id,
        token_family_id=family, now=now)
    assert loaded is not None, "grant-less user must load, not be denied"
    assert loaded.grant_id is None and loaded.grant_status is None

    # the resource gate (_assert_resource_authority) must accept the same
    # grant-less context — this is the exact 403 the operator's app hit
    profile = repo.application_profile(context=loaded, now=now)
    assert profile["username"] == "u21.test"
    assert profile["application"]["application_id"] == (
        app_all["application_id"])
