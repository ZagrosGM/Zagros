"""f-panel-7 — application user_access_mode ('all_users' | 'bound_only').

Everything runs against REAL objects on a REAL Alembic-created schema
(the platform migration set, including 0023_application_user_access_mode):
a real PlatformRuntime, the real ApplicationAuthRepository SQL paths
(grants join, mode column), the real audit table and the real auth-service
gate. No test doubles for the code under test.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "cryptography", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


def _env_for(db_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
        "UVICORN_PORT": "8041",
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    db = tmp_path_factory.mktemp("appmode") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    # Warm the real app package exactly like test_admin_api (evict any
    # stub-era modules first so the real builder loads fresh).
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018 - force warm-up

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()

    # create_application requires an existing owner Admin row.
    from app.persistence.models import AdminModel

    with rt.session_factory() as session:
        session.add(AdminModel(username="mode-owner", password_hash="x",
                               is_sudo=True))
        session.commit()

    yield {"rt": rt}


def _enrollment_user_ctx(stack, app_public_id: str, config_kid: str,
                         app_username: str):
    """Real SQL path: request-key context + enrollment user context."""
    repo = stack["rt"].application_auth_repository
    key_ctx = repo.enrollment_request_key(app_public_id, config_kid)
    return repo.enrollment_user_context(context=key_ctx, username=app_username)


def _last_audit(stack, action: str) -> dict | None:
    from sqlalchemy import select

    from app.persistence.models import AuditLogModel

    rt = stack["rt"]
    with rt.session_factory() as session:
        row = session.execute(
            select(AuditLogModel)
            .where(AuditLogModel.action == action)
            .order_by(AuditLogModel.id.desc())
        ).scalars().first()
        return dict(row.detail_json) if row is not None else None


class TestUserAccessMode:
    def test_create_defaults_to_all_users(self, stack):
        repo = stack["rt"].application_auth_repository
        app = repo.create_application(
            owner_admin_id=1, name="Testi", api_base_url="https://app.example.com",
            default_lang="en", branding={})
        assert app["user_access_mode"] == "all_users"
        stack["app"] = app

    def test_create_rejects_invalid_mode(self, stack):
        from app.applicationapi.errors import ApplicationForbidden

        repo = stack["rt"].application_auth_repository
        with pytest.raises(ApplicationForbidden):
            repo.create_application(
                owner_admin_id=1, name="bad", api_base_url="https://b.example.com",
                default_lang="en", branding={}, user_access_mode="everyone")

    def test_list_and_get_include_mode(self, stack):
        repo = stack["rt"].application_auth_repository
        public_id = stack["app"]["application_id"]
        listed = [a for a in repo.list_applications() if a["public_id"] == public_id]
        assert listed and listed[0]["user_access_mode"] == "all_users"
        assert repo.get_application(public_id)["user_access_mode"] == "all_users"

    def test_mode_gates_enrollment_login(self, stack):
        """The core f-panel-7 contract over REAL repository SQL:

        all_users + no grant  -> allowed (the Testi fix)
        bound_only + no grant -> rejected
        bound_only + active grant -> allowed
        bound_only + revoked grant -> rejected
        """
        from app.applicationapi.errors import ApplicationForbidden
        from app.applicationapi.service import ApplicationAuthService

        rt = stack["rt"]
        repo = rt.application_auth_repository
        service = rt.application_auth
        assert isinstance(service, ApplicationAuthService)

        public_id = stack["app"]["application_id"]
        config_kid = stack["app"]["config_key_id"]

        # A user with issued app credentials (real legacy credential mint).
        user_id = rt.users.upsert_user(
            username="testi-user", status="active", access_mode="application")
        assert user_id > 0
        creds = asyncio.run(rt.client_api.issue_app_credentials(user_id))
        assert creds.username and creds.password
        stack["creds_username"] = creds.username

        now = datetime.now(tz=timezone.utc)

        # 1) default mode 'all_users', no grant -> allowed
        ctx = _enrollment_user_ctx(stack, public_id, config_kid, creds.username)
        assert ctx is not None and ctx.user_id == user_id
        assert ctx.access_mode == "application"
        assert ctx.application_access_mode == "all_users"
        assert ctx.grant_id is None
        ApplicationAuthService._validate_user_context(ctx, now)  # must not raise

        # 2) switch to 'bound_only' -> same user now rejected
        result = repo.set_user_access_mode(
            application_public_id=public_id, user_access_mode="bound_only")
        assert result["user_access_mode"] == "bound_only"
        ctx = _enrollment_user_ctx(stack, public_id, config_kid, creds.username)
        assert ctx.application_access_mode == "bound_only"
        with pytest.raises(ApplicationForbidden):
            ApplicationAuthService._validate_user_context(ctx, now)

        # audit trail proves the flip (from/to survive the allow-list)
        audit = _last_audit(stack, "application.access_mode.changed")
        assert audit is not None
        assert audit.get("from") == "all_users" and audit.get("to") == "bound_only"

        # 3) bind the user (active grant) -> allowed again
        grant = repo.grant_user(application_public_id=public_id, user_id=user_id)
        assert grant["status"] == "active"
        ctx = _enrollment_user_ctx(stack, public_id, config_kid, creds.username)
        assert ctx.grant_id == grant["grant_id"]
        assert ctx.grant_status == "active"
        ApplicationAuthService._validate_user_context(ctx, now)  # must not raise

        # 4) revoke the grant -> rejected, mode still 'bound_only'
        repo.revoke_user_grant(application_public_id=public_id, user_id=user_id)
        ctx = _enrollment_user_ctx(stack, public_id, config_kid, creds.username)
        assert ctx.grant_status == "revoked"
        with pytest.raises(ApplicationForbidden):
            ApplicationAuthService._validate_user_context(ctx, now)

    def test_bound_only_opt_in_survives_reopen(self, stack):
        """Flipping back to 'all_users' re-opens sign-in without a grant."""
        from app.applicationapi.service import ApplicationAuthService

        rt = stack["rt"]
        repo = rt.application_auth_repository
        public_id = stack["app"]["application_id"]
        config_kid = stack["app"]["config_key_id"]

        result = repo.set_user_access_mode(
            application_public_id=public_id, user_access_mode="all_users")
        assert result["user_access_mode"] == "all_users"
        ctx = _enrollment_user_ctx(stack, public_id, config_kid,
                                   stack["creds_username"])
        ApplicationAuthService._validate_user_context(
            ctx, datetime.now(tz=timezone.utc))  # must not raise

    def test_request_models_validate_mode(self, stack):
        from pydantic import ValidationError

        from app.applicationapi.auth_models import ApplicationCreateBody
        from app.platform.routers import ApplicationAccessModeBody

        body = ApplicationCreateBody(
            name="x", api_base_url="https://x.example.com", default_lang="en")
        assert body.user_access_mode == "all_users"
        assert ApplicationAccessModeBody(
            user_access_mode="bound_only").user_access_mode == "bound_only"
        with pytest.raises(ValidationError):
            ApplicationAccessModeBody(user_access_mode="everyone")
        with pytest.raises(ValidationError):
            ApplicationCreateBody(
                name="x", api_base_url="https://x.example.com",
                default_lang="en", user_access_mode="nonsense")
