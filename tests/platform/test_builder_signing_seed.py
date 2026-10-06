"""f-panel-8 — the app signing seed rides the build job fetch.

Verified against REAL objects on the REAL Alembic schema: the resolver
decrypts the application's ACTIVE signing key and the result regenerates
the exact published public key (Ed25519), revoked/inactive apps resolve
to None, and the fetch-job glue only attaches a well-formed synthetic
signing_key credential.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
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
        "UVICORN_PORT": "8042",
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
    db = tmp_path_factory.mktemp("buildseed") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018 - force warm-up

    from app.platform.runtime import PlatformRuntime

    rt = PlatformRuntime.from_env()
    rt.verify_schema()

    from app.persistence.models import AdminModel

    with rt.session_factory() as session:
        session.add(AdminModel(username="seed-owner", password_hash="x",
                               is_sudo=True))
        session.commit()
    yield {"rt": rt}


class _Resolver:
    """Duck-typed stand-in mirroring the runtime wiring (repo method ref)."""

    def __init__(self, repo) -> None:
        self._repo = repo

    def __call__(self, *, application_public_id: str):
        return self._repo.active_signing_seed(
            application_public_id=application_public_id)


def test_seed_resolves_and_matches_published_public_key(stack):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    repo = stack["rt"].application_auth_repository
    app = repo.create_application(
        owner_admin_id=1, name="SeedApp",
        api_base_url="https://seed.example.com", default_lang="en",
        branding={})
    public_id = app["application_id"]

    seed = repo.active_signing_seed(application_public_id=public_id)
    assert isinstance(seed, str) and len(seed) == 43
    assert "=" not in seed and "+" not in seed and "/" not in seed

    # The seed must regenerate EXACTLY the published signing public key —
    # this is the property the app attestation depends on.
    raw = base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4))
    derived = Ed25519PrivateKey.from_private_bytes(raw).public_key(
        ).public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        __import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw)
    published = base64.urlsafe_b64decode(
        app["signing_public_key"] + "=" * (-len(app["signing_public_key"]) % 4))
    assert derived == published
    stack["public_id"] = public_id


def test_seed_none_for_missing_or_revoked_application(stack):
    repo = stack["rt"].application_auth_repository
    assert repo.active_signing_seed(
        application_public_id="00000000-0000-0000-0000-000000000000") is None

    repo.revoke_application(application_public_id=stack["public_id"])
    assert repo.active_signing_seed(
        application_public_id=stack["public_id"]) is None


def test_glue_attaches_wellformed_credential_only_with_seed(stack):
    from app.builder.service import _app_signing_credential

    application = {"public_id": "app-1", "name": "SeedApp"}
    calls: list[str] = []

    def resolver(*, application_public_id):
        calls.append(application_public_id)
        return "A" * 43

    cred = _app_signing_credential("build-1", application, resolver)
    assert cred == {
        "public_id": "build-1-app-signing", "kind": "signing_key",
        "label": "application attestation seed (per-job)",
        "material": {"seed": "A" * 43}}
    assert calls == ["app-1"]

    # no resolver -> nothing attached (e.g. minimal test service setups)
    assert _app_signing_credential("build-1", application, None) is None
    # no application -> nothing attached and resolver never consulted
    assert _app_signing_credential("build-1", {}, resolver) is None
    assert calls == ["app-1"]
    # resolver returning None (revoked app) -> nothing attached
    assert _app_signing_credential(
        "build-1", application,
        lambda *, application_public_id: None) is None
