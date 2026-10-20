"""f-buildzero-1 — zero-touch local build worker bootstrap.

A fresh install ships a compose-managed worker container with no operator
to click "issue register token". The runtime startup keeps the fixed local
worker enrolled-able: it (re)creates ``local-pool-01`` and refreshes the
one-time register token file under ``<data>/build-worker/`` (0600). This
test pins the full worker-side contract on the REAL schema: the container
reads the file, exchanges the token exactly once, and a stale file is
re-armed on the next startup without duplicating the worker row.
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
        "UVICORN_PORT": "8047",
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
    db = tmp_path_factory.mktemp("buildzero") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)
    # Same contract as test_builder_signing_seed: only rebuild the app when
    # it is not warm — popping a warm app would leak this module's env into
    # every later test in the same process.
    if not hasattr(sys.modules.get("app"), "app"):
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            sys.modules.pop(name, None)
    import app as _app_warm

    _app_warm.app  # noqa: B018 - force the application build once
    from app.platform.runtime import PlatformRuntime

    saved_env = {k: os.environ.get(k) for k in
                 ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                  "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT")}
    try:
        rt = PlatformRuntime.from_env()
        rt.verify_schema()
        yield {"rt": rt}
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_local_worker_bootstrap_contract(stack, tmp_path):
    rt = stack["rt"]
    data = tmp_path / "data"

    out = rt.build_service.ensure_local_worker_bootstrap(str(data))
    assert out and out["worker_id"] == "local-pool-01"

    token_file = data / "build-worker" / "register-token"
    assert token_file.is_file()
    assert (token_file.stat().st_mode & 0o777) == 0o600

    # exactly ONE worker row, linux-labelled (queue builder:linux)
    rows = [w for w in rt.build_service.list_workers()
            if w["worker_id"] == "local-pool-01"]
    assert len(rows) == 1 and rows[0]["platform_labels"] == ["linux"]

    # the worker container contract: exchange the token exactly once
    api_token = rt.build_service._repo.exchange_register_token(
        "local-pool-01", token_file.read_text())
    assert api_token

    # the used token must NOT re-arm until the file goes stale…
    first = token_file.read_text()
    rt.build_service.ensure_local_worker_bootstrap(str(data))
    assert token_file.read_text() == first

    # …and a stale file (>12h) is refreshed so a lost worker.token can
    # re-enroll without any operator action
    old = time.time() - 13 * 3600
    os.utime(token_file, (old, old))
    rt.build_service.ensure_local_worker_bootstrap(str(data))
    refreshed = token_file.read_text()
    assert refreshed != first
    assert rt.build_service._repo.exchange_register_token(
        "local-pool-01", refreshed)

    # still exactly one row after all the refreshes
    rows = [w for w in rt.build_service.list_workers()
            if w["worker_id"] == "local-pool-01"]
    assert len(rows) == 1
