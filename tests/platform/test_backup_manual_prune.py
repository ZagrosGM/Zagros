"""f-backprune-2 (v1.1.3 bugfix 3) — "archives kept" is honored on MANUAL
backup creation too, not only by the scheduler.

The old /backup/create never pruned: an operator who only ever ran manual
backups watched the archive directory grow forever no matter what they set
"archives kept" to.
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
        "ZAGROS_SECRET_KEY": "backprune-test-key-0123456789",
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


def _set_keep(runtime, keep: int) -> None:
    store = runtime.backup_service
    settings, _state = store.load()
    from dataclasses import replace

    store.save(replace(settings, enabled=False, keep=keep))


def _seed_archives(runtime, count: int) -> list[str]:
    from app.platform import backup_store

    data_dir = backup_store.directory(
        __import__("app.platform.admin_api", fromlist=["_backup_data_dir"])
        ._backup_data_dir(runtime))
    names = []
    for i in range(count):
        artifact = backup_store.create(
            data_dir=str(data_dir.parent) if data_dir.name == "backups"
            else str(data_dir),
            database_url=runtime.database_url,
            legacy_database_url=os.environ.get("SQLALCHEMY_DATABASE_URL"),
            panel_version="test", name=f"seed-{i}.tar.gz")
        names.append(artifact.name)
    return names


def test_manual_create_prunes_to_keep(runtime):
    from app.platform import admin_api, backup_store

    _set_keep(runtime, keep=2)
    _seed_archives(runtime, 4)

    out = asyncio_run(admin_api.create_backup(None, runtime=runtime))
    # the fresh archive + the 2 newest seeds survive; the rest are gone
    artifacts = backup_store.list_artifacts(
        __import__("app.platform.admin_api", fromlist=["_backup_data_dir"])
        ._backup_data_dir(runtime))
    assert len(artifacts) == 2, (
        f"archives kept is honored on manual create: got {len(artifacts)}")
    assert len(out["pruned"]) == 3
    assert artifacts[0].name == out["artifact"]["name"], "newest first"


def test_keep_zero_keeps_everything(runtime):
    from app.platform import admin_api, backup_store

    _set_keep(runtime, keep=0)
    _seed_archives(runtime, 3)
    asyncio_run(admin_api.create_backup(None, runtime=runtime))
    artifacts = backup_store.list_artifacts(
        __import__("app.platform.admin_api", fromlist=["_backup_data_dir"])
        ._backup_data_dir(runtime))
    assert len(artifacts) == 4, "keep=0 means keep every archive"


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
