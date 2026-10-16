"""f-coresettings-1 — master core settings editor: mask round-trip safety,
schema validation, persistence + restart semantics."""
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
        "ZAGROS_SECRET_KEY": "coresettings-test-key-0123456789",
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


class _StubDriver:
    """A driver with a schema and no real process behind it."""

    from app.cores.types import CoreMetadata, CoreState

    def __init__(self, settings):
        self.settings = dict(settings)
        self._state = self.CoreState.RUNNING
        self.started = 0
        self.stopped = 0

    async def start(self):
        self.started += 1
        return None

    async def stop(self):
        self.stopped += 1
        return None


@pytest.fixture()
def stub_core(runtime, monkeypatch):
    from app.cores.types import CoreState

    class _Meta:
        id = "stub-core"
        config_schema = {
            "type": "object",
            "properties": {
                "listen_port": {"type": "integer", "default": 1194},
                "label": {"type": "string"},
                "secure_nat": {"type": "boolean"},
                "mode": {"type": "string", "enum": ["fast", "safe"]},
                "extra": {"type": "object"},
            },
        }
        default_settings = {"listen_port": 1194, "admin_password": "hunter2"}

    driver = _StubDriver({"listen_port": 1194, "admin_password": "s3cret"})
    driver.metadata = _Meta
    # register the stub class so the endpoints' get_driver_class resolves it
    from app.cores import registry as _registry

    class _StubClass:
        metadata = _Meta

        def __init__(self, settings=None):
            self.settings = dict(settings or {})

    monkeypatch.setitem(_registry._drivers, "stub-core", _StubClass)
    runtime.core_manager.attach("stub-core", driver, enabled=True)
    runtime.core_manager._states["stub-core"] = CoreState.RUNNING
    saved: dict = {}

    async def _save(core_id, *, state, enabled, settings):
        saved[core_id] = settings

    monkeypatch.setattr(runtime.core_manager._store, "save_state", _save)
    async def _persist(core_id):
        await runtime.core_manager._store.save_state(
            core_id, state=runtime.core_manager._states[core_id],
            enabled=runtime.core_manager._enabled.get(core_id, True),
            settings=runtime.core_manager.get(core_id).settings)
    monkeypatch.setattr(runtime.core_manager, "persist_settings", _persist)
    return driver


def test_settings_get_masks_secrets(runtime, stub_core):
    from app.platform import admin_api

    view = asyncio.run(admin_api.cores_settings_get("stub-core",
                                                    runtime=runtime))
    assert view["core"] == "stub-core"
    assert view["settings"]["admin_password"] == "set (6 chars)", \
        "secret masked"
    assert view["settings"]["listen_port"] == 1194
    assert "listen_port" in view["schema"]["properties"]


def test_settings_put_validates_schema_and_skips_masks(runtime, stub_core,
                                                       monkeypatch):
    from fastapi import HTTPException

    from app.platform import admin_api

    started: list[str] = []

    async def _fake_start(core_id):
        started.append(core_id)
        from app.cores.types import CoreStatus, CoreState, HealthStatus
        return CoreStatus(core_id=core_id, state=CoreState.RUNNING,
                          health=HealthStatus.HEALTHY)

    async def _fake_stop(core_id):
        return None

    monkeypatch.setattr(runtime.core_manager, "start_core", _fake_start)
    monkeypatch.setattr(runtime.core_manager, "stop_core", _fake_stop)

    class _Body:
        settings = {"listen_port": 1723, "label": "edge",
                    "admin_password": "set (6 chars)", "mode": "fast"}

    out = asyncio.run(admin_api.cores_settings_put(
        "stub-core", _Body(), runtime=runtime))
    # masked placeholder dropped; real edits applied
    assert out["applied"] == {"listen_port": 1723, "label": "edge",
                              "mode": "fast"}
    assert stub_core.settings["listen_port"] == 1723
    assert stub_core.settings["admin_password"] == "s3cret", \
        "round-tripping the mask never clobbers a secret"
    assert out["restarted"] is True and started == ["stub-core"]

    with pytest.raises(HTTPException) as err:
        asyncio.run(admin_api.cores_settings_put(
            "stub-core",
            type("B", (), {"settings": {"nonsense": 1}})(), runtime=runtime))
    assert err.value.status_code == 422
    with pytest.raises(HTTPException):
        asyncio.run(admin_api.cores_settings_put(
            "stub-core",
            type("B", (), {"settings": {"mode": "turbo"}})(), runtime=runtime))
    with pytest.raises(HTTPException):
        asyncio.run(admin_api.cores_settings_put(
            "stub-core",
            type("B", (), {"settings": {"listen_port": "abc"}})(),
            runtime=runtime))


def test_settings_put_keeps_stopped_core_stopped(runtime, stub_core,
                                                 monkeypatch):
    from app.cores.types import CoreState

    from app.platform import admin_api

    runtime.core_manager._states["stub-core"] = CoreState.INSTALLED
    starts: list[str] = []

    async def _fake_start(core_id):
        starts.append(core_id)
        raise AssertionError("stopped cores must not be started")

    monkeypatch.setattr(runtime.core_manager, "start_core", _fake_start)

    class _Body:
        settings = {"label": "changed"}

    out = asyncio.run(admin_api.cores_settings_put(
        "stub-core", _Body(), runtime=runtime))
    assert out["restarted"] is False and starts == []
    assert stub_core.settings["label"] == "changed"
