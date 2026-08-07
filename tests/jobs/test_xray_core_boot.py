"""Regression: the panel must BOOT on a fresh (unmigrated) database.

alpha.7 cold-start crashed inside ``app/jobs/0_xray_core.py::start_core``
with ``sqlite3.OperationalError: no such table: users`` because
``include_db_users()`` was called unconditionally at startup — the Zagros
product layer boots degraded by contract, the legacy xray job violated it.
"""
from __future__ import annotations

import importlib.util
import sys
import types


def _load_job_module(monkeypatch, db_broken: bool):
    """Load app/jobs/0_xray_core.py standalone (it has a digit-prefix name
    so it can't be imported normally) with stubbed legacy globals."""
    xray_mod = types.ModuleType("app.xray_stub")

    class _Cfg:
        def include_db_users(self):
            if db_broken:
                import sqlalchemy.exc

                raise sqlalchemy.exc.OperationalError(
                    "SELECT ...", {}, Exception("no such table: users"))
            return {"users": "merged"}

    class _Core:
        started = False
        restarted_with: list = []

        def restart(self, config):
            self.restarted_with.append(config)

        def start(self, config):
            pass

    xray_mod.config = _Cfg()
    xray_mod.core = _Core()
    xray_mod.nodes = {}

    app_stub = types.ModuleType("app")
    app_stub.app = types.SimpleNamespace(on_event=lambda *_a, **_k: (lambda f: f))
    app_stub.logger = __import__("logging").getLogger("test")
    app_stub.scheduler = None
    app_stub.xray = xray_mod
    monkeypatch.setitem(sys.modules, "app", app_stub)
    monkeypatch.setitem(sys.modules, "app.db", types.ModuleType("app.db"))
    sys.modules["app.db"].GetDB = None
    sys.modules["app.db"].crud = None
    monkeypatch.setitem(sys.modules, "app.models.node", types.ModuleType("app.models.node"))
    sys.modules["app.models.node"].NodeStatus = None
    monkeypatch.setitem(sys.modules, "config", types.ModuleType("config"))
    sys.modules["config"].JOB_CORE_HEALTH_CHECK_INTERVAL = 60
    monkeypatch.setitem(sys.modules, "xray_api.exc", types.ModuleType("xray_api.exc"))
    sys.modules["xray_api.exc"].XrayError = type("XrayError", (Exception,), {})
    xray_api_pkg = types.ModuleType("xray_api")
    xray_api_pkg.exc = sys.modules["xray_api.exc"]
    monkeypatch.setitem(sys.modules, "xray_api", xray_api_pkg)

    exc_mod = importlib.util.spec_from_file_location(
        "zagros_jobs_0_xray_core",
        __file__.replace(
            "tests/jobs/test_xray_core_boot.py",
            "app/jobs/0_xray_core.py",
        ),
    )
    mod = importlib.util.module_from_spec(exc_mod)
    exc_mod.loader.exec_module(mod)
    # steer the schema probe directly (it hits the real engine otherwise)
    mod._schema_has_users = lambda: not db_broken
    return mod


def test_health_check_boots_on_unmigrated_schema(monkeypatch, caplog):
    mod = _load_job_module(monkeypatch, db_broken=True)

    with caplog.at_level("CRITICAL"):
        mod.core_health_check()  # must NOT raise OperationalError

    # fell back to the plain file config and logged exactly why
    assert mod.xray.core.restarted_with == [mod.xray.config]
    assert "alembic upgrade head" in caplog.text
    assert "no 'users' table" in caplog.text


def test_health_check_uses_db_users_when_schema_ready(monkeypatch):
    mod = _load_job_module(monkeypatch, db_broken=False)

    mod.core_health_check()

    assert mod.xray.core.restarted_with == [{"users": "merged"}]
