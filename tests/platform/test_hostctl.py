"""Tests for app.platform.hostctl — the in-container ops bridge used by the
host `zagros` CLI.

Two execution modes, both REAL:
* runtime/core commands run in-process against a real SQLite schema with a
  test-double driver registered through the real registry;
* legacy admin commands run as subprocesses (``python -m app.platform.hostctl``)
  — exactly how the host CLI invokes them inside the container, i.e. through
  the real import machinery incl. ``app/__init__``.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi", "apscheduler", "jwt", "jdatetime")
_HAS_RUNTIME = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS_RUNTIME,
                                reason="full panel requirements not installed")

if _HAS_RUNTIME:
    from app.platform import hostctl  # via the REAL app package (no shim)


def _env_for(db_path: Path) -> dict[str, str]:
    """Split-schema env, mirroring the container: P3 on ZAGROS_DATABASE_URL,
    the legacy stack on its own SQLALCHEMY_DATABASE_URL database."""
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}\n{r.stdout}"


def _run(argv, capsys):
    rc = hostctl.main(argv)
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1, f"hostctl must print exactly one JSON line, got: {out}"
    return rc, json.loads(out[0])


def _run_sub(argv, env):
    """Subprocess invocation — the exact production call path."""
    p = subprocess.run([sys.executable, "-m", "app.platform.hostctl", *argv],
                       cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=300)
    lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
    assert lines, f"no JSON output on stdout.\nstdout={p.stdout}\nstderr={p.stderr[-2000:]}"
    return p.returncode, json.loads(lines[-1]), p.stderr


def _register_fake_core():
    """Register a minimal REAL driver class through the real registry."""
    from app.cores.base import BaseCoreDriver
    from app.cores.types import CoreMetadata, CoreState, CoreStatus, HealthStatus

    class FakeCore(BaseCoreDriver):
        metadata = CoreMetadata(
            id="hostctl-fake", name="Hostctl Fake", protocols=["fake"],
            capabilities=set(),
        )

        def __init__(self, settings=None):
            super().__init__(settings)
            self.started = False

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.started = False

        async def status(self) -> CoreStatus:
            return CoreStatus(
                core_id=self.metadata.id,
                state=CoreState.RUNNING if self.started else CoreState.STOPPED,
                health=HealthStatus.HEALTHY if self.started else HealthStatus.UNKNOWN,
                core_version="fake-1.0",
            )

        async def create_account(self, account) -> None:
            pass

        async def update_account(self, account) -> None:
            pass

        async def delete_account(self, account_id: str) -> None:
            pass

        async def build_client_config(self, account, node=None) -> str:
            return "fake://config"

        async def sync_accounts(self, accounts):
            self.synced_accounts = list(accounts)

    return FakeCore.metadata.id


@pytest.fixture()
def platform_env(tmp_path, monkeypatch):
    """Real schema on a tmp SQLite URL + master secret + fake driver."""
    db = tmp_path / "hostctl.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI"):
        monkeypatch.setenv(var, env[var])
    _migrate(env)
    fake_id = _register_fake_core()
    yield {"db": db, "env": env, "fake_id": fake_id}
    from app.cores.registry import unregister_driver

    unregister_driver(fake_id)


class TestVersion:
    def test_version_reports_app_version(self, capsys):
        rc, payload = _run(["version"], capsys)
        import re

        src = (ROOT / "app" / "__init__.py").read_text(encoding="utf-8")
        m = re.search(r'__version__\s*=\s*"([^"]+)"', src)
        assert m, "__version__ not found in app/__init__.py"

        assert rc == 0 and payload["ok"] is True
        assert payload["panel_version"] == m.group(1)


class TestDatabaseOps:
    def test_db_check_reachable_and_up_to_date(self, platform_env, capsys):
        rc, payload = _run(["db-check"], capsys)
        assert rc == 0 and payload["ok"] is True
        assert payload["reachable"] is True
        assert payload["driver"] == "sqlite"
        assert payload["up_to_date"] is True
        assert payload["alembic_current"] == payload["alembic_heads"]

    def test_db_check_detects_pending_migration(self, platform_env, capsys,
                                                tmp_path):
        db2 = tmp_path / "fresh.db"
        env = _env_for(db2)
        import os

        old = os.environ.get("ZAGROS_DATABASE_URL")
        os.environ["ZAGROS_DATABASE_URL"] = env["ZAGROS_DATABASE_URL"]
        try:
            rc, payload = _run(["db-check"], capsys)
        finally:
            if old is not None:
                os.environ["ZAGROS_DATABASE_URL"] = old
        assert rc != 0  # missing schema → verify_schema fails honestly

    def test_backup_sqlite_produces_valid_copy(self, platform_env, capsys, tmp_path):
        out = tmp_path / "snap" / "db.sqlite3"
        rc, payload = _run(["db-backup-sqlite", "--out", str(out)], capsys)
        assert rc == 0 and payload["ok"] is True
        assert out.exists() and payload["bytes"] > 0
        import sqlite3

        conn = sqlite3.connect(out)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        assert "alembic_version" in tables

    def test_backup_sqlite_refuses_other_drivers(self, platform_env, capsys,
                                                 monkeypatch):
        monkeypatch.setenv("ZAGROS_DATABASE_URL", "mysql+pymysql://u:p@h/db")
        rc, payload = _run(["db-backup-sqlite", "--out", "/tmp/x.sqlite3"], capsys)
        assert rc != 0 and payload["ok"] is False
        assert "SQLite" in payload["error"]


class TestCoreLifecycle:
    def test_install_list_start_stop_uninstall(self, platform_env, capsys):
        fake = platform_env["fake_id"]

        rc, payload = _run(["cores-install", fake], capsys)
        assert rc == 0 and payload["ok"] and payload["state"] == "installed"

        rc, payload = _run(["cores-list"], capsys)
        assert rc == 0 and payload["ok"]
        entry = next(c for c in payload["cores"] if c["id"] == fake)
        assert entry["state"] == "installed" and entry["enabled"] is True

        rc, payload = _run(["cores-start", fake], capsys)
        assert rc == 0 and payload["ok"] and payload["state"] == "running"

        # while store says running, transitions are panel-owned → exit 3
        rc, payload = _run(["cores-stop", fake], capsys)
        assert rc == hostctl.EXIT_PANEL_OWNED and payload["code"] == "PANEL_OWNED"

        # uninstall with force on a "running" core performs the removal
        rc, payload = _run(["cores-uninstall", fake, "--force"], capsys)
        assert rc == 0 and payload["ok"] and payload["uninstalled"] is True

        rc, payload = _run(["cores-list", "--no-probe"], capsys)
        assert all(c["id"] != fake for c in payload["cores"])

    def test_install_unknown_core_is_not_found(self, platform_env, capsys):
        rc, payload = _run(["cores-install", "no-such-core"], capsys)
        assert rc == hostctl.EXIT_NOT_FOUND and payload["ok"] is False
        assert "Available" in payload["error"]

    def test_start_uninstalled_is_not_found(self, platform_env, capsys):
        rc, payload = _run(["cores-start", "ghost"], capsys)
        assert rc == hostctl.EXIT_NOT_FOUND

    def test_sync_on_empty_user_base(self, platform_env, capsys):
        fake = platform_env["fake_id"]
        _run(["cores-install", fake], capsys)
        rc, payload = _run(["sync"], capsys)
        assert rc == 0 and payload["ok"]
        assert payload["cores"][fake]["synced"] == 0

    def test_sync_applies_accounts_through_driver(self, platform_env, capsys):
        fake = platform_env["fake_id"]
        _run(["cores-install", fake], capsys)
        from app.platform.runtime import PlatformRuntime

        rt = PlatformRuntime.from_env()
        uid = rt.users.upsert_user(username="alice")
        rt.users.upsert_core_account(
            user_id=uid, core_id=fake, protocol="fake",
            account_id="acc-1", settings={"token": "s3cret"},
        )
        rc, payload = _run(["sync", "--core", fake], capsys)
        assert rc == 0 and payload["ok"]
        assert payload["cores"][fake]["synced"] == 1


class TestAdminOps:
    """Legacy admin CRUD — invoked as subprocesses exactly like the container
    call path (full real app import incl. legacy stack)."""

    def test_create_list_reset(self, platform_env):
        env = platform_env["env"]
        rc, payload, _ = _run_sub(
            ["admin-create", "--username", "root", "--password", "pw-123", "--sudo"],
            env)
        assert rc == 0 and payload["ok"] and payload["is_sudo"] is True

        rc, payload, _ = _run_sub(["admin-list"], env)
        assert rc == 0 and any(a["username"] == "root" for a in payload["admins"])

        rc, payload, _ = _run_sub(
            ["admin-reset", "--username", "root", "--password", "pw-456"], env)
        assert rc == 0 and payload["ok"] and payload["password_reset"] is True

        # verify through the ORM in a production-like interpreter
        verify = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, '.');"
             "import app as _w; getattr(_w, 'app');"  # legacy import order guard
             "from app.db import GetDB, crud;"
             "from app.models.admin import pwd_context;"
             "db = GetDB().__enter__();"
             "a = crud.get_admin(db, 'root');"
             "assert a is not None and pwd_context.verify('pw-456', a.hashed_password);"
             "print('verified')"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        assert verify.returncode == 0 and "verified" in verify.stdout, verify.stderr[-1500:]

    def test_duplicate_admin_is_error(self, platform_env):
        env = platform_env["env"]
        _run_sub(["admin-create", "--username", "root", "--password", "x", "--sudo"], env)
        rc, payload, _ = _run_sub(
            ["admin-create", "--username", "root", "--password", "x", "--sudo"], env)
        assert rc != 0 and "already exists" in payload["error"]

    def test_reset_missing_admin_is_not_found(self, platform_env):
        rc, payload, _ = _run_sub(
            ["admin-reset", "--username", "ghost", "--password", "x"],
            platform_env["env"])
        assert rc == hostctl.EXIT_NOT_FOUND


class TestNodes:
    def test_nodes_list_empty(self, platform_env, capsys):
        rc, payload = _run(["nodes-list"], capsys)
        assert rc == 0 and payload["ok"] is True
        assert payload["nodes"] == []


class TestHealth:
    def test_health_composite(self, platform_env, capsys):
        rc, payload = _run(["health"], capsys)
        assert rc == 0 and payload["ok"] is True
        assert payload["healthy"] is True
        assert payload["db"]["reachable"] is True
        assert payload["cores"]["installed"] >= 0
