"""f-dbmerge-3 — one database on fresh installs, legacy retired after merge.

Three durable behaviors:

* fresh install (no legacy database file at all): the boot merge provisions
  the legacy schema inside the main database, writes the marker and NEVER
  creates a second database file;
* upgrade (legacy database with data): rows are copied into the main
  database, the marker records the counts and the legacy file is retired
  (renamed ``<name>.merged`` — byte-identical rollback copy, no engine ever
  opens it again);
* a leftover legacy file after an earlier merge is retired on any boot.

Run over the real legacy schema (``app.db.models`` via the merge module).
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


def _env(tmp_path: Path) -> dict[str, str]:
    return {
        **os.environ,
        "ZAGROS_DATABASE_URL": f"sqlite:///{tmp_path / 'main.db'}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{tmp_path / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
    }


@pytest.fixture(autouse=True)
def _restore_environ():
    """The merge mutates os.environ (ZAGROS_FORCE_LEGACY_RENAMES, URLs);
    never leak that into sibling tests and their alembic subprocesses."""
    snapshot = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(snapshot)


def _run_merge(env: dict[str, str]) -> int:
    # Production runs the merge as its own boot step (`python3 -m
    # app.dbmerge`); a subprocess mirrors that exactly and keeps the
    # module-level rename decisions of app.db.models isolated per scenario.
    r = subprocess.run(
        [sys.executable, "-m", "app.dbmerge"], cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"dbmerge failed:\n{r.stdout}\n{r.stderr}"
    return r.returncode


def _platform_settings_table(db: Path) -> None:
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE IF NOT EXISTS settings '
                '("key" VARCHAR PRIMARY KEY, value_json TEXT, '
                "updated_at DATETIME)")
    con.commit()
    con.close()


def _marker(db: Path) -> bool:
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "SELECT value_json FROM settings WHERE key = 'dbmerge'").fetchone()
        return row is not None
    finally:
        con.close()


def _table_exists(db: Path, table: str) -> bool:
    con = sqlite3.connect(db)
    try:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE name = ?", (table,)
        ).fetchone() is not None
    finally:
        con.close()


def test_fresh_install_never_creates_the_legacy_database(tmp_path: Path) -> None:
    env = _env(tmp_path)
    _platform_settings_table(tmp_path / "main.db")
    assert not (tmp_path / "legacy.db").exists()

    assert _run_merge(env) == 0

    # single database: no legacy file was fabricated, marker present, the
    # legacy schema lives inside the main database
    assert not (tmp_path / "legacy.db").exists()
    assert _marker(tmp_path / "main.db")
    assert _table_exists(tmp_path / "main.db", "legacy_users")


def test_upgrade_merges_rows_and_retires_the_legacy_file(tmp_path: Path) -> None:
    env = _env(tmp_path)
    _platform_settings_table(tmp_path / "main.db")
    con = sqlite3.connect(tmp_path / "legacy.db")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    con.execute("CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT)")
    con.execute("INSERT INTO users VALUES (1, 'olduser'), (2, 'second')")
    con.execute("INSERT INTO admins VALUES (1, 'oldadmin')")
    con.commit()
    con.close()

    assert _run_merge(env) == 0

    con = sqlite3.connect(tmp_path / "main.db")
    try:
        rows = con.execute(
            "SELECT COUNT(*) FROM legacy_users").fetchone()[0]
        admins = con.execute(
            "SELECT COUNT(*) FROM legacy_admins").fetchone()[0]
    finally:
        con.close()
    assert (rows, admins) == (2, 1)
    assert _marker(tmp_path / "main.db")
    # retired, not destroyed: renamed rollback copy, no live database left
    assert (tmp_path / "legacy.db.merged").exists()
    assert not (tmp_path / "legacy.db").exists()


def test_leftover_legacy_file_is_retired_on_later_boots(tmp_path: Path) -> None:
    env = _env(tmp_path)
    _platform_settings_table(tmp_path / "main.db")
    con = sqlite3.connect(tmp_path / "legacy.db")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    con.commit()
    con.close()
    assert _run_merge(env) == 0
    # simulate an operator restoring the old file (or an upgrade from a
    # panel version that kept it): the next boot must retire it again
    (tmp_path / "legacy.db").write_bytes(b"")
    assert _run_merge(env) == 0
    assert not (tmp_path / "legacy.db").exists()


def test_schema_only_legacy_file_folds_into_the_main_database(tmp_path: Path) -> None:
    """An installer-seeded legacy database with no operator data (the old
    'nothing to merge' dead-end) must still end up as ONE database."""
    env = _env(tmp_path)
    _platform_settings_table(tmp_path / "main.db")
    con = sqlite3.connect(tmp_path / "legacy.db")
    # schema-only: the four colliding tables exist but carry no rows
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    con.execute("CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT)")
    con.commit()
    con.close()

    r = subprocess.run(
        [sys.executable, "-m", "app.dbmerge"], cwd=str(ROOT), env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"dbmerge failed:\n{r.stdout}\n{r.stderr}"

    assert _marker(tmp_path / "main.db")
    assert _table_exists(tmp_path / "main.db", "legacy_users")
    assert not (tmp_path / "legacy.db").exists()
    assert (tmp_path / "legacy.db.merged").exists()
