"""Tests for app.env_loader — the .env discovery/migration/loading contract.

The loader has one global cache (``_loaded_path``); each test resets it and
restores os.environ afterwards, because load_dotenv(override=False) writes
directly into the real process environment.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import app.env_loader as env_loader  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_loader(tmp_path, monkeypatch):
    """Reset the loader cache, isolate os.environ, drop the override var."""
    snapshot = dict(os.environ)
    monkeypatch.delenv(env_loader.ENV_OVERRIDE_VAR, raising=False)
    env_loader._loaded_path = None
    yield
    env_loader._loaded_path = None
    os.environ.clear()
    os.environ.update(snapshot)


def _write_env(path: Path, **pairs) -> Path:
    path.write_text("".join(f"{k}={v}\n" for k, v in pairs.items()),
                    encoding="utf-8")
    return path


def test_default_env_path_is_cwd_independent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert env_loader.default_env_path() == str(ROOT / ".env")


def test_resolve_env_path_honors_override(tmp_path, monkeypatch):
    custom = tmp_path / "custom.env"
    monkeypatch.setenv(env_loader.ENV_OVERRIDE_VAR, str(custom))
    assert env_loader.resolve_env_path() == str(custom)


def test_missing_file_returns_none(tmp_path):
    target = tmp_path / ".env"
    assert env_loader.load_zagros_env(str(target)) is None
    assert not target.exists()


def test_loads_values_from_env_file(tmp_path):
    target = _write_env(tmp_path / ".env", ZAGROS_TEST_KEY="from-file",
                        ZAGROS_TEST_OTHER="other-value")
    loaded = env_loader.load_zagros_env(str(target))
    assert loaded == str(target)
    assert os.environ["ZAGROS_TEST_KEY"] == "from-file"
    assert os.environ["ZAGROS_TEST_OTHER"] == "other-value"


def test_real_environment_wins_over_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_TEST_KEY", "from-real-env")
    target = _write_env(tmp_path / ".env", ZAGROS_TEST_KEY="from-file")
    env_loader.load_zagros_env(str(target))
    assert os.environ["ZAGROS_TEST_KEY"] == "from-real-env"


def test_idempotent_second_call_is_cached(tmp_path):
    target = _write_env(tmp_path / ".env", ZAGROS_TEST_KEY="v1")
    first = env_loader.load_zagros_env(str(target))
    target.unlink()  # even with the file gone the cache holds
    assert env_loader.load_zagros_env(str(target)) == first


def test_legacy_zagros_env_is_migrated(tmp_path):
    legacy = _write_env(tmp_path / "zagros.env",
                        ZAGROS_TEST_KEY="legacy-value")
    legacy_text = legacy.read_text(encoding="utf-8")  # captured pre-move
    loaded = env_loader.load_zagros_env(str(tmp_path / ".env"))

    assert loaded == str(tmp_path / ".env")
    assert (tmp_path / ".env").read_text(encoding="utf-8") == legacy_text
    # legacy file kept for audit under its new name
    assert not (tmp_path / "zagros.env").exists()
    assert (tmp_path / "zagros.env.migrated").exists()
    # secure permissions on the new .env
    assert (tmp_path / ".env").stat().st_mode & 0o777 == 0o600
    # and its values are live
    assert os.environ["ZAGROS_TEST_KEY"] == "legacy-value"


def test_existing_env_wins_legacy_left_untouched(tmp_path):
    _write_env(tmp_path / "zagros.env", ZAGROS_TEST_KEY="legacy")
    _write_env(tmp_path / ".env", ZAGROS_TEST_KEY="current")
    loaded = env_loader.load_zagros_env(str(tmp_path / ".env"))

    assert loaded == str(tmp_path / ".env")
    assert os.environ["ZAGROS_TEST_KEY"] == "current"
    assert (tmp_path / "zagros.env").exists()  # untouched
    assert not (tmp_path / "zagros.env.migrated").exists()


def test_migration_is_idempotent(tmp_path):
    _write_env(tmp_path / "zagros.env", ZAGROS_TEST_KEY="legacy-value")
    env_loader._loaded_path = None
    env_loader.load_zagros_env(str(tmp_path / ".env"))

    env_loader._loaded_path = None  # simulate a fresh process
    second = env_loader.load_zagros_env(str(tmp_path / ".env"))
    assert second == str(tmp_path / ".env")
    assert (tmp_path / "zagros.env.migrated").exists()
    assert not (tmp_path / "zagros.env").exists()
