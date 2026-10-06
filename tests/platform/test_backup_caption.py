"""f-panel-9 — backup caption/description (multi-panel Telegram delivery).

Real store roundtrip on a real SQLite schema: caption/description persist,
public_dict exposes them, validation caps mirror Telegram's 1024-char
caption limit, and the delivered caption composes label lines + footer.
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

_NEED = ("sqlalchemy", "cryptography")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")


def _env_for(db_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ZAGROS_DATABASE_URL": f"sqlite:///{db_path}",
        "SQLALCHEMY_DATABASE_URL": f"sqlite:///{db_path.parent / 'legacy.db'}",
        "ZAGROS_SECRET_KEY": "test-secret-0123456789abcdef",
        "ZAGROS_ALEMBIC_INI": str(ROOT / "alembic.ini"),
        "UVICORN_PORT": "8043",
    })
    return env


def _migrate(env: dict[str, str]) -> None:
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ROOT / "alembic.ini"),
         "upgrade", "head"], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, f"alembic upgrade failed:\n{r.stderr}"


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    db = tmp_path_factory.mktemp("bkcap") / "platform.db"
    env = _env_for(db)
    for var in ("ZAGROS_DATABASE_URL", "SQLALCHEMY_DATABASE_URL",
                "ZAGROS_SECRET_KEY", "ZAGROS_ALEMBIC_INI", "UVICORN_PORT"):
        os.environ[var] = env[var]
    _migrate(env)

    from app.persistence.cipher import SecretsCipher, derive_key

    from app.platform.backup_service import SQLBackupServiceStore as BackupServiceStore

    return BackupServiceStore(
        __import__("sqlalchemy").orm.sessionmaker(
            bind=__import__("sqlalchemy").create_engine(
                f"sqlite:///{db}")),
        SecretsCipher(derive_key("test-secret-0123456789abcdef")))


class TestBackupCaption:
    def test_roundtrip_and_public_dict(self, store):
        from app.platform.backup_service import BackupServiceSettings

        settings = BackupServiceSettings(
            enabled=True, chat_id="-100123", bot_token="1:tok",
            caption="Tehran - main panel",
            description="production users; do not confuse with staging")
        saved = store.save(settings)
        assert saved.caption == "Tehran - main panel"
        loaded, _state = store.load()
        assert loaded.caption == "Tehran - main panel"
        assert "production users" in loaded.description
        public = loaded.public_dict()
        assert public["caption"] == "Tehran - main panel"
        assert public["description"].startswith("production users")

    def test_delivery_caption_composition(self, store):
        from app.platform.backup_service import (
            BackupServiceSettings,
            delivery_caption,
        )

        assert delivery_caption(
            BackupServiceSettings(), "2026-10-06T12:00:00Z", 4096) == (
            "Zagros backup 2026-10-06T12:00:00Z (4 KB)")
        caption = delivery_caption(
            BackupServiceSettings(caption="P1", description="main db"),
            "2026-10-06T12:00:00Z", 4096)
        assert caption == "P1\nmain db\nZagros backup 2026-10-06T12:00:00Z (4 KB)"

    def test_normalization_caps_and_validate(self, store):
        from app.platform.backup_service import BackupServiceSettings

        normalized = BackupServiceSettings(
            caption="x" * 500, description="y" * 2000).normalized()
        assert len(normalized.caption) <= 200
        assert len(normalized.description) <= 700
        problems = BackupServiceSettings(
            caption="x" * 500).validate()
        assert problems and "caption" in problems[0]
        assert BackupServiceSettings(caption="ok").validate() == []
