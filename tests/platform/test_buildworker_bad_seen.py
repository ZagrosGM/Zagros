"""f-buildworker-1 — a corrupted ``build_workers.last_seen_at`` must not
wedge the build queue.

SQLAlchemy hydrates DateTime columns by parsing the stored string, so any
non-ISO value in ``last_seen_at`` (manual edit, partial restore, stray
diagnostic write) makes EVERY worker heartbeat and claim fail with a 500.
The worker then cannot claim jobs and builds sit in ``queued`` forever —
the only visible symptom is a worker-side ``PanelError`` log line.

The repository now heals the poisoned column (NULL via a type-less UPDATE,
then retry) instead of crashing; the next heartbeat immediately persists a
fresh timestamp.
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "pydantic")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="panel requirements not installed")

sqlalchemy = pytest.importorskip("sqlalchemy")
sa_engine = sqlalchemy.create_engine
sa_text = sqlalchemy.text


def _make_repo(db_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.persistence.models import Base
    from app.builder.repository import BuildRepository

    engine = create_engine(f"sqlite:///{db_path}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return BuildRepository(factory, cipher=None), engine


def _raw_insert_bad_worker(engine):
    """Insert the worker row bypassing the ORM so ``last_seen_at`` holds a
    value no ISO parser accepts (the exact live failure)."""
    with engine.begin() as conn:
        conn.execute(sa_text(
            "INSERT INTO build_workers (worker_id, display_name, "
            "platform_labels, status, api_token_hash, created_at, updated_at, "
            "last_seen_at) VALUES ('linux-master', 'linux-master', "
            "'[\"linux\"]', 'active', 'deadbeef', "
            "'2026-10-12T08:35:11.966612', '2026-10-12T08:35:11.966612', "
            "'SA-TEST-123')"))


def _raw_seen(engine):
    with engine.connect() as conn:
        return conn.execute(sa_text(
            "SELECT last_seen_at FROM build_workers "
            "WHERE worker_id='linux-master'")).scalar_one()


def test_heartbeat_survives_bad_last_seen(tmp_path):
    repo, engine = _make_repo(tmp_path / "panel.db")
    _raw_insert_bad_worker(engine)

    out = repo.heartbeat("linux-master")

    assert out["worker_id"] == "linux-master"
    assert out["last_seen_at"] is not None
    healed = _raw_seen(engine)
    assert healed != "SA-TEST-123"
    datetime.fromisoformat(healed)  # parses again


def test_verify_token_survives_bad_last_seen(tmp_path):
    from app.builder.errors import WorkerAuthFailed
    repo, engine = _make_repo(tmp_path / "panel.db")
    _raw_insert_bad_worker(engine)

    with pytest.raises(WorkerAuthFailed):
        repo.verify_worker_token("linux-master", "wrong-token")

    # healed despite the failure: no longer the poisoned value; the next
    # heartbeat persists a real timestamp.
    healed = _raw_seen(engine)
    assert healed != "SA-TEST-123"
    if healed is not None:
        datetime.fromisoformat(healed)
