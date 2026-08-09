"""Online presence indicator semantics (alpha.7.5 items 14+15).

  * online  — fresh session evidence (device collect or legacy touch);
  * offline — no evidence AND at least one online-capable core answered;
  * unknown — a core failed its read OR NO online-capable core answered at
    all (a core without an online API must never fabricate 'offline').

Run: pytest tests/platform/test_online_states.py -q
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.platform import admin_api  # noqa: E402


class _KV:
    def __init__(self, snapshot):
        self._snapshot = snapshot

    async def get_value(self, key):
        assert key == "online.last_collect"
        return self._snapshot


class _Users:
    def __init__(self, rows):
        self._rows = rows

    def list_users(self, limit=100000):
        return self._rows


def _runtime(snapshot, usernames=("alice", "bob")):
    rows = [SimpleNamespace(id=i + 1, username=name)
            for i, name in enumerate(usernames)]
    return SimpleNamespace(kv=_KV(snapshot), users=_Users(rows))


def test_offline_only_when_an_online_capable_core_answered():
    runtime = _runtime({"ts": 1.0, "failed_cores": [], "probed_cores": 2,
                        "online_user_ids": []})
    out = asyncio.run(admin_api.users_online_states(runtime))
    assert set(out["states"].values()) == {"offline"}
    assert out["probed_cores"] == 2


def test_no_online_api_is_unknown_never_fake_offline():
    """item 15: a deployment whose cores all lack an online API must not
    claim 'offline' — everybody is honestly unknown."""
    runtime = _runtime({"ts": 1.0, "failed_cores": [], "probed_cores": 0,
                        "online_user_ids": []})
    out = asyncio.run(admin_api.users_online_states(runtime))
    assert set(out["states"].values()) == {"unknown"}
    assert out["probed_cores"] == 0


def test_failed_core_read_is_unknown():
    runtime = _runtime({"ts": 1.0, "failed_cores": ["sing-box"],
                        "probed_cores": 1, "online_user_ids": []})
    out = asyncio.run(admin_api.users_online_states(runtime))
    assert set(out["states"].values()) == {"unknown"}


def test_fresh_presence_evidence_is_online():
    runtime = _runtime({"ts": 1.0, "failed_cores": [], "probed_cores": 1,
                        "online_user_ids": [1]})
    out = asyncio.run(admin_api.users_online_states(runtime))
    assert out["states"]["alice"] == "online"
    assert out["states"]["bob"] == "offline"


def test_legacy_snapshot_without_probe_count_is_honestly_unknown():
    # a kv snapshot written by an older panel version carries no count —
    # absence of the count is NOT proof that anything answered
    runtime = _runtime({"ts": 1.0, "failed_cores": [], "online_user_ids": []})
    out = asyncio.run(admin_api.users_online_states(runtime))
    assert set(out["states"].values()) == {"unknown"}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
