"""Encrypted-at-rest node core desired-state persistence."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from app.cores.types import CoreState
from app.node_agent.security import NodeIdentityStore
from app.node_agent.state import NodeCoreStateStore


def test_state_settings_are_sealed_atomic_and_root_private(tmp_path: Path) -> None:
    store = NodeCoreStateStore(tmp_path)
    asyncio.run(store.save_state(
        "xray", state=CoreState.INSTALLED, enabled=False,
        settings={"api_secret": "never-on-disk", "config_path": "/data/xray.json"},
    ))
    text = (tmp_path / "cores.json").read_text()
    assert "never-on-disk" not in text
    assert '"settings_enc"' in text and '"settings"' not in text
    assert (tmp_path / "state.key").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "cores.json").stat().st_mode & 0o777 == 0o600
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert not (tmp_path / "cores.part").exists()

    loaded = asyncio.run(NodeCoreStateStore(tmp_path).load())
    assert loaded["xray"]["settings"] == {
        "api_secret": "never-on-disk", "config_path": "/data/xray.json"}


def test_state_rejects_tamper_and_wrong_local_key(tmp_path: Path) -> None:
    store = NodeCoreStateStore(tmp_path)
    asyncio.run(store.save_state(
        "ssh", state=CoreState.STOPPED, enabled=True,
        settings={"password": "sealed-value"},
    ))
    original_state = (tmp_path / "cores.json").read_text()
    original_key = (tmp_path / "state.key").read_bytes()

    payload = json.loads(original_state)
    ciphertext = payload["ssh"]["settings_enc"]
    payload["ssh"]["settings_enc"] = (
        ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:])
    (tmp_path / "cores.json").write_text(json.dumps(payload))
    with pytest.raises(Exception):
        asyncio.run(NodeCoreStateStore(tmp_path).load())

    (tmp_path / "cores.json").write_text(original_state)
    (tmp_path / "state.key").write_bytes(os.urandom(32))
    with pytest.raises(Exception):
        asyncio.run(NodeCoreStateStore(tmp_path).load())

    # Restoring the original key proves failures were authentication failures,
    # not an accidentally malformed state fixture.
    (tmp_path / "state.key").write_bytes(original_key)
    assert asyncio.run(NodeCoreStateStore(tmp_path).load())["ssh"]["settings"] == {
        "password": "sealed-value"}


def test_legacy_plaintext_signing_key_migrates_immediately(tmp_path: Path) -> None:
    import base64

    signing_key = bytes(range(32))
    (tmp_path / "identity.json").write_text(json.dumps({
        "node_id": "a" * 32,
        "registration_token_hash": "",
        "signing_key": base64.b64encode(signing_key).decode("ascii"),
        "registered_panel": "panel-legacy",
    }))
    identity = NodeIdentityStore(str(tmp_path))
    assert identity.signing_key() == signing_key
    persisted = json.loads((tmp_path / "identity.json").read_text())
    assert "signing_key" not in persisted
    assert persisted["signing_key_enc"]
    assert base64.b64encode(signing_key).decode("ascii") not in json.dumps(persisted)


def test_legacy_plaintext_state_migrates_once_without_data_loss(tmp_path: Path) -> None:
    secret = "legacy-plaintext-secret"
    (tmp_path / "cores.json").write_text(json.dumps({
        "wireguard": {
            "state": "installed", "enabled": True,
            "settings": {"private_key": secret, "interface": "wg9"},
        },
    }))
    loaded = asyncio.run(NodeCoreStateStore(tmp_path).load())
    assert loaded["wireguard"]["settings"]["private_key"] == secret
    migrated = (tmp_path / "cores.json").read_text()
    assert secret not in migrated
    assert "settings_enc" in migrated and '"settings"' not in migrated
