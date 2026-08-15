"""Native node registration, signing, replay and allowlisted lifecycle."""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import secrets
import time

import pytest
from fastapi.testclient import TestClient

from app.node_agent.security import signature


def _headers(node_id: str, key: bytes, method: str, path: str, body: bytes,
             *, nonce: str | None = None) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    return {
        "X-Zagros-Node": node_id,
        "X-Zagros-Timestamp": timestamp,
        "X-Zagros-Nonce": nonce,
        "X-Zagros-Signature": signature(
            key, method, path, timestamp, nonce, body),
        "Content-Type": "application/json",
    }


def _post_signed(client, node_id: str, key: bytes, path: str, payload: dict):
    body = json.dumps(payload, separators=(",", ":")).encode()
    return client.post(path, content=body,
                       headers=_headers(node_id, key, "POST", path, body))


def test_registration_signed_heartbeat_replay_guard_and_real_core_lifecycle(
    tmp_path, monkeypatch,
) -> None:
    token = "one-time-registration-token-123456"
    monkeypatch.setenv("ZAGROS_NODE_DATA", str(tmp_path))
    monkeypatch.setenv("ZAGROS_NODE_REGISTRATION_HASH",
                       hashlib.sha256(token.encode()).hexdigest())
    monkeypatch.setenv("ZAGROS_NODE_ALLOW_INSECURE_TEST", "1")
    # Rehydrate a production Xray adapter without starting a binary. This
    # proves native-node composition selects the standalone backend instead
    # of importing the panel's legacy DB/singletons. Error -> Stop is a real,
    # successful idempotent lifecycle transition through CoreManager.
    (tmp_path / "cores.json").write_text(json.dumps({
        "xray": {
            "state": "error", "enabled": False,
            "settings": {
                "executable_path": str(tmp_path / "xray"),
                "assets_path": str(tmp_path / "assets"),
                "config_path": str(tmp_path / "xray.json"),
            },
        },
    }))
    module = importlib.import_module("app.node_agent.app")
    module = importlib.reload(module)

    with TestClient(module.app) as client:
        registered = client.post("/v1/register", json={
            "panel_id": "panel-test-1", "registration_token": token})
        assert registered.status_code == 200, registered.text
        payload = registered.json()
        node_id = payload["node_id"]
        key = base64.b64decode(payload["signing_key"])
        assert len(key) == 32

        # Bootstrap token is burned; plaintext never appears in state.
        state_text = (tmp_path / "identity.json").read_text()
        assert token not in state_text
        assert payload["signing_key"] not in state_text
        identity_state = json.loads(state_text)
        assert identity_state["registration_token_hash"] == ""
        assert identity_state["signing_key_enc"]
        assert "signing_key" not in identity_state
        assert (tmp_path / "identity.key").stat().st_mode & 0o777 == 0o600
        again = client.post("/v1/register", json={
            "panel_id": "panel-test-2", "registration_token": token})
        assert again.status_code == 401

        path = "/v1/heartbeat"
        nonce = secrets.token_hex(16)
        headers = _headers(node_id, key, "GET", path, b"", nonce=nonce)
        assert client.get(path, headers=headers).status_code == 200
        replay = client.get(path, headers=headers)
        assert replay.status_code == 401 and "replayed" in replay.text
        # Replay state survives object/process reconstruction.
        from app.node_agent.security import NodeSecurityError, ReplayGuard
        with pytest.raises(NodeSecurityError, match="replayed"):
            ReplayGuard(str(tmp_path)).accept(
                nonce, int(headers["X-Zagros-Timestamp"]))
        assert (tmp_path / "replay.json").stat().st_mode & 0o777 == 0o600

        # No arbitrary command endpoint exists.
        shell = client.post("/v1/shell", content=b"{}",
                            headers=_headers(node_id, key, "POST", "/v1/shell", b"{}"))
        assert shell.status_code == 404

        from app.cores.drivers.xray.standalone import StandaloneXrayBackend
        assert isinstance(module.core_manager.get("xray")._backend,
                          StandaloneXrayBackend)
        xray_path = "/v1/cores/xray/lifecycle"
        stopped = _post_signed(client, node_id, key, xray_path, {
            "action": "stop", "settings": {}, "purge": False, "force": False})
        assert stopped.status_code == 200, stopped.text
        assert stopped.json()["state"] == "stopped"
        state_text = (tmp_path / "cores.json").read_text()
        assert "settings_enc" in state_text and '"settings"' not in state_text

        # A signed panel still has bounded authority: core ids and setting keys
        # are allowlisted; neither arbitrary adapters nor shell-like settings
        # can be smuggled through the lifecycle endpoint.
        unknown_path = "/v1/cores/node-test/lifecycle"
        unknown = _post_signed(client, node_id, key, unknown_path, {
            "action": "install", "settings": {}, "purge": False, "force": False})
        assert unknown.status_code == 403
        bad_setting = _post_signed(client, node_id, key, xray_path, {
            "action": "install", "settings": {"shell_command": "id"},
            "purge": False, "force": False})
        assert bad_setting.status_code == 422
        bad_action = _post_signed(client, node_id, key, xray_path, {
            "action": "shell", "settings": {}})
        assert bad_action.status_code == 422
