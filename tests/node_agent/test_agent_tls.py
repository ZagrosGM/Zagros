"""Real HTTPS subprocess integration for Panel API → Zagros Node lifecycle."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_real_panel_api_to_tls_agent_registration_health_lifecycle_and_revoke(
    tmp_path: Path,
) -> None:
    port = _free_port()
    cert, key = tmp_path / "node.crt", tmp_path / "node.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-sha256", "-subj", "/CN=127.0.0.1/O=Zagros Node Test",
        "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fingerprint = hashlib.sha256(subprocess.check_output(
        ["openssl", "x509", "-in", str(cert), "-outform", "der"])).hexdigest()
    token = "tls-one-time-registration-token-123"
    node_root = tmp_path / "state"
    node_root.mkdir()
    # A real production adapter is rehydrated in ERROR state so the panel can
    # drive an idempotent Error -> Stopped lifecycle without downloading or
    # starting a binary. The node's driver transform selects StandaloneXrayBackend.
    (node_root / "cores.json").write_text(json.dumps({
        "xray": {
            "state": "error", "enabled": False,
            "settings": {
                "executable_path": str(tmp_path / "runtime/xray"),
                "assets_path": str(tmp_path / "runtime/assets"),
                "config_path": str(tmp_path / "runtime/xray.json"),
            },
        },
    }))
    env = os.environ.copy()
    env.update({
        "ZAGROS_NODE_DATA": str(node_root),
        "ZAGROS_NODE_PORT": str(port),
        "ZAGROS_NODE_HOST": "127.0.0.1",
        "ZAGROS_NODE_TLS_CERT": str(cert),
        "ZAGROS_NODE_TLS_KEY": str(key),
        "ZAGROS_NODE_REGISTRATION_HASH": hashlib.sha256(token.encode()).hexdigest(),
    })
    process = subprocess.Popen(
        [sys.executable, "-m", "app.node_agent"], cwd=Path(__file__).parents[2],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f"agent exited: {process.stderr.read()[-2000:]}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("agent TLS port did not start")

        # Warm the real application import graph before admin_api so its
        # fail-closed sudo dependency binds the real Admin class rather than
        # the circular-import safety stub (test ordering must not change auth).
        import app as app_package
        app_package.app  # noqa: B018 - deliberate lazy-app attribute access

        from app.persistence.base import create_schema
        from app.persistence.models import NodeModel, PendingNodeRegistrationModel
        from app.platform import admin_api  # noqa: F401 - register routes
        from app.platform.routers import zagros_admin_router, zagros_router
        from app.platform.runtime import PlatformRuntime

        runtime = PlatformRuntime(
            database_url=f"sqlite:///{tmp_path / 'panel.db'}",
            master_secret="panel-real-tls-secret-0123456789",
        )
        create_schema(runtime.session_factory)
        panel = FastAPI()
        panel.state.zagros = runtime
        # The integration is about the authenticated node control plane. The
        # router's sudo dependency is tested elsewhere; override that one
        # dependency without bypassing any node signature/TLS verification.
        for dependency in zagros_admin_router.dependencies:
            panel.dependency_overrides[dependency.dependency] = lambda: {
                "username": "node-test-admin"}
        panel.include_router(zagros_router)
        panel.include_router(zagros_admin_router)

        with TestClient(panel) as client:
            pending_response = client.post("/api/zagros/nodes/pending", json={
                "name": "tls-node-1", "address": "127.0.0.1",
                "api_port": port, "expires_in_seconds": 900,
            })
            assert pending_response.status_code == 200, pending_response.text
            pending_result = pending_response.json()
            node_id = pending_result["node_id"]
            command = pending_result["installer_command"]
            assert "--pending-id" in command and "--registration-token" in command

            # The command is the sole disclosure point. Recover its shell-safe
            # test token to emulate the installer callback over the public,
            # token-authenticated route.
            import shlex
            words = shlex.split(command)
            registration_token = words[words.index("--registration-token") + 1]
            callback = client.post("/api/zagros/node-registration/callback", json={
                "pending_id": pending_result["pending_id"],
                "registration_token": registration_token,
                "bootstrap_token": token,
                "certificate_fingerprint": fingerprint,
                "agent_version": "1.0.0-test",
            })
            assert callback.status_code == 200, callback.text
            node = callback.json()
            assert node["agent_type"] == "zagros_native"
            assert node["certificate_fingerprint"] == fingerprint
            replay = client.post("/api/zagros/node-registration/callback", json={
                "pending_id": pending_result["pending_id"],
                "registration_token": registration_token,
                "bootstrap_token": token,
                "certificate_fingerprint": fingerprint,
            })
            assert replay.status_code == 401

            expired_response = client.post("/api/zagros/nodes/pending", json={
                "name": "tls-node-expired", "address": "127.0.0.1",
                "api_port": port, "expires_in_seconds": 60,
            })
            assert expired_response.status_code == 200
            expired_result = expired_response.json()
            expired_words = shlex.split(expired_result["installer_command"])
            expired_token = expired_words[expired_words.index("--registration-token") + 1]
            from datetime import datetime, timedelta, timezone
            with runtime.session_factory() as session:
                expired_row = session.get(PendingNodeRegistrationModel,
                                          expired_result["pending_id"])
                expired_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                session.commit()
            expired_callback = client.post("/api/zagros/node-registration/callback", json={
                "pending_id": expired_result["pending_id"],
                "registration_token": expired_token,
                "bootstrap_token": "unused-expired-bootstrap-token",
                "certificate_fingerprint": fingerprint,
            })
            assert expired_callback.status_code == 401
            with runtime.session_factory() as session:
                expired_row = session.get(PendingNodeRegistrationModel,
                                          expired_result["pending_id"])
                assert expired_row.status == "expired" and expired_row.consumed_at is None
            removed_expired = client.delete(
                f"/api/zagros/nodes/{expired_result['node_id']}")
            assert removed_expired.status_code == 200
            assert removed_expired.json()["remote_revoked"] is False

            # Panel persistence contains only AES-GCM ciphertext. Neither the
            # bootstrap token nor raw signing key is a database column/value.
            with runtime.session_factory() as session:
                row = session.get(NodeModel, node_id)
                assert row is not None and row.agent_credentials_enc
                serialized = json.dumps({
                    "credentials": row.agent_credentials_enc,
                    "settings": row.settings_json,
                })
                assert token not in serialized
                assert registration_token not in serialized
                assert "signing_key" not in serialized
                pending = session.get(PendingNodeRegistrationModel,
                                      pending_result["pending_id"])
                assert pending is not None and pending.status == "consumed"
                assert pending.consumed_at is not None
                assert len(pending.token_hash) == 64
                assert pending.token_hash != registration_token
                decrypted = runtime.cipher.decrypt_json(
                    row.agent_credentials_enc,
                    aad=f"node-agent:{row.agent_identity}")
                assert len(decrypted["signing_key"]) >= 40

            # Duplicate-name preflight happens before certificate/bootstrap
            # work, so it cannot consume another registration authority.
            duplicate = client.post("/api/zagros/nodes/register", json={
                "name": "tls-node-1", "address": "127.0.0.1", "port": port,
                "registration_token": "already-consumed-token-value",
                "certificate_fingerprint": fingerprint,
            })
            assert duplicate.status_code == 409

            heartbeat = client.post(f"/api/zagros/nodes/{node_id}/heartbeat")
            assert heartbeat.status_code == 200, heartbeat.text
            result = heartbeat.json()
            assert result["status"] == "connected"
            assert result["heartbeat"]["agent"] == "zagros-node"
            assert result["health"]["healthy"] is True
            assert "available" in result["cores"]
            assert "xray" in result["cores"]["installed"]

            with runtime.session_factory() as session:
                old_ciphertext = session.get(NodeModel, node_id).agent_credentials_enc
            mismatch = client.post(
                f"/api/zagros/nodes/{node_id}/reenroll",
                json={"certificate_fingerprint": "0" * 64})
            assert mismatch.status_code == 502
            with runtime.session_factory() as session:
                assert session.get(NodeModel, node_id).status == "connected"
                assert session.get(NodeModel, node_id).agent_credentials_enc == old_ciphertext
            reenrolled = client.post(
                f"/api/zagros/nodes/{node_id}/reenroll", json={})
            assert reenrolled.status_code == 200, reenrolled.text
            assert reenrolled.json()["status"] == "connected"
            with runtime.session_factory() as session:
                rotated = session.get(NodeModel, node_id)
                assert rotated.agent_credentials_enc != old_ciphertext
            after_rotation = client.post(f"/api/zagros/nodes/{node_id}/heartbeat")
            assert after_rotation.status_code == 200, after_rotation.text

            lifecycle = client.post(
                f"/api/zagros/nodes/{node_id}/cores/xray/lifecycle",
                json={"action": "stop", "settings": {},
                      "purge": False, "force": False},
            )
            assert lifecycle.status_code == 200, lifecycle.text
            assert lifecycle.json()["state"] == "stopped"
            log_result = client.get(
                f"/api/zagros/nodes/{node_id}/cores/xray/logs?tail=20")
            assert log_result.status_code == 200, log_result.text
            assert log_result.json()["core_id"] == "xray"

            deleted = client.delete(f"/api/zagros/nodes/{node_id}")
            assert deleted.status_code == 200, deleted.text
            assert deleted.json()["remote_revoked"] is True
            assert client.get("/api/zagros/nodes").json()["nodes"] == []

        identity = json.loads((node_root / "identity.json").read_text())
        assert identity["registration_token_hash"] == ""
        assert identity["signing_key_enc"] is None
        assert "signing_key" not in identity
        assert token not in (node_root / "identity.json").read_text()
        assert (node_root / "identity.key").stat().st_mode & 0o777 == 0o600
        assert "core.lifecycle" in (node_root / "audit.jsonl").read_text()
        sealed_state = (node_root / "cores.json").read_text()
        assert "settings_enc" in sealed_state and '"settings"' not in sealed_state
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        assert process.poll() is not None
