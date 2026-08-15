"""Panel Network validation and host-handoff regressions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cores.types import ListenerClaim
from app.platform.network_settings import (
    HostNetworkRequest,
    PanelNetworkSettings,
    detect_port_conflicts,
)


def test_panel_network_https_shape_and_public_url() -> None:
    settings = PanelNetworkSettings(
        domain="panel.example.com", port=8443, scheme="https",
        bind_address="0.0.0.0", trusted_proxies=["10.0.0.1", "10.0.0.0/24"],
        hsts=True, redirect_http_to_https=True,
        tls_certificate_id="certs/panel",
    )
    assert settings.public_url() == "https://panel.example.com:8443"
    assert settings.trusted_proxies == ["10.0.0.0/24", "10.0.0.1/32"]


@pytest.mark.parametrize("payload, match", [
    ({"bind_address": "host.example", "port": 8000}, "bind_address"),
    ({"bind_address": "0.0.0.0", "port": 8000, "scheme": "http", "hsts": True}, "HSTS"),
    ({"bind_address": "0.0.0.0", "port": 443, "scheme": "https", "domain": "panel.example.com"}, "certificate"),
    ({"bind_address": "0.0.0.0", "port": 8000, "trusted_proxies": ["bad"]}, "trusted proxy"),
])
def test_panel_network_rejects_ambiguous_or_unsafe_shape(payload, match) -> None:
    with pytest.raises(ValueError, match=match):
        PanelNetworkSettings.model_validate(payload)


def test_host_apply_request_is_atomic_private_and_secret_free(tmp_path: Path) -> None:
    settings = PanelNetworkSettings(
        domain="panel.example.com", port=443, scheme="https",
        bind_address="0.0.0.0", tls_certificate_id="certs/panel",
    )
    handoff = HostNetworkRequest(str(tmp_path))
    (tmp_path / ".agent-ready").touch()
    result = handoff.request(settings)
    path = tmp_path / "panel-network.request.json"
    assert result["accepted"] is True and result["status"] == "pending"
    assert path.stat().st_mode & 0o777 == 0o600
    body = json.loads(path.read_text())
    assert body["operation_id"] == result["operation_id"]
    assert body["settings"]["domain"] == "panel.example.com"
    assert not list(tmp_path.glob("*.part"))
    lowered = path.read_text().lower()
    assert "password" not in lowered and "private_key" not in lowered


def test_apply_is_honestly_disabled_without_host_agent(tmp_path: Path) -> None:
    handoff = HostNetworkRequest(str(tmp_path))
    with pytest.raises(RuntimeError, match="host network agent is not installed"):
        handoff.request(PanelNetworkSettings())


def test_unspecified_bind_is_never_advertised_as_a_public_host() -> None:
    settings = PanelNetworkSettings(port=8000, scheme="http", bind_address="0.0.0.0")
    assert settings.public_url() == "http://127.0.0.1:8000"


def test_port_443_conflict_is_attributed_to_softether_sstp(monkeypatch) -> None:
    import asyncio

    class Driver:
        async def listener_claims(self):
            return [ListenerClaim(
                core_id="softether", protocol="sstp", port=443,
                label="SoftEther SSTP")]

    class Manager:
        def list_cores(self): return ["softether"]
        def get(self, _core_id): return Driver()

    runtime = type("Runtime", (), {"core_manager": Manager()})()
    monkeypatch.setattr(
        "app.platform.network_settings._live_tcp_listeners",
        lambda _port: [("0.0.0.0", 7123, "vpnserver")],
    )
    settings = PanelNetworkSettings(
        domain="panel.example.com", port=443, scheme="http",
        bind_address="0.0.0.0")
    conflicts = asyncio.run(detect_port_conflicts(
        runtime, settings, current_panel_port=8000))
    assert len(conflicts) == 1
    assert conflicts[0].owner == "SoftEther SSTP"
    assert conflicts[0].protocol == "sstp"
    assert conflicts[0].message().startswith(
        "Port 443 is already owned by SoftEther SSTP")


def test_current_panel_listener_is_not_a_conflict(monkeypatch) -> None:
    import asyncio
    import os

    class Manager:
        def list_cores(self): return []

    runtime = type("Runtime", (), {"core_manager": Manager()})()
    monkeypatch.setattr(
        "app.platform.network_settings._live_tcp_listeners",
        lambda _port: [("0.0.0.0", os.getpid(), "python")],
    )
    conflicts = asyncio.run(detect_port_conflicts(
        runtime, PanelNetworkSettings(port=8000), current_panel_port=8000))
    assert conflicts == []


def test_public_transition_probe_is_image_only_after_success(monkeypatch) -> None:
    import asyncio

    from app.platform.routers import panel_network_transition_probe

    monkeypatch.setattr(
        HostNetworkRequest, "status",
        lambda self, operation_id=None: {"status": "pending"})
    pending = asyncio.run(panel_network_transition_probe("a" * 32))
    assert pending.status_code == 503

    monkeypatch.setattr(
        HostNetworkRequest, "status",
        lambda self, operation_id=None: {"status": "success",
                                         "operation_id": operation_id})
    ready = asyncio.run(panel_network_transition_probe("a" * 32))
    assert ready.status_code == 200
    assert ready.media_type == "image/svg+xml"
    assert b"<svg" in ready.body
