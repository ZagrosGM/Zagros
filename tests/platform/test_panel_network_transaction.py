"""Panel Network DB + root-agent transaction regressions."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.platform import admin_api
from app.platform.network_settings import HostNetworkRequest


class _KV:
    def __init__(self, values=None): self.values = dict(values or {})
    async def get_value(self, key): return self.values.get(key)
    async def set_value(self, key, value): self.values[key] = value


class _Manager:
    def list_cores(self): return []


class _Runtime:
    def __init__(self, initial):
        self.kv = _KV({
            admin_api._PANEL_NETWORK_KEY: initial,
            admin_api._PANEL_NETWORK_APPLIED_KEY: initial,
        })
        self.core_manager = _Manager()


_INITIAL = {
    "domain": "old.example.com", "port": 8000, "scheme": "http",
    "bind_address": "0.0.0.0", "trusted_proxies": [], "hsts": False,
    "redirect_http_to_https": False, "tls_certificate_id": None,
}
_CANDIDATE = {**_INITIAL, "domain": "new.example.com", "port": 8080}


def test_apply_without_host_agent_never_mutates_desired_state(monkeypatch) -> None:
    runtime = _Runtime(_INITIAL)
    monkeypatch.setattr(HostNetworkRequest, "agent_ready", lambda self: False)
    async def no_conflict(*_args, **_kwargs): return []
    monkeypatch.setattr(admin_api, "_validate_panel_port_ownership", no_conflict)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(admin_api.panel_network_apply(_CANDIDATE, runtime))
    assert caught.value.status_code == 503
    assert runtime.kv.values[admin_api._PANEL_NETWORK_KEY] == _INITIAL
    assert admin_api._PANEL_NETWORK_PENDING_KEY not in runtime.kv.values


def test_agent_failure_restores_previous_db_state(monkeypatch) -> None:
    runtime = _Runtime(_INITIAL)
    operation = "a" * 32
    monkeypatch.setattr(HostNetworkRequest, "agent_ready", lambda self: True)
    monkeypatch.setattr(
        HostNetworkRequest, "request",
        lambda self, settings, operation_id=None: {
            "accepted": True, "status": "pending",
            "operation_id": operation_id, "public_url": settings.public_url(),
        },
    )
    async def no_conflict(*_args, **_kwargs): return []
    monkeypatch.setattr(admin_api, "_validate_panel_port_ownership", no_conflict)
    monkeypatch.setattr(admin_api.secrets, "token_hex", lambda _n: operation)

    accepted = asyncio.run(admin_api.panel_network_apply(_CANDIDATE, runtime))
    assert accepted["operation_id"] == operation
    assert runtime.kv.values[admin_api._PANEL_NETWORK_KEY]["domain"] == "new.example.com"
    assert runtime.kv.values[admin_api._PANEL_NETWORK_PENDING_KEY]["previous"] == _INITIAL

    monkeypatch.setattr(
        HostNetworkRequest, "status",
        lambda self, operation_id=None: {
            "operation_id": operation_id, "status": "failed",
            "rolled_back": True, "message": "previous .env restored",
        },
    )
    result = asyncio.run(admin_api.panel_network_apply_status(operation, runtime))
    assert result["status"] == "failed" and result["rolled_back"] is True
    assert runtime.kv.values[admin_api._PANEL_NETWORK_KEY] == _INITIAL
    assert runtime.kv.values[admin_api._PANEL_NETWORK_PENDING_KEY] is None


def test_agent_success_finalizes_candidate_state(monkeypatch) -> None:
    runtime = _Runtime(_INITIAL)
    operation = "b" * 32
    runtime.kv.values[admin_api._PANEL_NETWORK_KEY] = dict(_CANDIDATE)
    runtime.kv.values[admin_api._PANEL_NETWORK_PENDING_KEY] = {
        "operation_id": operation, "previous": _INITIAL,
        "candidate": _CANDIDATE,
    }
    monkeypatch.setattr(
        HostNetworkRequest, "status",
        lambda self, operation_id=None: {
            "operation_id": operation_id, "status": "success",
            "rolled_back": False,
        },
    )
    result = asyncio.run(admin_api.panel_network_apply_status(operation, runtime))
    assert result["status"] == "success"
    assert runtime.kv.values[admin_api._PANEL_NETWORK_KEY] == _CANDIDATE
    assert runtime.kv.values[admin_api._PANEL_NETWORK_APPLIED_KEY] == _CANDIDATE
    assert runtime.kv.values[admin_api._PANEL_NETWORK_PENDING_KEY] is None
