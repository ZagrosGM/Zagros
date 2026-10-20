"""MirzaBot/Marzban compatibility regressions over Zagros native nodes."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

# Importing a router submodule directly would otherwise enter the legacy
# notification cycle before app.__init__ has preseeded its FastAPI singleton.
import app as _app_warm
_app_warm.app  # noqa: B018

from app.nodes.models import NodeCores, NodeView
from app.routers import node_compat, routers
from app.routers.user import get_user_subscription_updates


def _node(**over) -> NodeView:
    values = dict(
        id=7,
        name="Riga",
        address="203.0.113.7",
        port=62050,
        api_port=62051,
        status="connected",
        usage_coefficient=1.25,
        add_as_new_host=True,
        agent_type="zagros_native",
        agent_identity="node-7",
        agent_version="1.0.4",
        last_seen="2026-09-05T10:00:00+00:00",
        last_error=None,
        cores=NodeCores(installed={
            "xray": {"version": "26.3.27", "running": True}
        }),
    )
    values.update(over)
    return NodeView(**values)


def test_legacy_node_routes_are_registered_with_exact_mirza_methods() -> None:
    assert node_compat.router in routers
    routes = {(route.path, method)
              for route in node_compat.router.routes
              for method in getattr(route, "methods", set())}
    assert ("/api/nodes", "GET") in routes
    assert ("/api/nodes/usage", "GET") in routes
    assert ("/api/node/{node_id}", "GET") in routes
    assert ("/api/node/{node_id}", "PUT") in routes
    assert ("/api/node/{node_id}", "DELETE") in routes
    assert ("/api/node/{node_id}/reconnect", "POST") in routes


def test_list_is_a_direct_array_and_maps_fields_mirzabot_reads(monkeypatch) -> None:
    async def fake_list(_runtime):
        return [_node()]

    monkeypatch.setattr(node_compat, "list_nodes", fake_list)
    result = asyncio.run(node_compat.compat_nodes(
        _admin=SimpleNamespace(), runtime=SimpleNamespace()))
    assert isinstance(result, list) and len(result) == 1
    assert result[0] == {
        "id": 7,
        "name": "Riga",
        "address": "203.0.113.7",
        "port": 62050,
        "api_port": 62051,
        "usage_coefficient": 1.25,
        "status": "connected",
        "message": None,
        "xray_version": "26.3.27",
        "agent_type": "zagros_native",
        "agent_version": "1.0.4",
        "last_seen": "2026-09-05T10:00:00+00:00",
    }


def test_modify_translates_mirza_payload_to_native_node_update(monkeypatch) -> None:
    seen = {}

    async def fake_update(runtime, node_id, body):
        dump = getattr(body, "model_dump", None)
        seen.update(dump(exclude_none=True) if dump else body.dict(exclude_none=True))
        assert node_id == 7
        return _node(name=seen["name"], usage_coefficient=seen["usage_coefficient"])

    monkeypatch.setattr(node_compat, "update_node", fake_update)
    response = asyncio.run(node_compat.compat_node_update(
        7,
        node_compat.CompatNodeModify(name="New name", usage_coefficient=1.5),
        _admin=SimpleNamespace(), runtime=SimpleNamespace(),
    ))
    assert seen == {"name": "New name", "usage_coefficient": 1.5}
    assert response["name"] == "New name"
    assert response["usage_coefficient"] == 1.5


def test_mirza_legacy_subscription_update_snapshot_shape() -> None:
    seen_at = datetime(2026, 9, 5, 12, 30, tzinfo=timezone.utc)
    result = get_user_subscription_updates(
        offset=0, limit=1,
        dbuser=SimpleNamespace(
            sub_updated_at=seen_at, sub_last_user_agent="v2rayNG/1.9"),
    )
    assert result == {
        "updates": [{"created_at": seen_at, "user_agent": "v2rayNG/1.9"}],
        "total": 1,
    }


def test_native_status_cannot_be_forged_through_legacy_update() -> None:
    with pytest.raises(Exception) as exc:
        asyncio.run(node_compat.compat_node_update(
            7, node_compat.CompatNodeModify(status="disabled"),
            _admin=SimpleNamespace(), runtime=SimpleNamespace()))
    assert getattr(exc.value, "status_code", None) == 422
