"""alpha.7.9/alpha.8/alpha.8.1 routing desired-state replay regressions."""
from __future__ import annotations

import asyncio

import pytest

from app.platform.runtime import PlatformRuntime


class KV:
    def __init__(self, outbounds, rules):
        self.data = {
            "admin.outbounds.v1": outbounds,
            "admin.routing.rules.v1": rules,
        }
    async def get_value(self, key): return self.data.get(key)


class Outbounds:
    def __init__(self, events, fail=False):
        self.events = events; self.rows = []; self.fail = fail
    def list(self): return list(self.rows)
    def unregister(self, name): self.rows = [row for row in self.rows if row.name != name]
    def register(self, outbound): self.rows.append(outbound)
    async def deploy(self):
        self.events.append(("outbounds", [row.name for row in self.rows]))
        if self.fail: raise RuntimeError("interface did not appear")


class Routing:
    def __init__(self, events): self.events = events
    async def deploy(self, rules, *, outbounds):
        self.events.append(("rules", [row.name for row in rules],
                            [row.name for row in outbounds]))


def _runtime(*, fail=False):
    events = []
    runtime = object.__new__(PlatformRuntime)
    runtime.kv = KV(
        [{"name": "legacy-wg", "kind": "wireguard", "enabled": True,
          "settings": {"server": "198.51.100.9", "server_port": 51820,
                       "private_key": "x", "peer_public_key": "y",
                       "local_address": ["10.0.0.2/32"]}}],
        [{"name": "legacy-rule", "matcher": {"inbounds": ["openvpn"]},
          "action": "route_to", "outbound": "legacy-wg",
          "priority": 100, "enabled": True}],
    )
    runtime.outbound_manager = Outbounds(events, fail=fail)
    runtime.routing_engine = Routing(events)
    return runtime, events


def test_boot_replays_outbound_before_rule_for_old_kv_documents() -> None:
    runtime, events = _runtime()
    deferred = asyncio.run(runtime._hydrate_network_policy())
    assert deferred == set()
    assert events == [
        ("outbounds", ["legacy-wg"]),
        ("rules", ["legacy-rule"], ["legacy-wg"]),
    ]


def test_boot_report_fails_closed_when_policy_interface_cannot_restore() -> None:
    runtime, events = _runtime(fail=True)
    deferred = asyncio.run(runtime._hydrate_network_policy())
    assert deferred == {"policy"}
    assert events == [("outbounds", ["legacy-wg"])]


@pytest.mark.parametrize("released_baseline", [
    "v1.0.0-alpha.7.9", "v1.0.0-alpha.8", "v1.0.0-alpha.8.1",
])
def test_released_kv_shapes_replay_without_version_specific_loss(released_baseline) -> None:
    """All three released lines used the same KV source contract.

    Version metadata must not gate migration: names, grants and priorities
    converge through the shared replay path for every supported upgrade base.
    """
    runtime, events = _runtime()
    runtime.kv.data["release.source"] = released_baseline
    deferred = asyncio.run(runtime._hydrate_network_policy())
    assert deferred == set()
    assert events[0] == ("outbounds", ["legacy-wg"])
    assert events[1][1] == ["legacy-rule"]
