"""f-noderouting-2 (phase A, v1.1.3) — routing rules/outbounds on NODES.

Panel side:
  * ``RuleScope.applies_on_node`` — default scopes reach EVERY node, a
    node-scoped rule reaches only the nodes it lists;
  * ``effective_rules_for_node`` — the exact set one node must enforce;
  * ``_push_policy`` builds the FULL-state payload (rules + outbound
    profiles, credentials included) and skips old agents with a NOTE,
    never a silent drop.
Agent side:
  * ``PUT /v1/policy`` applies/tears down the plane; feature advertised.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_NEED = ("sqlalchemy", "fastapi")
_HAS = all(importlib.util.find_spec(m) for m in _NEED)
pytestmark = pytest.mark.skipif(not _HAS, reason="full panel requirements not installed")


# ---------------------------------------------------------------- panel --- #
def test_scope_reaches_every_node_by_default():
    from app.cores.routing.model import RoutingRule, RuleAction, RuleScope

    everywhere = RoutingRule(name="all", matcher=_matcher(),
                             action=RuleAction.ALLOW)
    assert everywhere.scope.applies_on_node(1)
    assert everywhere.scope.applies_on_node(42)
    assert not everywhere.scope.applies_on_master()

    pinned = RoutingRule(name="node2only", matcher=_matcher(),
                         action=RuleAction.ALLOW,
                         scope=RuleScope(nodes=[2]))
    assert pinned.scope.applies_on_node(2)
    assert not pinned.scope.applies_on_node(1)
    assert pinned.scope.applies_on_master()  # excluded from the master deploy


def _matcher():
    from app.cores.routing.model import RuleMatcher

    return RuleMatcher(geoips=["ir"])


def test_effective_rules_for_node_filters_enabled_and_scope():
    from app.cores.routing.model import (RoutingRule, RuleAction, RuleScope,
                                         effective_rules_for_node)

    rules = [
        RoutingRule(name="r1", matcher=_matcher(), action=RuleAction.ALLOW),
        RoutingRule(name="r2", matcher=_matcher(), action=RuleAction.ALLOW,
                    enabled=False),
        RoutingRule(name="r3", matcher=_matcher(), action=RuleAction.ALLOW,
                    scope=RuleScope(nodes=[2])),
        RoutingRule(name="r4", matcher=_matcher(), action=RuleAction.ALLOW,
                    scope=RuleScope(nodes=[7])),
    ]
    node2 = effective_rules_for_node(rules, 2)
    assert [r.name for r in node2] == ["r1", "r3"], (
        "disabled rules and other-node scopes never reach node 2")
    node7 = effective_rules_for_node(rules, 7)
    assert [r.name for r in node7] == ["r1", "r4"]


class _FakeKV:
    def __init__(self, store):
        self._store = store

    async def get_value(self, key):
        return self._store.get(key)

    async def set_value(self, key, value):
        self._store[key] = value


class _FakeClient:
    def __init__(self, features):
        self._features = features
        self.payloads = []

    def cores(self):
        return {"installed": {}, "features": self._features}

    def apply_policy(self, payload):
        self.payloads.append(payload)
        return {"ok": True, "applied": {}, "unsupported": {}, "notes": {}}


class _FakeRow:
    id = 2
    name = "node2"


@pytest.mark.skipif(not _HAS, reason="deps")
def test_push_policy_sends_full_state_and_skips_old_agents():
    from app.cores.outbounds.model import Outbound, OutboundKind
    from app.cores.routing.model import RoutingRule, RuleAction
    from app.nodes.service import _push_policy

    cipher = _NullCipher()
    outbounds = [Outbound(name="eu-exit", kind=OutboundKind.SOCKS,
                          settings={"server": "10.0.0.1", "server_port": 1080,
                                    "password": "hushhush"})]
    store = {
        "admin.routing.rules.v1": [
            RoutingRule(name="route-eu", matcher=_matcher(),
                        action=RuleAction.ROUTE_TO, outbound="eu-exit",
                        scope=__import__("app.cores.routing.model",
                                         fromlist=["RuleScope"]).RuleScope(nodes=[2])
                        ).model_dump(mode="json"),
            RoutingRule(name="other-node", matcher=_matcher(),
                        action=RuleAction.ALLOW,
                        scope=__import__("app.cores.routing.model",
                                         fromlist=["RuleScope"]).RuleScope(nodes=[9])
                        ).model_dump(mode="json"),
        ],
        "admin.outbounds.v1": cipher.encode(outbounds),
    }
    runtime = type("R", (), {"kv": _FakeKV(store), "cipher": cipher})()

    client = _FakeClient(features={"policy_routing": 1})
    result = SyncResultShim()
    summary = asyncio.run(_push_policy(runtime, client, _FakeRow(), result,
                                       features={"policy_routing": 1}))
    assert summary["pushed"] is True
    assert summary["rules"] == 1
    assert summary["outbounds"] == 1
    (payload,) = client.payloads
    assert payload["rules"][0]["name"] == "route-eu"
    assert payload["outbounds"][0]["name"] == "eu-exit"

    # old agent: a NOTE on the sync result, no payload sent
    client2 = _FakeClient(features={})
    result2 = SyncResultShim()
    outcome = asyncio.run(_push_policy(runtime, client2, _FakeRow(), result2,
                                       features={}))
    assert outcome is None
    assert any("NOT enforced" in note for note in result2.notes)
    assert client2.payloads == []


class SyncResultShim:
    def __init__(self):
        self.notes = []


class _NullCipher:
    """Round-trips profiles without real encryption (test shim)."""

    def encode(self, outbounds):
        from app.cores.outbounds.repository import OutboundSecretCodec

        return OutboundSecretCodec(self).encode(outbounds)

    def decrypt_json(self, blob, aad=None):
        import json

        return json.loads(blob) if isinstance(blob, str) else blob

    def encrypt_json(self, data, aad=None):
        import json

        return json.dumps(data)


def test_node_agent_advertises_and_accepts_policy():
    """The agent image (checked out at ../zagros-node) exposes PUT /v1/policy
    and advertises the feature — the panel sync gate keys off it."""
    agent = ROOT.parent / "zagros-node" / "node_agent" / "app.py"
    if not agent.is_file():
        pytest.skip("zagros-node checkout not present")
    src = agent.read_text()
    assert '"/v1/policy"' in src and "policy_routing" in src
    plane = ROOT.parent / "zagros-node" / "node_agent" / "policy_plane.py"
    assert plane.is_file()
    psrc = plane.read_text()
    assert "reconcile_on_boot" in psrc and "def teardown" in psrc
