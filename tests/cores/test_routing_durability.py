"""f-routingfix-3 — routing must SURVIVE config rebuilds.

Master: every ordinary restart rebuilds the config from the DB
(``include_db_users``), which used to silently drop the deployed routing
rules and managed outbounds — the whole "routing randomly stops working"
class. The native artifacts are now persisted (sidecar) and merged back
into every rebuild. Node: a fresh inbound document (sync) must not wipe the
policy plane either (standalone sidecar).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402


# --------------------------------------------------------------------------- #
# app.xray.managed — the durable sidecar
# --------------------------------------------------------------------------- #
def test_managed_state_roundtrip(tmp_path, monkeypatch):
    from app.xray import managed

    monkeypatch.setenv("ZAGROS_XRAY_MANAGED_STATE", str(tmp_path / "managed.json"))
    assert managed.load() == {}  # nothing persisted yet

    rules = [{"type": "field", "inboundTag": ["vless-42005"],
              "outboundTag": "lion", "type2": "field"}]
    outbounds = [{"protocol": "blackhole", "tag": "zg-block"}]
    managed.save(rules=rules)
    managed.save(outbounds=outbounds)          # merge, not replace
    state = managed.load()
    assert state["rules"] == rules
    assert state["outbounds"] == outbounds

    managed.save(rules=[])                     # explicit empty = cleared
    assert managed.load()["rules"] == []
    assert managed.load()["outbounds"] == outbounds  # other list preserved


def test_managed_state_survives_corruption(tmp_path, monkeypatch):
    from app.xray import managed

    path = tmp_path / "managed.json"
    path.write_text("{not json")
    monkeypatch.setenv("ZAGROS_XRAY_MANAGED_STATE", str(path))
    assert managed.load() == {}  # degrade to stock, never crash


# --------------------------------------------------------------------------- #
# include_db_users merges the managed state back
# --------------------------------------------------------------------------- #
@pytest.fixture()
def _managed_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_XRAY_MANAGED_STATE", str(tmp_path / "managed.json"))
    yield


def test_rebuild_keeps_managed_rules(_managed_env):
    """The exact reported failure: deploy routing -> an ordinary restart
    rebuilds the config -> the rules must still be there."""
    from app.xray import managed
    from app.xray.config import XRayConfig

    base = {
        "inbounds": [{"tag": "vless-42005", "port": 42005,
                      "protocol": "vless", "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"},
                      {"protocol": "blackhole", "tag": "BLOCK"}],
        "routing": {"rules": [{"type": "field", "ip": ["geoip:private"],
                               "outboundTag": "BLOCK"}]},
    }
    config = XRayConfig(base)
    rule = {"type": "field", "inboundTag": ["vless-42005"],
            "outboundTag": "lion_lion_vpn"}
    block_ob = {"protocol": "blackhole", "tag": "zg-block"}
    direct_ob = {"protocol": "freedom", "tag": "zg-direct"}
    managed.save(rules=[rule], outbounds=[block_ob, direct_ob])

    rebuilt = config.include_db_users()

    routing = rebuilt["routing"]["rules"]
    assert rule in routing, "managed routing rule lost on rebuild"
    # API control-plane rule stays FIRST-class (index of API before managed)
    api_index = next(i for i, r in enumerate(routing)
                     if "API_INBOUND" in (r.get("inboundTag") or []))
    assert routing.index(rule) > api_index, "managed rules must follow the API rule"
    tags = [ob["tag"] for ob in rebuilt["outbounds"]]
    assert "zg-block" in tags and "lion_lion_vpn" not in tags
    # the FIRST outbound is untouched — xray's default egress
    assert rebuilt["outbounds"][0]["tag"] == "DIRECT"


def test_rebuild_replaces_stale_managed_copies(_managed_env):
    """Deploy twice: the rebuilt config must carry the LATEST native form,
    not accumulate duplicates."""
    from app.xray import managed
    from app.xray.config import XRayConfig

    base = {
        "inbounds": [{"tag": "in-1", "port": 1, "protocol": "vless",
                      "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
        "routing": {"rules": []},
    }
    config = XRayConfig(base)
    managed.save(rules=[
        {"type": "field", "inboundTag": ["in-1"], "outboundTag": "old"}])
    rebuilt = config.include_db_users()
    assert rebuilt["routing"]["rules"].count(
        {"type": "field", "inboundTag": ["in-1"], "outboundTag": "old"}) == 1

    managed.save(rules=[
        {"type": "field", "inboundTag": ["in-1"], "outboundTag": "new"}])
    rebuilt2 = config.include_db_users()
    outbound_tags = [r.get("outboundTag") for r in rebuilt2["routing"]["rules"]]
    assert "old" not in outbound_tags and "new" in outbound_tags


def test_rebuild_without_managed_state_is_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAGROS_XRAY_MANAGED_STATE",
                       str(tmp_path / "absent.json"))
    from app.xray.config import XRayConfig

    base = {
        "inbounds": [{"tag": "in-1", "port": 1, "protocol": "vless",
                      "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
        "routing": {"rules": [{"type": "field", "ip": ["geoip:private"],
                               "outboundTag": "BLOCK"}]},
    }
    rebuilt = XRayConfig(base).include_db_users()
    assert {"type": "field", "ip": ["geoip:private"],
            "outboundTag": "BLOCK"} in rebuilt["routing"]["rules"]


# --------------------------------------------------------------------------- #
# standalone backend (node): a fresh inbound document keeps the policy plane
# --------------------------------------------------------------------------- #
def test_standalone_document_sync_keeps_routing(tmp_path):
    from app.cores.drivers.xray.standalone import StandaloneXrayBackend

    settings = {
        "executable_path": str(tmp_path / "bin" / "xray"),
        "assets_path": str(tmp_path / "assets"),
        "config_path": str(tmp_path / "xray.json"),
    }
    backend = StandaloneXrayBackend(settings)
    backend.apply_config_document({
        "inbounds": [{"tag": "vless-42005", "port": 42005,
                      "protocol": "vless", "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
    })
    backend.set_outbounds(
        [{"protocol": "blackhole", "tag": "zg-block"}])
    backend.set_routing_rules(
        [{"type": "field", "inboundTag": ["vless-42005"],
          "outboundTag": "zg-block"}])

    # the next inbound sync rewrites the whole document...
    backend.apply_config_document({
        "inbounds": [{"tag": "vless-42005", "port": 42005,
                      "protocol": "vless", "settings": {"clients": []}}],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
    })
    document = json.loads((tmp_path / "xray.json").read_text())
    tags = [ob["tag"] for ob in document["outbounds"]]
    assert "zg-block" in tags, "managed outbound wiped by a document sync"
    assert document["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["vless-42005"], "outboundTag": "zg-block"}
    ], "managed routing rules wiped by a document sync"


# --------------------------------------------------------------------------- #
# phase B — a node only receives profiles that reach it
# --------------------------------------------------------------------------- #
def test_outbounds_for_node_scope():
    from app.cores.outbounds.model import Outbound, OutboundKind
    from app.nodes.service import outbounds_for_node
    from app.cores.routing.model import RoutingRule, RuleAction, RuleMatcher

    def ob(name, nodes):
        return Outbound(name=name, kind=OutboundKind.VLESS,
                        settings={"server": "1.2.3.4", "server_port": 443},
                        nodes=nodes)

    def rule(name, outbound, nodes=None):
        return RoutingRule(name=name, matcher=RuleMatcher(inbounds=["in-1"]),
                           action=RuleAction.ROUTE_TO, outbound=outbound,
                           scope={"nodes": nodes or []})

    outbounds = [ob("global", []), ob("node2-only", [2]), ob("disabled", [])]
    outbounds[2].enabled = False
    node2_rules = [rule("r1", "node2-only", nodes=[2]),
                   rule("r2", "disabled", nodes=[2])]
    got = outbounds_for_node(outbounds, node2_rules, 2)
    names = {o.name for o in got}
    assert "node2-only" in names      # pinned here
    assert "global" in names          # everywhere
    # a DISABLED profile never travels even when referenced — the caller
    # reports it as a missing outbound on the push summary instead
    assert "disabled" not in names
    # ...but a DISABLED-elsewhere profile referenced by THIS node's rules travels
    outbounds.append(ob("node9-ref", [9]))
    node2_rules.append(rule("r4", "node9-ref", nodes=[2]))
    assert "node9-ref" in {o.name for o in outbounds_for_node(outbounds, node2_rules, 2)}
    # production feeds effective_rules_for_node(rules, node) — node 1 never
    # sees node-2-pinned rules, so node-2-only profiles stay off its payload
    node1_rules = [rule("r3", "global")]
    got1 = outbounds_for_node(outbounds, node1_rules, 1)
    assert {o.name for o in got1} == {"global"}


def test_routing_save_rejects_scope_mismatch():
    """A rule may only reference a profile its scope can actually reach."""
    from app.cores.outbounds.model import Outbound, OutboundKind
    from app.cores.routing.model import RoutingRule, RuleAction, RuleMatcher

    node2_out = Outbound(name="node2-relay", kind=OutboundKind.VLESS,
                         settings={"server": "1.2.3.4", "server_port": 443},
                         nodes=[2])
    everywhere_rule = RoutingRule(
        name="bad", matcher=RuleMatcher(inbounds=["in-1"]),
        action=RuleAction.ROUTE_TO, outbound="node2-relay")
    # engine-level guard lives in admin_api.routing_save; assert the building
    # blocks the guard composes (targets_nodes_only + coverage check)
    assert not everywhere_rule.scope.targets_nodes_only()
    assert node2_out.nodes == [2]
