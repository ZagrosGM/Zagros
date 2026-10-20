"""Regression coverage for protocol/dataplane capability negotiation."""
from __future__ import annotations

import asyncio

import pytest

from app.cores.capabilities import (
    OutboundDataplane,
    SupportState,
    outbound_capabilities,
    outbound_capability,
    outbound_product_capability,
    routing_compatibility,
)
from app.cores.drivers.xray import XrayDriver
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RuleMatcher, RoutingRule, RuleAction
from app.cores.routing.policy import PolicyRoutingManager
from tests.cores.policy_fakes import EmptyCoreManager, FakeRunner
from tests.cores.test_xray_driver import FakeBackend as FakeXrayBackend


def test_capability_matrix_distinguishes_ssh_tun_and_softether_product_limits() -> None:
    matrix = outbound_capabilities()
    runtime_ssh = matrix[OutboundKind.SSH]
    assert runtime_ssh.state in (SupportState.SUPPORTED, SupportState.NOT_INSTALLED)
    # Product compatibility is independent from package presence on this test
    # host; runtime inventory is allowed to refine it to NOT_INSTALLED.
    ssh = outbound_product_capability(OutboundKind.SSH)
    assert ssh.state is SupportState.SUPPORTED
    assert ssh.application_proxy is True
    assert ssh.application_level is True
    assert ssh.dataplane is OutboundDataplane.POLICY_TUN
    assert ssh.tun is True
    assert ssh.kernel_routing is True
    assert ssh.native_core_translation == {"xray", "sing-box"}
    assert ssh.transports == {"tcp"}
    assert ssh.traffic_networks == {"tcp"}
    assert ssh.routing_source_cores == {
        "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp",
    }
    assert ssh.accounting is False
    assert "source" in str(ssh.accounting_reason)
    assert "diagnostics only" in str(ssh.accounting_reason)

    supported, reason = routing_compatibility(
        ssh, source_cores={"xray"}, networks={"tcp"})
    assert supported is SupportState.SUPPORTED and reason is None
    service_source, reason = routing_compatibility(
        ssh, source_cores={"wireguard"}, networks={"tcp"})
    assert service_source is SupportState.SUPPORTED and reason is None
    invalid_network, _ = routing_compatibility(
        ssh, source_cores={"sing-box"}, networks={"tcp", "udp"})
    assert invalid_network is SupportState.NOT_APPLICABLE

    wireguard = matrix[OutboundKind.WIREGUARD]
    assert wireguard.transports == {"udp"}  # outer carrier
    assert wireguard.traffic_networks == {"tcp", "udp"}  # tunnel payload
    for kind in (OutboundKind.HYSTERIA2, OutboundKind.TUIC):
        assert matrix[kind].transports == {"udp"}
        assert matrix[kind].traffic_networks == {"tcp", "udp"}
    assert matrix[OutboundKind.TROJAN].transports == {"tcp"}
    assert matrix[OutboundKind.TROJAN].traffic_networks == {"tcp", "udp"}
    assert matrix[OutboundKind.HTTP].traffic_networks == {"tcp"}

    for kind in (
        OutboundKind.SOFTETHER_L2TP,
        OutboundKind.SOFTETHER_L2TP_RAW,
        OutboundKind.SOFTETHER_SSTP,
        OutboundKind.SOFTETHER_PPTP,
    ):
        capability = matrix[kind]
        assert capability.state is SupportState.UNSUPPORTED
        assert capability.selectable is False
        assert capability.reason
    native = matrix[OutboundKind.SOFTETHER_NATIVE]
    assert native.state in {SupportState.SUPPORTED, SupportState.NOT_INSTALLED}
    assert native.selectable is True
    assert native.tun is True
    assert native.dataplane is OutboundDataplane.POLICY_TUN
    assert native.routing_source_cores == {
        "xray", "sing-box", "openvpn", "wireguard", "ssh", "softether", "pptp"}
    assert native.accounting is True
    assert "vpnclient" in str(native.host_runtime)
    assert "PPTP" in matrix[OutboundKind.SOFTETHER_PPTP].reason


def test_policy_mode_uses_real_ssh_application_proxy_not_singbox_tun() -> None:
    assert PolicyRoutingManager._mode(OutboundKind.SSH) == "ssh"
    assert PolicyRoutingManager._mode(OutboundKind.WIREGUARD) == "wireguard"
    assert PolicyRoutingManager._mode(OutboundKind.OPENVPN) == "openvpn"
    assert PolicyRoutingManager._mode(OutboundKind.SOFTETHER_NATIVE) == "softether"
    assert PolicyRoutingManager._mode(OutboundKind.VLESS) == "proxy"
    assert PolicyRoutingManager._mode(
        OutboundKind.SHADOWSOCKS, {"policy_core": "xray"}) == "xray_proxy"


def test_xray_policy_runtime_is_explicit_real_process_chain(tmp_path, monkeypatch) -> None:
    class CoreManager:
        def __init__(self):
            self.xray = XrayDriver(backend=FakeXrayBackend())

        def list_cores(self):
            return ["xray"]

        def get(self, core_id):
            if core_id == "xray":
                return self.xray
            raise KeyError(core_id)

    monkeypatch.setattr(
        "app.cores.routing.policy.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"ip", "xray", "sing-box"} else None,
    )
    runner = FakeRunner()
    manager = PolicyRoutingManager(
        CoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    outbound = Outbound(
        name="ss-through-xray", kind=OutboundKind.SHADOWSOCKS,
        settings={
            "server": "198.51.100.8", "server_port": 8388,
            "method": "aes-256-gcm", "password": "do-not-leak",
            "policy_core": "xray",
        },
    )
    assert PolicyRoutingManager._mode(
        outbound.kind, outbound.settings) == "xray_proxy"
    domain = manager.prepare([outbound])[outbound.name]
    assert domain.mode == "xray_proxy" and domain.ready
    runtime = tmp_path / PolicyRoutingManager._hash(outbound.name)[:20]
    xray_doc = __import__("json").loads((runtime / "xray.json").read_text())
    adapter_doc = __import__("json").loads(
        (runtime / "xray-tun-adapter.json").read_text())
    assert xray_doc["outbounds"][0]["protocol"] == "shadowsocks"
    assert adapter_doc["outbounds"][0]["type"] == "socks"
    assert adapter_doc["outbounds"][0]["server_port"] == domain.proxy_port
    redirect = next(item for item in adapter_doc["inbounds"]
                    if item["type"] == "redirect")
    assert redirect["listen_port"] == domain.redirect_port
    argv_text = "\n".join(" ".join(call) for call, _input in runner.calls)
    assert "/usr/bin/xray run -c" in argv_text
    assert "/usr/bin/sing-box run -c" in argv_text
    assert "do-not-leak" not in argv_text
    manager.stop()
    assert not runtime.exists()

    with pytest.raises(ValueError, match="no Xray policy runtime"):
        Outbound(
            name="hy2-bad-xray", kind=OutboundKind.HYSTERIA2,
            settings={"server": "example.test", "server_port": 443,
                      "password": "x", "policy_core": "xray"},
        )


def test_ssh_policy_tun_accepts_service_tcp_but_rejects_udp_without_mutation(tmp_path) -> None:
    runner = FakeRunner()
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    outbound = Outbound(
        name="ssh-egress", kind=OutboundKind.SSH,
        settings={"server": "ssh.example.test", "server_port": 22,
                  "username": "alice", "password": "secret"},
    )
    rule = RoutingRule(
        name="service-via-ssh",
        matcher=RuleMatcher(inbounds=["openvpn"], networks=["tcp"]),
        action=RuleAction.ROUTE_TO, outbound=outbound.name,
    )
    manager.validate_plan([rule], [outbound])
    udp_rule = rule.model_copy(update={
        "matcher": RuleMatcher(inbounds=["openvpn"], networks=["tcp", "udp"]),
    })
    with pytest.raises(CoreError, match="TCP-only"):
        manager.validate_plan([udp_rule], [outbound])
    assert runner.calls == []
    assert manager.domain_views() == []


def test_valid_ssh_application_proxy_is_rendered_by_xray_as_local_socks() -> None:
    async def run() -> None:
        backend = FakeXrayBackend()
        driver = XrayDriver(backend=backend)
        outbound = Outbound(
            name="ssh-egress", kind=OutboundKind.SSH,
            settings={"server": "ssh.example.test", "server_port": 22,
                      "username": "alice", "password": "secret",
                      "_policy_socks_port": 31999},
        )
        report = await driver.deploy_outbounds([outbound])
        assert report.applied == ["ssh-egress"]
        native = next(item for item in backend.outbounds if item.get("tag") == "ssh-egress")
        assert native["protocol"] == "socks"
        assert native["settings"]["servers"] == [{
            "address": "127.0.0.1", "port": 31999, "udp": False,
        }]

        bare = outbound.model_copy(update={
            "settings": {key: value for key, value in outbound.settings.items()
                         if key != "_policy_socks_port"},
        })
        rejected = await driver.deploy_outbounds([bare])
        assert rejected.applied == []
        assert "no SSH outbound codec" in rejected.unsupported[0].reason

    asyncio.run(run())


def test_ssh_domain_uses_private_askpass_and_scoped_policy_tun(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.cores.routing.policy.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"ip", "ssh", "env", "sing-box"} else None,
    )
    runner = FakeRunner()
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    outbound = Outbound(
        name="ssh-egress", kind=OutboundKind.SSH,
        settings={"server": "ssh.example.test", "server_port": 2222,
                  "username": "alice", "password": "do-not-leak"},
    )
    domain = manager.prepare([outbound])[outbound.name]
    assert domain.mode == "ssh" and domain.ready
    assert "TCP-only fwmark" in domain.detail
    argv = next(call for call, _ in runner.calls if "/usr/bin/ssh" in call)
    assert "do-not-leak" not in " ".join(argv)
    adapter_argv = next(call for call, _ in runner.calls
                        if call[:2] == ["/usr/bin/sing-box", "run"])
    assert "ssh-tun-adapter.json" in " ".join(adapter_argv)
    assert any(call[:4] == ["ip", "rule", "add", "priority"]
               and str(domain.fwmark) in call for call, _ in runner.calls)
    password_file = tmp_path / PolicyRoutingManager._hash(outbound.name)[:20] / "password"
    assert password_file.read_text() == "do-not-leak\n"
    assert password_file.stat().st_mode & 0o777 == 0o600
    decorated = manager.decorate(outbound)
    assert decorated.settings["_policy_socks_port"] == domain.proxy_port
    assert decorated.settings["_policy_mark"] == domain.fwmark
    assert decorated.settings["_policy_interface"] == domain.interface
    manager.stop()
    assert not password_file.parent.exists()


def test_ssh_application_rule_must_be_explicitly_tcp(tmp_path) -> None:
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=FakeRunner(),
        sleep=lambda _: None,
    )
    outbound = Outbound(
        name="ssh-egress", kind=OutboundKind.SSH,
        settings={"server": "ssh.example.test", "server_port": 22,
                  "username": "alice", "password": "secret"},
    )
    rule = RoutingRule(
        name="unsafe-udp-capable-rule", matcher=RuleMatcher(inbounds=["xray-in"]),
        action=RuleAction.ROUTE_TO, outbound=outbound.name,
    )
    with pytest.raises(CoreError, match="TCP-only"):
        manager.validate_plan([rule], [outbound], core_ids=["xray"])


def test_source_core_map_is_backend_authority_for_ssh_compatibility(tmp_path) -> None:
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=FakeRunner(),
        sleep=lambda _: None,
    )
    outbound = Outbound(
        name="ssh-egress", kind=OutboundKind.SSH,
        settings={"server": "ssh.example.test", "server_port": 22,
                  "username": "alice", "password": "secret"},
    )
    rule = RoutingRule(
        name="native-tcp", matcher=RuleMatcher(
            inbounds=["same-visible-tag"], networks=["tcp"]),
        action=RuleAction.ROUTE_TO, outbound=outbound.name,
    )
    manager.validate_plan(
        [rule], [outbound], source_core_map={"same-visible-tag": "xray"})
    # Kernel/service sources use the same narrowly scoped TCP policy TUN.
    manager.validate_plan(
        [rule], [outbound],
        source_core_map={"same-visible-tag": "wireguard"})
    # Unknown/deleted tags fail closed; the backend never guesses ownership
    # from a prefix or silently broadens the source set.
    with pytest.raises(CoreError, match="unknown/deleted inbound"):
        manager.validate_plan(
            [rule], [outbound], source_core_map={"another-tag": "xray"})


def test_softether_schema_comes_from_same_capability_contract() -> None:
    from app.cores.outbounds.profile_schema import outbound_schemas

    schemas = outbound_schemas()
    for kind in ("softether_l2tp", "softether_l2tp_raw", "softether_sstp",
                 "softether_pptp"):
        assert kind not in schemas
        # Historical rows remain decodable internally, but no public schema
        # advertises or offers the deprecated provider identity.
        assert outbound_capability(kind).selectable is False
    native = schemas["softether_native"]
    assert native["x-supported"] is True
    assert native["x-availability"] in {"supported", "not_installed"}
    assert native["x-capability"]["tun"] is True
    assert {"server", "server_port", "hub", "username", "password"} <= set(native["required"])
    assert "Virtual NIC" in native["description"]
    # SoftEther's standards-compatible OpenVPN listener needs no fake
    # SoftEther-specific kind: the production OpenVPN client/TUN is real.
    assert schemas["openvpn"]["x-supported"] is True
    assert "SoftEther OpenVPN-compatibility" in schemas["openvpn"]["description"]
