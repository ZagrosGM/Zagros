"""Regression coverage for protocol/dataplane capability negotiation."""
from __future__ import annotations

import asyncio

import pytest

from app.cores.capabilities import SupportState, outbound_capabilities, outbound_capability
from app.cores.drivers.xray import XrayDriver
from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RuleMatcher, RoutingRule, RuleAction
from app.cores.routing.policy import PolicyRoutingManager
from tests.cores.policy_fakes import EmptyCoreManager, FakeRunner
from tests.cores.test_xray_driver import FakeBackend as FakeXrayBackend


def test_capability_matrix_distinguishes_ssh_tun_and_softether_product_limits() -> None:
    matrix = outbound_capabilities()
    ssh = matrix[OutboundKind.SSH]
    assert ssh.state in (SupportState.SUPPORTED, SupportState.NOT_INSTALLED)
    assert ssh.application_proxy is True
    assert ssh.tun is False
    assert ssh.native_core_translation == {"xray", "sing-box"}
    assert ssh.transports == {"tcp"}

    for kind in (
        OutboundKind.SOFTETHER_L2TP,
        OutboundKind.SOFTETHER_L2TP_RAW,
        OutboundKind.SOFTETHER_SSTP,
        OutboundKind.SOFTETHER_PPTP,
        OutboundKind.SOFTETHER_NATIVE,
    ):
        capability = matrix[kind]
        assert capability.state is SupportState.UNSUPPORTED
        assert capability.selectable is False
        assert capability.reason
    assert "PptpGet" in matrix[OutboundKind.SOFTETHER_PPTP].reason


def test_policy_mode_uses_real_ssh_application_proxy_not_singbox_tun() -> None:
    assert PolicyRoutingManager._mode(OutboundKind.SSH) == "ssh"
    assert PolicyRoutingManager._mode(OutboundKind.WIREGUARD) == "wireguard"
    assert PolicyRoutingManager._mode(OutboundKind.OPENVPN) == "openvpn"
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


def test_invalid_ssh_tun_rule_fails_in_pure_preflight_without_runner_calls(tmp_path) -> None:
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
    with pytest.raises(CoreError, match="policy TUN"):
        manager.validate_plan([rule], [outbound])
    # The same profile is valid when deployment is explicitly native-Xray;
    # it is only the service-source/IP-TUN interpretation that is impossible.
    manager.validate_plan([rule], [outbound], core_ids=["xray"])
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


def test_ssh_domain_uses_private_askpass_and_no_kernel_table(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.cores.routing.policy.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"ip", "ssh", "env"} else None,
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
    assert "TCP application SOCKS" in domain.detail
    argv = next(call for call, _ in runner.calls if "/usr/bin/ssh" in call)
    assert "do-not-leak" not in " ".join(argv)
    assert not any(call[:4] == ["ip", "rule", "add", "priority"]
                   for call, _ in runner.calls)
    password_file = tmp_path / PolicyRoutingManager._hash(outbound.name)[:20] / "password"
    assert password_file.read_text() == "do-not-leak\n"
    assert password_file.stat().st_mode & 0o777 == 0o600
    decorated = manager.decorate(outbound)
    assert decorated.settings["_policy_socks_port"] == domain.proxy_port
    assert "_policy_mark" not in decorated.settings
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


def test_softether_schema_comes_from_same_capability_contract() -> None:
    from app.cores.outbounds.profile_schema import outbound_schemas

    schemas = outbound_schemas()
    for kind in ("softether_l2tp", "softether_l2tp_raw", "softether_sstp",
                 "softether_pptp", "softether_native"):
        assert schemas[kind]["x-supported"] is False
        assert schemas[kind]["x-availability"] == "unsupported"
        assert schemas[kind]["x-capability"]["tun"] is False
        assert schemas[kind]["x-disabled-reason"] == outbound_capability(kind).reason
    # SoftEther's standards-compatible OpenVPN listener needs no fake
    # SoftEther-specific kind: the production OpenVPN client/TUN is real.
    assert schemas["openvpn"]["x-supported"] is True
    assert "SoftEther OpenVPN-compatibility" in schemas["openvpn"]["description"]
