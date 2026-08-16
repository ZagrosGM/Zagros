"""Cross-core source classification, priority and first-match regressions."""
from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.model import RoutingRule, RuleAction, RuleMatcher
from app.cores.routing.policy import PolicyRoutingManager
from tests.cores.policy_fakes import FakeRunner


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


class OpenVPNSource:
    settings = {}
    def _listeners(self):
        return [
            {"tag": "openvpn", "subnet": "10.8.0.0", "netmask": "255.255.255.0"},
            {"tag": "ovpn-alt", "subnet": "10.9.0.0", "netmask": "255.255.255.0"},
        ]


class WireGuardSource:
    settings = {}
    def _listeners(self):
        return [
            {"tag": "wg-main", "subnet": "10.66.66.0/24"},
            {"tag": "wg-alt", "subnet": "10.67.67.0/24"},
        ]


class SoftEtherSource:
    settings = {"feature_tags": {"l2tp": "l2tp-main", "sstp": "sstp-main"}}


class SSHSource:
    settings = {"listeners": [{"tag": "ssh"}]}


class IsolatedSoftEtherSource(SoftEtherSource):
    settings = {
        "hub": "DEFAULT",
        "feature_tags": {"l2tp": "l2tp-main", "sstp": "sstp-main"},
    }

    def __init__(self):
        self.active: dict[str, dict[str, str]] = {}
        self.ensure_calls: list[str] = []
        self.disable_calls: list[str] = []

    def routing_source_specs(self):
        return [
            {"id": "hub:DEFAULT", "hub": "DEFAULT",
             "tags": ["l2tp-main", "sstp-main"],
             "subnet": "192.168.30.0/24"},
            {"id": "hub:ZAGROS-E2E-unit", "hub": "ZAGROS-E2E-unit",
             "tags": ["softether-e2e-unit"],
             "subnet": "192.168.88.0/24", "managed_by_zagros": True},
        ]

    def policy_sources(self):
        return list(self.active.values())

    def ensure_policy_source(self, source_id):
        self.ensure_calls.append(source_id)
        subnet = ("192.168.88.0/24" if source_id == "hub:ZAGROS-E2E-unit"
                  else "192.168.30.0/24")
        self.active[source_id] = {"id": source_id, "subnet": subnet}
        return dict(self.active[source_id])

    def disable_policy_source(self, source_id):
        self.disable_calls.append(source_id)
        self.active.pop(source_id, None)


class SourceManager:
    def __init__(self):
        self.drivers = {
            "openvpn": OpenVPNSource(),
            "wireguard": WireGuardSource(),
            "softether": SoftEtherSource(),
            "ssh": SSHSource(),
        }
    def list_cores(self): return list(self.drivers)
    def get(self, core_id): return self.drivers[core_id]


def _wg() -> Outbound:
    return Outbound(name="egress-wg", kind=OutboundKind.WIREGUARD, settings={
        "server": "203.0.113.5", "server_port": 51820,
        "private_key": _key(1), "peer_public_key": _key(2),
        "local_address": ["10.77.0.2/32"], "allowed_ips": ["0.0.0.0/0"],
    })


def _rule(name: str, tag: str, priority: int) -> RoutingRule:
    return RoutingRule(
        name=name, priority=priority, enabled=True,
        matcher=RuleMatcher(inbounds=[tag]),
        action=RuleAction.ROUTE_TO, outbound="egress-wg",
    )


def test_service_sources_map_to_real_subnets_and_one_policy_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        SourceManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    domain = manager.prepare([_wg()])["egress-wg"]
    rules = [_rule("wg-first", "wg-alt", 10),
             _rule("ovpn-second", "ovpn-alt", 20)]
    report = manager.apply_rules(rules)
    assert report.applied["wireguard"] == ["wg-first"]
    assert report.applied["openvpn"] == ["ovpn-second"]

    nft = runner.nft_scripts[-1]
    assert "ip saddr 10.67.67.0/24" in nft
    assert "ip saddr 10.9.0.0/24" in nft
    assert f"meta mark set {domain.fwmark} return" in nft
    assert nft.index("10.67.67.0/24") < nft.index("10.9.0.0/24")
    assert (f'meta mark {domain.fwmark} oifname "{domain.interface}" '
            "counter masquerade") in nft


def test_softether_securenat_is_reported_not_falsely_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        SourceManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    manager.prepare([_wg()])
    report = manager.preview_rules([_rule("soft-to-wg", "l2tp-main", 10)])
    gap = report.unsupported["softether"][0]
    assert gap.rule == "soft-to-wg"
    assert "SecureNAT" in gap.reason and "source" in gap.reason
    assert "soft-to-wg" not in report.applied.get("softether", [])


def test_managed_softether_hub_has_independent_source_and_symmetric_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    cores = SourceManager()
    isolated = IsolatedSoftEtherSource()
    cores.drivers["softether"] = isolated
    manager = PolicyRoutingManager(
        cores, runtime_root=str(tmp_path), runner=runner, sleep=lambda _: None,
    )
    domain = manager.prepare([_wg()])["egress-wg"]
    rule = _rule("isolated-soft-to-wg", "softether-e2e-unit", 10)
    report = manager.apply_rules([rule])

    assert isolated.ensure_calls == ["hub:ZAGROS-E2E-unit"]
    assert report.applied["softether"] == ["isolated-soft-to-wg"]
    nft = runner.nft_scripts[-1]
    assert "ip saddr 192.168.88.0/24" in nft
    assert "ip saddr 192.168.30.0/24" not in nft
    assert f"meta mark set {domain.fwmark} return" in nft

    manager.apply_rules([])
    assert isolated.disable_calls == ["hub:ZAGROS-E2E-unit"]
    assert "192.168.88.0/24" not in runner.nft_scripts[-1]


def test_managed_softether_source_rolls_back_when_nft_apply_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingNftRunner(FakeRunner):
        def run(self, argv, *, check=True, input_text=None, timeout=30):
            if list(argv)[:2] == ["nft", "-f"]:
                raise RuntimeError("synthetic nft transaction failure")
            return super().run(
                argv, check=check, input_text=input_text, timeout=timeout)

    runner = FailingNftRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    cores = SourceManager()
    isolated = IsolatedSoftEtherSource()
    cores.drivers["softether"] = isolated
    manager = PolicyRoutingManager(
        cores, runtime_root=str(tmp_path), runner=runner, sleep=lambda _: None,
    )
    manager.prepare([_wg()])
    with pytest.raises(RuntimeError, match="nft transaction failure"):
        manager.apply_rules([
            _rule("isolated-soft-to-wg", "softether-e2e-unit", 10),
        ])
    assert isolated.ensure_calls == ["hub:ZAGROS-E2E-unit"]
    assert isolated.disable_calls == ["hub:ZAGROS-E2E-unit"]
    assert isolated.active == {}
    assert manager._softether_routed == set()  # noqa: SLF001


def test_disabled_rule_is_not_emitted_but_remains_a_model_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        SourceManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    manager.prepare([_wg()])
    disabled = _rule("off", "wg-main", 5).model_copy(update={"enabled": False})
    # RoutingEngine filters disabled rows before calling policy; directly
    # applying an empty active set must produce no source classifier.
    manager.apply_rules([])
    nft = runner.nft_scripts[-1]
    assert "10.66.66.0/24" not in nft
    assert disabled.name == "off" and not disabled.enabled


def test_ssh_owner_uses_transparent_gateway_not_unbound_vrf_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sshd sockets are not VRF-bound; OUTPUT mark alone loses WG replies.

    A transparent redirect hands the original destination to the per-domain
    gateway whose dial socket is explicitly bound to the VRF.
    """
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        "app.cores.routing.policy.pwd.getpwall",
        lambda: [SimpleNamespace(pw_name="zg-alice", pw_uid=1234)],
    )
    manager = PolicyRoutingManager(
        SourceManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    domain = manager.prepare([_wg()])["egress-wg"]
    manager.apply_rules([_rule("ssh-via-wg", "ssh", 10)])
    nft = runner.nft_scripts[-1]
    assert "chain output_nat" in nft
    assert (f"meta skuid 1234 meta l4proto tcp counter "
            f"redirect to :{domain.redirect_port}") in nft
    assert f"meta skuid 1234 ct mark set {domain.return_mark}" not in nft


def test_softether_distinct_transport_decisions_fail_before_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        SourceManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    manager.prepare([_wg()])
    first = _rule("l2tp-via-wg", "l2tp-main", 10)
    second = RoutingRule(
        name="sstp-direct", priority=20,
        matcher=RuleMatcher(inbounds=["sstp-main"]),
        action=RuleAction.ALLOW,
    )
    with pytest.raises(Exception, match="shares one TAP/subnet"):
        manager.apply_rules([first, second])
