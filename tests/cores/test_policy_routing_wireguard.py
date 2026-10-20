"""WireGuard outbound policy-domain regressions."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.policy import PolicyRoutingManager
from tests.cores.policy_fakes import EmptyCoreManager, FakeRunner


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def _outbound() -> Outbound:
    return Outbound(
        name="warp-wireguard", kind=OutboundKind.WIREGUARD,
        settings={
            "server": "198.51.100.7", "server_port": 51820,
            "private_key": _key(1), "peer_public_key": _key(2),
            "preshared_key": _key(3),
            "local_address": ["10.99.0.2/32"],
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "mtu": 1380, "keepalive": 19,
        },
    )


def test_wireguard_domain_builds_interface_table_bypass_and_nat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    domain = manager.prepare([_outbound()])["warp-wireguard"]
    assert domain.ready and domain.mode == "wireguard"
    assert domain.interface.startswith("zgw") and len(domain.interface) <= 15
    assert domain.tunnel_interface == domain.interface
    assert domain.vrf_interface and domain.vrf_interface.startswith("zgr")
    assert domain.bypass_mark != domain.fwmark

    config = Path(domain.runtime_dir) / "wg.conf"
    text = config.read_text()
    assert config.stat().st_mode & 0o777 == 0o600
    assert f"FwMark = {domain.bypass_mark}" in text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
    assert "PersistentKeepalive = 19" in text

    commands = [argv for argv, _ in runner.calls]
    assert ["ip", "rule", "add", "priority", "900",
            "fwmark", f"{domain.bypass_mark}/0xffffffff", "lookup", "main"] in commands
    assert ["ip", "route", "replace", "table", str(domain.table_id),
            "default", "dev", domain.interface] in commands
    assert ["ip", "link", "set", "dev", domain.interface,
            "master", domain.vrf_interface] in commands
    command_text = "\n".join(" ".join(argv) for argv in commands)
    assert _key(1) not in command_text and _key(3) not in command_text


def test_wireguard_domain_decoration_turns_native_core_dial_into_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("app.cores.routing.policy.shutil.which",
                        lambda name: f"/usr/bin/{name}")
    manager = PolicyRoutingManager(
        EmptyCoreManager(), runtime_root=str(tmp_path), runner=runner,
        sleep=lambda _: None,
    )
    outbound = _outbound()
    domain = manager.prepare([outbound])[outbound.name]
    decorated = manager.decorate(outbound)
    assert decorated.settings["_policy_mark"] == domain.fwmark
    assert decorated.settings["_policy_table"] == domain.table_id
    assert "_policy_mark" not in outbound.settings
