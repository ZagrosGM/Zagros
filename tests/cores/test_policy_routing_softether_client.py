from __future__ import annotations

from pathlib import Path

import pytest

from app.cores.exceptions import CoreError
from app.cores.outbounds.model import Outbound, OutboundKind
from app.cores.routing.policy import PolicyRoutingManager, PolicyRuleReport
from tests.cores.policy_fakes import FakeRunner


class Backend:
    def __init__(self, root: Path) -> None:
        self.root = root

    def client_binary(self): return str(self.root / "vpnclient")
    def vpncmd_binary(self): return str(self.root / "vpncmd")


class Driver:
    def __init__(self, root: Path) -> None:
        self._backend = Backend(root)


class Cores:
    def __init__(self, root: Path) -> None:
        self.driver = Driver(root)

    def get(self, core_id: str):
        if core_id != "softether":
            raise KeyError(core_id)
        return self.driver

    def list_cores(self): return ["softether"]


def runtime_files(tmp_path: Path) -> Path:
    root = tmp_path / "softether-runtime"
    root.mkdir()
    for name in ("vpnclient", "vpncmd", "hamcore.se2"):
        path = root / name
        path.write_text(name)
        path.chmod(0o700)
    return root


def connected_commander(calls: list[list[str]]):
    def command(_argv, *, commands, **_kwargs):
        calls.append(list(commands))
        if commands[0].startswith("AccountStatusGet"):
            return """
Session Status|Connection Completed (Session Established)
Session Name|SID-ZG-1
Outgoing Data Size|1,234 bytes
Incoming Data Size|5,678 bytes
"""
        return "\n".join("The command completed successfully." for _ in commands)
    return command


def profile(password: str = "secret-123") -> Outbound:
    return Outbound(
        name="native-edge",
        kind=OutboundKind.SOFTETHER_NATIVE,
        settings={
            "server": "vpn.example.test", "server_port": 5555,
            "hub": "EDGE", "username": "alice", "password": password,
            "dhcp_timeout": 10,
        },
    )


def test_native_client_domain_owns_namespace_vnic_routes_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binaries = runtime_files(tmp_path)
    runner = FakeRunner()
    commands: list[list[str]] = []
    manager = PolicyRoutingManager(
        Cores(binaries), runtime_root=str(tmp_path / "routing"), runner=runner,
        sleep=lambda _seconds: None,
        softether_commander=connected_commander(commands),
    )
    monkeypatch.setattr(manager, "_resolve_ipv4", lambda _host: "198.51.100.20")
    monkeypatch.setattr(
        manager, "_softether_binaries",
        lambda: (str(binaries / "vpnclient"), str(binaries / "vpncmd"), "/bin/busybox"),
    )
    monkeypatch.setattr(manager, "_start_gateway", lambda _domain: None)

    domains = manager.prepare([profile()])
    domain = domains["native-edge"]
    assert domain.mode == "softether" and domain.ready
    assert domain.namespace and domain.namespace.startswith("zgn")
    assert domain.client_adapter and domain.client_adapter.startswith("vpn_zg")
    assert domain.client_address == "192.168.30.10"
    assert domain.client_gateway == "192.168.30.1"
    assert domain.route_gateway == PolicyRoutingManager._softether_links(
        domain.table_id)["data_peer"]
    assert domain.client_uplink_bytes == 1234
    assert domain.client_downlink_bytes == 5678

    flattened = [argv for argv, _stdin in runner.calls]
    assert any(argv[:3] == ["ip", "netns", "add"] for argv in flattened)
    assert any("vpnclient" in " ".join(argv) and argv[-1] == "start"
               for argv in flattened)
    assert any(argv[:5] == ["ip", "route", "replace", "table", str(domain.table_id)]
               and "via" in argv and domain.interface in argv for argv in flattened)
    assert any("unshare" in argv and "rp_filter" in " ".join(argv)
               for argv in flattened)
    watchdog = Path(domain.runtime_dir) / "lease" / "dhcp-watch.sh"
    assert watchdog.is_file()
    watchdog_text = watchdog.read_text()
    assert "had_address=1" in watchdog_text
    assert "udhcpc -f -n" in watchdog_text
    assert "route replace default via" in (
        Path(domain.runtime_dir) / "lease" / "udhcpc.sh").read_text()
    assert any(argv[-1] == str(watchdog) for argv in flattened)
    nft = manager._nft_script([], PolicyRuleReport())  # noqa: SLF001
    assert (f'meta mark {domain.fwmark} oifname "{domain.interface}" '
            "counter masquerade") in nft
    # Profile credentials travel only through the private PTY command channel,
    # never subprocess argv or command-runner stdin/logs.
    assert all("secret-123" not in " ".join(argv) and "secret-123" not in str(stdin)
               for argv, stdin in runner.calls)
    assert any(any(row.startswith("AccountPasswordSet") for row in batch)
               for batch in commands)

    view = manager.domain_views()[0]
    assert view["namespace"] == domain.namespace
    assert view["client_uplink_bytes"] == 1234
    assert view["client_downlink_bytes"] == 5678

    manager.prepare([])
    assert any(argv[:3] == ["ip", "netns", "del"] for argv, _ in runner.calls)
    assert not Path(domain.runtime_dir).exists()


def test_native_client_prepare_is_idempotent_when_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binaries = runtime_files(tmp_path)
    runner = FakeRunner(); commands: list[list[str]] = []
    manager = PolicyRoutingManager(
        Cores(binaries), runtime_root=str(tmp_path / "routing"), runner=runner,
        sleep=lambda _seconds: None,
        softether_commander=connected_commander(commands),
    )
    monkeypatch.setattr(manager, "_resolve_ipv4", lambda _host: "198.51.100.20")
    monkeypatch.setattr(manager, "_softether_binaries", lambda: (
        str(binaries / "vpnclient"), str(binaries / "vpncmd"), "/bin/busybox"))
    monkeypatch.setattr(manager, "_start_gateway", lambda _domain: None)
    first = manager.prepare([profile()])["native-edge"]
    start_count = sum("vpnclient" in " ".join(argv) and argv[-1] == "start"
                      for argv, _ in runner.calls)
    second = manager.prepare([profile()])["native-edge"]
    assert second is first
    assert sum("vpnclient" in " ".join(argv) and argv[-1] == "start"
               for argv, _ in runner.calls) == start_count


def test_native_client_requires_certificate_when_verification_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    binaries = runtime_files(tmp_path);runner = FakeRunner()
    manager = PolicyRoutingManager(
        Cores(binaries), runtime_root=str(tmp_path / "routing"), runner=runner,
        sleep=lambda _seconds: None, softether_commander=connected_commander([]),
    )
    monkeypatch.setattr(manager, "_resolve_ipv4", lambda _host: "198.51.100.20")
    monkeypatch.setattr(manager, "_softether_binaries", lambda: (
        str(binaries / "vpnclient"), str(binaries / "vpncmd"), "/bin/busybox"))
    outbound = profile().model_copy(deep=True)
    outbound.settings["verify_server_certificate"] = True
    with pytest.raises(CoreError, match="requires server_cert"):
        manager.prepare([outbound])
    assert not manager.domain_views()


def test_softether_link_plan_is_unique_and_inside_rfc6598() -> None:
    first = PolicyRoutingManager._softether_links(11000)
    last = PolicyRoutingManager._softether_links(28999)
    assert first["control_subnet"].startswith("100.")
    assert last["data_subnet"].startswith("100.")
    assert set(first.values()).isdisjoint(set(last.values()))
