"""Executable tests for XrayDriver policy (inbound selection, XTLS-flow
sanitization, suspend/update semantics, usage deltas, sealed payload shape).

Run: pytest tests/cores/test_xray_driver.py -v   OR   python tests/cores/test_xray_driver.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# --- import shim: load `app.cores` without executing app/__init__.py --------
ROOT = Path(__file__).resolve().parents[2]
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import CapabilityNotSupportedError, CoreError, CoreState  # noqa: E402
from app.cores.drivers.xray import XrayDriver, XrayUsageStat  # noqa: E402
from app.cores.types import CoreMetrics, UserAccount  # noqa: E402

# --------------------------------------------------------------------------- #
# fake backend
# --------------------------------------------------------------------------- #

INBOUNDS: dict[str, dict[str, Any]] = {
    "VLESS_TCP_REALITY": {
        "protocol": "vless", "network": "tcp", "tls": "reality",
        "header_type": "", "port": 443,
        "sni": ["www.microsoft.com"], "pbk": "PUBKEY-1", "sids": ["ab12"],
    },
    "VLESS_WS": {
        "protocol": "vless", "network": "ws", "tls": "none",
        "header_type": "", "port": 2083,
    },
    "VMESS_WS": {
        "protocol": "vmess", "network": "ws", "tls": "tls",
        "header_type": "", "port": 8443,
    },
}

HOSTS: dict[str, list[dict[str, Any]]] = {
    "VLESS_TCP_REALITY": [
        {
            "remark": "Reality · DE",
            "address": ["de.example.com"],
            "port": 443,
            "sni": ["www.microsoft.com"],
            "host": [],
            "path": None,
            "alpn": "h2",
            "fingerprint": "chrome",
            "tls": None,
        }
    ]
}


class FakeBackend:
    """Records every call; returns canned config/stats. XrayBackend-shaped."""

    def __init__(self, inbounds=None, hosts=None, stats=None, online=None):
        self._inbounds = inbounds if inbounds is not None else INBOUNDS
        self._hosts = hosts if hosts is not None else HOSTS
        self._stats = stats if stats is not None else [XrayUsageStat("1.alice", 100, 1000, None)]
        self._online = online if online is not None else []
        self.added: list[tuple[str, str, str, dict]] = []
        self.removed: list[tuple[str, str]] = []
        self.routing_rules: list[dict] = []
        self.outbounds: list[dict] = []
        self.running = False
        self.start_calls = 0

    # process
    def start(self): self.running = True; self.start_calls += 1
    def stop(self): self.running = False
    def restart(self): self.start(); self.stop(); self.start()
    def is_running(self): return self.running
    def version(self): return "1.8.23"
    def metrics(self): return CoreMetrics(cpu_percent=2.5, memory_bytes=42_000_000)
    def logs(self, tail: int = 200): return [f"xray line {i}" for i in range(min(tail, 2))]

    # config
    def inbounds(self) -> Mapping[str, dict[str, Any]]: return dict(self._inbounds)
    def host_options(self, tag: str) -> Sequence[dict[str, Any]]: return list(self._hosts.get(tag, []))

    # users
    def add_user(self, tag, protocol, email, settings):
        self.added.append((tag, protocol, email, dict(settings)))

    def remove_user(self, tag, email):
        self.removed.append((tag, email))

    # stats
    def usage(self, reset: bool = False): return list(self._stats)
    def online_accounts(self): return list(self._online)

    # config injection
    def set_routing_rules(self, rules): self.routing_rules = list(rules)
    def set_outbounds(self, outbounds): self.outbounds = list(outbounds)

    def ensure_listener(self, protocol, port):
        tag = f"zg-chain-{protocol}-{port}"
        self._inbounds.setdefault(tag, {"protocol": protocol, "port": port, "network": "tcp"})



def _driver(**kwargs) -> tuple[XrayDriver, FakeBackend]:
    backend = FakeBackend(**kwargs)
    return XrayDriver(backend=backend), backend


def _vless_account(**over) -> UserAccount:
    base = dict(
        user_id=1,
        username="alice",
        account_id="1.alice",
        protocol="vless",
        settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision"},
    )
    base.update(over)
    return UserAccount(**base)


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #


def test_registered_in_global_registry() -> None:
    from app.cores.registry import available_drivers

    assert "xray" in available_drivers()


def test_create_account_targets_only_matching_inbounds_and_sanitizes_flow() -> None:
    async def main():
        driver, backend = _driver()
        await driver.create_account(_vless_account())

        added = {(tag, proto) for tag, proto, _, _ in backend.added}
        assert added == {("VLESS_TCP_REALITY", "vless"), ("VLESS_WS", "vless")}
        by_tag = {tag: settings for tag, _, _, settings in backend.added}
        # flow survives on TCP+Reality ...
        assert by_tag["VLESS_TCP_REALITY"]["flow"] == "xtls-rprx-vision"
        # ... but XTLS flow is stripped on websocket transports
        assert by_tag["VLESS_WS"]["flow"] == ""

    asyncio.run(main())


def test_create_account_respects_excluded_and_missing_inbounds() -> None:
    async def main():
        driver, backend = _driver()
        await driver.create_account(
            _vless_account(settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                                     "excluded_inbounds": ["VLESS_WS"]})
        )
        assert {tag for tag, *_ in backend.added} == {"VLESS_TCP_REALITY"}

        # no matching inbound at all -> hard error
        empty = FakeBackend(inbounds={"ONLY_NEGAR_SSID": INBOUNDS["VMESS_WS"]})
        driver2 = XrayDriver(backend=empty)
        try:
            await driver2.create_account(_vless_account())
            raise AssertionError("expected CoreError when no inbound matches")
        except CoreError:
            pass

    asyncio.run(main())


def test_create_rejects_unknown_protocol_and_disabled_is_noop() -> None:
    async def main():
        driver, backend = _driver()
        try:
            await driver.create_account(_vless_account(protocol="wireguard"))
            raise AssertionError("unsupported protocol must raise")
        except CoreError:
            pass
        await driver.create_account(_vless_account(enabled=False))
        assert backend.added == []

    asyncio.run(main())


def test_update_wipes_everywhere_then_readds() -> None:
    async def main():
        driver, backend = _driver()
        await driver.update_account(_vless_account())
        # removed from *every* inbound, incl. other protocols (legacy alter semantics)
        assert {tag for tag, _ in backend.removed} == set(INBOUNDS)
        # then re-added only to vless inbounds
        assert {tag for tag, *_ in backend.added} == {"VLESS_TCP_REALITY", "VLESS_WS"}

    asyncio.run(main())


def test_suspend_and_resume() -> None:
    async def main():
        driver, backend = _driver()
        await driver.suspend_account("1.alice")
        assert {tag for tag, _ in backend.removed} == set(INBOUNDS)
        await driver.resume_account(_vless_account())
        assert len(backend.added) == 2

    asyncio.run(main())


def test_usage_reports_deltas_and_keeps_node_split() -> None:
    async def main():
        stats = [
            XrayUsageStat("1.alice", 100, 1000, None),
            XrayUsageStat("1.alice", 40, 60, 7),      # node 7
            XrayUsageStat("2.bob", 5, 5, None),
        ]
        driver, backend = _driver(stats=stats)

        first = await driver.get_usage(account_ids=["1.alice"])
        total_up = sum(r.uplink_bytes for r in first)
        total_down = sum(r.downlink_bytes for r in first)
        assert (total_up, total_down) == (140, 1060)
        assert {r.node_id for r in first} == {None, 7}

        # counters flat -> second call reports zero deltas (not double counting)
        second = await driver.get_usage(account_ids=["1.alice"])
        assert all(r.uplink_bytes == 0 and r.downlink_bytes == 0 for r in second)

    asyncio.run(main())


def test_usage_baselines_persist_for_main_and_node_counters() -> None:
    async def main():
        stats = [
            XrayUsageStat("1.alice", 100, 1000, None),
            XrayUsageStat("1.alice", 40, 60, 7),
        ]
        driver, _backend = _driver(stats=stats)
        await driver.get_usage(account_ids=["1.alice"])
        snapshot = driver.usage_tracker_snapshot(["1.alice"])
        assert snapshot == {
            "1.alice": (100, 1000),
            "1.alice::node::7": (40, 60),
        }

        restarted, _backend2 = _driver(stats=stats)
        restarted.restore_usage_baselines(snapshot)
        same = await restarted.get_usage(account_ids=["1.alice"])
        assert all((r.uplink_bytes, r.downlink_bytes) == (0, 0) for r in same)

    asyncio.run(main())


def test_online_devices_and_filtering() -> None:
    async def main():
        driver, backend = _driver(online=["1.alice", "2.bob"])
        assert [s.account_id for s in await driver.get_online_devices()] == ["1.alice", "2.bob"]
        filtered = await driver.get_online_devices(account_ids=["1.alice"])
        assert [s.account_id for s in filtered] == ["1.alice"]

    asyncio.run(main())


def test_shadowsocks_client_fragment_has_no_invalid_tls_or_transport_fields() -> None:
    driver, _backend = _driver()
    outbound = driver._compose_outbound(  # noqa: SLF001
        "shadowsocks", {"method": "aes-256-gcm", "password": "secret"},
        "Shadowsocks TCP", {"port": 1080, "network": "tcp", "tls": "none"},
        {"address": ["vpn.example.test"]},
    )
    assert outbound["type"] == "shadowsocks"
    assert outbound["server"] == "vpn.example.test"
    assert "tls" not in outbound and "transport" not in outbound


def test_build_client_config_payload_shape_and_redaction() -> None:
    async def main():
        driver, _ = _driver()
        cfg = await driver.build_client_config(_vless_account())

        assert cfg.engine == "sing-box" and cfg.protocol == "vless"
        assert "SECRET-SCAN" not in repr(cfg)

        outbound = cfg.payload["outbounds"][0]
        assert outbound["server"] == "de.example.com"
        assert outbound["server_port"] == 443
        assert outbound["uuid"] == "b831381d-6324-4d53-ad4f-8cda48b30811"
        assert outbound["flow"] == "xtls-rprx-vision"
        assert outbound["tls"]["enabled"] is True
        assert outbound["tls"]["server_name"] == "www.microsoft.com"
        assert outbound["tls"]["reality"]["public_key"] == "PUBKEY-1"
        assert outbound["tls"]["reality"]["short_id"] == "ab12"
        assert cfg.display_name == "Reality · DE"

        blob = repr(cfg) + repr(cfg.public_view())
        for secret in ("de.example.com", "b831381d", "PUBKEY-1", "www.microsoft.com"):
            assert secret not in blob, f"secret leaked: {secret}"

    asyncio.run(main())


def test_lifecycle_and_status_mapping() -> None:
    async def main():
        driver, backend = _driver()
        assert (await driver.status()).state == CoreState.STOPPED
        await driver.start()
        status = await driver.status()
        assert status.state == CoreState.RUNNING
        assert status.core_version == "1.8.23"
        assert status.metrics and status.metrics.memory_bytes == 42_000_000
        logs = [line async for line in driver.get_logs(tail=1)]
        assert logs == ["xray line 0"]

    asyncio.run(main())


def test_capabilities() -> None:
    driver, _ = _driver()
    from app.cores import Capability

    for cap in (Capability.USER_MANAGEMENT, Capability.USAGE_ACCOUNTING,
                Capability.ONLINE_TRACKING, Capability.MULTI_NODE):
        assert driver.supports(cap)
    assert driver.supports(Capability.SELF_INSTALL)
    # real install/update/uninstall is covered by the e2e real-binary suite


# --------------------------------------------------------------------------- #
# standalone runner
# --------------------------------------------------------------------------- #

def _run_all() -> None:
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except BaseException:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    _run_all()


def test_uninstall_refuses_foreign_binary(tmp_path) -> None:
    """Safety policy: uninstall must never delete a binary Zagros did NOT install."""
    from app.cores.exceptions import CoreError
    from app.cores.drivers.xray.driver import _uninstall_xray

    exe = tmp_path / "xray"
    exe.write_bytes(b"foreign-system-binary")
    try:
        _uninstall_xray({"executable_path": str(exe), "assets_path": None}, purge=False)
        raise AssertionError("expected CoreError")
    except CoreError:
        pass
    assert exe.exists(), "foreign binary must remain untouched"


def test_uninstall_removes_marked_binary(tmp_path) -> None:
    from app.cores.drivers.xray.driver import _uninstall_xray

    exe = tmp_path / "xray"
    exe.write_bytes(b"panel-managed-binary")
    (tmp_path / "xray.zagros-installed").write_text("v1.0.0\n")
    _uninstall_xray({"executable_path": str(exe), "assets_path": None}, purge=False)
    assert not exe.exists()


def test_legacy_backend_routing_preserves_xray_api_control_plane() -> None:
    from types import SimpleNamespace

    from app.cores.drivers.xray.backend import LegacyXrayBackend

    api_rule = {
        "type": "field", "inboundTag": ["API_INBOUND"],
        "outboundTag": "API",
    }
    backend = LegacyXrayBackend({})
    backend._mod = SimpleNamespace(  # noqa: SLF001 - isolated adapter regression
        config={"routing": {"rules": [api_rule, {
            "type": "field", "inboundTag": ["old"], "outboundTag": "DIRECT"}]}},
        core=SimpleNamespace(started=False),
    )
    new_rule = {"type": "field", "inboundTag": ["test"], "outboundTag": "Open"}
    backend.set_routing_rules([new_rule])
    assert backend._mod.config["routing"]["rules"] == [api_rule, new_rule]


def test_outbound_redeploy_and_base_rules_keep_one_copy_of_custom_tag() -> None:
    """Repeat Deploy used to append custom names, then base setup deleted them."""
    from app.cores.outbounds.model import Outbound, OutboundKind
    from app.cores.routing.model import RouteContext, RoutingRule, RuleAction, RuleMatcher

    driver, backend = _driver()
    outbound = Outbound(
        name="Open", kind=OutboundKind.OPENVPN,
        settings={"ovpn_content": "client\nremote vpn.example 443",
                  "_policy_mark": 12001},
    )
    asyncio.run(driver.deploy_outbounds([outbound]))
    asyncio.run(driver.deploy_outbounds([outbound]))
    rule = RoutingRule(
        name="via-open", matcher=RuleMatcher(inbounds=["VLESS_TCP_REALITY"]),
        action=RuleAction.ROUTE_TO, outbound="Open", priority=10,
    )
    asyncio.run(driver.deploy_routing_rules(
        [rule], RouteContext(available_outbounds=["Open"])))
    tags = [item["tag"] for item in backend.outbounds]
    assert tags.count("Open") == 1
    assert {"zg-direct", "zg-block", "zg-dns", "Open"} <= set(tags)
    custom = next(item for item in backend.outbounds if item["tag"] == "Open")
    assert custom["protocol"] == "freedom"
    assert custom["streamSettings"]["sockopt"]["mark"] == 12001
