"""Executable tests for SingBoxDriver: config rendering, user lifecycle,
routing/outbound translation fidelity, chain ingress, sealed payloads.

Run: pytest tests/cores/test_singbox_driver.py -v   OR   python tests/cores/test_singbox_driver.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import CoreError, CoreState  # noqa: E402
from app.cores.drivers.singbox import SingBoxDriver  # noqa: E402
from app.cores.outbounds import Outbound, OutboundKind  # noqa: E402
from app.cores.routing import RouteContext, RoutingRule, RuleAction, RuleMatcher  # noqa: E402
from app.cores.types import CoreMetrics, UserAccount  # noqa: E402


class FakeSingBoxBackend:
    def __init__(self, running: bool = False):
        self.configs: list[dict] = []
        self.running = running
        self.restarts = 0
        self.started = 0
        self.stopped = 0

    def apply_config(self, config: dict[str, Any]) -> None:
        self.configs.append(config)

    def start(self): self.running = True; self.started += 1
    def stop(self): self.running = False; self.stopped += 1

    def restart(self):
        self.restarts += 1

    def is_running(self): return self.running
    def version(self): return "1.11.4"
    def metrics(self): return CoreMetrics(cpu_percent=3.0, memory_bytes=51_000_000)
    def logs(self, tail: int = 200): return [f"sing-box log {i}" for i in range(min(tail, 2))]


class FakeStatsSource:
    """Fake TrafficStatsSource: hand-set cumulative counters per user."""

    def __init__(self):
        self.counters: dict[str, tuple[int, int]] = {}
        self.fails = 0

    def query_user_counters(self) -> dict[str, tuple[int, int]]:
        if self.fails:
            self.fails -= 1
            raise CoreError("stats API unreachable (simulated)")
        return dict(self.counters)


def _driver(settings: dict | None = None, running: bool = False,
            stats: FakeStatsSource | None = None):
    backend = FakeSingBoxBackend(running=running)
    stats = stats or FakeStatsSource()
    return SingBoxDriver(settings=settings, backend=backend, stats=stats), backend, stats


def _vless(**over) -> UserAccount:
    base = dict(user_id=1, username="alice", account_id="1.alice", protocol="vless",
                settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811"})
    base.update(over)
    return UserAccount(**base)


def _inbound(config: dict, tag: str) -> dict:
    return next(i for i in config["inbounds"] if i["tag"] == tag)


# --------------------------------------------------------------------------- #

def test_persisted_self_installed_binary_survives_backend_recreation(tmp_path) -> None:
    from app.cores.drivers.singbox.backend import LocalSingBoxBackend

    binary = tmp_path / "sing-box"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    backend = LocalSingBoxBackend({
        "work_dir": str(tmp_path),
        # Exact alpha.7.7 persisted shape: a bare name, while SELF_INSTALL
        # had actually written work_dir/sing-box.
        "executable_path": "sing-box",
    })
    assert backend.executable == str(binary)
    assert backend._proc.argv[0] == str(binary)


def test_listener_readiness_classifies_native_quic_as_udp() -> None:
    from app.cores.drivers.singbox.backend import LocalSingBoxBackend

    expected = LocalSingBoxBackend._expected_listeners({"inbounds": [
        {"type": "hysteria2", "listen_port": 4430},
        {"type": "tuic", "listen_port": 5443},
        {"type": "vless", "listen_port": 8443},
        {"type": "shadowsocks", "listen_port": 8388},
    ]})
    assert expected == {
        ("udp", 4430), ("udp", 5443), ("tcp", 8443),
        ("tcp", 8388), ("udp", 8388),
    }


def test_render_contains_all_protocol_inbounds_and_users() -> None:
    async def main():
        driver, backend, _s = _driver()
        await driver.create_account(_vless())
        config = backend.configs[-1]
        tags = {i["tag"] for i in config["inbounds"]}
        # sing-box >=1.11 rejects empty-user inbounds → only populated ones render
        assert {"vless-in"} <= tags
        assert "vmess-in" not in tags
        users = _inbound(config, "vless-in")["users"]
        assert users == [{"name": "1.alice", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]

    asyncio.run(main())


def test_suspend_removes_user_from_rendered_config_and_resume_restores() -> None:
    async def main():
        driver, backend, _s = _driver()
        await driver.create_account(_vless())
        await driver.suspend_account("1.alice")
        # suspended user → no enabled users → inbound omitted from render
        tags = {i["tag"] for i in backend.configs[-1]["inbounds"]}
        assert "vless-in" not in tags
        await driver.resume_account(_vless())
        assert len(_inbound(backend.configs[-1], "vless-in")["users"]) == 1

    asyncio.run(main())


def test_sync_accounts_converges_wholesale() -> None:
    async def main():
        driver, backend, _s = _driver()
        await driver.create_account(_vless())
        await driver.create_account(_vless(account_id="9.stale", user_id=9, username="stale"))
        await driver.sync_accounts([_vless()])
        users = _inbound(backend.configs[-1], "vless-in")["users"]
        assert [u["name"] for u in users] == ["1.alice"]

    asyncio.run(main())


def test_running_core_restarts_on_republish_stopped_core_only_renders() -> None:
    async def main():
        driver, backend, _s = _driver(running=True)
        await driver.create_account(_vless())
        assert backend.restarts == 1
        driver2, backend2, _s2 = _driver(running=False)
        await driver2.create_account(_vless())
        assert backend2.restarts == 0 and len(backend2.configs) == 1

    asyncio.run(main())


def test_routing_translation_fidelity_and_no_silent_drops() -> None:
    async def main():
        driver, backend, _s = _driver()  # geo DBs NOT configured by default
        rules = [
            RoutingRule(name="ads", matcher=RuleMatcher(domain_suffixes=["ads.example"]),
                        action=RuleAction.BLOCK, priority=10),
            RoutingRule(name="process", matcher=RuleMatcher(process_names=["telegram"]),
                        action=RuleAction.ROUTE_TO, outbound="wg-up", priority=20),
            RoutingRule(name="geo", matcher=RuleMatcher(geoips=["ir"]),
                        action=RuleAction.BLOCK, priority=30),
            RoutingRule(name="rewrite", matcher=RuleMatcher(domains=["a.com"]),
                        action=RuleAction.REDIRECT, redirect_to="127.0.0.1:8080", priority=40),
            RoutingRule(name="fakes", matcher=RuleMatcher(domains=["b.com"]),
                        action=RuleAction.FAKE_DNS, priority=50),
        ]
        report = await driver.deploy_routing_rules(rules, RouteContext(available_outbounds=["wg-up"]))

        # applied: ads (reject) + process (native process_name)
        assert set(report.applied) == {"ads", "process"}
        rendered = backend.configs[-1]["route"]["rules"]
        assert rendered[0] == {"protocol": "dns", "action": "hijack-dns"}  # built-in DNS interception first
        assert rendered[1] == {"action": "reject", "domain_suffix": ["ads.example"]}
        assert rendered[2]["process_name"] == ["telegram"] and rendered[2]["outbound"] == "wg-up"

        # reported, never silently dropped
        gaps = {u.rule: u.reason for u in report.unsupported}
        assert set(gaps) == {"geo", "rewrite", "fakes"}
        assert "geoip_db" in gaps["geo"]
        assert "inbound type" in gaps["rewrite"]
        assert "fakeip" in gaps["fakes"]

    asyncio.run(main())


def test_routing_route_to_unknown_outbound_is_reported() -> None:
    async def main():
        driver, _b, _s = _driver()
        rule = RoutingRule(name="chain", matcher=RuleMatcher(domains=["x.com"]),
                           action=RuleAction.ROUTE_TO, outbound="ghost")
        report = await driver.deploy_routing_rules([rule], RouteContext(available_outbounds=[]))
        assert report.applied == [] and report.unsupported[0].fields == ["outbound"]

    asyncio.run(main())


def test_outbound_translation_native_set_and_gaps() -> None:
    async def main():
        driver, backend, _s = _driver()
        outbounds = [
            Outbound(name="up-socks", kind=OutboundKind.SOCKS,
                     settings={"server": "127.0.0.1", "server_port": 9999,
                               "username": "u", "password": "p"}),
            Outbound(name="up-wg", kind=OutboundKind.WIREGUARD,
                     settings={"server": "10.0.0.1", "server_port": 51820,
                               "private_key": "PRIV", "peer_public_key": "PUB",
                               "local_address": ["10.0.0.2/32"], "reserved": [1, 2, 3]}),
            Outbound(name="up-hy2", kind=OutboundKind.HYSTERIA2,
                     settings={"server": "hy.example", "server_port": 443,
                               "password": "pw", "sni": "cdn.example"}),
            Outbound(name="up-ovpn", kind=OutboundKind.OPENVPN,
                     settings={"server": "ovpn.example", "server_port": 1194}),
            Outbound(name="sink", kind=OutboundKind.BLOCK, settings={}),
            Outbound(name="bad-socks", kind=OutboundKind.SOCKS,
                     settings={"server": "127.0.0.1"}),  # missing port -> reported
        ]
        report = await driver.deploy_outbounds(outbounds)

        assert set(report.applied) == {"up-socks", "up-wg", "up-hy2"}
        native = {o["tag"]: o for o in backend.configs[-1]["outbounds"]}
        assert native["up-socks"]["username"] == "u" and native["up-socks"]["version"] == "5"
        assert native["up-wg"]["peer_public_key"] == "PUB" and native["up-wg"]["reserved"] == [1, 2, 3]
        assert native["up-hy2"]["tls"]["server_name"] == "cdn.example"

        gaps = {u.name: u.reason for u in report.unsupported}
        assert set(gaps) == {"up-ovpn", "sink", "bad-socks"}
        assert "openvpn" in gaps["up-ovpn"]
        assert "action=block" in gaps["sink"]
        assert "server_port" in gaps["bad-socks"]

    asyncio.run(main())


def test_chain_listener_lifecycle() -> None:
    async def main():
        driver, backend, _s = _driver()
        assert await driver.get_chain_endpoints() == []
        ep = await driver.ensure_chain_listener("socks", 40001)
        assert (ep.host, ep.port, ep.protocol) == ("127.0.0.1", 40001, "socks")
        listeners = [i for i in backend.configs[-1]["inbounds"] if i["tag"] == "zg-chain-socks-40001"]
        assert listeners and listeners[0]["listen_port"] == 40001
        # idempotent + visible
        assert await driver.ensure_chain_listener("socks", 40001) == ep
        assert len(await driver.get_chain_endpoints()) == 1
        # wireguard cannot be a chain *listener*
        try:
            await driver.ensure_chain_listener("wireguard", 40002)
            raise AssertionError("must reject non-proxy chain listeners")
        except CoreError:
            pass

    asyncio.run(main())


def test_build_client_config_payload_and_redaction() -> None:
    async def main():
        driver, _b, _s = _driver(settings={"advertise_host": "203.0.113.7"})
        cfg = await driver.build_client_config(_vless(settings={"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision"}))
        outbound = cfg.payload["outbounds"][0]
        assert outbound["server"] == "203.0.113.7"
        assert outbound["server_port"] == 10001
        assert outbound["flow"] == "xtls-rprx-vision"
        blob = repr(cfg) + repr(cfg.public_view())
        assert "203.0.113.7" not in blob and "b831381d" not in blob

    asyncio.run(main())


def test_lifecycle_status_AND_logs() -> None:
    async def main():
        driver, backend, _s = _driver()
        assert (await driver.status()).state == CoreState.STOPPED
        await driver.start()
        assert backend.started == 1 and (await driver.status()).state == CoreState.RUNNING
        status = await driver.status()
        assert status.core_version == "1.11.4" and status.metrics.memory_bytes == 51_000_000
        assert [l async for l in driver.get_logs(tail=1)] == ["sing-box log 0"]
        await driver.stop()
        assert backend.stopped == 1

    asyncio.run(main())



def test_stats_block_rendered_with_user_list() -> None:
    async def run() -> None:
        driver, backend, _ = _driver()
        await driver.create_account(_vless())
        await driver.create_account(UserAccount(
            user_id=2, username="bob", account_id="2.bob", protocol="trojan",
            settings={"password": "pw"}))
        experimental = backend.configs[-1]["experimental"]
        api = experimental["v2ray_api"]
        assert api["listen"] == "127.0.0.1:19091"
        assert api["stats"]["enabled"] is True
        assert api["stats"]["users"] == ["1.alice", "2.bob"]
        assert "vless-in" in api["stats"]["inbounds"]

        # stats block can be turned off for binaries without v2ray_api
        driver2, backend2, _ = _driver({"stats_enabled": False})
        await driver2.create_account(_vless())
        assert "experimental" not in backend2.configs[-1]

    asyncio.run(run())


def test_usage_accounting_deltas_and_missing_user_guard() -> None:
    async def run() -> None:
        driver, _b, stats = _driver()
        await driver.create_account(_vless())
        stats.counters = {"1.alice": (3000, 5000), "9.ghost": (999, 999)}

        first = await driver.get_usage()
        assert len(first) == 1  # ghost counters never billed
        rec = first[0]
        assert (rec.uplink_bytes, rec.downlink_bytes) == (3000, 5000)

        stats.counters = {"1.alice": (4000, 5000)}
        second = await driver.get_usage()
        assert (second[0].uplink_bytes, second[0].downlink_bytes) == (1000, 0)

        # core restart (counters reset) → clamped to zero, never negative
        stats.counters = {"1.alice": (50, 10)}
        third = await driver.get_usage()
        assert (third[0].uplink_bytes, third[0].downlink_bytes) == (0, 0)

    asyncio.run(run())


def test_stats_outage_surfaces_as_degraded_health() -> None:
    async def run() -> None:
        from app.cores.types import HealthStatus

        driver, backend, stats = _driver(running=True)
        await driver.create_account(_vless())
        stats.counters = {"1.alice": (10, 10)}
        await driver.get_usage()  # healthy read clears any previous error

        stats.fails = 1
        try:
            await driver.get_usage()
            raise AssertionError("get_usage must surface stats failures")
        except CoreError:
            pass
        status = await driver.status()
        assert status.health == HealthStatus.DEGRADED
        assert "unreachable" in (status.message or "")

        stats.counters = {"1.alice": (20, 20)}  # recovery clears degradation
        await driver.get_usage()
        status = await driver.status()
        assert status.health == HealthStatus.HEALTHY

    asyncio.run(run())


def test_online_detection_counter_delta_heuristic() -> None:
    async def run() -> None:
        driver, _b, stats = _driver()
        await driver.create_account(_vless())
        stats.counters = {"1.alice": (100, 100)}
        assert await driver.get_online_devices() == []     # baseline poll: no growth yet
        stats.counters = {"1.alice": (250, 100)}           # grew → online
        sessions = await driver.get_online_devices()
        assert len(sessions) == 1
        assert sessions[0].account_id == "1.alice"
        assert sessions[0].ip is None                      # API exposes no IPs: reported honestly
        assert await driver.get_online_devices() == []     # no further growth → offline

    asyncio.run(run())


def _run_all() -> None:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
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


# --------------------------------------------------------------------- #
# StatsService dialect negotiation (alpha.7.4): sing-box >= 1.12 serves the
# stats API as v2ray.core.app.stats.command.StatsService, xray/<=1.11 as
# xray.app.stats.command.StatsService — the client must serve both.
# --------------------------------------------------------------------- #
def test_stats_source_negotiates_v2ray_core_dialect() -> None:
    """gRPC UNIMPLEMENTED on the xray dialect must fall through to the
    v2ray.core dialect (the wire-identical sing-box >= 1.12 name)."""
    import grpc
    from xray_api.proto.app.stats.command import command_pb2

    from app.cores.drivers.singbox.backend import V2RayStatsSource

    called: list[str] = []

    class _FakeUnary:
        def __init__(self, path: str):
            self._path = path
        def __call__(self, request, timeout=None):
            called.append(self._path)
            if self._path.startswith("/xray.app."):
                err = grpc.RpcError("unknown service xray.app.stats.command.StatsService")
                err.code = lambda: grpc.StatusCode.UNIMPLEMENTED  # type: ignore[attr-defined]
                err.details = lambda: "unknown service xray..."  # type: ignore[attr-defined]
                raise err
            stat = command_pb2.Stat(name="user>>>u1>>>traffic>>>downlink", value=2048)
            return command_pb2.QueryStatsResponse(stat=[stat])

    class _FakeChannel:
        def unary_unary(self, path, request_serializer=None, response_deserializer=None):
            return _FakeUnary(path)
        def close(self):
            pass

    src = V2RayStatsSource("127.0.0.1:19091")
    import unittest.mock as mock
    with mock.patch("grpc.insecure_channel", lambda target: _FakeChannel()):
        counters = src.query_user_counters()
    assert counters == {"u1": (0, 2048)}
    assert src._dialect == "v2ray.core.app.stats.command.StatsService"
    assert called[0] == "/xray.app.stats.command.StatsService/QueryStats"


def test_stats_source_when_no_dialect_matches_error_names_both() -> None:
    import grpc

    from app.cores.drivers.singbox.backend import V2RayStatsSource

    class _FakeUnary:
        def __init__(self, path: str):
            self._path = path
        def __call__(self, request, timeout=None):
            err = grpc.RpcError(f"unknown service {self._path}")
            err.code = lambda: grpc.StatusCode.UNIMPLEMENTED  # type: ignore[attr-defined]
            err.details = lambda: "unknown"  # type: ignore[attr-defined]
            raise err

    class _FakeChannel:
        def unary_unary(self, path, request_serializer=None, response_deserializer=None):
            return _FakeUnary(path)
        def close(self):
            pass

    src = V2RayStatsSource("127.0.0.1:19091")
    import unittest.mock as mock
    with mock.patch("grpc.insecure_channel", lambda target: _FakeChannel()):
        try:
            src.query_user_counters()
            raise AssertionError("must fail when no dialect is served")
        except CoreError as exc:
            assert "xray.app.stats.command.StatsService" in str(exc)
            assert "v2ray.core.app.stats.command.StatsService" in str(exc)
