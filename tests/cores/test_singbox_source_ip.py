from __future__ import annotations

import pytest

from app.cores.drivers.singbox.driver import SingBoxDriver
from app.cores.types import UserAccount


class Backend:
    def __init__(self):
        self.lines = [
            "2026-09-05T12:00:00Z INFO [12345 0ms] inbound/hysteria2[hy2]: inbound connection from 198.51.100.44:54321",
            "2026-09-05T12:00:00Z INFO [12345 1ms] inbound/hysteria2[hy2]: [1.alice.hysteria2] inbound connection to 1.1.1.1:443",
        ]
        self.closed = []

    def logs(self, tail=200): return self.lines[-tail:]
    def clash_connections(self):
        return [{"id": "flow-1", "metadata": {"sourceIP": "198.51.100.44"}}]
    def close_connections_from(self, ip):
        self.closed.append(ip)
        return 1
    def probe_v2ray_support(self): return False


class Stats:
    def query_user_counters(self): return {}


@pytest.mark.asyncio
async def test_hysteria_log_context_maps_account_to_clash_source_and_closes_it():
    backend = Backend()
    driver = SingBoxDriver(backend=backend, stats=Stats())
    driver._accounts["1.alice.hysteria2"] = UserAccount(
        user_id=1, username="alice", account_id="1.alice.hysteria2",
        protocol="hysteria2", settings={"password": "secret"},
    )
    sessions = await driver.get_online_devices()
    assert [(row.account_id, row.ip) for row in sessions] == [
        ("1.alice.hysteria2", "198.51.100.44")]
    assert sessions[0].metadata["provider"] == "sing-box-log+clash"
    assert await driver.terminate_source_ip("198.51.100.44") == 1
    assert backend.closed == ["198.51.100.44"]


def test_render_enables_loopback_clash_api_and_info_logs():
    driver = SingBoxDriver(backend=Backend(), stats=Stats())
    config = driver.render_config()
    assert config["log"]["level"] == "info"
    assert config["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:19092"
