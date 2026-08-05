"""Hysteria2 driver tests — official Traffic Stats API fixtures:

  * real /traffic + /online payload parsing (docs-verbatim shapes)
  * usage deltas (tx=uplink, rx=downlink) + restart clamp
  * online device counting (client instances per user)
  * kick on suspend/delete/password change
  * config render (userpass map, masquerade, traffic secret)
  * honest absence of HOT_RELOAD (restart on publish) & SPEED_LIMIT
  * chain ingress user provisioning + metadata contract
  * sealed share-url build

Run: pytest tests/cores/test_hysteria2_driver.py -v  OR  python tests/cores/test_hysteria2_driver.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability, CoreError  # noqa: E402
from app.cores.drivers.hysteria2 import Hysteria2Driver, parse_online, parse_traffic  # noqa: E402
from app.cores.types import CoreMetrics, UserAccount  # noqa: E402

# docs-verbatim samples (v2.hysteria.network/docs/advanced/Traffic-Stats-API)
TRAFFIC_SAMPLE = json.dumps({"1.alice": {"tx": 514, "rx": 4017},
                             "2.bob": {"tx": 7790, "rx": 446623}})
ONLINE_SAMPLE = json.dumps({"1.alice": 2, "2.bob": 1})


class FakeHy2Backend:
    def __init__(self):
        self.configs: list[str] = []
        self.running = False
        self.restarts = 0
        self._traffic: dict[str, tuple[int, int]] = {}
        self._online: dict[str, int] = {}
        self.kicked: list[list[str]] = []

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.running = True; self.restarts += 1
    def is_running(self): return self.running
    def version(self): return "v2.6.1"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def install_binary(self): return "v2.6.1"
    def ensure_tls(self, cn: str): return ("/fake/server.crt", "/fake/server.key")
    def apply_config(self, yaml_text: str): self.configs.append(yaml_text)
    def traffic(self): return dict(self._traffic)
    def online(self): return dict(self._online)
    def kick(self, users): self.kicked.append(list(users))


def _driver(tmp: str | None = None) -> tuple[Hysteria2Driver, FakeHy2Backend]:
    backend = FakeHy2Backend()
    settings = {"work_dir": tmp or tempfile.mkdtemp(prefix="mzhy2-test-")}
    return Hysteria2Driver(settings, backend=backend), backend


def _account(user: int, name: str, password: str = "secret", enabled: bool = True) -> UserAccount:
    return UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                       protocol="hysteria2", enabled=enabled,
                       settings={"password": password})


# ---------------------------------------------------------------------- #

def test_official_payload_parsing() -> None:
    traffic = parse_traffic(TRAFFIC_SAMPLE)
    assert traffic["1.alice"] == (514, 4017)      # tx=uplink, rx=downlink
    assert traffic["2.bob"] == (7790, 446623)
    online = parse_online(ONLINE_SAMPLE)
    assert online == {"1.alice": 2, "2.bob": 1}


def test_config_render_userpass_and_secret() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        conf = backend.configs[-1]
        assert "type: userpass" in conf
        assert "    1_alice: secret" in conf
        assert "listen: :443" in conf
        assert "url: https://www.bing.com" in conf
        assert "trafficStats:" in conf and "listen: 127.0.0.1:19999" in conf
        # disabled accounts are excluded from the userpass map
        await driver.create_account(_account(2, "bob", enabled=False))
        assert "2_bob" not in backend.configs[-1]

    asyncio.run(run())


def test_usage_deltas_and_clamp() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        backend._traffic = {"1_alice": (514, 4017), "_mz-chain": (10, 10)}  # core-side sanitized names (real server shape)
        first = await driver.get_usage()
        assert len(first) == 1  # chain user never billed
        assert (first[0].uplink_bytes, first[0].downlink_bytes) == (514, 4017)

        backend._traffic = {"1_alice": (1024, 4017)}
        second = await driver.get_usage()
        assert (second[0].uplink_bytes, second[0].downlink_bytes) == (510, 0)

        backend._traffic = {"1_alice": (5, 5)}  # restart → clamp, no negatives
        third = await driver.get_usage()
        assert (third[0].uplink_bytes, third[0].downlink_bytes) == (0, 0)

    asyncio.run(run())


def test_online_devices_from_official_endpoint() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        await driver.create_account(_account(2, "bob"))
        backend._online = {"1_alice": 2, "2_bob": 1, "9_ghost": 3}
        sessions = await driver.get_online_devices()
        assert len(sessions) == 3                    # 2 alice instances + 1 bob
        by_account = [s.account_id for s in sessions]
        assert by_account.count("1.alice") == 2
        assert by_account.count("2.bob") == 1
        assert all(s.ip is None for s in sessions)   # API exposes no IPs: honest
        assert sessions[0].metadata["identity_note"]

    asyncio.run(run())


def test_suspend_delete_kicks_and_restarts_not_reloads() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        restarts = backend.restarts
        await driver.suspend_account("1.alice")
        assert backend.kicked[-1] == ["1_alice"]          # immediate session drop (core-side name)
        assert backend.restarts == restarts + 1           # publish restarts (no hot-reload)
        assert "1_alice:" not in backend.configs[-1]

        await driver.resume_account(_account(1, "alice"))
        assert "    1_alice: secret" in backend.configs[-1]

        # password change forces re-auth via kick
        await driver.update_account(_account(1, "alice", password="newpass"))
        assert backend.kicked[-1] == ["1_alice"]

        await driver.delete_account("1.alice")
        assert backend.kicked[-1] == ["1_alice"]
        assert "1.alice" not in driver._accounts

        # honest capability surface
        assert not driver.supports(Capability.HOT_RELOAD)
        assert not driver.supports(Capability.SPEED_LIMIT)

    asyncio.run(run())


def test_chain_ingress_provision_and_contract() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        try:
            await driver.ensure_chain_listener("socks", 40000)
            raise AssertionError("socks chain into hysteria2 must be refused")
        except CoreError:
            pass

        endpoint = await driver.ensure_chain_listener("hysteria2", 0)
        assert endpoint.protocol == "hysteria2"
        assert endpoint.requires_credentials
        md = endpoint.metadata
        assert md["password"] and md["sni"] == "updates.microsoft.com"
        assert md["insecure"] is True     # self-signed default, honestly exposed
        assert "_mz-chain" in backend.configs[-1]   # chain user rendered into config
        assert (await driver.get_chain_endpoints())[0].metadata["password"] == md["password"]

    asyncio.run(run())


def test_sealed_share_url_build() -> None:
    async def run():
        driver, _ = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        config = await driver.build_client_config(driver._accounts["1.alice"])
        url = config.payload["url"]
        assert url.startswith("hysteria2://1_alice:secret@127.0.0.1:443")
        assert "sni=updates.microsoft.com" in url
        assert "insecure=1" in url
        assert "secret" not in repr(config)          # redacted repr
        status = await driver.status()
        from app.cores.types import HealthStatus
        assert status.health in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# standalone + pytest runner                                             #
# ---------------------------------------------------------------------- #

def _run_standalone() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
