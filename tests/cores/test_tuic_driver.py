"""TUIC driver tests:

  * v5 config rendering (users map, TLS, congestion control)
  * credential auto-provisioning (uuid/password generated in place)
  * suspend/resume/delete via render+restart
  * honest capability absence (no usage, no online — locked by tests)
  * chain ingress uuid provisioning + metadata contract
  * sealed share-url build + redaction

Run: pytest tests/cores/test_tuic_driver.py -v  OR  python tests/cores/test_tuic_driver.py
"""
from __future__ import annotations

import asyncio
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
from app.cores.drivers.tuic import TUICDriver  # noqa: E402
from app.cores.types import CoreMetrics, UserAccount  # noqa: E402


class FakeTUICBackend:
    def __init__(self):
        self.configs: list[dict] = []
        self.running = False
        self.restarts = 0

    def start(self): self.running = True
    def stop(self): self.running = False
    def restart(self): self.running = True; self.restarts += 1
    def is_running(self): return self.running
    def version(self): return "tuic-server 1.0.0"
    def metrics(self): return CoreMetrics()
    def logs(self, tail: int = 200): return []
    def install_binary(self): return "tuic-server-1.0.0"
    def ensure_tls(self, cn: str): return ("/fake/tuic.crt", "/fake/tuic.key")
    def apply_config(self, config): self.configs.append(config)


def _driver(tmp: str | None = None) -> tuple[TUICDriver, FakeTUICBackend]:
    backend = FakeTUICBackend()
    settings = {"work_dir": tmp or tempfile.mkdtemp(prefix="mztuic-test-")}
    return TUICDriver(settings, backend=backend), backend


def _account(user: int, name: str, enabled: bool = True, settings: dict | None = None) -> UserAccount:
    return UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                       protocol="tuic", enabled=enabled, settings=settings or {})


def test_config_render_v5_shape() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        conf = backend.configs[-1]
        assert conf["server"] == "[::]:8443"
        assert conf["congestion_control"] == "bbr"
        assert conf["alpn"] == ["h3", "spdy/3.1"]
        assert conf["certificate"] == "/fake/tuic.crt"
        assert len(conf["users"]) == 1
        uuid_, password = next(iter(conf["users"].items()))
        assert len(uuid_) == 36 and uuid_.count("-") == 4     # real uuid4 shape
        assert len(password) == 16
        # generated credentials were written back for the panel to persist
        account = driver._accounts["1.alice"]
        assert account.settings["uuid"] == uuid_

    asyncio.run(run())


def test_suspend_resume_delete_lifecycle() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        account = _account(1, "alice")
        await driver.create_account(account)
        uuid_ = account.settings["uuid"]
        assert uuid_ in backend.configs[-1]["users"]

        await driver.suspend_account("1.alice")
        assert uuid_ not in backend.configs[-1]["users"]
        assert backend.restarts >= 2                            # restart strategy (no API)

        await driver.resume_account(account)
        assert uuid_ in backend.configs[-1]["users"]

        await driver.delete_account("1.alice")
        assert uuid_ not in backend.configs[-1]["users"]
        assert "1.alice" not in driver._accounts

    asyncio.run(run())


def test_honest_capability_absence_is_locked() -> None:
    """The protocol has NO stats/session API — claiming these would be fake."""
    driver, _ = _driver()
    for cap in (Capability.USAGE_ACCOUNTING, Capability.ONLINE_TRACKING,
                Capability.HOT_RELOAD, Capability.DEVICE_DETECTION,
                Capability.ROUTING, Capability.OUTBOUND_MANAGEMENT):
        assert not driver.supports(cap), f"{cap.value} must NOT be claimed for tuic"

    async def run():
        driver, _ = _driver()
        try:
            await driver.get_usage()
            raise AssertionError("get_usage must raise CapabilityNotSupportedError")
        except Exception as exc:
            assert "usage_accounting" in str(exc)

    asyncio.run(run())


def test_chain_ingress_uuid_provision() -> None:
    async def run():
        driver, backend = _driver()
        await driver.start()
        try:
            await driver.ensure_chain_listener("hysteria2", 0)
            raise AssertionError("wrong protocol chain must be refused")
        except CoreError:
            pass

        endpoint = await driver.ensure_chain_listener("tuic", 0)
        md = endpoint.metadata
        assert len(md["uuid"]) == 36 and md["password"]
        assert md["congestion_control"] == "bbr"
        assert md["sni"] == "cdn.cloudflare.com"
        assert md["insecure"] is True
        assert md["uuid"] in backend.configs[-1]["users"]
        # idempotent: same chain user on second call
        endpoint2 = await driver.ensure_chain_listener("tuic", 0)
        assert endpoint2.metadata["uuid"] == md["uuid"]

    asyncio.run(run())


def test_sealed_share_url_and_redaction() -> None:
    async def run():
        driver, _ = _driver()
        await driver.start()
        await driver.create_account(_account(1, "alice"))
        config = await driver.build_client_config(driver._accounts["1.alice"])
        url = config.payload["url"]
        assert url.startswith("tuic://")
        assert "@127.0.0.1:8443/" in url
        assert "congestion_control=bbr" in url
        assert "alpn=h3%2Cspdy%2F3.1" in url or "alpn=h3,spdy/3.1" in url
        assert "allow_insecure=1" in url
        password = driver._accounts["1.alice"].settings["password"]
        assert password not in repr(config) and password not in str(config)

    asyncio.run(run())


def test_missing_credentials_error_path() -> None:
    async def run():
        driver, _ = _driver()
        await driver.start()
        account = _account(9, "ghost")
        account.settings["uuid"] = "fixed-uuid-but-36chars-0000-000000000000"
        # build_client_config without password must fail honestly
        try:
            await driver.build_client_config(account)
            raise AssertionError("missing password must raise")
        except CoreError as exc:
            assert "password" in str(exc)

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
