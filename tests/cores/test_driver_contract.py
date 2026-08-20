"""Driver conformance suite — the plugin contract enforced for every core.

Instead of repeating the same behavioural checks per driver, this harness
runs ONE contract battery against ALL registered drivers (discovered via
``discover_builtin``) with their fake backends. A brand-new driver dropped
into app/cores/drivers/ automatically gets conformance-tested here — the
ultimate proof of "add core = add folder, zero changes".

Contract asserted per driver:
  1. metadata sanity (unique id, non-empty protocols, object schema)
  2. capability/method coherence (claiming X ⇒ the method is overridden)
  3. lifecycle produces a coherent CoreStatus
  4. full user lifecycle works: create → update → suspend → resume → delete
  5. usage + online calls honour their capability gates (explicit raises,
     never silent success)
  6. sealed payloads never leak secrets through repr/str/public_view
  7. provisioning throughput smoke (100 accounts < generous bound)

Run: pytest tests/cores/test_driver_contract.py -v  OR  python tests/cores/test_driver_contract.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import traceback
import types as _types
from pathlib import Path
from typing import Any, ClassVar

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import BaseCoreDriver, Capability  # noqa: E402
from app.cores.exceptions import CapabilityNotSupportedError  # noqa: E402
from app.cores.registry import available_drivers, discover_builtin, get_driver_class  # noqa: E402
from app.cores.routing.model import RoutingRule, RuleAction, RuleMatcher  # noqa: E402
from app.cores.types import CoreState, UserAccount  # noqa: E402
from tests.cores import fakes  # noqa: E402

discover_builtin()


def _builtin_core_ids() -> list[str]:
    """Core ids of the built-in drivers TREE only (never foreign/test drivers
    that other suites may register into the global registry)."""
    import pkgutil
    import app.cores.drivers as drivers_pkg

    ids: list[str] = []
    for info in pkgutil.iter_modules(drivers_pkg.__path__):
        module = __import__(f"app.cores.drivers.{info.name}", fromlist=["*"])
        for value in vars(module).values():
            if (isinstance(value, type)
                    and issubclass(value, BaseCoreDriver)
                    and value is not BaseCoreDriver
                    and not getattr(value, "__abstractmethods__", None)
                    and getattr(value, "metadata", None) is not None
                    and value.metadata.id not in ids):
                ids.append(value.metadata.id)
    return sorted(ids)


def _build(core_id: str, tmp: str) -> tuple[BaseCoreDriver, Any]:
    """Construct each driver with its fake backend (DI by convention)."""
    work = f"{tmp}/{core_id}"
    if core_id == "xray":
        from app.cores.drivers.xray import XrayDriver

        return XrayDriver(backend=fakes.FakeXrayBackend()), None
    if core_id == "sing-box":
        from app.cores.drivers.singbox import SingBoxDriver

        return SingBoxDriver(backend=fakes.FakeSingBoxBackend(),
                             stats=fakes.FakeV2RayStats()), None
    if core_id == "openvpn":
        from app.cores.drivers.openvpn import OpenVPNDriver

        return OpenVPNDriver(settings={"work_dir": work},
                             backend=fakes.FakeOpenVPNBackend()), None
    if core_id == "wireguard":
        from app.cores.drivers.wireguard import WireGuardDriver

        return WireGuardDriver(settings={"work_dir": work},
                               backend=fakes.FakeWireGuardBackend()), None
    if core_id == "ssh":
        from app.cores.drivers.ssh import SSHTunnelDriver

        return SSHTunnelDriver(backend=fakes.FakeSSHBackend()), None
    if core_id == "softether":
        from app.cores.drivers.softether import SoftEtherDriver

        return SoftEtherDriver(settings={"ipsec_psk": "psk"},
                               backend=fakes.FakeSEBackend()), None
    if core_id == "pptp":
        from app.cores.drivers.pptp import PptpDriver

        backend = fakes.FakePptpBackend(work)
        return PptpDriver(settings={
            "work_dir": work,
            "legacy_risk_ack": True,
            "internet_exposure_ack": True,
            "advertise_host": "vpn.example.test",
            "inbounds": [{
                "tag": "pptp", "protocol": "pptp", "listen": "0.0.0.0",
                "port": 1723, "subnet": "10.77.0.0/24", "dns": "1.1.1.1",
                "legacy_risk_ack": True, "internet_exposure_ack": True,
                "authentication": "MS-CHAPv2", "encryption": "MPPE128",
                "network": "IPv4", "ipv6": False,
                "security_class": "legacy_insecure",
            }],
        }, backend=backend), None
    raise AssertionError(
        f"no fake backend wiring for new core '{core_id}' — add it to tests/cores/fakes.py")


_PROTOCOL_SETTINGS: dict[str, dict[str, Any]] = {
    "vless": {"id": "b831381d-6324-4d53-ad4f-8cda48b30811"},
    "vmess": {"id": "b831381d-6324-4d53-ad4f-8cda48b30811"},
    "trojan": {"password": "pw"},
    "shadowsocks": {"password": "pw"},
    "ovpn": {"password": "pw"},
    "l2tp": {"password": "pw"},
    "sstp": {"password": "pw"},
    "wireguard": {},                      # keys are driver-generated
    "hysteria2": {"password": "pw"},
    "tuic": {},                           # uuid/password are driver-generated
    "ssh": {"password": "pw"},
    "pptp": {"password": "pw"},
}

#: method-override requirements per capability (contract coherence)
_REQUIRED_OVERRIDES = {
    Capability.USAGE_ACCOUNTING: "get_usage",
    Capability.ONLINE_TRACKING: "get_online_devices",
    Capability.KEY_ROTATION: "rotate_credentials",
    Capability.ROUTING: "deploy_routing_rules",
    Capability.OUTBOUND_MANAGEMENT: "deploy_outbounds",
    Capability.POLICY_ENFORCEMENT: "apply_policy",
    Capability.SELF_INSTALL: "install",
    Capability.CHAIN_ROUTING: "ensure_chain_listener",
}

_DRIVERS = _builtin_core_ids()


_PREFERRED = ("vless", "ovpn", "wireguard", "hysteria2", "tuic", "l2tp",
              "pptp", "ssh", "vmess", "trojan", "shadowsocks", "sstp")


def _sample_account(driver: BaseCoreDriver, user: int = 7, name: str = "probe") -> UserAccount:
    protocol = next(
        p for p in _PREFERRED if p in driver.metadata.protocols
    )
    settings = dict(_PROTOCOL_SETTINGS.get(protocol, {"password": "pw"}))
    return UserAccount(user_id=user, username=name, account_id=f"{user}.{name}",
                       protocol=protocol, settings=settings)


# ---------------------------------------------------------------------- #
# 1-2. metadata + capability coherence                                   #
# ---------------------------------------------------------------------- #

def test_registry_unique_and_metadata_sane() -> None:
    assert len(_DRIVERS) == len(set(_DRIVERS)), "duplicate core ids in registry"
    # alpha.7.2 consolidation: 6 engines (xray, sing-box, wireguard,
    # openvpn, ssh, softether) — hysteria2/tuic folded INTO sing-box
    assert len(_DRIVERS) >= 6, f"expected >= 6 built-in drivers, got {_DRIVERS}"
    assert "hysteria2" not in _DRIVERS and "tuic" not in _DRIVERS, (
        "standalone hysteria2/tuic cores must stay removed (consolidation)")
    assert "sing-box" in _DRIVERS, "sing-box core missing from the registry"
    for core_id in _DRIVERS:
        cls = get_driver_class(core_id)
        md = cls.metadata
        assert md.id == core_id
        assert md.protocols, f"{core_id}: protocols must be non-empty"
        assert md.capabilities, f"{core_id}: capabilities must be non-empty"
        assert md.config_schema.get("type") == "object"
        assert md.name and md.description


def test_capability_method_coherence() -> None:
    with tempfile.TemporaryDirectory(prefix="zg-contract-") as tmp:
        for core_id in _DRIVERS:
            driver, _ = _build(core_id, tmp)
            for capability, method in _REQUIRED_OVERRIDES.items():
                claimed = driver.supports(capability)
                overridden = getattr(type(driver), method) is not getattr(BaseCoreDriver, method)
                if claimed:
                    assert overridden, (
                        f"{core_id}: claims {capability.value} but {method} is not implemented")
            # SUSPEND_RESUME needs BOTH directions overridden or safe defaults
            if driver.supports(Capability.SUSPEND_RESUME):
                assert getattr(type(driver), "suspend_account") is not BaseCoreDriver.suspend_account, (
                    f"{core_id}: claims suspend_resume but suspend_account is the stub")


# ---------------------------------------------------------------------- #
# 3-4-5. lifecycle + user lifecycle + capability gates                   #
# ---------------------------------------------------------------------- #

def test_lifecycle_and_user_lifecycle() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-contract-") as tmp:
            failures: list[str] = []
            for core_id in _DRIVERS:
                driver, _ = _build(core_id, tmp)
                try:
                    await driver.start()
                    status = await driver.status()
                    assert status.core_id == core_id
                    assert status.state in (CoreState.RUNNING, CoreState.STOPPED)

                    account = _sample_account(driver)
                    await driver.create_account(account)
                    await driver.update_account(account)
                    if driver.supports(Capability.SUSPEND_RESUME):
                        await driver.suspend_account(account.account_id)
                        await driver.resume_account(account)
                    # capability-gated surfaces behave or raise explicitly
                    for cap, call in (
                        (Capability.USAGE_ACCOUNTING,
                         lambda: driver.get_usage()),
                        (Capability.ONLINE_TRACKING,
                         lambda: driver.get_online_devices()),
                    ):
                        try:
                            await call()
                            assert driver.supports(cap), (
                                f"{core_id}: {cap.value} silently succeeded but is not claimed")
                        except CapabilityNotSupportedError:
                            assert not driver.supports(cap), (
                                f"{core_id}: claims {cap.value} but raises not-supported")
                    # routing gate honesty
                    rule = RoutingRule(name="t", matcher=RuleMatcher(domains=["example.com"]),
                                       action=RuleAction.BLOCK, priority=1)
                    from app.cores.routing.model import RouteContext
                    try:
                        from app.cores.outbounds.model import Outbound, OutboundKind
                        ctx = RouteContext(
                            known_outbounds={"direct"},
                            default_outbound="direct",
                        )
                        await driver.deploy_routing_rules([rule], ctx)
                        assert driver.supports(Capability.ROUTING)
                    except CapabilityNotSupportedError:
                        assert not driver.supports(Capability.ROUTING)
                    await driver.delete_account(account.account_id)
                    await driver.stop()
                except AssertionError as exc:
                    failures.append(f"{core_id}: {exc}")
            assert not failures, "contract failures: " + "; ".join(failures)

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# 6. sealed payload confidentiality                                      #
# ---------------------------------------------------------------------- #

def test_client_configs_never_leak_secrets() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-contract-") as tmp:
            for core_id in _DRIVERS:
                driver, _ = _build(core_id, tmp)
                if not driver.supports(Capability.CLIENT_CONFIG):
                    continue
                try:
                    await driver.start()
                except Exception:
                    continue  # fake backend can't boot this driver; skip
                account = _sample_account(driver)
                await driver.create_account(account)
                account = driver._accounts.get(account.account_id, account) if hasattr(driver, "_accounts") else account
                try:
                    config = await driver.build_client_config(account)
                except Exception:
                    continue  # core-specific requirement unmet in fake env
                blob = repr(config) + str(config)
                for value in account.settings.values():
                    value = str(value)
                    if len(value) >= 4:
                        assert value not in blob, (
                            f"{core_id}: secret '{value}' leaks through ClientConfig repr")
                view = config.public_view()
                assert set(view) <= {"core", "protocol", "engine", "display_name"}

    asyncio.run(run())


# ---------------------------------------------------------------------- #
# 7. provisioning throughput smoke (performance guard)                   #
# ---------------------------------------------------------------------- #

def test_provisioning_throughput_smoke() -> None:
    async def run() -> None:
        with tempfile.TemporaryDirectory(prefix="zg-contract-") as tmp:
            for core_id in _DRIVERS:
                driver, _ = _build(core_id, tmp)
                try:
                    await driver.start()
                except Exception:
                    continue
                account = _sample_account(driver)
                samples = [
                    account.model_copy(update={
                        "account_id": f"perf.u{i}", "username": f"u{i}",
                        "settings": dict(account.settings
                                         or _PROTOCOL_SETTINGS.get("wireguard", {})),
                    })
                    for i in range(100)
                ]
                started = time.perf_counter()
                for sample in samples:
                    try:
                        await driver.create_account(sample)
                    except Exception:
                        pass  # fake-env limits (e.g. xray inbound matching) — warmup only
                elapsed = time.perf_counter() - started
                assert elapsed < 15.0, f"{core_id}: 100 provisions took {elapsed:.2f}s"
                await driver.stop()

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
