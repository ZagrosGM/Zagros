"""OutboundManager tests: registry validation, chain (CORE) resolution,
self-chain skipping, endpoint provisioning, and cycle detection.

Run: pytest tests/cores/test_outbounds.py -v   OR   python tests/cores/test_outbounds.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import CoreError, CoreManager, EventBus  # noqa: E402
from app.cores.drivers.singbox import SingBoxDriver  # noqa: E402
from app.cores.drivers.xray import XrayDriver  # noqa: E402
from app.cores.outbounds import Outbound, OutboundKind, OutboundManager  # noqa: E402
from tests.cores.test_core_manager import BareDriver, InMemoryStore  # noqa: E402
from tests.cores.test_singbox_driver import FakeSingBoxBackend  # noqa: E402
from tests.cores.test_xray_driver import FakeBackend as FakeXrayBackend  # noqa: E402


async def _world() -> tuple[OutboundManager, CoreManager, FakeSingBoxBackend, FakeXrayBackend]:
    mgr = CoreManager(store=InMemoryStore(), bus=EventBus())
    xb, sb = FakeXrayBackend(), FakeSingBoxBackend()
    mgr.attach("xray", XrayDriver(backend=xb))
    mgr.attach("sing-box", SingBoxDriver(backend=sb))
    mgr.attach("barebox", BareDriver())          # no OUTBOUND_MANAGEMENT
    return OutboundManager(mgr), mgr, sb, xb


def test_registry_validation() -> None:
    async def main():
        obm, *_ = await _world()
        obm.register(Outbound(name="up", kind=OutboundKind.SOCKS,
                              settings={"server": "1.2.3.4", "server_port": 1080}))
        # duplicate
        try:
            obm.register(Outbound(name="up", kind=OutboundKind.SOCKS,
                                  settings={"server": "1.2.3.4", "server_port": 1080}))
            raise AssertionError("duplicate outbound name must raise")
        except CoreError:
            pass
        # CORE to an uninstalled core
        try:
            obm.register(Outbound(name="ghost", kind=OutboundKind.CORE,
                                  settings={"core_id": "wireguard"}))
            raise AssertionError("chain to missing core must raise")
        except CoreError:
            pass
        # upstream kinds require a server (model-level)
        try:
            Outbound(name="bad", kind=OutboundKind.SOCKS, settings={"server_port": 1080})
            raise AssertionError("missing server must be rejected by the model")
        except ValueError:
            pass

    asyncio.run(main())


def test_materialize_chain_endpoint_is_provisioned_and_resolved() -> None:
    async def main():
        obm, mgr, sb, xb = await _world()
        obm.register(Outbound(name="to-sb", kind=OutboundKind.CORE,
                              settings={"core_id": "sing-box", "protocol": "socks"}))
        concrete = await obm.materialize(obm.get("to-sb"), requester_core_id="xray")

        assert concrete.kind is OutboundKind.SOCKS
        assert concrete.settings["server"] == "127.0.0.1"
        assert isinstance(concrete.settings["server_port"], int) and concrete.settings["server_port"] > 0
        # endpoint was actually created on the sing-box (fake) backend
        chain_inbounds = [i for i in sb.configs[-1]["inbounds"] if i["tag"].startswith("zg-chain-")]
        assert chain_inbounds and chain_inbounds[0]["listen_port"] == concrete.settings["server_port"]

    asyncio.run(main())


def test_self_chain_and_full_cycle_are_rejected() -> None:
    async def main():
        obm, mgr, sb, xb = await _world()
        obm.register(Outbound(name="to-sb", kind=OutboundKind.CORE, settings={"core_id": "sing-box"}))
        obm.register(Outbound(name="to-xr", kind=OutboundKind.CORE, settings={"core_id": "xray"}))

        # direct misuse: asking sing-box to chain into sing-box
        try:
            await obm.materialize(obm.get("to-sb"), requester_core_id="sing-box")
            raise AssertionError("self-chain must raise")
        except CoreError:
            pass

        # deploy-all: sing-box binds xray (edge sb→xr); then xray binding
        # sing-box would close the loop -> the whole plan is rejected
        try:
            await obm.deploy(core_ids=["sing-box", "xray"])
            raise AssertionError("cycle must abort the deployment plan")
        except CoreError as exc:
            assert "cycle" in str(exc).lower()

    asyncio.run(main())


def test_deploy_without_cycles_applies_and_reports_gaps() -> None:
    async def main():
        obm, mgr, sb, xb = await _world()
        obm.register(Outbound(name="to-sb", kind=OutboundKind.CORE, settings={"core_id": "sing-box"}))
        obm.register(Outbound(name="wg-up", kind=OutboundKind.WIREGUARD,
                              settings={"server": "10.0.0.1", "server_port": 51820,
                                        "private_key": "PRIV", "peer_public_key": "PUB",
                                        "local_address": ["10.0.0.2/32"]}))
        obm.register(Outbound(name="ovpn-up", kind=OutboundKind.OPENVPN,
                              settings={"server": "10.0.0.9", "server_port": 1194}))
        report = await obm.deploy(core_ids=["xray", "sing-box", "barebox"])

        # barebox: reported as incapable for each outbound
        assert len(report.results["barebox"].unsupported) == 3
        # xray: chain resolved to socks outbound; wireguard native; openvpn reported
        xr = report.results["xray"]
        assert set(xr.applied) == {"to-sb", "wg-up"}
        assert {u.name for u in xr.unsupported} == {"ovpn-up"}
        wg_native = {o["tag"]: o for o in xb.outbounds}["wg-up"]
        assert wg_native["protocol"] == "wireguard" and wg_native["settings"]["peers"][0]["publicKey"] == "PUB"
        # sing-box: same set natively (it is the chain target here, so to-sb skipped with note)
        sbx = report.results["sing-box"]
        assert set(sbx.applied) == {"wg-up"}
        assert any("to-sb" in note for note in sbx.notes)
        assert {u.name for u in sbx.unsupported} == {"ovpn-up"}

    asyncio.run(main())


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
