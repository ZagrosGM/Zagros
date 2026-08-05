"""RoutingEngine integration tests: fan-out across real drivers with fake
backends, and the no-silent-drop invariant on every core.

Run: pytest tests/cores/test_routing.py -v   OR   python tests/cores/test_routing.py
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

from app.cores import (  # noqa: E402
    Capability,
    CapabilityNotSupportedError,
    CoreError,
    CoreManager,
    EventBus,
)
from app.cores.routing import (  # noqa: E402
    RouteDeploymentReport,
    RoutingEngine,
    RoutingRule,
    RuleAction,
    RuleMatcher,
)
from app.cores.drivers.singbox import SingBoxDriver  # noqa: E402
from app.cores.drivers.xray import XrayDriver  # noqa: E402
from tests.cores.test_core_manager import BareDriver, InMemoryStore  # noqa: E402
from tests.cores.test_singbox_driver import FakeSingBoxBackend  # noqa: E402
from tests.cores.test_xray_driver import FakeBackend as FakeXrayBackend  # noqa: E402


def _rules() -> list[RoutingRule]:
    return [
        RoutingRule(name="geo-block", matcher=RuleMatcher(geoips=["ir"]),
                    action=RuleAction.BLOCK, priority=10),
        RoutingRule(name="proc", matcher=RuleMatcher(process_names=["telegram"]),
                    action=RuleAction.ALLOW, priority=20),
        RoutingRule(name="ads", matcher=RuleMatcher(domain_suffixes=["ads.net"]),
                    action=RuleAction.BLOCK, priority=30),
        RoutingRule(name="rewrite", matcher=RuleMatcher(domains=["a.com"]),
                    action=RuleAction.REDIRECT, redirect_to="127.0.0.1:8080", priority=40),
    ]


async def _setup() -> tuple[RoutingEngine, CoreManager, FakeXrayBackend, FakeSingBoxBackend]:
    mgr = CoreManager(store=InMemoryStore(), bus=EventBus())
    xray_backend, singbox_backend = FakeXrayBackend(), FakeSingBoxBackend()
    mgr.attach("xray", XrayDriver(backend=xray_backend))
    mgr.attach("sing-box", SingBoxDriver(backend=singbox_backend))
    mgr.attach("barebox", BareDriver())          # no ROUTING capability
    return RoutingEngine(mgr), mgr, xray_backend, singbox_backend


def test_rule_validation() -> None:
    # empty matcher
    try:
        RoutingRule(name="empty", matcher=RuleMatcher(), action=RuleAction.BLOCK)
        raise AssertionError("empty matcher must be rejected")
    except ValueError:
        pass
    # route_to needs an outbound
    try:
        RoutingRule(name="rt", matcher=RuleMatcher(domains=["a.com"]), action=RuleAction.ROUTE_TO)
        raise AssertionError("route_to without outbound must be rejected")
    except ValueError:
        pass
    # redirect needs host:port
    try:
        RoutingRule(name="rd", matcher=RuleMatcher(domains=["a.com"]),
                    action=RuleAction.REDIRECT, redirect_to="nope")
        raise AssertionError("bad redirect_to must be rejected")
    except ValueError:
        pass


def test_validate_rejects_duplicate_names_and_sorts() -> None:
    engine = None

    async def main() -> None:
        nonlocal engine
        engine, *_ = await _setup()

    asyncio.run(main())
    rules = _rules() + [_rules()[0].model_copy(update={"priority": 5})]
    try:
        engine.validate(rules)
        raise AssertionError("duplicate names must raise CoreError")
    except CoreError:
        pass
    ordered = engine.validate(list(reversed(_rules())))
    assert [r.name for r in ordered] == ["geo-block", "proc", "ads", "rewrite"]  # by priority


def test_deploy_covers_every_rule_on_every_core() -> None:
    async def main():
        engine, mgr, xb, sb = await _setup()
        all_names = {r.name for r in engine.validate(_rules())}
        report: RouteDeploymentReport = await engine.deploy(_rules())

        # every core accounted for, no silent drops anywhere
        for core_id in ("xray", "sing-box", "barebox"):
            res = report.results[core_id]
            covered = set(res.applied) | {u.rule for u in res.unsupported}
            assert covered == all_names, f"{core_id}: dropped {all_names - covered}"

        # barebox: no routing support -> everything reported
        assert report.results["barebox"].applied == []
        # xray: process rule unsupported, redirect unsupported, geo+ads applied
        xr = report.results["xray"]
        assert {u.rule for u in xr.unsupported} == {"proc", "rewrite"}
        assert set(xr.applied) == {"geo-block", "ads"}
        # sing-box: geo (no geo DB configured) + redirect unsupported
        sbx = report.results["sing-box"]
        assert {u.rule for u in sbx.unsupported} == {"geo-block", "rewrite"}
        assert set(sbx.applied) == {"proc", "ads"}

        # translations actually arrived at the (fake) cores
        assert len(xb.routing_rules) == 2                    # geo-block + ads
        assert {o["tag"] for o in xb.outbounds} == {"zg-direct", "zg-block", "zg-dns"}
        sb_rules = sb.configs[-1]["route"]["rules"]
        # built-in DNS interception rule first, then the panel rules
        assert len(sb_rules) == 3 and sb_rules[0] == {"protocol": "dns", "action": "hijack-dns"}
        assert sb_rules[1]["process_name"] == ["telegram"]

        # gaps property feeds the admin warning UI
        assert set(report.gaps) == {"xray", "sing-box", "barebox"}

    asyncio.run(main())


def test_deploy_without_routing_capability_raises_at_driver_level_too() -> None:
    async def main():
        bare = BareDriver()
        try:
            await bare.deploy_routing_rules(_rules(), None)  # ctx irrelevant; gate fires first
            raise AssertionError("capability gate must fire")
        except CapabilityNotSupportedError:
            pass

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
