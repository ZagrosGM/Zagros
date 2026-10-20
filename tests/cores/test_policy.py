"""Executable tests for the global PolicyEngine.

Run: pytest tests/cores/test_policy.py -v   OR   python tests/cores/test_policy.py
"""
from __future__ import annotations

import sys
import traceback
import types as _types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import Capability  # noqa: E402
from app.cores.policy import (  # noqa: E402
    AdmissionContext,
    HourWindow,
    PolicyEngine,
    PolicyProfile,
    Violation,
)
from app.cores.routing import RuleAction  # noqa: E402

ENGINE = PolicyEngine()
NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)  # Monday 12:00


def _ctx(**over) -> AdmissionContext:
    base = dict(now=NOW, device_uid="dev-1")
    base.update(over)
    return AdmissionContext(**base)


def _violations(profile: PolicyProfile, ctx: AdmissionContext) -> list[Violation]:
    return ENGINE.evaluate(profile, ctx).violations


def test_expiry_and_quota() -> None:
    profile = PolicyProfile(
        expire_at=NOW, data_limit_bytes=100,
    )
    # expire_at is inclusive: AT the instant of expiry the user is done
    assert Violation.EXPIRED in _violations(profile, _ctx())
    assert Violation.QUOTA_EXCEEDED in _violations(profile, _ctx(used_bytes=100))
    assert Violation.QUOTA_EXCEEDED not in _violations(profile, _ctx(used_bytes=99))


def test_device_limit_is_global_and_idempotent_for_existing_device() -> None:
    profile = PolicyProfile(device_limit=2)
    # two slots busy, a THIRD device knocks -> blocked, regardless of core
    assert Violation.DEVICE_LIMIT_REACHED in _violations(
        profile, _ctx(device_uid="dev-3", active_device_uids=["dev-1", "dev-2"])
    )
    # an already-active device reconnecting never consumes a new slot
    assert Violation.DEVICE_LIMIT_REACHED not in _violations(
        profile, _ctx(device_uid="dev-1", active_device_uids=["dev-1", "dev-2"])
    )
    # unlimited by default
    assert not _violations(PolicyProfile(), _ctx(active_device_uids=["a"] * 99))


def test_allowed_hours_including_overnight_windows() -> None:
    window = HourWindow(days=[0], start="22:00", end="06:00")  # Monday night
    profile = PolicyProfile(allowed_hours=[window])
    mon_23 = NOW.replace(hour=23)
    tue_03 = datetime(2026, 8, 4, 3, 0, tzinfo=timezone.utc)   # Tuesday 03:00 -> still Monday's window
    tue_12 = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    assert not _violations(profile, _ctx(now=mon_23))
    assert not _violations(profile, _ctx(now=tue_03))
    assert Violation.OUTSIDE_ALLOWED_HOURS in _violations(profile, _ctx(now=tue_12))
    assert Violation.OUTSIDE_ALLOWED_HOURS in _violations(profile, _ctx(now=NOW))  # Monday noon


def test_ip_limit() -> None:
    profile = PolicyProfile(max_ips=2)
    assert Violation.IP_LIMIT_REACHED in _violations(
        profile, _ctx(client_ip="203.0.113.9", active_ips=["10.0.0.1", "10.0.0.2"])
    )
    assert not _violations(
        profile, _ctx(client_ip="10.0.0.1", active_ips=["10.0.0.1", "10.0.0.2"])
    )


def test_country_and_asn_locks() -> None:
    profile = PolicyProfile(
        allowed_countries=["de"], blocked_countries=["cn"],
        allowed_asns=[1234], blocked_asns=[666],
    )
    assert Violation.COUNTRY_NOT_ALLOWED in _violations(profile, _ctx(country="IR", asn=1234))
    assert Violation.COUNTRY_BLOCKED in _violations(profile, _ctx(country="cn", asn=1234))
    assert Violation.ASN_NOT_ALLOWED in _violations(profile, _ctx(country="de", asn=999))
    assert Violation.ASN_BLOCKED in _violations(profile, _ctx(country="de", asn=666))
    assert ENGINE.evaluate(profile, _ctx(country="de", asn=1234)).allowed


def test_enforcement_map_transparency() -> None:
    profile = PolicyProfile(data_limit_bytes=1, speed_limit_kbps=500,
                            blocked_countries=["cn"])
    xray_caps = {Capability.GEO_ROUTING}                      # xray: geo yes, speed no
    hysteria_caps = {Capability.GEO_ROUTING, Capability.SPEED_LIMIT}
    m_xray = ENGINE.enforcement_map(profile, xray_caps)
    assert m_xray["data_limit_bytes"] == "panel"
    assert m_xray["country_lock"] == "core"
    assert m_xray["speed_limit_kbps"].startswith("unsupported-on-core")
    assert ENGINE.enforcement_map(profile, hysteria_caps)["speed_limit_kbps"] == "core"


def test_country_lock_becomes_routing_rules() -> None:
    profile = PolicyProfile(blocked_countries=["cn", "kp"])
    rules = ENGINE.to_block_rules(profile)
    assert len(rules) == 1 and rules[0].action is RuleAction.BLOCK
    assert rules[0].matcher.geoips == ["cn", "kp"]
    # whitelist is panel-only (no native "not-in-set" on cores) -> no rule
    assert ENGINE.to_block_rules(PolicyProfile(allowed_countries=["de"])) == []


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
