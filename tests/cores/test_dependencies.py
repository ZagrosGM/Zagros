"""Tests for shared-feature dependencies (provides/requires):
dependency reports and the uninstall guard (vpn-ui 'feats' pattern).

Run: pytest tests/cores/test_dependencies.py -v   OR   python tests/cores/test_dependencies.py
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

from app.cores import CoreManager, CoreMetadata, CoreStateError, EventBus  # noqa: E402
from tests.cores.test_core_manager import FakeDriver, InMemoryStore  # noqa: E402


def _manager() -> CoreManager:
    return CoreManager(store=InMemoryStore(), bus=EventBus())


def _provider() -> FakeDriver:
    driver = FakeDriver()
    driver.metadata = driver.metadata.model_copy(
        update={"id": "ikev2", "provides": {"strongswan"}}
    )
    return driver


def _consumer(with_req: bool = True) -> FakeDriver:
    driver = FakeDriver()
    driver.metadata = driver.metadata.model_copy(
        update={"id": "l2tp", "requires": {"strongswan"} if with_req else set()}
    )
    return driver


def test_dependency_report_marks_satisfied() -> None:
    async def main():
        mgr = _manager()
        mgr.attach("ikev2", _provider())
        mgr.attach("l2tp", _consumer())
        report = mgr.dependency_report("l2tp")
        assert report["requires"] == ["strongswan"]
        assert report["provided_by"]["strongswan"] == "ikev2"
        assert report["missing"] == []
        assert mgr.dependents("ikev2") == ["l2tp"]

    asyncio.run(main())


def test_dependency_report_missing_when_no_provider() -> None:
    mgr = _manager()
    mgr.attach("l2tp", _consumer())
    report = mgr.dependency_report("l2tp")
    assert report["missing"] == ["strongswan"]
    assert report["provided_by"]["strongswan"] is None


def test_uninstall_guard_blocks_provider_with_dependents() -> None:
    async def main():
        mgr = _manager()
        mgr.attach("ikev2", _provider())
        mgr.attach("l2tp", _consumer())
        try:
            await mgr.uninstall_core("ikev2")
            raise AssertionError("uninstalling a required provider must be blocked")
        except CoreStateError as exc:
            assert "l2tp" in str(exc)
        # ...unless forced
        await mgr.uninstall_core("ikev2", force=True)
        assert "ikev2" not in mgr.list_cores()

    asyncio.run(main())


def test_uninstall_allowed_when_no_dependents() -> None:
    async def main():
        mgr = _manager()
        mgr.attach("ikev2", _provider())
        mgr.attach("l2tp", _consumer(with_req=False))
        await mgr.uninstall_core("ikev2")
        assert "ikev2" not in mgr.list_cores()

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
