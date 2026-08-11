"""Executable tests for the multi-core plugin system (no real VPN needed).

A fake driver proves the whole contract end-to-end: lifecycle state machine,
provisioning fan-out with per-core isolation, capability gating, state
persistence, events, and secret redaction.

Run with pytest:
    pytest tests/cores/test_core_manager.py -v

or standalone (no test framework required):
    python tests/cores/test_core_manager.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

# --- import shim: load `app.cores` WITHOUT executing app/__init__.py --------
# (the real one builds the FastAPI app and reads env at import time)
ROOT = Path(__file__).resolve().parents[2]
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores import (  # noqa: E402
    BaseCoreDriver,
    Capability,
    CapabilityNotSupportedError,
    ClientConfig,
    CoreManager,
    CoreMetadata,
    CoreState,
    CoreStateError,
    CoreStatus,
    DeviceSession,
    Event,
    EventBus,
    HealthStatus,
    UsageRecord,
    UserAccount,
)

# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #


class FakeDriver(BaseCoreDriver):
    """In-memory driver implementing the full contract."""

    metadata = CoreMetadata(
        id="fakebox",
        name="FakeBox",
        protocols=["fake"],
        capabilities={
            Capability.USER_MANAGEMENT,
            Capability.SUSPEND_RESUME,
            Capability.USAGE_ACCOUNTING,
            Capability.ONLINE_TRACKING,
            Capability.SERVICE_CONTROL,
            Capability.SELF_INSTALL,
            Capability.CLIENT_CONFIG,
        },
        config_schema={"type": "object", "properties": {"bin": {"type": "string"}}},
        default_settings={"bin": "/bin/true"},
    )

    def __init__(self, settings: dict[str, Any] | None = None):
        super().__init__(settings)
        self.installed = False
        self.running = False
        self.starts = 0
        self.accounts: dict[str, UserAccount] = {}

    async def install(self) -> None:
        self.installed = True

    async def uninstall(self, purge: bool = False) -> None:
        self.installed = False
        self.accounts.clear()

    async def update(self, version: str | None = None) -> str:
        return version or "9.9.9"

    async def start(self) -> None:
        if self.settings.get("fail_start"):
            raise RuntimeError("start boom")
        self.running = True
        self.starts += 1

    async def stop(self) -> None:
        self.running = False

    async def status(self) -> CoreStatus:
        return CoreStatus(
            core_id="fakebox",
            state=CoreState.RUNNING if self.running else CoreState.STOPPED,
            health=HealthStatus.HEALTHY,
            core_version="9.9.9",
        )

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        for i in range(min(tail, 3)):
            yield f"fakebox log line {i}"

    async def create_account(self, account: UserAccount) -> None:
        if self.settings.get("fail_provision"):
            raise RuntimeError("provision boom")
        self.accounts[account.account_id] = account

    async def update_account(self, account: UserAccount) -> None:
        self.accounts[account.account_id] = account

    async def delete_account(self, account_id: str) -> None:
        self.accounts.pop(account_id, None)

    async def suspend_account(self, account_id: str) -> None:
        self.accounts[account_id] = self.accounts[account_id].model_copy(
            update={"enabled": False}
        )

    async def get_usage(
        self, account_ids: list[str] | None = None, since: Any | None = None
    ) -> list[UsageRecord]:
        ids = account_ids or list(self.accounts)
        return [
            UsageRecord(core_id="fakebox", account_id=a, uplink_bytes=10, downlink_bytes=20)
            for a in ids
        ]

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        ids = account_ids or list(self.accounts)
        return [
            DeviceSession(core_id="fakebox", account_id=a, ip="10.8.0.2") for a in ids
        ]

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        return ClientConfig(
            core_id="fakebox",
            protocol="fake",
            engine="sing-box",
            payload={"uuid": "SECRET-UUID", "server": "203.0.113.10", "sni": "cdn.example.com"},
            display_name=account.username,
        )


class FailingProvisionDriver(FakeDriver):
    """Same driver but its provisioning always blows up."""

    metadata = FakeDriver.metadata.model_copy(update={"id": "failbox"})

    def __init__(self, settings: dict[str, Any] | None = None):
        merged = dict(settings or {})
        merged["fail_provision"] = True
        super().__init__(merged)


class BareDriver(BaseCoreDriver):
    """Direct subclass with the bare minimum — stats methods NOT overridden,
    so the base-class capability gate must fire for them."""

    metadata = CoreMetadata(
        id="barebox",
        name="BareBox",
        protocols=["bare"],
        capabilities={Capability.CLIENT_CONFIG},
    )

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def status(self) -> CoreStatus:
        return CoreStatus(core_id="barebox", state=CoreState.STOPPED)

    async def create_account(self, account: UserAccount) -> None:
        pass

    async def update_account(self, account: UserAccount) -> None:
        pass

    async def delete_account(self, account_id: str) -> None:
        pass

    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        return ClientConfig(core_id="barebox", protocol="bare", engine="sing-box", payload={})


class InMemoryStore:
    """CoreStateStore port — fake implementation recording everything."""

    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}
        self.saved_states: list[tuple[str, CoreState]] = []

    async def load(self) -> dict[str, dict[str, Any]]:
        return {k: dict(v) for k, v in self.data.items()}

    async def save_state(
        self,
        core_id: str,
        *,
        state: CoreState,
        enabled: bool,
        settings: dict[str, Any] | None = None,
    ) -> None:
        self.data[core_id] = {
            "state": state.value,
            "enabled": enabled,
            "settings": settings or self.data.get(core_id, {}).get("settings", {}),
        }
        self.saved_states.append((core_id, state))

    async def remove(self, core_id: str) -> None:
        self.data.pop(core_id, None)


def _account(user_id: int = 1, username: str = "alice") -> UserAccount:
    return UserAccount(
        user_id=user_id,
        username=username,
        account_id=f"{user_id}.{username}",
        protocol="vless",
        settings={"id": "SECRET-UUID"},
    )


def _make_manager(settings: dict | None = None) -> tuple[CoreManager, InMemoryStore, EventBus]:
    store, bus = InMemoryStore(), EventBus()
    return CoreManager(store=store, bus=bus), store, bus


# --------------------------------------------------------------------------- #
# tests (sync wrappers around asyncio — no pytest-asyncio needed)
# --------------------------------------------------------------------------- #


def test_install_start_stop_uninstall_lifecycle() -> None:
    async def main() -> None:
        mgr, store, _ = _make_manager()
        assert await mgr.install_core("fakebox") == CoreState.INSTALLED

        status = await mgr.start_core("fakebox")
        assert status.state == CoreState.RUNNING
        assert mgr.get("fakebox").running is True

        status = await mgr.stop_core("fakebox")
        assert status.state == CoreState.STOPPED

        await mgr.uninstall_core("fakebox")
        assert "fakebox" not in mgr.list_cores()
        assert "fakebox" not in store.data

        # persistence trail proves every transition hit the store
        assert ("fakebox", CoreState.INSTALLED) in store.saved_states
        assert ("fakebox", CoreState.STOPPED) in store.saved_states

    asyncio.run(main())


def test_illegal_transitions_raise() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")

        try:
            await mgr.start_core("fakebox")
            raise AssertionError("double start should raise CoreStateError")
        except CoreStateError:
            pass

        await mgr.stop_core("fakebox")
        try:
            await mgr.stop_core("fakebox")
            raise AssertionError("stopping a stopped core should raise")
        except CoreStateError:
            pass

    asyncio.run(main())


def test_restart_updates_state_and_driver() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")
        status = await mgr.restart_core("fakebox")
        assert status.state == CoreState.RUNNING
        assert mgr.get("fakebox").starts == 2

    asyncio.run(main())


def test_disable_blocks_start() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.disable_core("fakebox")
        try:
            await mgr.start_core("fakebox")
            raise AssertionError("disabled core must not start")
        except CoreStateError:
            pass

    asyncio.run(main())


def test_provision_user_fanout_and_isolation() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.install_core("failbox")
        await mgr.start_core("fakebox")

        results = await mgr.provision_user({"fakebox": _account(), "failbox": _account()})
        by_core = {r.core_id: r for r in results}

        assert by_core["fakebox"].success is True
        assert by_core["failbox"].success is False and "boom" in (by_core["failbox"].error or "")
        # failure on one core never blocked the other
        assert "1.alice" in mgr.get("fakebox").accounts

    asyncio.run(main())


def test_deprovision_user() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.provision_user({"fakebox": _account()})
        results = await mgr.deprovision_user({"fakebox": "1.alice"})
        assert all(r.success for r in results)
        assert mgr.get("fakebox").accounts == {}

    asyncio.run(main())


def test_capability_gating() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("barebox")
        driver = mgr.get("barebox")
        assert not driver.supports(Capability.USAGE_ACCOUNTING)
        for call in (
            lambda: driver.get_usage(),
            lambda: driver.get_online_devices(),
        ):
            try:
                await call()
                raise AssertionError("unsupported capability must raise")
            except CapabilityNotSupportedError:
                pass
        # capability-gated aggregation silently skips unsupported cores
        records = await mgr.aggregate_usage({"barebox": ["1.alice"]})
        assert records == []

    asyncio.run(main())


def test_usage_and_online_aggregation() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.provision_user({"fakebox": _account()})
        usage = await mgr.aggregate_usage({"fakebox": ["1.alice"]})
        assert len(usage) == 1 and usage[0].downlink_bytes == 20
        online = await mgr.online_devices({"fakebox": ["1.alice"]})
        assert online[0].ip == "10.8.0.2"

    asyncio.run(main())


def test_events_are_published() -> None:
    async def main() -> None:
        mgr, _, bus = _make_manager()
        seen: list[dict] = []

        async def spy(payload: dict) -> None:
            seen.append(payload)

        bus.subscribe(Event.CORE_STATE_CHANGED, spy)
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")

        states = [p["state"] for p in seen if p["core_id"] == "fakebox"]
        assert "installed" in states and "starting" in states and "running" in states

    asyncio.run(main())


def test_boot_rehydrates_from_store_and_distrusts_running() -> None:
    async def main() -> None:
        mgr, store, _ = _make_manager()
        await mgr.install_core("fakebox", settings={"bin": "/bin/echo"})
        await mgr.start_core("fakebox")

        # simulate a panel restart: same store, brand-new manager
        mgr2, _, _ = _make_manager()
        mgr2._store = store
        await mgr2.boot()
        assert mgr2.list_cores() == ["fakebox"]
        # RUNNING must never be trusted across a restart -> STOPPED awaiting verification
        assert mgr2._states["fakebox"] == CoreState.STOPPED
        assert mgr2.get("fakebox").settings["bin"] == "/bin/echo"

    asyncio.run(main())


def test_client_config_never_leaks_secrets() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        cfg = await mgr.get("fakebox").build_client_config(_account())

        blob = repr(cfg) + str(cfg) + repr(cfg.public_view())
        for secret in ("SECRET-UUID", "203.0.113.10", "cdn.example.com"):
            assert secret not in blob, f"secret leaked into a string representation: {secret}"
        assert cfg.public_view() == {
            "core": "fakebox",
            "protocol": "fake",
            "engine": "sing-box",
            "display_name": "alice",
        }
        # but the sealed channel can still read the payload internally
        assert cfg.payload["uuid"] == "SECRET-UUID"

    asyncio.run(main())


def test_get_logs_and_status_all() -> None:
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")
        logs = await mgr.get_logs("fakebox", tail=2)
        assert logs == ["fakebox log line 0", "fakebox log line 1"]
        statuses = await mgr.status_all()
        assert len(statuses) == 1 and statuses[0].health == HealthStatus.HEALTHY

    asyncio.run(main())


def test_studio_apply_heals_error_record_when_daemon_is_already_live() -> None:
    async def main() -> None:
        manager, store, _ = _make_manager()
        driver = FakeDriver()
        driver.running = True

        async def apply(_document): pass

        driver.apply_studio_document = apply
        manager.attach("fakebox", driver, enabled=True, state=CoreState.ERROR)
        await store.save_state("fakebox", state=CoreState.ERROR,
                               enabled=True, settings=driver.settings)
        await manager.apply_studio_document("fakebox", {"inbounds": []})
        assert manager._states["fakebox"] is CoreState.RUNNING
        assert (await store.load())["fakebox"]["state"] == "running"

    asyncio.run(main())


def test_studio_apply_serializes_and_persists_driver_settings() -> None:
    async def main() -> None:
        manager, store, _ = _make_manager()
        driver = FakeDriver({"bin": "/bin/true"})

        async def apply(document):
            driver.settings["listen_port"] = document["inbounds"][0]["port"]
            driver.settings["ipsec_psk"] = "persisted-secret"

        driver.apply_studio_document = apply
        manager.attach("fakebox", driver, enabled=True, state=CoreState.RUNNING)
        await store.save_state("fakebox", state=CoreState.RUNNING,
                               enabled=True, settings=driver.settings)
        await manager.apply_studio_document("fakebox", {
            "inbounds": [{"tag": "new", "port": 43123}],
        })
        saved = (await store.load())["fakebox"]
        assert saved["state"] == "running"
        assert driver.running is True  # stale RUNNING record recovered process
        assert saved["settings"]["listen_port"] == 43123
        assert saved["settings"]["ipsec_psk"] == "persisted-secret"

    asyncio.run(main())


# --------------------------------------------------------------------------- #
# health-monitor lifecycle reconciliation (alpha.7.2 item 3):
# a healthy RUNNING process must never be displayed as Error
# --------------------------------------------------------------------------- #

def test_health_cycle_heals_error_state_when_probe_is_running() -> None:
    """Reported bug: start() raised AFTER the process came up → recorded
    ERROR while the binary served on. The monitor's probe is ground truth:
    one cycle flips the record back to RUNNING (and persists/emits it)."""
    async def main() -> None:
        mgr, store, bus = _make_manager()
        seen: list[dict] = []

        async def spy(payload: dict) -> None:
            seen.append(payload)

        bus.subscribe(Event.CORE_STATE_CHANGED, spy)
        await mgr.install_core("fakebox")

        driver = mgr.get("fakebox")
        driver.running = True                           # process IS up
        mgr._states["fakebox"] = CoreState.ERROR        # ...but record says error
        await store.save_state("fakebox", state=CoreState.ERROR, enabled=True)

        await mgr._health_cycle({})
        assert mgr._states["fakebox"] == CoreState.RUNNING
        persisted = (await store.load())["fakebox"]["state"]
        assert persisted == CoreState.RUNNING.value
        assert any(p.get("state") == CoreState.RUNNING.value
                   and p.get("core_id") == "fakebox" for p in seen)

    asyncio.run(main())


def test_health_cycle_detects_crash_when_probe_is_stopped() -> None:
    """Recorded RUNNING + probe says stopped = crashed/killed out-of-band —
    mark STOPPED instead of showing a green card for a dead core."""
    async def main() -> None:
        mgr, store, _ = _make_manager()
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")      # recorded RUNNING, really up
        mgr.get("fakebox").running = False   # ...then the process dies

        await mgr._health_cycle({})
        assert mgr._states["fakebox"] == CoreState.STOPPED
        persisted = (await store.load())["fakebox"]["state"]
        assert persisted == CoreState.STOPPED.value

    asyncio.run(main())


def test_health_cycle_keeps_error_when_probe_is_stopped() -> None:
    """A FAILED core (recorded ERROR, process down) must not resurrect."""
    async def main() -> None:
        mgr, _, _ = _make_manager()
        await mgr.install_core("fakebox")
        mgr._states["fakebox"] = CoreState.ERROR
        mgr.get("fakebox").running = False

        await mgr._health_cycle({})
        assert mgr._states["fakebox"] == CoreState.ERROR

    asyncio.run(main())


def test_health_cycle_probe_exception_never_flips_lifecycle() -> None:
    """A flaky probe degrades health only — lifecycle MUST stay put."""
    async def main() -> None:
        mgr, _, bus = _make_manager()
        seen: list[dict] = []

        async def spy(payload: dict) -> None:
            seen.append(payload)

        bus.subscribe(Event.CORE_HEALTH_CHANGED, spy)
        await mgr.install_core("fakebox")
        await mgr.start_core("fakebox")

        async def boom():
            raise RuntimeError("probe exploded")

        mgr.get("fakebox").health_check = boom
        tracker: dict[str, HealthStatus] = {}
        await mgr._health_cycle(tracker)
        assert mgr._states["fakebox"] == CoreState.RUNNING
        assert tracker["fakebox"] == HealthStatus.UNHEALTHY
        assert any(p.get("health") == HealthStatus.UNHEALTHY.value
                   and p.get("core_id") == "fakebox" for p in seen)

    asyncio.run(main())


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
