"""CoreManager — the single orchestration point every VPN core goes through.

Responsibilities:
  * lifecycle state machine per core (install → start/stop/restart → uninstall)
  * state persistence behind the :class:`CoreStateStore` port (DIP)
  * fan-out user provisioning across cores with per-core results
  * usage / online-device aggregation (capability-gated)
  * health monitoring loop + domain events

Nothing in the rest of the panel talks to a driver directly.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol

from app.cores.base import BaseCoreDriver
from app.cores.events import Event, EventBus
from app.cores.exceptions import (
    CapabilityNotSupportedError,
    CoreNotFoundError,
    CoreStateError,
    DriverNotFoundError,
)
from app.cores.registry import get_driver_class
from app.cores.types import (
    Capability,
    CoreState,
    CoreStatus,
    DeviceSession,
    HealthStatus,
    ProvisionResult,
    UsageRecord,
    UserAccount,
)

logger = logging.getLogger("zagros.cores.manager")

SettingsProvider = Callable[[str], Awaitable[dict[str, Any]]]
SettingsTransform = Callable[[str, dict[str, Any]], dict[str, Any]]

# Cores the panel itself is made of — attached automatically at boot, never
# persisted in the platform store and never removable/disablable through the
# core-management surface (their binaries and lifecycle belong to the panel;
# "uninstall xray" would delete the panel's own engine). The guard lives at
# manager level so every caller (admin API, host CLI, studio, tests) gets the
# same honest refusal. Start/stop/restart stay allowed — those are real admin
# operations on the built-in engine, same as the legacy "restart core".
BUILTIN_CORE_IDS: frozenset[str] = frozenset({"xray"})


class CoreStateStore(Protocol):
    """Port: persistence of installed cores. Implemented by an SQLAlchemy
    adapter (fase 3) and by in-memory fakes (tests)."""

    async def load(self) -> dict[str, dict[str, Any]]:
        """Return ``{core_id: {"state": str, "enabled": bool, "settings": dict}}``."""
        ...

    async def save_state(
        self,
        core_id: str,
        *,
        state: CoreState,
        enabled: bool,
        settings: dict[str, Any] | None = None,
    ) -> None:
        ...

    async def remove(self, core_id: str) -> None:
        ...


class CoreManager:
    """Orchestrates installed core instances. Async-first, lock-guarded."""

    def __init__(
        self,
        store: CoreStateStore,
        bus: EventBus | None = None,
        settings_provider: SettingsProvider | None = None,
        builtin_core_ids: frozenset[str] | None = None,
        settings_transform: SettingsTransform | None = None,
    ) -> None:
        self._store = store
        self._builtin_core_ids = (BUILTIN_CORE_IDS if builtin_core_ids is None
                                  else frozenset(builtin_core_ids))
        self._bus = bus or EventBus()
        self._settings_provider = settings_provider
        self._settings_transform = settings_transform
        self._drivers: dict[str, BaseCoreDriver] = {}
        self._states: dict[str, CoreState] = {}
        self._enabled: dict[str, bool] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._monitor_task: asyncio.Task | None = None

    # ------------------------------------------------------------------ #
    # boot / inventory
    # ------------------------------------------------------------------ #
    async def boot(self) -> None:
        """Rehydrate managed cores from the store (called at app startup)."""
        saved = await self._store.load()
        for core_id, record in saved.items():
            try:
                cls = get_driver_class(core_id)
            except DriverNotFoundError:
                logger.warning(
                    "Persisted core '%s' has no registered driver; skipping.", core_id
                )
                continue
            settings = dict(record.get("settings") or {})
            if self._settings_transform is not None:
                settings = self._settings_transform(core_id, settings)
            self._drivers[core_id] = cls(settings=settings)
            state = CoreState(record.get("state", CoreState.INSTALLED.value))
            # a panel reboot means we must re-verify by starting; never trust RUNNING
            self._states[core_id] = (
                CoreState.STOPPED
                if state in (CoreState.RUNNING, CoreState.STARTING,
                             CoreState.STOPPING)
                else state
            )
            self._enabled[core_id] = bool(record.get("enabled", True))
        logger.info("CoreManager boot: %d persisted core(s) loaded.", len(self._drivers))

    def list_cores(self) -> list[str]:
        return sorted(self._drivers)

    def attach(
        self,
        core_id: str,
        driver: BaseCoreDriver,
        *,
        enabled: bool = True,
        state: CoreState = CoreState.INSTALLED,
    ) -> None:
        """Attach an already-constructed driver instance.

        Used by dependency-injected wiring (custom backends) and tests.
        """
        self._drivers[core_id] = driver
        self._states[core_id] = state
        self._enabled[core_id] = enabled

    def is_enabled(self, core_id: str) -> bool:
        return self._enabled.get(core_id, False)

    def get(self, core_id: str) -> BaseCoreDriver:
        try:
            return self._drivers[core_id]
        except KeyError:
            raise CoreNotFoundError(core_id) from None

    async def _resolve_settings(self, core_id: str) -> dict[str, Any]:
        if self._settings_provider is None:
            return {}
        return await self._settings_provider(core_id)

    # ------------------------------------------------------------------ #
    # install / uninstall / update / enable
    # ------------------------------------------------------------------ #
    async def install_core(
        self, core_id: str, settings: dict[str, Any] | None = None, *, enabled: bool = True
    ) -> CoreState:
        async with self._locks[core_id]:
            if core_id in self._drivers:
                raise CoreStateError(f"Core '{core_id}' is already installed.")
            cls = get_driver_class(core_id)  # KeyError -> DriverNotFoundError
            effective_settings = dict(settings or await self._resolve_settings(core_id))
            if self._settings_transform is not None:
                effective_settings = self._settings_transform(core_id, effective_settings)
            driver = cls(settings=effective_settings)
            self._drivers[core_id] = driver
            self._states[core_id] = CoreState.LOADED
            self._enabled[core_id] = enabled
            try:
                await driver.install()
            except CapabilityNotSupportedError:
                pass  # binary managed externally (e.g. by the OS); nothing to do
            except Exception:
                self._drivers.pop(core_id, None)
                self._states.pop(core_id, None)
                self._enabled.pop(core_id, None)
                raise
            await self._set_state(core_id, CoreState.INSTALLED)
            await self._store.save_state(
                core_id,
                state=self._states[core_id],
                enabled=enabled,
                settings=driver.settings,
            )
            logger.info("Core '%s' installed.", core_id)
            return self._states[core_id]

    async def uninstall_core(self, core_id: str, *, purge: bool = False, force: bool = False) -> None:
        if core_id in self._builtin_core_ids:
            raise CoreStateError(
                f"Core '{core_id}' is the panel's built-in engine and cannot be "
                "uninstalled — it is not a managed add-on. You may start/stop/"
                "restart it, but its binary and data belong to the panel."
            )
        # shared-feature guard: refuse to uninstall a provider others require
        dependents = self.dependents(core_id)
        if dependents and not force:
            raise CoreStateError(
                f"Core '{core_id}' provides features required by {dependents}; "
                f"uninstall those first or pass force=True."
            )
        async with self._locks[core_id]:
            driver = self.get(core_id)
            if self._states[core_id] == CoreState.RUNNING:
                await self._transition(core_id, driver, CoreState.STOPPING, CoreState.STOPPED, driver.stop)
            try:
                await driver.uninstall(purge=purge)
            except CapabilityNotSupportedError:
                pass
            await self._set_state(core_id, CoreState.UNINSTALLED)
            self._drivers.pop(core_id, None)
            self._states.pop(core_id, None)
            self._enabled.pop(core_id, None)
            await self._store.remove(core_id)
            logger.info("Core '%s' uninstalled (purge=%s).", core_id, purge)

    # ------------------------------------------------------------------ #
    # shared-feature dependencies (provides/requires)
    # ------------------------------------------------------------------ #
    def dependents(self, core_id: str) -> list[str]:
        """Installed cores whose ``requires`` overlap this core's ``provides``."""
        try:
            provider = self.get(core_id)
        except CoreNotFoundError:
            return []
        return sorted(
            cid
            for cid, driver in self._drivers.items()
            if cid != core_id and driver.metadata.requires & provider.metadata.provides
        )

    def dependency_report(self, core_id: str) -> dict[str, Any]:
        """Which requires are satisfied by which core, and which are missing
        (missing may still be fine if the host OS provides them — reported,
        not enforced)."""
        driver = self.get(core_id)
        providers: dict[str, str | None] = {}
        missing: list[str] = []
        for feat in sorted(driver.metadata.requires):
            owner = next(
                (
                    cid
                    for cid, other in self._drivers.items()
                    if cid != core_id and feat in other.metadata.provides
                ),
                None,
            )
            providers[feat] = owner
            if owner is None:
                missing.append(feat)
        return {"requires": sorted(driver.metadata.requires), "provided_by": providers, "missing": missing}

    async def update_core(self, core_id: str, version: str | None = None) -> str:
        async with self._locks[core_id]:
            driver = self.get(core_id)
            new_version = await driver.update(version)
            logger.info("Core '%s' updated to %s.", core_id, new_version)
            return new_version

    async def enable_core(self, core_id: str) -> None:
        self.get(core_id)
        self._enabled[core_id] = True
        await self._store.save_state(core_id, state=self._states[core_id], enabled=True)

    async def disable_core(self, core_id: str) -> None:
        if core_id in self._builtin_core_ids:
            raise CoreStateError(
                f"Core '{core_id}' is the panel's built-in engine and cannot be "
                "disabled through core management — hiding it would silently "
                "drop its users from delivery while the engine keeps serving "
                "them. Stop it explicitly if that is what you intend."
            )
        if self._states.get(core_id) == CoreState.RUNNING:
            await self.stop_core(core_id)
        async with self._locks[core_id]:
            self.get(core_id)
            self._enabled[core_id] = False
            await self._store.save_state(core_id, state=self._states[core_id], enabled=False)

    # ------------------------------------------------------------------ #
    # start / stop / restart + state machine
    # ------------------------------------------------------------------ #
    async def apply_studio_document(self, core_id: str,
                                    document: dict[str, Any]) -> None:
        """Serialize studio materialization with lifecycle operations and
        persist driver-mutated settings on the same core-state row.

        Service drivers (WireGuard/OpenVPN/SSH/SoftEther) translate studio
        fields into their settings. Previously those mutations lived only in
        memory: panel restart reloaded stale ports/PSKs/endpoint hosts even
        though the studio document itself survived. This is the single
        orchestration boundary for apply vs start/stop/restart races.
        """
        async with self._locks[core_id]:
            driver = self.get(core_id)
            hook = getattr(driver, "apply_studio_document", None)
            if hook is None:
                raise CapabilityNotSupportedError(
                    core_id, "studio_document_apply")
            state_before = self._states[core_id]
            try:
                await hook(document)
            except Exception:
                # A live apply may need to recreate an interface/process. If
                # that fails, do not preserve a stale RUNNING record while the
                # listener is physically gone; the boot report/repair command
                # must see the real blocker.
                try:
                    actual = await driver.status()
                except Exception:
                    actual = None
                if (state_before is CoreState.RUNNING and
                        (actual is None or actual.state is not CoreState.RUNNING)):
                    await self._set_state(core_id, CoreState.ERROR)
                raise

            # A corrected inbound is the recovery path for a core whose prior
            # default config failed. RUNNING must also mean the process is
            # really alive; otherwise a successful wizard response with no
            # listener is a lie. A physically single-listener service can
            # explicitly declare that deleting its final inbound means
            # stop+cleanup; never auto-restart such an empty document.
            path = driver.metadata.studio_inbounds_path
            empty_stops = bool(driver.metadata.stop_when_no_inbounds and path)
            if empty_stops:
                node: Any = document
                for segment in (item for item in str(path).split("/") if item):
                    node = node.get(segment) if isinstance(node, dict) else None
                empty_stops = not isinstance(node, list) or not node

            if empty_stops:
                actual = await driver.status()
                if actual.state is CoreState.RUNNING:
                    await driver.stop()
                if state_before in (CoreState.RUNNING, CoreState.ERROR):
                    await self._set_state(core_id, CoreState.STOPPED)
            elif state_before in (CoreState.RUNNING, CoreState.ERROR):
                actual = await driver.status()
                if actual.state is CoreState.RUNNING:
                    # A system-owned daemon (notably SoftEther) can recover
                    # while the manager record is still ERROR. Persist probe
                    # truth now instead of waiting for the health-monitor tick.
                    if state_before is not CoreState.RUNNING:
                        await self._set_state(core_id, CoreState.RUNNING)
                else:
                    await self._set_state(core_id, CoreState.STARTING)
                    try:
                        await driver.start()
                    except Exception:
                        await self._set_state(core_id, CoreState.ERROR)
                        raise
                    await self._set_state(core_id, CoreState.RUNNING)

            await self._store.save_state(
                core_id,
                state=self._states[core_id],
                enabled=self._enabled.get(core_id, False),
                settings=driver.settings,
            )

    async def persist_settings(self, core_id: str) -> None:
        """Persist a driver's validated live settings under its lifecycle lock.

        Managed SoftEther Virtual Hub metadata is changed by a live vpncmd
        transaction rather than Config Studio.  Keeping persistence behind the
        manager prevents API code from reaching into SQL rows or racing a core
        restart.  Drivers remain responsible for never placing credentials in
        ``settings``.
        """
        async with self._locks[core_id]:
            driver = self.get(core_id)
            await self._store.save_state(
                core_id,
                state=self._states[core_id],
                enabled=self._enabled.get(core_id, False),
                settings=driver.settings,
            )

    async def create_softether_policy_hub(self, **kwargs) -> dict[str, Any]:
        """Create + persist an isolated SoftEther hub as one manager operation."""
        core_id = "softether"
        async with self._locks[core_id]:
            driver = self.get(core_id)
            create = getattr(driver, "create_policy_hub", None)
            delete = getattr(driver, "delete_policy_hub", None)
            if not callable(create) or not callable(delete):
                raise CapabilityNotSupportedError(core_id, "managed_policy_hubs")
            created = await asyncio.to_thread(create, **kwargs)
            try:
                await self._store.save_state(
                    core_id, state=self._states[core_id],
                    enabled=self._enabled.get(core_id, False),
                    settings=driver.settings,
                )
            except Exception:
                # No unpersisted live hub may survive a database failure.
                try:
                    await asyncio.to_thread(delete, str(created["hub"]))
                except Exception:  # noqa: BLE001 - preserve persistence error
                    logger.exception(
                        "failed to roll back unpersisted SoftEther policy hub %s",
                        created.get("hub"))
                raise
            return created

    async def delete_softether_policy_hub(self, hub: str) -> None:
        """Delete a Zagros-owned hub and persist the reduced metadata set."""
        core_id = "softether"
        async with self._locks[core_id]:
            driver = self.get(core_id)
            delete = getattr(driver, "delete_policy_hub", None)
            if not callable(delete):
                raise CapabilityNotSupportedError(core_id, "managed_policy_hubs")
            await asyncio.to_thread(delete, hub)
            # Remote deletion is authoritative. Retry of this same admin call is
            # idempotent at vpncmd level, while stale DB metadata would recreate
            # a false inbound after reboot, so persistence failure is surfaced.
            await self._store.save_state(
                core_id, state=self._states[core_id],
                enabled=self._enabled.get(core_id, False),
                settings=driver.settings,
            )

    async def start_core(self, core_id: str) -> CoreStatus:
        async with self._locks[core_id]:
            driver = self.get(core_id)
            if not self._enabled[core_id]:
                raise CoreStateError(f"Core '{core_id}' is disabled; enable it first.")
            state = self._states[core_id]
            if state == CoreState.RUNNING:
                raise CoreStateError(f"Core '{core_id}' is already running.")
            if state not in (CoreState.INSTALLED, CoreState.STOPPED, CoreState.ERROR):
                raise CoreStateError(
                    f"Cannot start core '{core_id}' from state '{state.value}'."
                )
            await self._transition(core_id, driver, CoreState.STARTING, CoreState.RUNNING, driver.start)
            return await driver.status()

    async def stop_core(self, core_id: str) -> CoreStatus:
        async with self._locks[core_id]:
            driver = self.get(core_id)
            state = self._states[core_id]
            if state not in (CoreState.RUNNING, CoreState.ERROR, CoreState.STARTING):
                raise CoreStateError(
                    f"Cannot stop core '{core_id}' from state '{state.value}'."
                )
            await self._transition(core_id, driver, CoreState.STOPPING, CoreState.STOPPED, driver.stop)
            return await driver.status()

    async def restart_core(self, core_id: str) -> CoreStatus:
        async with self._locks[core_id]:
            driver = self.get(core_id)
            state = self._states[core_id]
            if state != CoreState.RUNNING:
                raise CoreStateError(f"Only a running core can be restarted ('{core_id}' is '{state.value}').")
            await self._set_state(core_id, CoreState.STOPPING)
            await driver.stop()
            await self._set_state(core_id, CoreState.STARTING)
            try:
                await driver.start()
            except Exception:
                await self._set_state(core_id, CoreState.ERROR)
                raise
            await self._set_state(core_id, CoreState.RUNNING)
            return await driver.status()

    async def start_enabled(self) -> None:
        """Boot policy: start every enabled, previously-running core."""
        for core_id in self.list_cores():
            # Built-ins (currently Xray) are owned by the legacy application
            # lifespan.  A persisted built-in row may be rehydrated before that
            # process is attached; starting it here races/double-starts the same
            # engine and produces a false boot traceback even though it is live.
            if core_id in self._builtin_core_ids:
                continue
            if not self._enabled[core_id]:
                continue
            if self._states[core_id] not in (CoreState.INSTALLED, CoreState.STOPPED, CoreState.ERROR):
                continue
            try:
                await self.start_core(core_id)
            except Exception:
                logger.exception("Auto-start failed for core '%s'.", core_id)

    async def stop_all(self) -> None:
        for core_id in self.list_cores():
            if self._states.get(core_id) == CoreState.RUNNING:
                try:
                    await self.stop_core(core_id)
                except Exception:
                    logger.exception("Graceful stop failed for core '%s'.", core_id)

    async def _transition(
        self,
        core_id: str,
        driver: BaseCoreDriver,
        intermediate: CoreState,
        success: CoreState,
        action: Callable[[], Awaitable[None]],
    ) -> None:
        await self._set_state(core_id, intermediate)
        try:
            await action()
        except Exception:
            await self._set_state(core_id, CoreState.ERROR)
            raise
        await self._set_state(core_id, success)

    async def _set_state(self, core_id: str, state: CoreState) -> None:
        self._states[core_id] = state
        await self._store.save_state(
            core_id, state=state, enabled=self._enabled.get(core_id, False)
        )
        await self._bus.emit(
            Event.CORE_STATE_CHANGED, {"core_id": core_id, "state": state.value}
        )

    # ------------------------------------------------------------------ #
    # status & health
    # ------------------------------------------------------------------ #
    async def status(self, core_id: str) -> CoreStatus:
        driver = self.get(core_id)
        try:
            status = await driver.status()
        except Exception as exc:
            status = CoreStatus(
                core_id=core_id,
                state=self._states.get(core_id, CoreState.ERROR),
                health=HealthStatus.UNHEALTHY,
                version_reason=f"status probe failed: {type(exc).__name__}",
                message=str(exc),
            )
        status.enabled = self._enabled.get(core_id, False)
        return status

    async def status_all(self) -> list[CoreStatus]:
        return list(await asyncio.gather(*(self.status(cid) for cid in self.list_cores())))

    async def get_logs(self, core_id: str, tail: int = 200) -> list[str]:
        driver = self.get(core_id)
        return [line async for line in driver.get_logs(tail=tail)]

    async def health_monitor(self, interval: float = 30.0) -> None:
        """Poll installed cores; publish health transitions AND reconcile the
        persisted lifecycle with the live probe truth.

        Rationale (reported bug, alpha.7.2 item 3): a sing-box core whose
        start() raised AFTER the process came up was marked ERROR while the
        binary kept serving — and the UI kept showing "error", because the
        persisted state outranked the probe and the old monitor only polled
        RUNNING cores. The probe is the ground truth for liveness:

        * live RUNNING  + recorded ERROR (or INSTALLED/STOPPED) → RUNNING
          (the process is verifiably up — self-heal the record);
        * live STOPPED  + recorded RUNNING → STOPPED (the core crashed or
          was killed out-of-band — detected instead of shown green);
        * live STOPPED  + recorded ERROR stays ERROR (a failed core must
          not silently resurrect);
        * probe EXCEPTION changes health to UNHEALTHY only — a flaky probe
          must never flip lifecycle state.
        """
        last_health: dict[str, HealthStatus] = {}
        try:
            while True:
                await self._health_cycle(last_health)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.info("CoreManager health monitor stopped.")
            raise

    async def _health_cycle(self, last_health: dict[str, HealthStatus]) -> None:
        for core_id in self.list_cores():
            recorded = self._states.get(core_id)
            if recorded in (
                CoreState.UNINSTALLED, CoreState.LOADED,
                CoreState.STARTING, CoreState.STOPPING,
            ):
                continue  # transient/absent states are not probed
            previous = last_health.get(core_id, HealthStatus.UNKNOWN)
            try:
                status = await asyncio.wait_for(
                    self.get(core_id).health_check(), timeout=15
                )
                health = status.health
            except Exception as exc:
                logger.warning("Health check failed for core '%s': %s", core_id, exc)
                health = HealthStatus.UNHEALTHY
                status = None
            if status is not None:
                if status.state == CoreState.RUNNING and recorded != CoreState.RUNNING:
                    logger.info(
                        "core '%s' is live (probe) while recorded '%s' — "
                        "reconciling to running", core_id, recorded,
                    )
                    await self._set_state(core_id, CoreState.RUNNING)
                elif status.state != CoreState.RUNNING and recorded == CoreState.RUNNING:
                    logger.warning(
                        "core '%s' recorded running but probe says '%s' — "
                        "marking stopped (crash or external kill detected)",
                        core_id, status.state.value,
                    )
                    await self._set_state(core_id, CoreState.STOPPED)
            if health != previous:
                last_health[core_id] = health
                await self._bus.emit(
                    Event.CORE_HEALTH_CHANGED,
                    {"core_id": core_id, "health": health.value},
                )

    def start_health_monitor(self, interval: float = 30.0) -> asyncio.Task:
        if self._monitor_task and not self._monitor_task.done():
            return self._monitor_task
        self._monitor_task = asyncio.create_task(self.health_monitor(interval))
        return self._monitor_task

    async def stop_health_monitor(self) -> None:
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------ #
    # user provisioning fan-out (saga-lite)
    # ------------------------------------------------------------------ #
    async def sync_accounts(self, core_id: str,
                            accounts: list[UserAccount]) -> None:
        """Serialize a full desired-account replay with core lifecycle.

        Startup/upgrade recovery uses this before listeners start whenever the
        driver supports offline reconciliation. Keeping it on CoreManager
        prevents a concurrent Studio restart or account mutation from
        publishing a half-restored config.
        """
        async with self._locks[core_id]:
            await self.get(core_id).sync_accounts(accounts)

    async def provision_user(
        self, accounts: Mapping[str, UserAccount]
    ) -> list[ProvisionResult]:
        """Create the user's accounts on every requested core.

        One core failing never blocks the others — each core reports its own
        ``ProvisionResult`` so the service layer can flag rows for reconciliation.
        """
        async def _create(core_id: str, account: UserAccount) -> ProvisionResult:
            try:
                driver = self.get(core_id)
            except CoreNotFoundError as exc:
                return ProvisionResult(core_id=core_id, account_id=account.account_id,
                                       success=False, error=str(exc))
            try:
                await driver.create_account(account)
                return ProvisionResult(core_id=core_id, account_id=account.account_id, success=True)
            except Exception as exc:
                logger.error("Provisioning on core '%s' failed: %s", core_id, exc)
                return ProvisionResult(core_id=core_id, account_id=account.account_id,
                                       success=False, error=str(exc))

        return list(await asyncio.gather(*(
            _create(core_id, account) for core_id, account in accounts.items()
        )))

    async def update_user(self, accounts: Mapping[str, UserAccount]) -> list[ProvisionResult]:
        async def _update(core_id: str, account: UserAccount) -> ProvisionResult:
            try:
                await self.get(core_id).update_account(account)
                return ProvisionResult(core_id=core_id, account_id=account.account_id, success=True)
            except Exception as exc:
                return ProvisionResult(core_id=core_id, account_id=account.account_id,
                                       success=False, error=str(exc))

        return list(await asyncio.gather(*(
            _update(core_id, account) for core_id, account in accounts.items()
        )))

    async def suspend_user(self, accounts: Mapping[str, UserAccount]) -> list[ProvisionResult]:
        """Suspend the user's access on every core — simultaneously.

        Strategy per core (capability-driven, never name-driven):
          * SUSPEND_RESUME → cheap native ``suspend_account``
          * else USER_MANAGEMENT → ``update_account(enabled=False)``
          * else → explicit failure result (no pretend-suspends)
        """
        async def _suspend(core_id: str, account: UserAccount) -> ProvisionResult:
            try:
                driver = self.get(core_id)
                if driver.supports(Capability.SUSPEND_RESUME):
                    await driver.suspend_account(account.account_id)
                elif driver.supports(Capability.USER_MANAGEMENT):
                    await driver.update_account(account.model_copy(update={"enabled": False}))
                else:
                    raise CapabilityNotSupportedError(core_id, Capability.SUSPEND_RESUME.value)
                return ProvisionResult(core_id=core_id, account_id=account.account_id, success=True)
            except Exception as exc:
                logger.error("Suspend on core '%s' failed: %s", core_id, exc)
                return ProvisionResult(core_id=core_id, account_id=account.account_id,
                                       success=False, error=str(exc))

        return list(await asyncio.gather(*(
            _suspend(core_id, account) for core_id, account in accounts.items()
        )))

    async def resume_user(self, accounts: Mapping[str, UserAccount]) -> list[ProvisionResult]:
        """Resume the user's access on every core — simultaneously."""
        async def _resume(core_id: str, account: UserAccount) -> ProvisionResult:
            try:
                driver = self.get(core_id)
                if driver.supports(Capability.SUSPEND_RESUME):
                    await driver.resume_account(account)
                elif driver.supports(Capability.USER_MANAGEMENT):
                    await driver.update_account(account.model_copy(update={"enabled": True}))
                else:
                    raise CapabilityNotSupportedError(core_id, Capability.SUSPEND_RESUME.value)
                return ProvisionResult(core_id=core_id, account_id=account.account_id, success=True)
            except Exception as exc:
                logger.error("Resume on core '%s' failed: %s", core_id, exc)
                return ProvisionResult(core_id=core_id, account_id=account.account_id,
                                       success=False, error=str(exc))

        return list(await asyncio.gather(*(
            _resume(core_id, account) for core_id, account in accounts.items()
        )))

    async def deprovision_user(self, accounts: Mapping[str, str]) -> list[ProvisionResult]:
        """Remove a user's accounts: ``{core_id: account_id}``."""
        async def _delete(core_id: str, account_id: str) -> ProvisionResult:
            try:
                await self.get(core_id).delete_account(account_id)
                return ProvisionResult(core_id=core_id, account_id=account_id, success=True)
            except Exception as exc:
                return ProvisionResult(core_id=core_id, account_id=account_id,
                                       success=False, error=str(exc))

        return list(await asyncio.gather(*(
            _delete(core_id, account_id) for core_id, account_id in accounts.items()
        )))

    # ------------------------------------------------------------------ #
    # statistics aggregation (capability-gated, error-isolated)
    # ------------------------------------------------------------------ #
    async def aggregate_usage(
        self, accounts: Mapping[str, list[str]]
    ) -> list[UsageRecord]:
        """Collect usage records for the given accounts per core."""
        async def _collect(core_id: str, account_ids: list[str]) -> list[UsageRecord]:
            try:
                driver = self.get(core_id)
                if not driver.supports(Capability.USAGE_ACCOUNTING):
                    return []
                return await driver.get_usage(account_ids=account_ids)
            except Exception:
                logger.exception("Usage collection failed for core '%s'.", core_id)
                return []

        groups = await asyncio.gather(*(
            _collect(core_id, ids) for core_id, ids in accounts.items()
        ))
        return [record for group in groups for record in group]

    async def online_devices(
        self, accounts: Mapping[str, list[str]]
    ) -> list[DeviceSession]:
        async def _collect(core_id: str, account_ids: list[str]) -> list[DeviceSession]:
            try:
                driver = self.get(core_id)
                if not driver.supports(Capability.ONLINE_TRACKING):
                    return []
                return await driver.get_online_devices(account_ids=account_ids)
            except Exception:
                logger.exception("Online-device collection failed for core '%s'.", core_id)
                return []

        groups = await asyncio.gather(*(
            _collect(core_id, ids) for core_id, ids in accounts.items()
        ))
        return [session for group in groups for session in group]
