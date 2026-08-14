"""Zagros platform runtime — dependency injection composition root.

Built once at application startup, stored on ``app.state.zagros`` and
injected into routers. Owns:

* persistence (engine/session factory, repositories, cipher),
* the multicore CoreManager (+ engines) booted from stored core state,
* portal / client-API / studio / dashboard services.

Schema ownership: Alembic. The runtime does NOT silently create tables —
``verify_schema()`` fails fast with an actionable message if the schema is
missing (run ``alembic upgrade head`` first).
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

from app.adminapi.dashboard import DashboardService
from app.clientapi.service import ClientApiService
from app.clientapi.tokens import SignedTokenService
from app.cores.manager import CoreManager
from app.cores.outbounds.manager import OutboundManager
from app.cores.registry import discover_builtin
from app.cores.routing.engine import RoutingEngine
from app.persistence import (
    SecretsCipher,
    SQLCoreStateStore,
    SQLDeviceStore,
    SQLOnlineDataAdapter,
    SQLPortalSettingsStore,
    SQLQuotaStore,
    SQLRefreshTokenStore,
    SQLSessionStore,
    SQLStudioStore,
    SQLUsageJournal,
    SQLBaselineStore,
    UserRepository,
    create_session_factory,
)
from app.persistence.base import Base
from app.portal.service import PortalService
from app.studio.service import ConfigStudioService


class PlatformConfigError(RuntimeError):
    pass


class PlatformRuntime:
    def __init__(self, *, database_url: str, master_secret: str,
                 client_token_ttl: int = 900) -> None:
        if not master_secret or len(master_secret) < 16:
            raise PlatformConfigError(
                "ZAGROS_SECRET_KEY is missing or shorter than 16 characters. "
                "Set it in your .env (see .env.example) — it protects stored "
                "credentials and sealed delivery."
            )
        self.database_url = database_url
        self.session_factory = create_session_factory(database_url)

        # persistence layer
        self.cipher = SecretsCipher.from_master_secret(master_secret)
        self.users = UserRepository(self.session_factory, self.cipher)
        self.core_state = SQLCoreStateStore(self.session_factory)
        self.quota = SQLQuotaStore(self.session_factory)
        self.baselines = SQLBaselineStore(self.session_factory)
        self.usage_journal = SQLUsageJournal(self.session_factory)
        self.devices = SQLDeviceStore(self.session_factory)
        self.sessions_store = SQLSessionStore(self.session_factory)
        self.refresh_tokens = SQLRefreshTokenStore(self.session_factory)
        self.portal_settings = SQLPortalSettingsStore(self.session_factory)
        self.studio_store = SQLStudioStore(self.session_factory)
        # item 13: cross-core Host Settings entries (delivery expansion)
        from app.persistence.repositories import SQLCoreHostStore
        self.core_hosts = SQLCoreHostStore(self.session_factory)

        # multicore
        self.core_manager = CoreManager(store=self.core_state)
        discover_builtin()
        from app.cores.routing.policy import PolicyRoutingManager

        self.policy_router = PolicyRoutingManager(
            self.core_manager, identity_provider=self._policy_identities)
        self.routing_engine = RoutingEngine(
            self.core_manager, policy_router=self.policy_router)
        self.outbound_manager = OutboundManager(
            self.core_manager, policy_router=self.policy_router)

        # data adapters + services
        self.online_data = SQLOnlineDataAdapter(
            self.session_factory, self.users, self.quota, self.core_manager
        )
        self.portal = PortalService(self.online_data, self.portal_settings,
                                    host_store=self.core_hosts)
        token_secret = hashlib.sha256(
            b"zagros/client-tokens/v1|" + self.cipher._key
        ).digest()
        self.tokens = SignedTokenService(token_secret, ttl_seconds=client_token_ttl)
        # per-user subscription-token rotation markers (portal URLs die on rotate)
        from app.persistence.repositories import SQLSettingsKV
        self.kv = SQLSettingsKV(self.session_factory)
        from app.clientapi.stores import InMemoryConnectTokenStore

        self.client_api = ClientApiService(
            self.online_data, self.refresh_tokens, InMemoryConnectTokenStore(),
            self.tokens,
        )
        self.studio = ConfigStudioService(self.studio_store)
        self.dashboard = DashboardService(
            self.core_manager,
            user_stats=_RuntimeUserStats(self.session_factory),
            usage_provider=_RuntimeUsageByCore(self.session_factory),
            node_provider=_RuntimeNodeProvider(self.session_factory),
            routing_engine=self.routing_engine,
            outbound_manager=self.outbound_manager,
            device_store=self.devices,
        )

    @classmethod
    def from_env(cls) -> "PlatformRuntime":
        import os

        # Compose only MOUNTS the .env file; merge it here so the runtime
        # sees the file's values even though nothing is injected into the
        # container environment (real env vars still win, file never
        # overrides). Idempotent — see app/env_loader.py.
        from app.env_loader import load_zagros_env

        load_zagros_env()

        url = (os.environ.get("ZAGROS_DATABASE_URL")
               or os.environ.get("SQLALCHEMY_DATABASE_URL")
               or "sqlite:///zagros.db")
        secret = os.environ.get("ZAGROS_SECRET_KEY", "")
        return cls(database_url=url, master_secret=secret)

    def _policy_identities(self, names: list[str]) -> dict[str, tuple[int, int]]:
        """Allocate/read stable table+mark ids in one SQL transaction."""
        from sqlalchemy import select

        from app.cores.routing.policy import PolicyRoutingManager
        from app.persistence.models import RoutingDomainModel

        wanted = sorted(set(str(name) for name in names if str(name)))
        with self.session_factory() as session:
            rows = session.execute(select(RoutingDomainModel)).scalars().all()
            mapping = {row.outbound_name: (int(row.table_id), int(row.fwmark))
                       for row in rows}
            used = {table for table, _mark in mapping.values()}
            for name in wanted:
                if name in mapping:
                    continue
                table_id = PolicyRoutingManager._table_for(name, used)  # noqa: SLF001
                used.add(table_id)
                session.add(RoutingDomainModel(
                    outbound_name=name, table_id=table_id, fwmark=table_id))
                mapping[name] = (table_id, table_id)
            session.commit()
        return {name: mapping[name] for name in wanted}

    async def _retry_deferred_boot_work(
        self,
        operation,
        pending: set[str],
        *,
        label: str,
        attempts: int = 30,
        delay_seconds: float = 2.0,
    ) -> set[str]:
        """Bounded warm-up retries for live-control-plane cores.

        SoftEther can answer the first reachability probe while vpncmd user
        mutation still returns protocol error 2 for several seconds. A single
        immediate post-start replay left encrypted accounts deferred until an
        operator edited/reinstalled them. Retry only the already-deferred core
        set; successful engines are never touched twice.
        """
        remaining = set(pending)
        for attempt in range(1, attempts + 1):
            if not remaining:
                break
            if attempt > 1 and delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
            remaining = await operation(remaining)
            if remaining:
                logger.warning(
                    "%s reconciliation still deferred after warm-up attempt %d/%d: %s",
                    label, attempt, attempts, sorted(remaining),
                )
        return remaining

    async def boot_cores(self) -> None:
        await self.core_manager.boot()
        # Restore listener documents first, then replay encrypted account
        # desired state BEFORE start where the driver can work offline. This
        # closes the image-upgrade gap where a fresh driver instance had zero
        # users/peers: sing-box omitted old listeners, OpenVPN could not
        # authorize, and subscriptions became "unavailable" until a manual
        # sync/reinstall.
        studio_deferred = await self._hydrate_studio_documents()
        account_deferred = await self._restore_core_accounts()
        await self.core_manager.start_enabled()
        # Live-managed engines (SoftEther in particular) cannot apply Studio
        # or user state until their daemon is up. Retry only the operations
        # that honestly failed offline; successful config cores are not
        # restarted a second time.
        if studio_deferred:
            studio_deferred = await self._retry_deferred_boot_work(
                self._hydrate_studio_documents, studio_deferred,
                label="studio",
            )
        if account_deferred:
            account_deferred = await self._retry_deferred_boot_work(
                self._restore_core_accounts, account_deferred,
                label="account",
            )
        await self._attach_builtin_xray()
        # Xray is attached after add-on auto-start so CoreManager never starts
        # it twice. Its SQL Studio document must nevertheless be replayed: in
        # alpha.7.7 XRAY_JSON lived in the replaceable image layer, while the
        # complete accepted document already survived in SQL.
        if "xray" in self.core_manager.list_cores():
            studio_deferred |= await self._hydrate_studio_documents({"xray"})
            try:
                status = await self.core_manager.status("xray")
                from app.cores.types import CoreState

                if status.state is not CoreState.RUNNING:
                    await self.core_manager.start_core("xray")
            except Exception as exc:  # noqa: BLE001 — other cores still boot
                logger.error("built-in xray recovery/start failed: %s", exc)
        # Rules/outbounds are desired state just like Studio documents and
        # accounts. Older boots restored the latter two but silently forgot
        # the network graph, so every update/restart returned service traffic
        # to the master's eth0. Replay only after all source interfaces and
        # the built-in Xray adapter exist.
        routing_deferred = await self._hydrate_network_policy()
        await self._write_boot_report(
            studio_deferred, account_deferred, routing_deferred)

    async def _hydrate_network_policy(self) -> set[str]:
        """Replay persisted outbounds + rules into native and kernel runtimes.

        The KV documents remain the compatibility source for alpha.7.9,
        alpha.8 and alpha.8.1.  Deployment is deliberately after core boot:
        OpenVPN/WireGuard source interfaces and the sing-box binary must exist
        before policy domains/classifiers can be validated.
        """
        try:
            raw_outbounds = await self.kv.get_value("admin.outbounds.v1") or []
            raw_rules = await self.kv.get_value("admin.routing.rules.v1") or []
            from app.cores.outbounds.model import Outbound
            from app.cores.routing.model import RoutingRule

            outbounds = [Outbound.model_validate(item) for item in raw_outbounds]
            rules = [RoutingRule.model_validate(item) for item in raw_rules]
            for existing in list(self.outbound_manager.list()):
                self.outbound_manager.unregister(existing.name)
            for outbound in outbounds:
                self.outbound_manager.register(outbound)
            await self.outbound_manager.deploy()
            await self.routing_engine.deploy(rules, outbounds=outbounds)
            logger.info(
                "network policy hydration: restored %d outbound(s), %d rule(s)",
                len(outbounds), len(rules),
            )
            return set()
        except Exception as exc:  # noqa: BLE001 — report must fail closed
            logger.error("network policy hydration failed: %s", exc)
            return {"policy"}

    async def _write_boot_report(
        self, studio_deferred: set[str], account_deferred: set[str],
        routing_deferred: set[str] | None = None,
    ) -> None:
        """Persist one secret-free, atomic reconciliation verdict for host repair.

        The host CLI cannot introspect process-local driver state from another
        Python process. This report is emitted by the live panel *after* Studio,
        account replay and starts, allowing ``zagros repair`` to fail loudly on
        any enabled core that is still down without needing admin credentials.
        """
        try:
            statuses = await self.core_manager.status_all()
            payload = {
                "generated_at": int(time.time()),
                "studio_deferred": sorted(studio_deferred),
                "account_deferred": sorted(account_deferred),
                "routing_deferred": sorted(routing_deferred or set()),
                "cores": [
                    {
                        "id": status.core_id,
                        "enabled": bool(status.enabled),
                        "state": status.state.value,
                        "health": status.health.value,
                        "version": status.core_version,
                        "message": status.message,
                    }
                    for status in statuses
                ],
            }
            path = os.environ.get(
                "ZAGROS_BOOT_REPORT",
                "/var/lib/zagros/runtime-boot-report.json",
            )
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            part = path + ".part"
            with open(part, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True)
                fh.write("\n")
            os.chmod(part, 0o600)
            os.replace(part, path)
        except Exception as exc:  # noqa: BLE001 — report failure cannot kill panel
            logger.error("cannot write runtime boot report: %s", exc)

    async def _hydrate_studio_documents(
        self, core_ids: set[str] | None = None,
    ) -> set[str]:
        """Re-apply persisted studio documents into drivers BEFORE they start.

        Root fix (alpha.7.1): Studio documents live in SQL and drivers keep
        the applied result IN MEMORY — so a panel restart silently dropped
        every wizard-created listener the next time a core started (the old
        doc was re-applied only when somebody pressed Apply again). Xray is
        exempt: apply already persists XRAY_JSON on disk and its boot seed
        is that file. Every other enabled core gets its stored document
        pushed through the same strict apply path the wizard uses, so a core
        boots with EXACTLY the config the studio shows.

        A stored document that no longer applies (engine downgraded, stale
        fields) is logged LOUDLY and skipped — it must never abort panel
        boot; the surfaces the operator anyway (status/delivery) stay honest.
        """
        deferred: set[str] = set()
        for core_id in self.core_manager.list_cores():
            if core_ids is not None and core_id not in core_ids:
                continue
            try:
                driver = self.core_manager.get(core_id)
            except Exception:  # noqa: BLE001 — core vanished mid-boot
                continue
            hook = getattr(driver, "apply_studio_document", None)
            if hook is None:
                continue
            try:
                doc = await self.studio_store.get_document(core_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("studio hydration: cannot read document for %s: %s",
                               core_id, exc)
                deferred.add(core_id)
                continue
            if not doc:
                continue
            try:
                before = copy.deepcopy(doc)
                normalizer = getattr(driver, "normalize_studio_document", None)
                if callable(normalizer):
                    normalized = normalizer(doc)
                    if normalized is not None:
                        doc = normalized
                await self.core_manager.apply_studio_document(core_id, doc)
                if doc != before:
                    await self.studio_store.save_document(core_id, doc)
                    logger.warning(
                        "studio hydration: %s legacy document normalized and persisted",
                        core_id,
                    )
                logger.info("studio hydration: %s restored from persisted document", core_id)
            except Exception as exc:  # noqa: BLE001
                deferred.add(core_id)
                logger.error(
                    "studio hydration: persisted document for %s could not "
                    "apply in this boot phase (%s) — it will be retried after "
                    "enabled daemons start; the stored document is unchanged.",
                    core_id, exc,
                )
        return deferred

    async def _restore_core_accounts(
        self, core_ids: set[str] | None = None,
    ) -> set[str]:
        """Replay every persisted non-Xray account into fresh driver memory.

        Core processes are not the desired-state database. Container/image
        replacement reconstructs driver objects, so users/peers/auth tables
        must be replayed from encrypted SQL on every boot. Drivers that can
        reconcile while stopped do so before Start; live-only drivers are
        returned for one post-start retry. Any credential repaired from an
        old incomplete row is written back even when the first phase fails.
        """
        deferred: set[str] = set()
        for core_id in self.core_manager.list_cores():
            if core_ids is not None and core_id not in core_ids:
                continue
            if not self.core_manager.is_enabled(core_id):
                continue
            try:
                rows = await asyncio.to_thread(
                    self.users.accounts_of_core, core_id, decrypt=True)
            except Exception as exc:  # noqa: BLE001
                logger.error("account hydration: cannot read %s accounts: %s",
                             core_id, exc)
                deferred.add(core_id)
                continue
            accounts = []
            originals: dict[str, tuple[bool, dict]] = {}
            for row in rows:
                try:
                    owner = await asyncio.to_thread(
                        self.users.get_user, int(row["user_id"]))
                except Exception as exc:  # noqa: BLE001
                    deferred.add(core_id)
                    logger.error(
                        "account hydration: owner lookup failed for %s/%s: %s",
                        core_id, row.get("account_id"), exc,
                    )
                    continue
                if owner is None:
                    logger.warning(
                        "account hydration: %s/%s has no owner row; skipped",
                        core_id, row["account_id"],
                    )
                    continue
                from app.cores.types import UserAccount

                stored_enabled = bool(row["enabled"])
                settings = copy.deepcopy(row["settings"] or {})
                account = UserAccount(
                    user_id=int(row["user_id"]),
                    username=str(owner.username),
                    account_id=str(row["account_id"]),
                    protocol=str(row["protocol"]),
                    enabled=stored_enabled and str(owner.status) == "active",
                    settings=settings,
                )
                accounts.append(account)
                originals[account.account_id] = (
                    stored_enabled, copy.deepcopy(settings))
            try:
                await self.core_manager.sync_accounts(core_id, accounts)
                logger.info("account hydration: %s restored %d account(s)",
                            core_id, len(accounts))
            except Exception as exc:  # noqa: BLE001
                deferred.add(core_id)
                logger.error(
                    "account hydration: %s could not reconcile in this boot "
                    "phase (%s); it will be retried after daemon start",
                    core_id, exc,
                )
            finally:
                # Drivers may repair credentials in place before a later I/O
                # failure. Persist only real changes; do not churn ciphertext
                # for byte-identical rows on every reboot.
                for account in accounts:
                    stored_enabled, before = originals[account.account_id]
                    if account.settings == before:
                        continue
                    try:
                        await asyncio.to_thread(
                            self.users.upsert_core_account,
                            user_id=account.user_id,
                            core_id=core_id,
                            account_id=account.account_id,
                            protocol=account.protocol,
                            enabled=stored_enabled,
                            settings=account.settings,
                        )
                    except Exception as exc:  # noqa: BLE001
                        deferred.add(core_id)
                        logger.error(
                            "account hydration: repaired credentials for %s/%s "
                            "could not be persisted (%s)",
                            core_id, account.account_id, exc,
                        )
        return deferred

    async def _attach_builtin_xray(self) -> None:
        """Attach the panel's built-in xray engine as a protected core.

        Without this the platform CoreManager simply did not know "xray":
        every ``user_core_accounts`` mirror row the legacy bridge writes was
        discarded at materialization time ("core not enabled/loaded"), which
        made the multi-core portal & subscription come out EMPTY for the very
        protocols most users have. Attaching the real XrayDriver (legacy
        backend) makes xray first-class in delivery, catalog, status and
        routing — while the manager guard marks it non-removable and the
        usage recorder skips it (the legacy stack already accounts xray
        traffic; folding it again would double-count).

        Attached AFTER ``start_enabled`` on purpose: the legacy lifespan owns
        xray's boot-time process start; the manager must never auto-start it.
        An operator-persisted xray entry always wins over the auto-attach.
        """
        from app.cores.manager import BUILTIN_CORE_IDS

        for core_id in BUILTIN_CORE_IDS:
            if core_id in self.core_manager.list_cores():
                continue
            if core_id == "xray":
                from app.cores.drivers.xray.driver import XrayDriver

                driver = XrayDriver()
            else:  # pragma: no cover - future built-ins declare their driver here
                continue
            from app.cores.types import CoreState

            state = CoreState.STOPPED
            try:
                status = await driver.status()
                state = status.state
            except Exception:  # noqa: BLE001 — legacy stack not importable here
                logger.warning(
                    "built-in core '%s': status probe failed at boot; attaching "
                    "as STOPPED (delivery keeps working, health stays honest)",
                    core_id,
                )
            self.core_manager.attach(core_id, driver, enabled=True, state=state)
            logger.info("built-in core '%s' attached (state=%s).", core_id, state.value)

    def verify_schema(self) -> None:
        from sqlalchemy import inspect

        engine = self.session_factory.kw["bind"]
        existing = set(inspect(engine).get_table_names())
        required = set(Base.metadata.tables) - {"alembic_version"}
        missing = sorted(required - existing)
        if missing:
            raise PlatformConfigError(
                "Zagros schema is incomplete "
                f"(missing tables: {', '.join(missing)}). "
                "Run `alembic upgrade head` first — schema changes always go "
                "through Alembic, never through silent auto-creation."
            )


# ---------------------------------------------------------------------- #
# dashboard providers bound to SQL
# ---------------------------------------------------------------------- #

class _RuntimeUserStats:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def user_totals(self) -> dict[str, int]:
        import asyncio
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import func, select

        from app.persistence.models import UserModel

        def _sync() -> dict[str, int]:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=90)
            with self._sf() as s:
                total = s.scalar(select(func.count(UserModel.id))) or 0
                active = s.scalar(
                    select(func.count(UserModel.id)).where(UserModel.status == "active")
                ) or 0
                online = s.scalar(
                    select(func.count(UserModel.id)).where(UserModel.online_at >= cutoff)
                ) or 0
                return {"total": total, "active": active, "online": online}

        return await asyncio.to_thread(_sync)

    async def quota_alerts(self, *, ratio: float, limit: int):
        import asyncio

        from app.adminapi.dashboard import Alert, AlertSeverity
        from sqlalchemy import select

        from app.persistence.models import UserModel, UserUsageModel

        def _sync() -> list[tuple[str, float]]:
            with self._sf() as s:
                rows = s.execute(
                    select(UserModel.username, UserUsageModel.uplink_bytes,
                           UserUsageModel.downlink_bytes, UserModel.data_limit_bytes)
                    .join(UserUsageModel, UserUsageModel.user_id == UserModel.id)
                    .where(UserModel.data_limit_bytes.isnot(None))
                ).all()
                out = []
                for username, up, down, lim in rows:
                    if lim:
                        out.append((username, (up + down) / lim))
                return out

        alerts: list[Alert] = []
        for username, use_ratio in await asyncio.to_thread(_sync):
            if use_ratio >= ratio:
                alerts.append(Alert(
                    severity=(AlertSeverity.CRITICAL if use_ratio >= 1.0
                              else AlertSeverity.WARNING),
                    code="quota.nearly_full", target=username,
                    message=f"'{username}' used {use_ratio:.0%} of the data limit",
                ))
        alerts.sort(key=lambda a: a.severity.value)
        return alerts[:limit]


class _RuntimeUsageByCore:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def usage_by_core(self) -> dict[str, tuple[int, int]]:
        import asyncio

        from sqlalchemy import func, select

        from app.persistence.models import UsageRecordModel

        def _sync() -> dict[str, tuple[int, int]]:
            with self._sf() as s:
                rows = s.execute(
                    select(UsageRecordModel.core_id,
                           func.sum(UsageRecordModel.uplink_bytes),
                           func.sum(UsageRecordModel.downlink_bytes))
                    .group_by(UsageRecordModel.core_id)
                ).all()
                return {core: (int(up or 0), int(down or 0)) for core, up, down in rows}

        return await asyncio.to_thread(_sync)


class _RuntimeNodeProvider:
    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    async def node_states(self):
        import asyncio

        from app.adminapi.dashboard import NodeHealthView
        from sqlalchemy import select

        from app.persistence.models import NodeModel

        def _sync():
            with self._sf() as s:
                return [
                    NodeHealthView(node_id=r.id, name=r.name, address=r.address,
                                   status=r.status, last_seen=r.last_seen)
                    for r in s.execute(select(NodeModel)).scalars().all()
                ]

        return await asyncio.to_thread(_sync)
