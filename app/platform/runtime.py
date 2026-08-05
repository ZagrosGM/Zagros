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

import hashlib

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

        # multicore
        self.core_manager = CoreManager(store=self.core_state)
        discover_builtin()
        self.routing_engine = RoutingEngine(self.core_manager)
        self.outbound_manager = OutboundManager(self.core_manager)

        # data adapters + services
        self.online_data = SQLOnlineDataAdapter(
            self.session_factory, self.users, self.quota, self.core_manager
        )
        self.portal = PortalService(self.online_data, self.portal_settings)
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

        url = (os.environ.get("ZAGROS_DATABASE_URL")
               or os.environ.get("SQLALCHEMY_DATABASE_URL")
               or "sqlite:///zagros.db")
        secret = os.environ.get("ZAGROS_SECRET_KEY", "")
        return cls(database_url=url, master_secret=secret)

    async def boot_cores(self) -> None:
        await self.core_manager.boot()
        await self.core_manager.start_enabled()

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
