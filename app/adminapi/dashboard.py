"""Dashboard aggregation — one snapshot powering the Zagros dashboard UI.

Aggregates from the hexagonal ports only: CoreManager (status), quota
store (usage), device/session stores (activity), routing/outbound engines
(last deployment reports) and a user-stats provider port. Every number is
derived, never cached across refreshes — the dashboard is always live.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from app.cores.manager import CoreManager
from app.cores.types import CoreState, HealthStatus


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Alert(BaseModel):
    severity: AlertSeverity
    code: str                        # core.unhealthy / core.degraded / node.offline / ...
    message: str
    target: str | None = None


class CoreHealthView(BaseModel):
    core_id: str
    name: str = ""
    state: str
    health: str
    enabled: bool = True
    version: str | None = None
    uptime_seconds: float | None = None
    active_accounts: int = 0
    active_sessions: int = 0
    message: str | None = None


class LiveUsageGauge(BaseModel):
    """Per-core usage totals (up/down) as reported by the journal provider."""

    core_id: str
    uplink_bytes: int = 0
    downlink_bytes: int = 0

    @property
    def total_bytes(self) -> int:
        return self.uplink_bytes + self.downlink_bytes


class NodeHealthView(BaseModel):
    node_id: int
    name: str
    address: str
    status: str
    last_seen: datetime | None = None


class DeploymentStatusView(BaseModel):
    deployed_at_available: bool = False
    per_core: dict[str, dict[str, Any]] = Field(default_factory=dict)
    unsupported_total: int = 0


class DashboardSnapshot(BaseModel):
    generated_at: datetime
    users_total: int
    users_online: int
    users_active: int = 0
    usage_total_bytes: int
    usage_by_core: list[LiveUsageGauge] = Field(default_factory=list)
    cores: list[CoreHealthView] = Field(default_factory=list)
    nodes: list[NodeHealthView] = Field(default_factory=list)
    devices_active: int = 0
    sessions_active: int = 0
    routing_status: DeploymentStatusView = Field(default_factory=DeploymentStatusView)
    outbound_status: DeploymentStatusView = Field(default_factory=DeploymentStatusView)
    alerts: list[Alert] = Field(default_factory=list)


class UserStatsProvider(Protocol):
    async def user_totals(self) -> dict[str, int]:
        """{"total": n, "active": n, "online": n} — online by ``online_at``."""

    async def quota_alerts(self, *, ratio: float, limit: int) -> list[Alert]:
        """Users above ``ratio`` of their data limit (top ``limit``)."""


class UsageByCoreProvider(Protocol):
    async def usage_by_core(self) -> dict[str, tuple[int, int]]:
        """{core_id: (uplink, downlink)} totals from the usage journal."""


class NodeStatusProvider(Protocol):
    async def node_states(self) -> list[NodeHealthView]: ...


class DashboardService:
    def __init__(
        self,
        core_manager: CoreManager,
        user_stats: UserStatsProvider,
        usage_provider: UsageByCoreProvider,
        node_provider: NodeStatusProvider | None = None,
        *,
        routing_engine: Any | None = None,
        outbound_manager: Any | None = None,
        device_store: Any | None = None,
        session_manager: Any | None = None,
        quota_alert_ratio: float = 0.9,
        quota_alert_limit: int = 10,
    ) -> None:
        self._cores = core_manager
        self._users = user_stats
        self._usage = usage_provider
        self._nodes = node_provider
        self._routing = routing_engine
        self._outbounds = outbound_manager
        self._devices = device_store
        self._sessions = session_manager
        self._ratio = quota_alert_ratio
        self._limit = quota_alert_limit

    @staticmethod
    def _deployment_status(report: Any | None) -> DeploymentStatusView:
        if report is None:
            return DeploymentStatusView()
        per_core: dict[str, dict[str, Any]] = {}
        unsupported = 0
        for core_id, result in report.results.items():
            applied = len(getattr(result, "applied", []) or [])
            uns = list(getattr(result, "unsupported", []) or [])
            unsupported += len(uns)
            per_core[core_id] = {"applied": applied, "unsupported": len(uns)}
        return DeploymentStatusView(
            deployed_at_available=True, per_core=per_core,
            unsupported_total=unsupported,
        )

    async def snapshot(self) -> DashboardSnapshot:
        statuses = await self._cores.status_all()
        core_views = [
            CoreHealthView(
                core_id=s.core_id,
                name=getattr(s, "name", "") or "",
                state=s.state.value if isinstance(s.state, CoreState) else str(s.state),
                health=s.health.value if isinstance(s.health, HealthStatus) else str(s.health),
                enabled=s.enabled,
                version=s.core_version,
                uptime_seconds=s.uptime_seconds,
                active_accounts=(s.metrics.active_accounts if s.metrics else 0),
                active_sessions=(s.metrics.active_sessions if s.metrics else 0),
                message=s.message,
            )
            for s in statuses
        ]
        totals = await self._users.user_totals()
        usage_map = await self._usage.usage_by_core()
        nodes = await self._nodes.node_states() if self._nodes else []

        devices_active = 0
        if self._devices is not None:
            devices_active = sum(
                1 for d in await self._devices.all() if d.current_core
            )
        sessions_active = 0
        if self._sessions is not None:
            sessions_active = len(self._sessions.active())

        alerts: list[Alert] = []
        for view in core_views:
            if view.state not in (CoreState.RUNNING.value, CoreState.STOPPED.value):
                continue
            if view.health == HealthStatus.UNHEALTHY.value:
                alerts.append(Alert(severity=AlertSeverity.CRITICAL,
                                    code="core.unhealthy", target=view.core_id,
                                    message=f"Core '{view.core_id}' is unhealthy"
                                            + (f": {view.message}" if view.message else "")))
            elif view.health == HealthStatus.DEGRADED.value:
                alerts.append(Alert(severity=AlertSeverity.WARNING,
                                    code="core.degraded", target=view.core_id,
                                    message=f"Core '{view.core_id}' is degraded"
                                            + (f": {view.message}" if view.message else "")))
        if self._cores is not None:
            for core_id, view in ((c.core_id, c) for c in core_views):
                if view.state == CoreState.ERROR.value:
                    alerts.append(Alert(severity=AlertSeverity.CRITICAL,
                                        code="core.error", target=core_id,
                                        message=f"Core '{core_id}' is in ERROR state"))
        for node in nodes:
            if node.status not in ("connected", "healthy", "online"):
                alerts.append(Alert(severity=AlertSeverity.WARNING,
                                    code="node.offline", target=node.name,
                                    message=f"Node '{node.name}' is {node.status}"))
        alerts.extend(await self._users.quota_alerts(
            ratio=self._ratio, limit=self._limit
        ))
        severity_order = {AlertSeverity.CRITICAL: 0, AlertSeverity.WARNING: 1,
                          AlertSeverity.INFO: 2}
        alerts.sort(key=lambda a: severity_order[a.severity])

        return DashboardSnapshot(
            generated_at=datetime.now(timezone.utc),
            users_total=totals.get("total", 0),
            users_online=totals.get("online", 0),
            users_active=totals.get("active", 0),
            usage_total_bytes=sum(up + down for up, down in usage_map.values()),
            usage_by_core=[LiveUsageGauge(core_id=c, uplink_bytes=up, downlink_bytes=down)
                           for c, (up, down) in sorted(usage_map.items())],
            cores=core_views,
            nodes=nodes,
            devices_active=devices_active,
            sessions_active=sessions_active,
            routing_status=self._deployment_status(
                getattr(self._routing, "last_report", None)),
            outbound_status=self._deployment_status(
                getattr(self._outbounds, "last_report", None)),
            alerts=alerts,
        )
