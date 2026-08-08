"""Shared data-transfer objects exchanged between the panel and core drivers.

These types deliberately contain **zero** xray/sing-box/... specifics. A driver
maps its native concepts (xray account, wg peer, ovpn CN, hysteria user) onto
``UserAccount`` and back.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CoreState(str, Enum):
    """Lifecycle states of an installed core instance (see CoreManager)."""

    LOADED = "loaded"            # driver instantiated, binaries not prepared
    INSTALLED = "installed"      # ready to start
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    UNINSTALLED = "uninstalled"


class HealthStatus(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class Capability(str, Enum):
    """Feature flags a driver may advertise.

    The UI hides/shows controls based on these, and calling an unsupported
    operation raises :class:`CapabilityNotSupportedError`.
    """

    USER_MANAGEMENT = "user_management"        # create/update/delete accounts
    SUSPEND_RESUME = "suspend_resume"          # cheap suspend without re-provision
    USAGE_ACCOUNTING = "usage_accounting"      # per-account traffic counters
    ONLINE_TRACKING = "online_tracking"        # live sessions / online devices
    HOT_RELOAD = "hot_reload"                  # apply config without full restart
    SERVICE_CONTROL = "service_control"        # panel-controlled start/stop
    SELF_INSTALL = "self_install"              # can fetch/update its own binary
    CLIENT_CONFIG = "client_config"            # can build client connection payloads
    MULTI_NODE = "multi_node"                  # supports panel-managed remote nodes

    # --- capability system v2 (routing / outbound / chain / policy) ---
    ROUTING = "routing"                        # native in-core routing rules
    GEO_ROUTING = "geo_routing"                # geosite / geoip matching
    PROCESS_ROUTING = "process_routing"        # process-name matching
    OUTBOUND_MANAGEMENT = "outbound_management"  # programmable outbounds
    CHAIN_ROUTING = "chain_routing"            # can host/be target of core chains
    UDP_SUPPORT = "udp_support"                # UDP relay supported
    DEVICE_DETECTION = "device_detection"      # reports device/agent identity
    SPEED_LIMIT = "speed_limit"                # native per-account bandwidth cap
    POLICY_ENFORCEMENT = "policy_enforcement"  # native time/ip/bandwidth policy hooks
    KEY_ROTATION = "key_rotation"              # native credential/key rotation per account


class CoreMetadata(BaseModel):
    """Static, class-level description of a core type (its driver)."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-_]{1,31}$")
    name: str
    description: str = ""
    protocols: list[str]
    capabilities: set[Capability]
    config_schema: dict[str, Any] = Field(default_factory=dict)   # JSON Schema
    default_settings: dict[str, Any] = Field(default_factory=dict)
    driver_version: str = "1.0.0"
    homepage: str | None = None
    #: "owner/repo" when this core's binary is fetched from GitHub releases
    #: (drives the version picker in the install dialog; None = the binary
    #: comes from the OS / elsewhere and the picker honestly hides itself).
    release_repo: str | None = None
    #: shared system features this core OFFERS to others (idea: vpn-ui feats)
    provides: set[str] = Field(default_factory=set)   # e.g. {"strongswan", "pppd"}
    #: shared features this core NEEDS (satisfied by another core's provides,
    #: or by the host OS — reported via CoreManager.dependency_report)
    requires: set[str] = Field(default_factory=set)
    #: JSON Pointer to the inbound list inside this core's studio config
    #: document, if the core supports the visual Inbound Wizard (else None —
    #: the Studio honestly reports the wizard as unsupported for this core).
    studio_inbounds_path: str | None = None
    #: How many inbounds the engine physically serves (None = unlimited).
    #: Single-listener engines (wireguard, openvpn, ssh)
    #: declare 1 — the wizard then REPLACES the listener instead of
    #: appending a second one the engine could never bind (the old flow
    #: appended and died with a bare 500).
    studio_max_inbounds: int | None = None


class CoreMetrics(BaseModel):
    cpu_percent: float = 0.0
    memory_bytes: int = 0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    active_accounts: int = 0
    active_sessions: int = 0


class CoreStatus(BaseModel):
    core_id: str
    state: CoreState
    health: HealthStatus = HealthStatus.UNKNOWN
    enabled: bool = True
    core_version: str | None = None          # version of the underlying binary
    pid: int | None = None
    uptime_seconds: float | None = None
    message: str | None = None
    metrics: CoreMetrics | None = None
    checked_at: datetime = Field(default_factory=_utcnow)


class UserAccount(BaseModel):
    """A user's account **on one core**.

    Panel identity is ``user_id``; the core only ever sees ``account_id``
    (e.g. ``"42.alice"`` as an xray email, or a WireGuard public key).
    ``settings`` carries core-specific secret material (uuid/password/keys)
    which is stored encrypted at rest by the repository layer.
    """

    user_id: int
    username: str
    account_id: str
    protocol: str                            # vless / wireguard / ovpn / hysteria2 / ...
    enabled: bool = True
    expire_at: datetime | None = None
    data_limit_bytes: int | None = None
    settings: dict[str, Any] = Field(default_factory=dict)


class ProvisionResult(BaseModel):
    core_id: str
    account_id: str
    success: bool
    error: str | None = None


class UsageRecord(BaseModel):
    core_id: str
    account_id: str
    node_id: int | None = None
    uplink_bytes: int = 0
    downlink_bytes: int = 0
    recorded_at: datetime = Field(default_factory=_utcnow)


class DeviceSession(BaseModel):
    core_id: str
    account_id: str
    node_id: int | None = None
    ip: str | None = None
    connected_at: datetime | None = None
    last_activity: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChainEndpoint(BaseModel):
    """A listener a core exposes so *other* cores can chain traffic into it.

    OutboundManager resolves ``Outbound(kind=CORE)`` references into concrete
    upstreams using these endpoints (host/port/protocol). Drivers create them
    on demand via ``ensure_chain_listener``.
    """

    core_id: str
    protocol: str                            # socks / http / mixed / vless / ...
    host: str = "127.0.0.1"
    port: int
    network: str = "tcp"
    tls: bool = False
    requires_credentials: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClientConfig(BaseModel):
    """Opaque client connection payload produced by a driver.

    This object travels **only** through the sealed-delivery channel to the
    mobile app. ``repr``/``str`` are redacted and :meth:`public_view` is the
    only serialization helper — it can never leak ``payload``.
    """

    core_id: str
    protocol: str
    engine: str                              # client engine hint: sing-box / wireguard / openvpn / ssh
    payload: dict[str, Any] = Field(repr=False)
    display_name: str = ""

    def __repr__(self) -> str:  # pragma: no cover - safety guard
        return (
            f"ClientConfig(core_id={self.core_id!r}, protocol={self.protocol!r}, "
            f"engine={self.engine!r}, payload=<REDACTED>)"
        )

    __str__ = __repr__

    def public_view(self) -> dict[str, Any]:
        """Everything the client UI is allowed to display. Secrets stripped."""
        return {
            "core": self.core_id,
            "protocol": self.protocol,
            "engine": self.engine,
            "display_name": self.display_name,
        }
