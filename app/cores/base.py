"""The contract every VPN-core plugin implements.

A driver adapts one core technology (xray, sing-box, wireguard, openvpn, ...)
to the panel. It owns process lifecycle, user provisioning, statistics and
client-config generation **for that core only** — orchestration across cores
is the job of :class:`app.cores.manager.CoreManager`.

Authoring a new core = subclass + set ``metadata`` + implement the abstract
methods. Concrete subclasses auto-register in the global registry.
"""
from __future__ import annotations

import abc
import inspect
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, ClassVar

from app.cores.exceptions import CapabilityNotSupportedError
from app.cores.types import (
    Capability,
    ChainEndpoint,
    CoreMetadata,
    CoreStatus,
    CoreVersionInfo,
    DeviceSession,
    ListenerClaim,
    UsageRecord,
    UserAccount,
    ClientConfig,
)

if TYPE_CHECKING:
    from app.cores.delivery import DeliveryContext, DeliveryProfile
    from app.cores.outbounds.model import Outbound, TranslatedOutbound
    from app.cores.policy.model import PolicyProfile
    from app.cores.routing.model import RouteContext, RoutingRule, TranslatedRoute


class BaseCoreDriver(abc.ABC):
    """Interface Segregation via capabilities: implement what your core can do.

    Non-implemented optional operations raise :class:`CapabilityNotSupportedError`
    (and are hidden in the UI thanks to :attr:`metadata.capabilities`).
    """

    #: Static identity/capabilities of this core type. Defined per subclass.
    metadata: ClassVar[CoreMetadata]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register every concrete driver class into the global registry."""
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        from app.cores.registry import register_driver

        register_driver(cls)

    def __init__(self, settings: dict[str, Any] | None = None):
        merged = dict(self.metadata.default_settings)
        merged.update(settings or {})
        self.settings: dict[str, Any] = merged

    # ------------------------------------------------------------------ #
    # capabilities
    # ------------------------------------------------------------------ #
    def supports(self, capability: Capability) -> bool:
        return capability in self.metadata.capabilities

    def _require(self, capability: Capability) -> None:
        if not self.supports(capability):
            raise CapabilityNotSupportedError(self.metadata.id, capability.value)

    # ------------------------------------------------------------------ #
    # lifecycle — abstract
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    async def start(self) -> None:
        """Start the core process/service."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop the core process/service (idempotent)."""

    @abc.abstractmethod
    async def status(self) -> CoreStatus:
        """Current state, health, binary version and live metrics."""

    async def version(self) -> CoreVersionInfo:
        """Probe the installed engine independently of its running state.

        Backends expose a synchronous ``version()`` command adapter.  Drivers
        no longer decide ad-hoc that a stopped process has no version: an
        installed binary is still versionable, and an unknown result carries a
        reason instead of becoming a silent blank in Overview.
        """
        import asyncio

        probe = getattr(getattr(self, "_backend", None), "version", None)
        if not callable(probe):
            return CoreVersionInfo(
                reason=f"{self.metadata.name} adapter has no version probe")
        try:
            value = await asyncio.to_thread(probe)
        except Exception as exc:  # version failure must not break status
            return CoreVersionInfo(
                reason=f"version probe failed: {type(exc).__name__}: {exc}")
        value = str(value or "").strip()
        if not value:
            return CoreVersionInfo(
                reason="runtime binary is not installed or returned no parseable version")
        return CoreVersionInfo(version=value)

    async def restart(self) -> None:
        """Default restart strategy; override for graceful/hot reload."""
        await self.stop()
        await self.start()

    async def health_check(self) -> CoreStatus:
        """External probes may override this for deeper checks."""
        return await self.status()

    # ------------------------------------------------------------------ #
    # install / update / uninstall — optional (SELF_INSTALL)
    # ------------------------------------------------------------------ #
    async def install(self) -> None:
        """Fetch/prepare binaries & initial config. Optional."""
        self._require(Capability.SELF_INSTALL)

    async def update(self, version: str | None = None) -> str:
        """Update the underlying binary; returns the new version."""
        self._require(Capability.SELF_INSTALL)
        raise NotImplementedError  # pragma: no cover

    async def uninstall(self, purge: bool = False) -> None:
        """Remove binaries; ``purge=True`` also removes config/data."""
        self._require(Capability.SELF_INSTALL)

    async def get_logs(self, tail: int = 200) -> AsyncIterator[str]:
        """Stream/read recent log lines."""
        self._require(Capability.SERVICE_CONTROL)
        raise NotImplementedError  # pragma: no cover
        yield  # pragma: no cover - keeps this an async generator

    # ---- usage-tracker restart safety (recorder job persists baselines) ----
    def usage_tracker_snapshot(self, account_ids: list[str] | None = None) -> dict:
        """Baselines of the driver-internal usage tracker, for the recorder
        job to persist. Empty dict when the driver has no tracker."""
        tracker = getattr(self, "_usage", None)
        if hasattr(tracker, "baseline_snapshot"):
            try:
                return dict(tracker.baseline_snapshot(account_ids))
            except Exception:  # noqa: BLE001 — persistence must never break reads
                return {}
        return {}

    def restore_usage_baselines(self, baselines: dict) -> None:
        """Boot-time restore of persisted cumulative baselines — prevents
        the "panel restart re-emits the whole counter" double-count."""
        tracker = getattr(self, "_usage", None)
        if hasattr(tracker, "restore") and baselines:
            try:
                tracker.restore(baselines)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ #
    # kernel bandwidth identity (management-plane only)
    # ------------------------------------------------------------------ #
    def bandwidth_identities(self) -> dict[str, dict[str, list]]:
        """Stable account identities consumable by the shared kernel limiter.

        Drivers return inner IPs and/or Unix UIDs. Empty means the provider
        propagates identity by socket mark or an external authenticated-event
        adapter (Xray/sing-box/SoftEther).
        """
        return {}

    # ------------------------------------------------------------------ #
    # user management — abstract core of the contract
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    async def create_account(self, account: UserAccount) -> None:
        """Provision a user onto this core (idempotent recommended).

        Contract: a driver MAY generate missing credentials (uuid, password,
        keypairs) and write them back into ``account.settings`` **in place**.
        The service layer must persist the account afterwards, so generated
        secrets survive restarts (stored encrypted at rest — doc §6).
        """

    @abc.abstractmethod
    async def update_account(self, account: UserAccount) -> None:
        """Apply changes (limits, expiry, settings) to an existing account."""

    @abc.abstractmethod
    async def delete_account(self, account_id: str) -> None:
        """Remove a user from this core (missing user must not raise)."""

    async def suspend_account(self, account_id: str) -> None:
        """Default suspend = list+disable; override with a cheap native switch."""
        self._require(Capability.SUSPEND_RESUME)
        raise NotImplementedError  # pragma: no cover

    async def resume_account(self, account: UserAccount) -> None:
        self._require(Capability.SUSPEND_RESUME)
        await self.update_account(account)

    async def rotate_credentials(self, account: UserAccount) -> UserAccount:
        """Rotate an account's secret material (uuid / password / keypair).

        Requires KEY_ROTATION. The returned account carries the NEW
        credentials; the old ones stop working immediately. The service layer
        persists the result and (optionally) re-delivers the sealed config.
        """
        self._require(Capability.KEY_ROTATION)
        raise NotImplementedError  # pragma: no cover

    async def sync_accounts(self, accounts: list[UserAccount]) -> None:
        """Reconcile desired state (naive default: create/update each).

        Called after a core was down during user changes, so panels converge
        to the DB state instead of drifting apart.
        """
        self._require(Capability.USER_MANAGEMENT)
        for account in accounts:
            await self.create_account(account)

    # ------------------------------------------------------------------ #
    # statistics — capability gated
    # ------------------------------------------------------------------ #
    async def get_usage(
        self,
        account_ids: list[str] | None = None,
        since: Any | None = None,
    ) -> list[UsageRecord]:
        self._require(Capability.USAGE_ACCOUNTING)
        raise NotImplementedError  # pragma: no cover

    async def get_online_devices(
        self, account_ids: list[str] | None = None
    ) -> list[DeviceSession]:
        self._require(Capability.ONLINE_TRACKING)
        raise NotImplementedError  # pragma: no cover

    # ------------------------------------------------------------------ #
    # client config — abstract (sealed delivery only)
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    async def build_client_config(
        self, account: UserAccount, node: Any | None = None
    ) -> ClientConfig:
        """Build the *secret* connection payload for the mobile app.

        The result must only leave the server through the sealed channel
        (see docs §7.3) — never through plain serialization.
        """

    # ------------------------------------------------------------------ #
    # delivery description — powers the Subscription Portal dynamically
    # ------------------------------------------------------------------ #
    async def describe_delivery(
        self,
        account: UserAccount,
        context: "DeliveryContext | None" = None,
    ) -> "DeliveryProfile":
        """Describe the user-facing connection material for an account.

        The Subscription Portal renders ONLY these descriptors — presentation
        code never hardcodes driver ids. Default implementation derives an
        honest profile from :meth:`build_client_config`'s payload shape.
        Override to produce richer, protocol-specific artifacts (multiple
        share links per inbound/host, credential tables, QR payloads).

        Drivers may raise :class:`CoreError` when the account's connection
        material does not exist at all (e.g. missing inbound); they must
        never fabricate artifacts.
        """
        from app.cores.delivery import profile_from_client_config

        config = await self.build_client_config(account)
        return profile_from_client_config(config, account=account)

    # ------------------------------------------------------------------ #
    # routing translation — capability gated (ROUTING)
    # ------------------------------------------------------------------ #
    async def deploy_routing_rules(
        self, rules: list["RoutingRule"], ctx: "RouteContext"
    ) -> "TranslatedRoute":
        """Translate the central rule set to native form and apply it.

        Contract: **no silent drops** — every rule must appear in either
        ``applied`` or ``unsupported`` (with reason) of the returned report.
        """
        self._require(Capability.ROUTING)
        raise NotImplementedError  # pragma: no cover

    async def translate_routing_rules(
        self, rules: list["RoutingRule"], ctx: "RouteContext"
    ) -> "TranslatedRoute":
        """DRY preview of :meth:`deploy_routing_rules` — same report shape,
        zero core mutations. The default honestly marks preview as
        unavailable; drivers with a pure translator override it."""
        self._require(Capability.ROUTING)
        from app.cores.routing.model import TranslatedRoute

        return TranslatedRoute(
            core_id=self.metadata.id,
            notes=["dry preview is not implemented for this driver "
                   "(deploy produces the authoritative apply report)"])

    # ------------------------------------------------------------------ #
    # outbound translation — capability gated (OUTBOUND_MANAGEMENT)
    # ------------------------------------------------------------------ #
    async def deploy_outbounds(
        self, outbounds: list["Outbound"]
    ) -> "TranslatedOutbound":
        """Translate central outbound definitions into native outbounds."""
        self._require(Capability.OUTBOUND_MANAGEMENT)
        raise NotImplementedError  # pragma: no cover

    # ------------------------------------------------------------------ #
    # policy enforcement — capability gated (POLICY_ENFORCEMENT)
    # ------------------------------------------------------------------ #
    async def apply_policy(self, account: UserAccount, profile: "PolicyProfile") -> list[str]:
        """Apply natively-enforceable constraints; return constraint names applied."""
        self._require(Capability.POLICY_ENFORCEMENT)
        raise NotImplementedError  # pragma: no cover

    # ------------------------------------------------------------------ #
    # session teardown & chain ingress
    # ------------------------------------------------------------------ #
    async def kick_account(self, account: UserAccount) -> None:
        """Drop live sessions without deleting the account (device enforcement).

        Default works on any core with user management: remove + re-add.
        """
        self._require(Capability.USER_MANAGEMENT)
        await self.delete_account(account.account_id)
        await self.create_account(account)

    async def listener_claims(self) -> list[ListenerClaim]:
        """Host-network listeners owned by this adapter (empty = not exposed).

        This is an ownership/introspection contract, not a request to open a
        socket.  Panel/subscription apply preflight combines these claims with
        the kernel's live listener table to produce an exact conflict reason.
        """
        return []

    async def get_chain_endpoints(self) -> list[ChainEndpoint]:
        """Loopback listeners other cores may chain into (empty = none)."""
        return []

    async def ensure_chain_listener(self, protocol: str, port: int) -> ChainEndpoint:
        """Create (or return) a chain-ingress listener. Requires CHAIN_ROUTING."""
        self._require(Capability.CHAIN_ROUTING)
        raise NotImplementedError  # pragma: no cover
