"""Data-driven runtime capability contract shared by API, planners and UI.

A protocol name alone is not enough to decide whether an outbound can back a
routing policy.  The planner needs to know *which dataplane* can host it and
whether the host runtime is present.  This module is deliberately independent
from dashboard code and core-specific renderers: one immutable matrix drives
schema availability, API validation and policy-domain planning.
"""
from __future__ import annotations

import os
import shutil
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel, Field

from app.cores.outbounds.model import Outbound, OutboundKind


class SupportState(str, Enum):
    """Why a feature can or cannot be selected on this deployment."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    ENVIRONMENT_LIMITED = "environment_limited"
    NOT_INSTALLED = "not_installed"
    NOT_APPLICABLE = "not_applicable"


class OutboundDataplane(str, Enum):
    """How traffic actually enters an outbound implementation.

    This is intentionally not inferred from the protocol name.  In particular,
    OpenSSH dynamic forwarding is an application TCP proxy, while WireGuard and
    OpenVPN are packet TUNs even though their outer carriers are UDP/TCP.
    """

    NATIVE_ACTION = "native_action"
    APPLICATION_PROXY = "application_proxy"
    APPLICATION_TCP = "application_tcp"
    POLICY_TUN = "policy_tun"
    KERNEL_TUN = "kernel_tun"
    DYNAMIC_CORE = "dynamic_core"
    NONE = "none"


class RoutingContext(str, Enum):
    POLICY_TUN = "policy_tun"
    NATIVE_APPLICATION_TCP = "native_application_tcp"


_APPLICATION_SOURCE_CORES = frozenset({"xray", "sing-box"})
_SERVICE_SOURCE_CORES = frozenset({"openvpn", "wireguard", "ssh", "softether"})


class OutboundCapability(BaseModel):
    """One outbound protocol's executable/routing contract.

    ``application_proxy`` means at least one native core can render the
    profile for application-level traffic. ``tun`` means the shared Linux
    policy plane can safely turn it into an IP TUN egress. These are separate
    on purpose: an OpenSSH dynamic forward is a valid TCP application proxy
    but cannot back the generic policy TUN.
    """

    kind: OutboundKind
    state: SupportState
    direction: str = "outbound"
    dataplane: OutboundDataplane = OutboundDataplane.NONE
    # Outer/carrier transports (for example WireGuard itself uses UDP).  These
    # are retained as ``transports`` for API compatibility.
    transports: set[str] = Field(default_factory=set)
    # Payload networks that a routing rule may safely send through the
    # dataplane.  This must not be conflated with the outer carrier.
    traffic_networks: set[str] = Field(default_factory=set)
    routing_contexts: set[RoutingContext] = Field(default_factory=set)
    routing_source_cores: set[str] = Field(default_factory=set)
    application_proxy: bool = False
    application_level: bool = False
    tun: bool = False
    kernel_routing: bool = False
    # Per-outbound byte accounting is distinct from the source core's user
    # accounting.  The current policy domains expose health/process evidence,
    # not a persistent per-outbound usage ledger.
    accounting: bool = False
    accounting_reason: str | None = None
    native_core_translation: set[str] = Field(default_factory=set)
    host_runtime: str | None = None
    reason: str | None = None

    @property
    def selectable(self) -> bool:
        """Whether the product has an implementation worth configuring.

        A missing package is not the same as an unsupported protocol: profiles
        may be prepared while a runtime is not installed, but deployment still
        fails honestly until the package/core exists.
        """
        return self.state not in (SupportState.UNSUPPORTED,
                                  SupportState.NOT_APPLICABLE)

    def public(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "selectable": self.selectable,
            "direction": self.direction,
            "dataplane": self.dataplane.value,
            "transports": sorted(self.transports),
            "traffic_networks": sorted(self.traffic_networks),
            "routing_contexts": sorted(context.value for context in self.routing_contexts),
            "routing_source_cores": sorted(self.routing_source_cores),
            "application_proxy": self.application_proxy,
            "application_level": self.application_level,
            "tun": self.tun,
            "kernel_routing": self.kernel_routing,
            "accounting": self.accounting,
            "accounting_reason": self.accounting_reason,
            "native_core_translation": sorted(self.native_core_translation),
            "host_runtime": self.host_runtime,
            "reason": self.reason,
        }


_SOFTETHER_SERVER_ONLY = (
    "This Zagros installation contains SoftEther VPN Server and vpncmd server "
    "management only. vpncmd /CLIENT manages a separately running VPN Client "
    "service; vpncmd is not a client dataplane and no vpnclient service or "
    "validated Zagros client adapter is installed."
)

_SOFTETHER_REASONS = {
    OutboundKind.SOFTETHER_L2TP: (
        _SOFTETHER_SERVER_ONLY + " SoftEther VPN Client is not a generic "
        "L2TP/IPsec client; a separately managed L2TP/IPsec client adapter "
        "would be required."
    ),
    OutboundKind.SOFTETHER_L2TP_RAW: (
        _SOFTETHER_SERVER_ONLY + " Raw L2TP has no supported Linux client "
        "adapter in Zagros."
    ),
    OutboundKind.SOFTETHER_SSTP: (
        _SOFTETHER_SERVER_ONLY + " A separately managed SSTP client runtime "
        "and transactional routing adapter would be required."
    ),
    OutboundKind.SOFTETHER_PPTP: (
        "Unsupported by the SoftEther stable server/client contract used by "
        "Zagros: there is no PPTP listener/client adapter, and PptpGet / "
        "PptpEnable are not vpncmd server commands. The live SoftEther "
        "transport matrix records binary version and command-inventory evidence; "
        "no PPTP UI/client is fabricated."
    ),
    OutboundKind.SOFTETHER_NATIVE: (
        _SOFTETHER_SERVER_ONLY + " Native SoftEther egress requires the "
        "separate vpnclient service plus a production routing/lifecycle adapter."
    ),
}


def _base_capability(kind: OutboundKind) -> OutboundCapability:
    if kind in (OutboundKind.DIRECT, OutboundKind.BLOCK, OutboundKind.BLACKHOLE,
                OutboundKind.DNS):
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.NATIVE_ACTION,
            traffic_networks={"tcp", "udp"},
            routing_contexts={RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES),
            application_proxy=True, application_level=True,
            native_core_translation={"xray", "sing-box"},
            reason="native core action; no client runtime is required",
        )
    if kind in (OutboundKind.OPENVPN, OutboundKind.WIREGUARD):
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=(OutboundDataplane.KERNEL_TUN
                       if kind is OutboundKind.WIREGUARD
                       else OutboundDataplane.POLICY_TUN),
            transports={"tcp", "udp"} if kind is OutboundKind.OPENVPN else {"udp"},
            traffic_networks={"tcp", "udp"},
            routing_contexts={RoutingContext.POLICY_TUN,
                              RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES | _SERVICE_SOURCE_CORES),
            application_proxy=True, tun=True, kernel_routing=True,
            native_core_translation={"xray", "sing-box"},
            host_runtime="openvpn" if kind is OutboundKind.OPENVPN else "wg+ip",
        )
    if kind is OutboundKind.SSH:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.APPLICATION_TCP,
            transports={"tcp"}, traffic_networks={"tcp"},
            routing_contexts={RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES),
            application_proxy=True, application_level=True,
            tun=False, kernel_routing=False,
            accounting=False,
            accounting_reason=(
                "One shared dynamic-forward transport cannot attribute its "
                "multiplexed bytes to source users. Per-user quota/accounting "
                "remains owned by the Xray or sing-box source; SSH inbound "
                "accounts use their separate persistent host collector."
            ),
            native_core_translation={"xray", "sing-box"},
            host_runtime="OpenSSH dynamic forwarding",
            reason=(
                "A managed OpenSSH SOCKS process provides real TCP application "
                "egress to Xray/sing-box. SSH has no UDP or generic TUN dataplane."
            ),
        )
    if kind in {
        OutboundKind.SOCKS, OutboundKind.HTTP, OutboundKind.VLESS,
        OutboundKind.VMESS, OutboundKind.TROJAN, OutboundKind.SHADOWSOCKS,
        OutboundKind.HYSTERIA2, OutboundKind.TUIC,
    }:
        transports = {"tcp", "udp"}
        traffic_networks = {"tcp", "udp"}
        if kind is OutboundKind.HTTP:
            transports = traffic_networks = {"tcp"}
        elif kind is OutboundKind.TROJAN:
            transports = {"tcp"}  # TCP/TLS outer carrier; protocol relays UDP
        elif kind in (OutboundKind.HYSTERIA2, OutboundKind.TUIC):
            transports = {"udp"}  # QUIC outer carrier; tunnel relays TCP+UDP
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.POLICY_TUN,
            transports=transports, traffic_networks=traffic_networks,
            routing_contexts={RoutingContext.POLICY_TUN,
                              RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES | _SERVICE_SOURCE_CORES),
            application_proxy=True, tun=True, kernel_routing=True,
            native_core_translation={"xray", "sing-box"},
            host_runtime="sing-box",
        )
    if kind in _SOFTETHER_REASONS:
        return OutboundCapability(
            kind=kind, state=SupportState.UNSUPPORTED,
            dataplane=OutboundDataplane.NONE,
            host_runtime="separate client provider required",
            reason=_SOFTETHER_REASONS[kind],
        )
    if kind is OutboundKind.CORE:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.DYNAMIC_CORE,
            traffic_networks={"tcp", "udp"},
            application_proxy=True, application_level=True,
            reason="resolved dynamically from the target core's chain endpoint",
        )
    return OutboundCapability(
        kind=kind, state=SupportState.NOT_APPLICABLE,
        reason="no outbound capability contract is registered",
    )


def _runtime_binary(runtime: Any | None, core_id: str, fallback: str) -> str | None:
    if runtime is not None:
        try:
            driver = runtime.core_manager.get(core_id)
            backend = getattr(driver, "_backend", None)
            for value in (
                getattr(backend, "executable", None),
                driver.settings.get("executable_path"),
            ):
                if value and (os.path.isfile(str(value)) or shutil.which(str(value))):
                    return str(value)
        except Exception:  # the static contract remains available without a core
            pass
    return shutil.which(fallback)


def outbound_product_capability(kind: OutboundKind | str) -> OutboundCapability:
    """Return implementation support without inspecting the current host."""
    return _base_capability(OutboundKind(kind))


def outbound_capability(kind: OutboundKind | str, runtime: Any | None = None) -> OutboundCapability:
    """Return static product support refined by this host's runtime inventory."""

    kind = OutboundKind(kind)
    cap = outbound_product_capability(kind)
    if cap.state is not SupportState.SUPPORTED:
        return cap

    missing: str | None = None
    if kind is OutboundKind.OPENVPN and not shutil.which("openvpn"):
        missing = "openvpn client binary is not installed"
    elif kind is OutboundKind.WIREGUARD and (
        not shutil.which("wg") or not shutil.which("ip")
    ):
        missing = "wireguard-tools and iproute2 are required"
    elif cap.tun and kind not in (OutboundKind.OPENVPN, OutboundKind.WIREGUARD) \
            and _runtime_binary(runtime, "sing-box", "sing-box") is None:
        missing = "sing-box is not installed; it is the host TUN adapter for this profile"
    elif kind is OutboundKind.SSH and not shutil.which("ssh"):
        missing = "the OpenSSH client is not installed"

    if missing:
        return cap.model_copy(update={
            "state": SupportState.NOT_INSTALLED,
            "reason": missing,
        })
    return cap


def outbound_capabilities(runtime: Any | None = None) -> dict[OutboundKind, OutboundCapability]:
    return {kind: outbound_capability(kind, runtime) for kind in OutboundKind}


def normalize_rule_networks(values: Iterable[str]) -> set[str]:
    """Normalize matcher values such as ``["tcp,udp"]`` without guessing.

    An empty matcher means both packet families may reach the target.  That is
    important for TCP-only application proxies: ``any`` must not accidentally
    be treated as TCP-only merely because the first generated connection was
    TCP.
    """

    raw = {item.strip().lower() for value in values
           for item in str(value).split(",") if item.strip()}
    return raw or {"tcp", "udp"}


def routing_compatibility(
    capability: OutboundCapability,
    *,
    source_cores: Iterable[str],
    networks: Iterable[str],
) -> tuple[SupportState, str | None]:
    """Pure source → target compatibility verdict used by API and planner."""

    cores = {str(core).strip().lower() for core in source_cores if str(core).strip()}
    payload = normalize_rule_networks(networks)
    if capability.state is not SupportState.SUPPORTED:
        return capability.state, capability.reason
    unsupported_networks = payload - capability.traffic_networks
    if unsupported_networks:
        return SupportState.NOT_APPLICABLE, (
            f"{capability.kind.value} carries routing payloads only for "
            f"{sorted(capability.traffic_networks)}; the rule may match "
            f"{sorted(unsupported_networks)}"
        )
    if not cores:
        return SupportState.ENVIRONMENT_LIMITED, (
            "select a source inbound so its core/dataplane can be evaluated"
        )
    unsupported_cores = cores - capability.routing_source_cores
    if unsupported_cores:
        return SupportState.NOT_APPLICABLE, (
            f"{capability.kind.value} ({capability.dataplane.value}) cannot be "
            f"a routing target for source core(s) {sorted(unsupported_cores)}"
        )
    return SupportState.SUPPORTED, None


def validate_selectable(outbounds: Iterable[Outbound], runtime: Any | None = None) -> None:
    """Reject only enabled profiles whose capability state is not selectable."""

    errors: list[str] = []
    for outbound in outbounds:
        if not outbound.enabled:
            continue
        cap = outbound_capability(outbound.kind, runtime)
        if not cap.selectable:
            errors.append(
                f"{outbound.name} ({outbound.kind.value}): "
                f"{cap.state.value}: {cap.reason or 'unavailable'}"
            )
    if errors:
        raise ValueError("unavailable outbound profile(s): " + "; ".join(errors))
