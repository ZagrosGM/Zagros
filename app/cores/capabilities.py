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
_SERVICE_SOURCE_CORES = frozenset({
    "openvpn", "wireguard", "ssh", "softether", "pptp",
})


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
    provider: str | None = None
    protocol: str | None = None
    authentication: list[str] = Field(default_factory=list)
    ip_versions: set[str] = Field(default_factory=set)
    security_class: str = "standard"
    peer_compatibility: set[str] = Field(default_factory=set)
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
            "provider": self.provider,
            "protocol": self.protocol or self.kind.value,
            "authentication": list(self.authentication),
            "ip_versions": sorted(self.ip_versions),
            "security_class": self.security_class,
            "peer_compatibility": sorted(self.peer_compatibility),
            "reason": self.reason,
        }


_SOFTETHER_NATIVE_ONLY = (
    "SoftEther vpnclient implements the native SoftEther protocol. It is not a "
    "generic client for the server's L2TP/IPsec, raw L2TP, SSTP or OpenVPN "
    "compatibility listeners; those transports require their own client engine."
)

_SOFTETHER_REASONS = {
    OutboundKind.SOFTETHER_L2TP: (
        _SOFTETHER_NATIVE_ONLY + " A separately managed strongSwan/XFRM plus "
        "xl2tpd/PPP lifecycle would be a different outbound provider and is not "
        "implemented by this native-client adapter."
    ),
    OutboundKind.SOFTETHER_L2TP_RAW: (
        _SOFTETHER_NATIVE_ONLY + " Stable Linux vpnclient exposes no raw-L2TP "
        "account/virtual-NIC mode."
    ),
    OutboundKind.SOFTETHER_SSTP: (
        _SOFTETHER_NATIVE_ONLY + " A separately managed SSTP/PPP client and "
        "transactional routing adapter would be required."
    ),
    OutboundKind.SOFTETHER_PPTP: (
        "Unsupported by the SoftEther stable server/client contract used by "
        "Zagros: there is no PPTP server listener and native vpnclient does not "
        "turn PPTP into a Virtual NIC account. No PPTP UI/client is fabricated."
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
            provider="native core action",
            protocol=kind.value,
            authentication=[],
            ip_versions={"ipv4", "ipv6"},
            security_class="not_applicable",
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
            provider="OpenVPN client" if kind is OutboundKind.OPENVPN else "Linux WireGuard",
            protocol="OpenVPN" if kind is OutboundKind.OPENVPN else "WireGuard",
            authentication=(
                ["TLS certificate", "optional username/password"]
                if kind is OutboundKind.OPENVPN else
                ["NoiseIK public/private key", "optional preshared key"]
            ),
            ip_versions={"ipv4"},
            security_class="standard",
        )
    if kind is OutboundKind.SSH:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.POLICY_TUN,
            transports={"tcp"}, traffic_networks={"tcp"},
            routing_contexts={RoutingContext.POLICY_TUN,
                              RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES | _SERVICE_SOURCE_CORES),
            application_proxy=True, application_level=True,
            tun=True, kernel_routing=True,
            accounting=False,
            accounting_reason=(
                "The scoped TUN feeds one shared dynamic-forward transport and "
                "therefore cannot attribute target bytes to source users. "
                "Authoritative quota/accounting remains owned by each source "
                "core; target interface counters are diagnostics only."
            ),
            native_core_translation={"xray", "sing-box"},
            host_runtime="OpenSSH dynamic forwarding + scoped sing-box TUN adapter",
            provider="OpenSSH client with policy TUN bridge",
            protocol="SSH dynamic forwarding",
            authentication=["server host key", "password or private key"],
            ip_versions={"ipv4"},
            security_class="standard",
            reason=(
                "A per-outbound TUN/redirect adapter carries only selected TCP "
                "flows into the authenticated OpenSSH SOCKS process. UDP and "
                "global transparent interception remain unsupported."
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
        authentication = {
            OutboundKind.SOCKS: ["optional username/password"],
            OutboundKind.HTTP: ["optional username/password"],
            OutboundKind.VLESS: ["UUID", "optional TLS/REALITY server identity"],
            OutboundKind.VMESS: ["UUID"],
            OutboundKind.TROJAN: ["password", "TLS server certificate"],
            OutboundKind.SHADOWSOCKS: ["pre-shared password"],
            OutboundKind.HYSTERIA2: ["password", "TLS server certificate"],
            OutboundKind.TUIC: ["UUID/password", "TLS server certificate"],
        }[kind]
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
            provider="Xray or sing-box selected policy runtime",
            protocol=kind.value,
            authentication=authentication,
            ip_versions={"ipv4"},
            security_class=("compatibility" if kind is OutboundKind.VMESS else "standard"),
        )
    if kind in {
        OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
        OutboundKind.SSTP, OutboundKind.PPTP,
    }:
        contracts = {
            OutboundKind.L2TP_IPSEC: {
                "provider": "strongSwan+xl2tpd+pppd",
                "protocol": "L2TP/IPsec",
                "authentication": ["IKEv1 pre-shared key", "PPP MS-CHAPv2"],
                "security_class": "compatibility",
                "host_runtime": "charon+swanctl+xl2tpd+pppd+network-namespace",
                "peer_compatibility": {"softether"},
                "reason": (
                    "An isolated strongSwan IKE/XFRM transport plus xl2tpd/PPP "
                    "session provides real L2TP/IPsec egress."
                ),
            },
            OutboundKind.L2TP_RAW: {
                "provider": "xl2tpd+pppd",
                "protocol": "raw L2TP",
                "authentication": ["PPP MS-CHAPv2"],
                "security_class": "legacy_insecure",
                "host_runtime": "xl2tpd+pppd+network-namespace",
                "peer_compatibility": {"softether"},
                "reason": (
                    "Raw L2TP has no IPsec/TLS confidentiality and is exposed "
                    "only behind an explicit Legacy/Insecure acknowledgement."
                ),
            },
            OutboundKind.SSTP: {
                "provider": "sstp-client+pppd",
                "protocol": "SSTP",
                "authentication": ["TLS server certificate", "PPP MS-CHAPv2"],
                "security_class": "compatibility",
                "host_runtime": "sstpc+pppd+network-namespace",
                "peer_compatibility": {"softether"},
                "reason": (
                    "A real SSTP/PPP client is used with mandatory CA and "
                    "hostname certificate verification."
                ),
            },
            OutboundKind.PPTP: {
                "provider": "pptp-linux+pppd",
                "protocol": "PPTP",
                "authentication": ["PPP MS-CHAPv2"],
                "security_class": "legacy_insecure",
                "host_runtime": "pptp-linux+pppd+network-namespace",
                "peer_compatibility": {"accel-ppp", "reference-pptp"},
                "reason": (
                    "Independent legacy PPTP client using fixed TCP/1723, "
                    "GRE/47 and mandatory MPPE128; never a SoftEther mode."
                ),
            },
        }
        contract = contracts[kind]
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.POLICY_TUN,
            transports=({"udp"} if kind in {
                OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
            } else {"tcp", "gre"} if kind is OutboundKind.PPTP else {"tcp"}),
            traffic_networks={"tcp", "udp"},
            routing_contexts={RoutingContext.POLICY_TUN,
                              RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES | _SERVICE_SOURCE_CORES),
            application_proxy=True, tun=True, kernel_routing=True,
            accounting=True,
            accounting_reason=(
                "Persistent per-outbound deltas are folded from the owned PPP "
                "interface generation; source-user quota remains source-core owned."
            ),
            native_core_translation={"xray", "sing-box"},
            ip_versions={"ipv4"},
            **contract,
        )
    if kind is OutboundKind.SOFTETHER_NATIVE:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.POLICY_TUN,
            transports={"tcp", "udp"},
            traffic_networks={"tcp", "udp"},
            routing_contexts={RoutingContext.POLICY_TUN,
                              RoutingContext.NATIVE_APPLICATION_TCP},
            routing_source_cores=set(_APPLICATION_SOURCE_CORES | _SERVICE_SOURCE_CORES),
            application_proxy=True,
            tun=True,
            kernel_routing=True,
            accounting=True,
            accounting_reason=(
                "vpncmd AccountStatusGet exposes exact native-session incoming "
                "and outgoing byte totals for this dedicated client account."
            ),
            native_core_translation={"xray", "sing-box"},
            host_runtime="vpnclient+vpncmd+network-namespace+Virtual-NIC",
            provider="SoftEther vpnclient",
            protocol="SoftEther native",
            authentication=["username/password", "optional pinned server certificate"],
            ip_versions={"ipv4"},
            security_class="compatibility",
            peer_compatibility={"softether"},
            reason=(
                "A dedicated vpnclient instance, Virtual NIC, DHCP lease and "
                "isolated namespace/table provide a real native SoftEther egress."
            ),
        )
    if kind in _SOFTETHER_REASONS:
        return OutboundCapability(
            kind=kind, state=SupportState.UNSUPPORTED,
            dataplane=OutboundDataplane.NONE,
            host_runtime="separate client provider required",
            provider="none (deprecated SoftEther-labelled alias)",
            protocol=kind.value,
            security_class="unsupported",
            reason=_SOFTETHER_REASONS[kind],
        )
    if kind is OutboundKind.CORE:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            dataplane=OutboundDataplane.DYNAMIC_CORE,
            traffic_networks={"tcp", "udp"},
            application_proxy=True, application_level=True,
            provider="dynamic target core chain endpoint",
            protocol="dynamic",
            ip_versions={"ipv4", "ipv6"},
            security_class="target_dependent",
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
    elif kind in {
        OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
        OutboundKind.SSTP, OutboundKind.PPTP,
    }:
        requirements = {
            OutboundKind.L2TP_IPSEC: ("pppd", "xl2tpd", "swanctl"),
            OutboundKind.L2TP_RAW: ("pppd", "xl2tpd"),
            OutboundKind.SSTP: ("pppd", "sstpc"),
            OutboundKind.PPTP: ("pppd", "pptp"),
        }[kind]
        absent = [binary for binary in requirements if shutil.which(binary) is None]
        if kind is OutboundKind.L2TP_IPSEC and not any(
            os.path.isfile(path) for path in (
                "/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon",
            )
        ):
            absent.append("charon")
        if absent:
            missing = (
                f"{kind.value} client runtime is not installed: "
                + ", ".join(sorted(set(absent)))
            )
        elif not os.path.exists("/dev/ppp"):
            missing = "/dev/ppp is required by PPP outbound providers"
    elif kind is OutboundKind.SOFTETHER_NATIVE:
        client = None
        vpncmd = None
        if runtime is not None:
            try:
                backend = getattr(runtime.core_manager.get("softether"), "_backend", None)
                client = getattr(backend, "client_binary", lambda: None)()
                vpncmd = getattr(backend, "vpncmd_binary", lambda: None)()
            except Exception:
                pass
        else:
            client = shutil.which("vpnclient")
            vpncmd = shutil.which("vpncmd")
        tools = [name for name in ("ip", "iptables", "busybox")
                 if not shutil.which(name)]
        if not client or not vpncmd:
            missing = (
                "SoftEther core runtime must include both vpnclient and vpncmd; "
                "Install/Reinstall the SoftEther core"
            )
        elif tools:
            missing = "SoftEther client namespace requires " + ", ".join(tools)
    elif cap.tun and kind not in (
        OutboundKind.OPENVPN, OutboundKind.WIREGUARD,
        OutboundKind.SOFTETHER_NATIVE,
    ) and _runtime_binary(runtime, "sing-box", "sing-box") is None:
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
