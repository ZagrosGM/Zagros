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
    transports: set[str] = Field(default_factory=set)
    application_proxy: bool = False
    tun: bool = False
    kernel_routing: bool = False
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
            "transports": sorted(self.transports),
            "application_proxy": self.application_proxy,
            "tun": self.tun,
            "kernel_routing": self.kernel_routing,
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
        "Unsupported: the installed SoftEther 4.x server runtime exposes no "
        "PPTP command or listener capability (PptpGet is not a vpncmd command). "
        "No PPTP UI/client is fabricated."
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
            application_proxy=True,
            native_core_translation={"xray", "sing-box"},
            reason="native core action; no client runtime is required",
        )
    if kind in (OutboundKind.OPENVPN, OutboundKind.WIREGUARD):
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            transports={"tcp", "udp"} if kind is OutboundKind.OPENVPN else {"udp"},
            application_proxy=True, tun=True, kernel_routing=True,
            native_core_translation={"xray", "sing-box"},
            host_runtime="openvpn" if kind is OutboundKind.OPENVPN else "wg+ip",
        )
    if kind is OutboundKind.SSH:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED, transports={"tcp"},
            application_proxy=True, tun=False, kernel_routing=False,
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
        if kind in (OutboundKind.HTTP, OutboundKind.TROJAN):
            transports = {"tcp"}
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED, transports=transports,
            application_proxy=True, tun=True, kernel_routing=True,
            native_core_translation={"xray", "sing-box"},
            host_runtime="sing-box",
        )
    if kind in _SOFTETHER_REASONS:
        return OutboundCapability(
            kind=kind, state=SupportState.UNSUPPORTED,
            host_runtime="separate client provider required",
            reason=_SOFTETHER_REASONS[kind],
        )
    if kind is OutboundKind.CORE:
        return OutboundCapability(
            kind=kind, state=SupportState.SUPPORTED,
            application_proxy=True,
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


def outbound_capability(kind: OutboundKind | str, runtime: Any | None = None) -> OutboundCapability:
    """Return static product support refined by this host's runtime inventory."""

    kind = OutboundKind(kind)
    cap = _base_capability(kind)
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
