"""Runtime-evidenced SoftEther server/client transport capabilities.

SoftEther's server, bridge, client and command utility are separate programs.
Seeing ``vpncmd`` or a running ``vpnserver`` therefore proves neither a client
packet dataplane nor support for every legacy protocol.  This module keeps the
three relevant facts separate for every transport:

* upstream/runtime command support;
* Zagros server-side implementation support;
* Zagros outbound client/dataplane support.

The probe is read-only: ``Help`` and version/path inventory only.  It never
tries an Enable command merely to discover whether that command exists.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from app.cores.capabilities import SupportState, outbound_capability
from app.cores.outbounds.model import OutboundKind


class SoftEtherDirectionCapability(BaseModel):
    state: SupportState
    direction: str
    dataplane: str
    tcp: bool = False
    udp: bool = False
    tun: bool = False
    application_level: bool = False
    accounting: bool = False
    provider: str | None = None
    canonical_outbound_kind: str | None = None
    runtime_version: str | None = None
    required_commands: list[str] = Field(default_factory=list)
    observed_commands: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    reason: str | None = None


_REQUIRED_SERVER_COMMANDS: dict[str, tuple[str, ...]] = {
    "native": ("ServerInfoGet", "ListenerList"),
    "l2tp_ipsec": ("IPsecGet", "IPsecEnable"),
    "l2tp_raw": ("IPsecGet", "IPsecEnable"),
    "sstp": ("SstpGet", "SstpEnable"),
    "openvpn": ("OpenVpnGet", "OpenVpnEnable"),
    "pptp": ("PptpGet", "PptpEnable"),
}

_SERVER_NETWORKS: dict[str, tuple[bool, bool]] = {
    "native": (True, True),
    "l2tp_ipsec": (True, True),
    "l2tp_raw": (True, True),
    "sstp": (True, False),
    "openvpn": (True, True),
    "pptp": (True, False),
}

_OUTBOUND_KINDS: dict[str, OutboundKind | None] = {
    "native": OutboundKind.SOFTETHER_NATIVE,
    "l2tp_ipsec": OutboundKind.SOFTETHER_L2TP,
    "l2tp_raw": OutboundKind.SOFTETHER_L2TP_RAW,
    "sstp": OutboundKind.SOFTETHER_SSTP,
    "openvpn": OutboundKind.OPENVPN,
    "pptp": OutboundKind.SOFTETHER_PPTP,
}

_WIZARD_PROTOCOLS = {
    "softether": "native",
    "l2tp": "l2tp_ipsec",
    "l2tp_raw": "l2tp_raw",
    "sstp": "sstp",
    "ovpn": "openvpn",
    "pptp": "pptp",
}


def parse_server_command_inventory(text: str) -> set[str]:
    """Parse ``vpncmd Help`` command rows, not localized descriptions."""

    commands: set[str] = set()
    for line in (text or "").splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9]+)\s+-\s+", line)
        if match:
            commands.add(match.group(1))
    return commands


def _backend(runtime: Any | None):
    if runtime is None:
        return None
    try:
        return getattr(runtime.core_manager.get("softether"), "_backend", None)
    except Exception:  # absent/unloaded core is a runtime state, not an error
        return None


def _probe(runtime: Any | None) -> dict[str, Any]:
    backend = _backend(runtime)
    if backend is None:
        return {
            "state": SupportState.NOT_INSTALLED,
            "version": None,
            "commands": set(),
            "evidence": ["SoftEther core is not installed in CoreManager"],
            "reason": "SoftEther server runtime is not installed",
        }
    vpncmd = getattr(backend, "vpncmd_binary", lambda: None)()
    vpnserver = getattr(backend, "server_binary", lambda: None)()
    version = getattr(backend, "version", lambda: None)()
    evidence = [
        f"vpncmd={vpncmd or 'missing'}",
        f"vpnserver={vpnserver or 'missing'}",
        f"version={version or 'unknown'}",
    ]
    if not vpncmd or not vpnserver:
        return {
            "state": SupportState.NOT_INSTALLED,
            "version": version,
            "commands": set(),
            "evidence": evidence,
            "reason": "vpnserver and vpncmd are both required for a server capability probe",
        }
    try:
        if hasattr(backend, "server_command_inventory"):
            commands = set(backend.server_command_inventory())
        else:
            commands = parse_server_command_inventory(
                backend._cmd("Help", hub=False))  # noqa: SLF001 - adapter seam
    except Exception as exc:  # stopped/auth-limited runtime stays distinguishable
        return {
            "state": SupportState.ENVIRONMENT_LIMITED,
            "version": version,
            "commands": set(),
            "evidence": [*evidence, f"Help probe failed: {type(exc).__name__}"],
            "reason": f"live vpncmd command inventory is unavailable: {type(exc).__name__}: {exc}",
        }
    evidence.append(f"vpncmd server command count={len(commands)}")
    return {
        "state": SupportState.SUPPORTED,
        "version": version,
        "commands": commands,
        "evidence": evidence,
        "reason": None,
    }


def softether_transport_capabilities(runtime: Any | None = None) -> dict[str, dict[str, dict]]:
    """Return transport-specific server and outbound-client facts.

    OpenVPN compatibility deliberately maps to the real, standard ``openvpn``
    outbound.  It is not relabelled as a SoftEther client.  Every other client
    family stays unsupported until a dedicated provider/lifecycle adapter
    exists, even if somebody manually drops a binary on PATH.
    """

    probe = _probe(runtime)
    commands: set[str] = probe["commands"]
    result: dict[str, dict[str, dict]] = {}
    for transport, required_tuple in _REQUIRED_SERVER_COMMANDS.items():
        required = set(required_tuple)
        observed = sorted(required & commands)
        tcp, udp = _SERVER_NETWORKS[transport]
        if probe["state"] is SupportState.SUPPORTED:
            missing = sorted(required - commands)
            if missing:
                server_state = SupportState.UNSUPPORTED
                server_reason = (
                    f"SoftEther {probe['version'] or 'runtime'} does not expose "
                    f"required server command(s) {missing}; observed {observed}"
                )
            elif transport == "pptp":
                # Defensive: if a future binary gains commands, Zagros still
                # must not claim support before its deploy/listener path exists.
                server_state = SupportState.UNSUPPORTED
                server_reason = (
                    "runtime exposes PPTP commands but the Zagros SoftEther "
                    "driver has no verified PPTP deploy/listener implementation"
                )
            else:
                server_state = SupportState.SUPPORTED
                server_reason = None
        else:
            server_state = probe["state"]
            server_reason = probe["reason"]

        server = SoftEtherDirectionCapability(
            state=server_state,
            direction="inbound",
            dataplane="softether_server_hub",
            tcp=tcp,
            udp=udp,
            tun=False,
            application_level=False,
            accounting=server_state is SupportState.SUPPORTED,
            provider="vpnserver+vpncmd",
            runtime_version=probe["version"],
            required_commands=sorted(required),
            observed_commands=observed,
            evidence=list(probe["evidence"]),
            reason=server_reason,
        )

        kind = _OUTBOUND_KINDS[transport]
        assert kind is not None
        outbound = outbound_capability(kind, runtime)
        if transport == "openvpn":
            client_reason = (
                "SoftEther OpenVPN compatibility is reached by the standard "
                "OpenVPN client/TUN; SoftEther vpnserver is the remote server, "
                "not the local client dataplane."
            )
        else:
            client_reason = outbound.reason
        client = SoftEtherDirectionCapability(
            state=outbound.state,
            direction="outbound",
            dataplane=outbound.dataplane.value,
            tcp="tcp" in outbound.traffic_networks,
            udp="udp" in outbound.traffic_networks,
            tun=outbound.tun,
            application_level=outbound.application_level,
            accounting=outbound.accounting,
            provider=("openvpn client" if transport == "openvpn"
                      else "no Zagros client provider"),
            canonical_outbound_kind=kind.value,
            runtime_version=probe["version"],
            evidence=(
                [*probe["evidence"], "canonical outbound kind=openvpn"]
                if transport == "openvpn" else
                [*probe["evidence"], "no production client lifecycle adapter"]
            ),
            reason=client_reason,
        )
        result[transport] = {
            "server": server.model_dump(mode="json"),
            "client": client.model_dump(mode="json"),
        }
    return result


def apply_softether_wizard_capabilities(
    blueprint: dict[str, Any], runtime: Any | None,
) -> dict[str, Any]:
    """Refine the static wizard blueprint with this exact live binary."""

    matrix = softether_transport_capabilities(runtime)
    for protocol in blueprint.get("protocols", []):
        transport = _WIZARD_PROTOCOLS.get(str(protocol.get("id")))
        if not transport:
            continue
        capability = matrix[transport]["server"]
        protocol["availability"] = capability["state"]
        protocol["reason"] = capability.get("reason")
        protocol["capability"] = capability
        if capability["state"] != SupportState.SUPPORTED.value:
            protocol["transports"] = []
    blueprint["transport_capabilities"] = matrix
    return blueprint
