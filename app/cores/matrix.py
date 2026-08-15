"""Canonical cross-core operational capability matrix.

These cells describe implemented product paths, not protocol folklore.  The
matrix is consumed as structured data by the admin API and regression tests;
protocol-specific wizard/outbound availability uses the same five states.
"""
from __future__ import annotations

from app.cores.types import CoreFeatureCapability, FeatureAvailability

S = FeatureAvailability.SUPPORTED
U = FeatureAvailability.UNSUPPORTED
E = FeatureAvailability.ENVIRONMENT_LIMITED
N = FeatureAvailability.NOT_APPLICABLE

FEATURES = (
    "inbound", "outbound", "routing_source", "routing_destination", "tun",
    "traffic_accounting", "host_settings", "subscription", "tls",
    "version_probe", "node_support",
)


def _cell(state: FeatureAvailability, detail: str) -> CoreFeatureCapability:
    return CoreFeatureCapability(state=state, detail=detail)


# Evidence anchors are the adapter methods/capabilities named in each detail.
# Keeping this in one module prevents per-UI allow/deny lists.
_PROFILES: dict[str, dict[str, CoreFeatureCapability]] = {
    "xray": {
        "inbound": _cell(S, "Config Studio inbounds + Xray renderer"),
        "outbound": _cell(S, "native Xray deploy_outbounds renderer"),
        "routing_source": _cell(S, "native Xray routing rules"),
        "routing_destination": _cell(S, "native named Xray outbounds"),
        "tun": _cell(N, "Xray routing is in-process; shared host TUN is provided by sing-box"),
        "traffic_accounting": _cell(S, "gRPC per-account counters"),
        "host_settings": _cell(S, "legacy Xray host expansion"),
        "subscription": _cell(S, "driver delivery descriptors + share links"),
        "tls": _cell(S, "TLS/REALITY inbound renderer"),
        "version_probe": _cell(S, "binary/legacy adapter version probe"),
        "node_support": _cell(S, "native signed Zagros node agent; legacy Xray path remains migration-only"),
    },
    "sing-box": {
        "inbound": _cell(S, "Config Studio + sing-box renderer"),
        "outbound": _cell(S, "native sing-box deploy_outbounds renderer"),
        "routing_source": _cell(S, "native sing-box route rules"),
        "routing_destination": _cell(S, "native named sing-box outbounds"),
        "tun": _cell(S, "shared Linux policy TUN adapter"),
        "traffic_accounting": _cell(S, "V2Ray-compatible traffic stats adapter"),
        "host_settings": _cell(S, "core-host delivery expansion"),
        "subscription": _cell(S, "driver delivery descriptors + share links"),
        "tls": _cell(S, "TLS/REALITY inbound renderer"),
        "version_probe": _cell(S, "sing-box version command"),
        "node_support": _cell(S, "native signed Zagros node agent reuses this CoreManager adapter"),
    },
    "openvpn": {
        "inbound": _cell(S, "real OpenVPN server listener processes"),
        "outbound": _cell(S, "real OpenVPN client policy domain"),
        "routing_source": _cell(S, "source subnet classification in Linux policy plane"),
        "routing_destination": _cell(S, "isolated OpenVPN client interface/table"),
        "tun": _cell(S, "OpenVPN tun client interface"),
        "traffic_accounting": _cell(S, "management interface/session counters"),
        "host_settings": _cell(S, "core-host delivery expansion"),
        "subscription": _cell(S, "OpenVPN profile delivery"),
        "tls": _cell(S, "OpenVPN PKI/TLS"),
        "version_probe": _cell(S, "openvpn --version"),
        "node_support": _cell(S, "native signed Zagros node agent reuses this CoreManager adapter"),
    },
    "wireguard": {
        "inbound": _cell(S, "real kernel WireGuard interfaces"),
        "outbound": _cell(S, "real WireGuard client policy domain"),
        "routing_source": _cell(S, "source subnet classification in Linux policy plane"),
        "routing_destination": _cell(S, "isolated WireGuard interface/table"),
        "tun": _cell(S, "kernel WireGuard interface"),
        "traffic_accounting": _cell(S, "wg peer transfer counters"),
        "host_settings": _cell(S, "core-host delivery expansion"),
        "subscription": _cell(S, "WireGuard profile delivery"),
        "tls": _cell(N, "WireGuard uses NoiseIK, not TLS"),
        "version_probe": _cell(S, "wg --version parser"),
        "node_support": _cell(S, "native signed Zagros node agent reuses this CoreManager adapter"),
    },
    "ssh": {
        "inbound": _cell(S, "real OpenSSH listener/account management"),
        "outbound": _cell(S, "managed OpenSSH dynamic-forward TCP application proxy"),
        "routing_source": _cell(S, "per-UID TCP classification in Linux policy plane"),
        "routing_destination": _cell(E, "TCP application-level SOCKS only; not a policy TUN"),
        "tun": _cell(U, "OpenSSH dynamic forwarding does not provide an IP TUN dataplane"),
        "traffic_accounting": _cell(S, "SFTP/SCP stream counters + per-UID bidirectional conntrack forwarding counters"),
        "host_settings": _cell(S, "core-host delivery expansion"),
        "subscription": _cell(S, "SSH credential/config delivery"),
        "tls": _cell(N, "SSH transport is not TLS"),
        "version_probe": _cell(S, "sshd -V parser"),
        "node_support": _cell(S, "native signed Zagros node agent reuses this CoreManager adapter"),
    },
    "softether": {
        "inbound": _cell(S, "vpnserver/vpncmd hub features"),
        "outbound": _cell(U, "server-only runtime; no vpnclient service/adapter"),
        "routing_source": _cell(S, "routed TAP source subnet (shared hub decision)"),
        "routing_destination": _cell(U, "SoftEther server cannot dial a client egress"),
        "tun": _cell(U, "no supported SoftEther client policy domain"),
        "traffic_accounting": _cell(S, "vpncmd user/session counters"),
        "host_settings": _cell(S, "core-host delivery expansion"),
        "subscription": _cell(S, "L2TP/SSTP/OpenVPN/native delivery descriptors"),
        "tls": _cell(S, "native SoftEther/SSTP TLS server"),
        "version_probe": _cell(S, "vpncmd version parser"),
        "node_support": _cell(S, "native signed Zagros node agent reuses this CoreManager adapter"),
    },
}


def capability_matrix(
    core_ids: list[str] | None = None,
    *,
    installed: set[str] | None = None,
) -> dict[str, dict[str, dict]]:
    """Static product matrix, optionally refined by runtime installation.

    Unsupported/not-applicable product facts remain facts on an absent core;
    implementation-backed cells become the distinct ``not_installed`` state.
    """
    ids = core_ids if core_ids is not None else list(_PROFILES)
    result: dict[str, dict[str, dict]] = {}
    for core_id in ids:
        if core_id not in _PROFILES:
            continue
        cells: dict[str, dict] = {}
        for feature in FEATURES:
            cell = _PROFILES[core_id][feature]
            if (installed is not None and core_id not in installed
                    and cell.state in (S, E)):
                cell = _cell(
                    FeatureAvailability.NOT_INSTALLED,
                    f"{core_id} is not installed; implementation: {cell.detail}")
            cells[feature] = cell.model_dump(mode="json")
        result[core_id] = cells
    return result
