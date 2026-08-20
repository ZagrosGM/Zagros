"""Core-agnostic outbound model for the central Outbound Manager.

An outbound is *what traffic leaves through*: direct, a sink (block/blackhole),
a DNS handler, a classic proxy (socks/http), an upstream VPN server
(vless/wireguard/hysteria2/...), or **another panel core** (``CORE``) — the
building block of chain routing. Drivers translate each outbound they can
handle natively and explicitly report the rest.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class OutboundKind(str, Enum):
    DIRECT = "direct"
    BLOCK = "block"
    BLACKHOLE = "blackhole"
    DNS = "dns"
    SOCKS = "socks"
    HTTP = "http"
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"
    WIREGUARD = "wireguard"
    HYSTERIA2 = "hysteria2"
    TUIC = "tuic"
    OPENVPN = "openvpn"
    SSH = "ssh"
    # Canonical independent Linux client providers.  L2TP/SSTP profiles may
    # target SoftEther compatibility listeners, but their local engines are
    # PPP/IPsec clients — never SoftEther vpnclient aliases.
    L2TP_IPSEC = "l2tp_ipsec"
    L2TP_RAW = "l2tp_raw"
    SSTP = "sstp"
    PPTP = "pptp"
    # SoftEther transport families are direction-specific. Native uses the
    # separately installed vpnclient engine and a real isolated Virtual NIC;
    # the other labels remain visible but unsupported until their distinct
    # Linux client providers/lifecycles exist.
    SOFTETHER_L2TP = "softether_l2tp"
    SOFTETHER_L2TP_RAW = "softether_l2tp_raw"
    SOFTETHER_SSTP = "softether_sstp"
    SOFTETHER_PPTP = "softether_pptp"
    SOFTETHER_NATIVE = "softether_native"
    CORE = "core"          # chain target: another managed core instance


PPP_CLIENT_KINDS = frozenset({
    OutboundKind.L2TP_IPSEC,
    OutboundKind.L2TP_RAW,
    OutboundKind.SSTP,
    OutboundKind.PPTP,
})

LEGACY_SOFTETHER_OUTBOUND_KINDS = frozenset({
    # Historical public IDs retained only so encrypted legacy rows remain
    # parseable/redactable/deletable. They are never public selectors and new
    # writes remain unsupported; canonical providers are the independent PPP
    # kinds plus SOFTETHER_NATIVE.
    OutboundKind.SOFTETHER_L2TP,
    OutboundKind.SOFTETHER_L2TP_RAW,
    OutboundKind.SOFTETHER_SSTP,
    OutboundKind.SOFTETHER_PPTP,
})

SOFTETHER_CLIENT_KINDS = frozenset({
    *LEGACY_SOFTETHER_OUTBOUND_KINDS,
    OutboundKind.SOFTETHER_NATIVE,
})

SOFTETHER_CLIENT_LIMITATION = (
    "The native SoftEther protocol has a dedicated vpnclient/Virtual-NIC "
    "implementation. L2TP, raw L2TP, SSTP and PPTP are different client "
    "protocols and remain disabled until a separately verified provider and "
    "transactional lifecycle exists."
)


class Outbound(BaseModel):
    """A named, typed egress definition.

    For ``kind=CORE``: ``settings = {"core_id": "wireguard", "protocol": "socks",
    "port": 41001}`` — protocol/port are *preferences* the manager resolves via
    the target core's chain endpoints. For upstream kinds: ``server``,
    ``server_port`` and protocol-specific credentials in ``settings``.
    """

    # Case-insensitive start-any-alnum: uppercase letters are legitimate in
    # outbound names (bug fix alpha.7 — the previous lowercase-only pattern
    # rejected names like "Warp-EU" with no good reason). Length 2..64.
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9\-_.]{1,63}$")
    kind: OutboundKind
    settings: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @model_validator(mode="after")
    def _validate(self) -> "Outbound":
        if self.kind is OutboundKind.CORE:
            if not self.settings.get("core_id"):
                raise ValueError(f"Outbound '{self.name}': kind=core requires settings.core_id.")
        policy_core = str(self.settings.get("policy_core") or "").strip().lower()
        if policy_core not in ("", "sing-box", "xray"):
            raise ValueError(
                f"Outbound '{self.name}': settings.policy_core must be xray or sing-box")
        if policy_core == "xray" and self.kind not in {
            OutboundKind.SOCKS, OutboundKind.HTTP, OutboundKind.VLESS,
            OutboundKind.VMESS, OutboundKind.TROJAN, OutboundKind.SHADOWSOCKS,
        }:
            raise ValueError(
                f"Outbound '{self.name}': kind={self.kind.value} has no Xray policy runtime")
        if self.kind in (
            OutboundKind.SOCKS, OutboundKind.HTTP, OutboundKind.VLESS,
            OutboundKind.VMESS, OutboundKind.TROJAN, OutboundKind.SHADOWSOCKS,
            OutboundKind.WIREGUARD, OutboundKind.HYSTERIA2, OutboundKind.TUIC,
            OutboundKind.OPENVPN, OutboundKind.SSH,
            OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW,
            OutboundKind.SSTP, OutboundKind.PPTP,
            OutboundKind.SOFTETHER_NATIVE,
        ):
            # A full uploaded OpenVPN profile carries its own remote/proto;
            # requiring duplicate form fields made Upload succeed visually but
            # Save/Test fail validation before the profile could be parsed.
            profile_supplies_endpoint = (
                self.kind is OutboundKind.OPENVPN
                and bool(str(self.settings.get("ovpn_content") or "").strip())
            )
            if not self.settings.get("server") and not profile_supplies_endpoint:
                raise ValueError(f"Outbound '{self.name}': kind={self.kind.value} requires settings.server.")
        if self.kind is OutboundKind.SOFTETHER_NATIVE:
            import re

            missing = [key for key in ("server_port", "hub", "username", "password")
                       if not self.settings.get(key)]
            if missing:
                raise ValueError(
                    f"Outbound '{self.name}': native SoftEther requires "
                    + ", ".join(missing)
                )
            hub = str(self.settings["hub"])
            username = str(self.settings["username"])
            secret = str(self.settings["password"])
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,31}", hub):
                raise ValueError(f"Outbound '{self.name}': invalid SoftEther hub")
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
                raise ValueError(f"Outbound '{self.name}': invalid SoftEther username")
            if (len(secret) > 128 or any(ch.isspace() or ch in {'\"', "'"}
                                         for ch in secret)):
                raise ValueError(
                    f"Outbound '{self.name}': SoftEther password must be 1-128 "
                    "non-whitespace characters without quotes"
                )
        if self.kind in PPP_CLIENT_KINDS:
            import ipaddress
            import re

            required = ["server_port", "username", "password"]
            if self.kind is OutboundKind.L2TP_IPSEC:
                required.append("ipsec_psk")
            missing = [key for key in required if self.settings.get(key) in (None, "")]
            if missing:
                raise ValueError(
                    f"Outbound '{self.name}': {self.kind.value} requires "
                    + ", ".join(missing)
                )
            try:
                port = int(self.settings["server_port"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Outbound '{self.name}': invalid server_port") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"Outbound '{self.name}': invalid server_port")
            if self.kind in (OutboundKind.L2TP_IPSEC, OutboundKind.L2TP_RAW) \
                    and port != 1701:
                raise ValueError(
                    f"Outbound '{self.name}': {self.kind.value} uses fixed UDP/1701")
            if self.kind is OutboundKind.PPTP and port != 1723:
                raise ValueError(
                    f"Outbound '{self.name}': PPTP control port is fixed to TCP/1723")
            username = str(self.settings.get("username") or "")
            if not re.fullmatch(r"[^\x00\r\n]{1,190}", username):
                raise ValueError(f"Outbound '{self.name}': invalid PPP username")
            for key in ("password", "ipsec_psk"):
                if key not in self.settings:
                    continue
                secret = str(self.settings.get(key) or "")
                if not 1 <= len(secret) <= 256 or any(ch in secret for ch in "\x00\r\n"):
                    raise ValueError(
                        f"Outbound '{self.name}': invalid {key} (1-256 chars, no NUL/newline)")
            if self.settings.get("ipv6") is True:
                raise ValueError(
                    f"Outbound '{self.name}': {self.kind.value} is IPv4-only")
            if self.kind in (OutboundKind.L2TP_RAW, OutboundKind.PPTP) \
                    and self.settings.get("legacy_risk_ack") is not True:
                raise ValueError(
                    f"Outbound '{self.name}': {self.kind.value} requires explicit "
                    "legacy/insecure risk acknowledgement")
            probe_url = str(self.settings.get("test_url") or "").strip()
            if probe_url:
                from urllib.parse import urlsplit

                parsed = urlsplit(probe_url)
                if (parsed.scheme != "https" or not parsed.hostname
                        or parsed.username or parsed.password or parsed.fragment):
                    raise ValueError(
                        f"Outbound '{self.name}': test_url must be an HTTPS URL "
                        "without credentials or a fragment")
            probe_ca = str(self.settings.get("probe_ca_pem") or "").strip()
            if probe_ca and "-----BEGIN CERTIFICATE-----" not in probe_ca:
                raise ValueError(
                    f"Outbound '{self.name}': probe_ca_pem is not a PEM certificate")
            raw_samples = self.settings.get("test_samples", 20)
            if raw_samples in (None, ""):
                raw_samples = 20
            try:
                samples = int(raw_samples)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Outbound '{self.name}': test_samples must be 20-30") from exc
            if not 20 <= samples <= 30:
                raise ValueError(
                    f"Outbound '{self.name}': test_samples must be 20-30")
            if self.kind is OutboundKind.SSTP:
                bypasses = (
                    "allow_insecure", "insecure", "cert_warn",
                    "skip_cert_verify", "verify_certificate",
                )
                enabled_bypasses = [key for key in bypasses
                                    if (key == "verify_certificate"
                                        and self.settings.get(key) is False)
                                    or (key != "verify_certificate"
                                        and bool(self.settings.get(key)))]
                if enabled_bypasses:
                    raise ValueError(
                        f"Outbound '{self.name}': SSTP TLS certificate verification "
                        f"cannot be bypassed ({enabled_bypasses})")
                server_name = str(
                    self.settings.get("tls_server_name")
                    or self.settings.get("server") or ""
                ).strip()
                if not server_name or any(ch.isspace() for ch in server_name):
                    raise ValueError(
                        f"Outbound '{self.name}': SSTP needs a valid TLS server name")
                # An IP literal is permitted only when its certificate actually
                # contains that IP SAN; sstpc/OpenSSL performs the live check.
                try:
                    ipaddress.ip_address(server_name)
                except ValueError:
                    if not re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9.-]+", server_name):
                        raise ValueError(
                            f"Outbound '{self.name}': invalid SSTP TLS server name") from None
        return self


class UnsupportedOutbound(BaseModel):
    name: str
    reason: str


class TranslatedOutbound(BaseModel):
    """Per-core result of an outbound deployment."""

    core_id: str
    applied: list[str] = Field(default_factory=list)
    unsupported: list[UnsupportedOutbound] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    payload: list[dict[str, Any]] = Field(default_factory=list)   # native outbounds
    materialized: dict[str, "Outbound"] = Field(default_factory=dict)  # CORE refs resolved

    @property
    def complete(self) -> bool:
        return not self.unsupported


class OutboundDeploymentReport(BaseModel):
    results: dict[str, TranslatedOutbound]
    deployed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def gaps(self) -> dict[str, list[UnsupportedOutbound]]:
        return {cid: r.unsupported for cid, r in self.results.items() if r.unsupported}
