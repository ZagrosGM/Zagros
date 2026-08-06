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
    CORE = "core"          # chain target: another managed core instance


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
        elif self.kind in (
            OutboundKind.SOCKS, OutboundKind.HTTP, OutboundKind.VLESS,
            OutboundKind.VMESS, OutboundKind.TROJAN, OutboundKind.SHADOWSOCKS,
            OutboundKind.WIREGUARD, OutboundKind.HYSTERIA2, OutboundKind.TUIC,
            OutboundKind.OPENVPN, OutboundKind.SSH,
        ):
            if not self.settings.get("server"):
                raise ValueError(f"Outbound '{self.name}': kind={self.kind.value} requires settings.server.")
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
