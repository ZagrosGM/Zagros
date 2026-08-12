"""Strict WireGuard client-profile importer for outbound configuration.

Only client material is accepted: one [Interface], one [Peer], valid key
shapes, at least one local Address and one Endpoint.  The parser performs no
IO and never logs/returns a profile's private material outside the authenticated
admin response that requested the import.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import re
from typing import Any


class WireGuardProfileError(ValueError):
    pass


def _key(value: str, label: str, *, optional: bool = False) -> str:
    value = (value or "").strip()
    if optional and not value:
        return ""
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise WireGuardProfileError(f"{label} must be a base64 WireGuard key") from exc
    if len(raw) != 32:
        raise WireGuardProfileError(f"{label} must decode to exactly 32 bytes")
    return value


def _list(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _endpoint(value: str) -> tuple[str, int]:
    value = (value or "").strip()
    match = re.fullmatch(r"\[([^]]+)]:(\d+)", value)
    if match:
        host, port_raw = match.groups()
    else:
        try:
            host, port_raw = value.rsplit(":", 1)
        except ValueError as exc:
            raise WireGuardProfileError(
                "Peer Endpoint must be host:port (IPv6 must use [address]:port)"
            ) from exc
    host = host.strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise WireGuardProfileError("Peer Endpoint port must be an integer") from exc
    if not host or not 1 <= port <= 65535:
        raise WireGuardProfileError("Peer Endpoint must contain a valid host and port")
    return host, port


def parse_wireguard_profile(content: str) -> dict[str, Any]:
    text = (content or "").lstrip("\ufeff").strip()
    if not text:
        raise WireGuardProfileError("WireGuard profile is empty")
    if len(re.findall(r"(?im)^\s*\[peer]\s*$", text)) != 1:
        raise WireGuardProfileError("WireGuard outbound import requires exactly one [Peer]")
    parser = configparser.ConfigParser(
        interpolation=None, strict=True, inline_comment_prefixes=("#", ";"))
    parser.optionxform = str.lower
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise WireGuardProfileError(f"invalid WireGuard INI profile: {exc}") from exc
    if set(parser.sections()) != {"Interface", "Peer"}:
        raise WireGuardProfileError(
            "WireGuard profile must contain exactly [Interface] and [Peer]")
    interface, peer = parser["Interface"], parser["Peer"]
    private_key = _key(interface.get("privatekey", ""), "Interface PrivateKey")
    peer_public_key = _key(peer.get("publickey", ""), "Peer PublicKey")
    preshared_key = _key(
        peer.get("presharedkey", ""), "Peer PresharedKey", optional=True)
    addresses = _list(interface.get("address", ""))
    if not addresses:
        raise WireGuardProfileError("Interface Address is required")
    try:
        addresses = [str(ipaddress.ip_interface(value)) for value in addresses]
    except ValueError as exc:
        raise WireGuardProfileError(f"invalid Interface Address: {exc}") from exc
    allowed_ips = _list(peer.get("allowedips", "")) or ["0.0.0.0/0", "::/0"]
    try:
        allowed_ips = [str(ipaddress.ip_network(value, strict=False)) for value in allowed_ips]
    except ValueError as exc:
        raise WireGuardProfileError(f"invalid Peer AllowedIPs: {exc}") from exc
    server, server_port = _endpoint(peer.get("endpoint", ""))
    settings: dict[str, Any] = {
        "server": server,
        "server_port": server_port,
        "private_key": private_key,
        "peer_public_key": peer_public_key,
        "local_address": addresses,
        "allowed_ips": allowed_ips,
    }
    if preshared_key:
        settings["preshared_key"] = preshared_key
    dns = _list(interface.get("dns", ""))
    if dns:
        settings["dns"] = dns
    for ini_key, output_key, default, low, high, section in (
        ("mtu", "mtu", 1420, 576, 9000, interface),
        ("persistentkeepalive", "keepalive", 25, 0, 65535, peer),
    ):
        raw = section.get(ini_key, "")
        if not raw:
            settings[output_key] = default
            continue
        try:
            number = int(raw)
        except ValueError as exc:
            raise WireGuardProfileError(f"{ini_key} must be an integer") from exc
        if not low <= number <= high:
            raise WireGuardProfileError(f"{ini_key} must be between {low} and {high}")
        settings[output_key] = number
    return settings
