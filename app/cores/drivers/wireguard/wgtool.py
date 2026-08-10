"""Pure helpers around the `wg` wireguard-tools command line.

Everything here is deterministic text↔model logic with **no IO**, so it is
exhaustively unit-testable with captured fixtures:

  * :func:`parse_wg_dump` — `wg show all dump` output → structured peers
    (this is the ONLY realistic source of per-peer rx/tx/handshake data).
  * :func:`strip_config`  — equivalent of `wg-quick strip`: reduce a full
    interface config to the subset `wg syncconf` accepts (live apply).
  * :func:`render_interface` / :func:`render_client` — INI renderers.
  * key validation + free-IP allocation helpers.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def is_valid_key(value: str) -> bool:
    """WireGuard keys are 32-byte Curve25519 values, base64-encoded (44 chars)."""
    return bool(_KEY_RE.match(value))


@dataclass(frozen=True, slots=True)
class PeerStat:
    interface: str
    public_key: str
    preshared_key: str | None
    endpoint: str | None              # "host:port" as reported by wg (or None)
    allowed_ips: tuple[str, ...]
    latest_handshake: int             # unix seconds; 0 = never
    transfer_rx: int                  # bytes client→server (server received)
    transfer_tx: int                  # bytes server→client (server sent)
    persistent_keepalive: int


@dataclass(frozen=True, slots=True)
class WireGuardDump:
    interfaces: tuple[str, ...]
    peers: tuple[PeerStat, ...]
    listen_ports: dict[str, int] = field(default_factory=dict)


def parse_wg_dump(text: str) -> WireGuardDump:
    """Parse `wg show all dump` (machine-readable, tab-separated).

    Interface line: if\\tpriv\\tpub\\tlisten\\tfwmark
    Peer line:      if\\tpub\\tpsk\\tendpoint\\tallowed\\thandshake\\trx\\ttx\\tkeepalive
    """
    interfaces: dict[str, int] = {}
    seen_order: list[str] = []
    peers: list[PeerStat] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        cols = line.split("\t")
        if len(cols) == 5:  # interface
            name, _priv, _pub, listen, _fwmark = cols
            interfaces[name] = int(listen)
            seen_order.append(name)
        elif len(cols) >= 9:  # peer (allowed-ips may contain no tabs; safe)
            (name, pubkey, psk, endpoint, allowed,
             handshake, rx, tx, keepalive) = cols[:9]
            peers.append(PeerStat(
                interface=name,
                public_key=pubkey,
                preshared_key=None if psk == "(none)" else psk,
                endpoint=None if endpoint == "(none)" else endpoint,
                allowed_ips=tuple(a.strip() for a in allowed.split(",") if a.strip()),
                latest_handshake=int(handshake),
                transfer_rx=int(rx),
                transfer_tx=int(tx),
                persistent_keepalive=int(keepalive),
            ))
        else:  # pragma: no cover - defensive: unknown row from newer wg
            continue
    return WireGuardDump(
        interfaces=tuple(seen_order),
        peers=tuple(peers),
        listen_ports=interfaces,
    )


# ---------------------------------------------------------------------- #
# config rendering + stripping                                           #
# ---------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class DesiredPeer:
    """Panel-desired state of one peer (what MUST exist in the interface)."""

    comment: str                      # account id (rendered as INI comment)
    public_key: str
    allowed_ips: tuple[str, ...]
    preshared_key: str | None = None


# Standard forwarding/NAT hook block. IPv4 forwarding is deliberately NOT a
# PostUp sysctl: Docker host-network containers mount /proc/sys read-only, so
# changing it after interface creation fails and leaves a half-started tunnel.
# LocalWireGuardBackend preflights forwarding before wg-quick; the installer
# enables and persists it on the host. PostUp/PostDown own firewall state only:
#   * FORWARD accepts for the tunnel interface, `-C || -A` = idempotent
#     even across an unclean flap (no duplicated rules ever);
#   * MASQUERADE is scoped to this tunnel's source subnet and the default-route
#     interface discovered at runtime (no fake eth0; no cross-core rule theft);
#   * PostDown removes exactly the rules PostUp added (`|| true` keeps a
#     partially-applied prior state from breaking teardown).
# `wg syncconf` never sees these lines (strip drops every Post* key), so
# live peer updates stay non-disruptive.
_FORWARD_NAT_HOOKS: tuple[str, ...] = (
    "PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || "
    "iptables -A FORWARD -i %i -j ACCEPT",
    "PostUp = iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || "
    "iptables -A FORWARD -o %i -j ACCEPT",
    'PostUp = IF=$(ip route show default 2>/dev/null | '
    "awk '/^default/ {print $5; exit}'); if [ -n \"$IF\" ]; then "
    'iptables -t nat -C POSTROUTING -s {source} -o "$IF" -j MASQUERADE 2>/dev/null || '
    'iptables -t nat -A POSTROUTING -s {source} -o "$IF" -j MASQUERADE; fi',
    "PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true",
    "PostDown = iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true",
    'PostDown = IF=$(ip route show default 2>/dev/null | '
    "awk '/^default/ {print $5; exit}'); if [ -n \"$IF\" ]; then "
    'iptables -t nat -D POSTROUTING -s {source} -o "$IF" -j MASQUERADE 2>/dev/null || true; fi',
)


def render_interface(
    *,
    private_key: str,
    address: str,
    listen_port: int,
    peers: list[DesiredPeer],
    dns: list[str] | None = None,
    table_off: bool = True,
    forward_nat: bool = False,
) -> str:
    """Full wg-quick compatible interface file.

    ``forward_nat=True`` appends the PostUp/PostDown forwarding+MASQUERADE
    hook block (item 12) — required for the panel's default full-tunnel
    client configs to actually carry traffic.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    if table_off:
        lines.append("Table = off")
    if forward_nat:
        source = str(ipaddress.ip_interface(address).network)
        lines += [hook.replace("{source}", source) for hook in _FORWARD_NAT_HOOKS]
    for peer in peers:
        lines += [
            "",
            f"# {peer.comment}",
            "[Peer]",
            f"PublicKey = {peer.public_key}",
        ]
        if peer.preshared_key:
            lines.append(f"PresharedKey = {peer.preshared_key}")
        lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")
    return "\n".join(lines) + "\n"


_STRIPPED_IFACE_KEYS = {"privatekey", "listenport", "fwmark"}
_STRIPPED_PEER_KEYS = {"publickey", "presharedkey", "allowedips", "persistentkeepalive"}


def strip_config(config_text: str) -> str:
    """`wg-quick strip` equivalent: keep only keys `wg setconf/syncconf` know.

    Deterministic re-implementation (we cannot rely on wg-quick being present
    at strip time in minimal containers).
    """
    sections: list[list[str]] = []
    current: list[str] = []
    section = ""
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            current = [line.lower()]
            sections.append(current)
            section = line.strip("[]").strip().lower()
            current[0] = f"[{'Interface' if section == 'interface' else 'Peer'}]"
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        key_l = key.lower()
        if section == "interface" and key_l in _STRIPPED_IFACE_KEYS:
            current.append(f"{key} = {value}")
        elif section == "peer" and key_l in _STRIPPED_PEER_KEYS:
            current.append(f"{key} = {value}")
    # drop empty sections (e.g. an Interface with no kept keys is still valid)
    rendered = ["\n".join(sec) for sec in sections if len(sec) > 1 or sec[0] == "[Peer]"]
    return "\n\n".join(rendered) + "\n"


def render_client(
    *,
    private_key: str,
    address: str,
    server_public_key: str,
    endpoint_host: str,
    endpoint_port: int,
    preshared_key: str | None = None,
    dns: list[str] | None = None,
    allowed_ips: tuple[str, ...] = ("0.0.0.0/0", "::/0"),
    persistent_keepalive: int = 25,
    mtu: int | None = None,
) -> str:
    """Client-side INI (the sealed payload for the app / QR)."""
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
    ]
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines += [
        f"AllowedIPs = {', '.join(allowed_ips)}",
        f"Endpoint = {endpoint_host}:{endpoint_port}",
        f"PersistentKeepalive = {persistent_keepalive}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- #
# IP allocation                                                          #
# ---------------------------------------------------------------------- #

def allocate_address(subnet: str, taken: set[str]) -> str:
    """Pick the lowest free host address in *subnet* as a /32 (or /128).

    The first host is always reserved for the server (see :func:`server_address`).
    Deterministic (lowest-first) → stable assignments across restarts when
    the set of accounts is unchanged.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = network.hosts()
    server_ip = next(hosts, None)
    if server_ip is None:
        raise ValueError(f"subnet {subnet} has no usable host addresses")
    for host in hosts:  # iteration starts at the second host
        candidate = f"{host}/{network.max_prefixlen}"
        if candidate not in taken:
            return candidate
    raise ValueError(f"subnet {subnet} exhausted — no free peer addresses")


def server_address(subnet: str) -> str:
    """Interface address of the server inside *subnet* (first host)."""
    network = ipaddress.ip_network(subnet, strict=False)
    first = next(iter(network.hosts()), None)
    if first is None:  # pragma: no cover - /32 subnets are useless for servers
        raise ValueError(f"subnet {subnet} has no usable host address")
    return f"{first}/{network.prefixlen}"
