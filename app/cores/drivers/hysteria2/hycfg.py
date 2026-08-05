"""Pure helpers for the Hysteria2 driver (no IO — fixture-testable).

  * :func:`render_server_yaml` — deterministic server config for our fixed
    schema (no pyyaml dependency; the subset we emit is hand-rolled).
  * :func:`render_client_share` — `hysteria2://` share URL (sealed channel).
  * traffic-API payload models (``/traffic`` cumulative counters, ``/online``
    per-user client-instance counts) parsed defensively.
"""
from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Hy2User:
    name: str
    password: str


def render_server_yaml(
    *,
    listen: str,
    port: int,
    cert_path: str,
    key_path: str,
    users: list[Hy2User],
    masquerade_url: str,
    traffic_listen: str,
    traffic_secret: str | None = None,
    bandwidth_up: str | None = None,
    bandwidth_down: str | None = None,
    obfs_password: str | None = None,
) -> str:
    """Render the hysteria2 server config (authoritative fields only)."""
    lines = [
        f"listen: :{port}" if listen in ("0.0.0.0", "::", "") else f"listen: {listen}:{port}",
        "",
        "tls:",
        f"  cert: {cert_path}",
        f"  key: {key_path}",
        "",
        "auth:",
        "  type: userpass",
        "  userpass:",
    ]
    for user in users:
        lines.append(f"    {user.name}: {user.password}")
    if not users:
        lines[-1] += " {}"  # userpass: {} — valid empty map when no users yet

    lines += [
        "",
        "masquerade:",
        "  type: proxy",
        "  proxy:",
        f"    url: {masquerade_url}",
        "    rewriteHost: true",
        "",
        # official key is camelCase `trafficStats` (verified against the real
        # binary: it silently ignores the snake_case variant and binds nothing)
        "trafficStats:",
        f"  listen: {traffic_listen}",
    ]
    if traffic_secret:
        lines.append(f"  secret: {traffic_secret}")
    if obfs_password:
        lines += [
            "",
            "obfs:",
            "  type: salamander",
            f"  salamander:",
            f"    password: {obfs_password}",
        ]
    if bandwidth_up or bandwidth_down:
        lines += ["", "bandwidth:"]
        if bandwidth_up:
            lines.append(f"  up: {bandwidth_up}")
        if bandwidth_down:
            lines.append(f"  down: {bandwidth_down}")
    return "\n".join(lines) + "\n"


def render_client_share(
    *,
    name: str,
    password: str,
    host: str,
    port: int,
    sni: str | None = None,
    insecure: bool = False,
    obfs_password: str | None = None,
    remark: str = "",
) -> str:
    """hysteria2://share URL (standard format used by clients)."""
    query: dict[str, str] = {}
    if sni:
        query["sni"] = sni
    if insecure:
        query["insecure"] = "1"
    if obfs_password:
        query["obfs"] = "salamander"
        query["obfs-password"] = obfs_password
    qs = urllib.parse.urlencode(query)
    user = urllib.parse.quote(name, safe="")
    frag = urllib.parse.quote(remark, safe="")
    url = f"hysteria2://{user}:{urllib.parse.quote(password, safe='')}@{host}:{port}"
    if qs:
        url += f"/?{qs}"
    if frag:
        url += f"#{frag}"
    return url


def parse_traffic(body: str) -> dict[str, tuple[int, int]]:
    """Parse GET /traffic → {user: (uplink_bytes, downlink_bytes)}.

    Field semantics (official docs): ``tx`` = upload *from the client's
    perspective* (client → server ⇒ the user's UPLINK), ``rx`` = download
    (server → client ⇒ the user's DOWNLINK).
    """
    data = json.loads(body)
    out: dict[str, tuple[int, int]] = {}
    for user, counters in (data or {}).items():
        if not isinstance(counters, dict):
            continue
        tx = int(counters.get("tx", 0) or 0)
        rx = int(counters.get("rx", 0) or 0)
        out[str(user)] = (tx, rx)
    return out


def parse_online(body: str) -> dict[str, int]:
    """Parse GET /online → {user: connection_count} (client instances)."""
    data = json.loads(body)
    return {str(user): int(count) for user, count in (data or {}).items()}
