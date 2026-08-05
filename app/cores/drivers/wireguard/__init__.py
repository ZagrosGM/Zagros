"""WireGuard driver package (kernel WireGuard via wireguard-tools)."""
from app.cores.drivers.wireguard.backend import (
    LocalWireGuardBackend,
    WireGuardBackend,
)
from app.cores.drivers.wireguard.driver import WireGuardDriver
from app.cores.drivers.wireguard.wgtool import (
    DesiredPeer,
    PeerStat,
    WireGuardDump,
    allocate_address,
    is_valid_key,
    parse_wg_dump,
    render_client,
    render_interface,
    server_address,
    strip_config,
)

__all__ = [
    "WireGuardDriver",
    "WireGuardBackend",
    "LocalWireGuardBackend",
    "DesiredPeer",
    "PeerStat",
    "WireGuardDump",
    "allocate_address",
    "is_valid_key",
    "parse_wg_dump",
    "render_client",
    "render_interface",
    "server_address",
    "strip_config",
]
