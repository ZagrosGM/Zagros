"""Native Zagros node support (panel side).

The legacy Marzban Xray-only node transport (rpyc, ``app/xray/node.py``) has
been removed: a Zagros node is a separate, Docker-deployed agent that can
host **every** core the panel supports, driven over a certificate-pinned
HTTPS control plane with HMAC-signed commands.

* :mod:`app.nodes.models`  — API schemas and the pairing state machine
* :mod:`app.nodes.client`  — signed client + bootstrap discovery
* :mod:`app.nodes.service` — pairing, inventory, lifecycle, config sync
* :mod:`app.nodes.signing` — the wire-signature contract (shared with the agent)

The agent itself lives in its own repository:
https://github.com/ZagrosGM/zagros-node
"""
from app.nodes.client import (
    NodeClientError,
    ZagrosNodeClient,
    fetch_node_info,
    fetch_pinned_certificate,
)
from app.nodes.service import (
    core_lifecycle,
    core_logs,
    core_settings,
    create_node,
    delete_node,
    discover,
    get_node,
    heartbeat,
    installer_command,
    list_nodes,
    node_cores,
    pair,
    sync_node,
    update_core_settings,
    update_node,
)

__all__ = [
    "NodeClientError", "ZagrosNodeClient", "fetch_node_info",
    "fetch_pinned_certificate", "create_node", "installer_command",
    "list_nodes", "get_node", "discover", "pair", "heartbeat", "node_cores",
    "core_lifecycle", "core_logs", "core_settings", "update_core_settings",
    "sync_node", "update_node", "delete_node",
]
